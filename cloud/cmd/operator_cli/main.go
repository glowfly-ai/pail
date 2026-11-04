// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// operator_cli: M9 (LLD-v2 §7.2) operator recovery tool.
//
// Modes:
//
//	print-pubkey  load-or-create the operator keypair, print key_id + pubkey
//	unlock        signed Unlock RPC (SAFE_STOP -> NORMAL)
//	revoke        signed RevokeIssuerKey RPC (* -> LOCKDOWN, permanent)
//
// -nonce-b64/-ts override nonce/timestamp so replay and stale-window
// rejection can be exercised in E2E tests (§9 M9).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"log"
	"time"

	"google.golang.org/grpc"

	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/deploysec"
	"github.com/glowfly/pail/services/internal/grpcauth"
	"github.com/glowfly/pail/services/internal/operator"
	operatorpb "github.com/glowfly/pail/services/proto/operatorv1"
)

func main() {
	mode := flag.String("mode", "print-pubkey", "print-pubkey | unlock | revoke")
	keyfile := flag.String("keyfile", "/etc/pail/keys/operator_ed25519.json", "operator keypair JSON (created if missing)")
	keyID := flag.String("key-id", "op-key-1", "operator key_id (used when creating the keyfile)")
	addr := flag.String("addr", "127.0.0.1:50051", "pail-services gRPC addr")
	robot := flag.String("robot", "robot-1", "robot_id (unlock)")
	// `S17` (§3.7): 기본값 없음. `revoke` 는 되돌릴 수 없는 LOCKDOWN 이고, 기본값이
	// 있으면 **인자를 빠뜨린 실행이 특정 키를 폐기한다.** 무엇을 폐기할지는 사람이
	// 적어야 한다.
	issuerKeyID := flag.String("issuer-key-id", "", "issuer key_id to revoke (revoke; required)")
	nonceB64 := flag.String("nonce-b64", "", "nonce override, base64 (default: 16 random bytes)")
	ts := flag.Int64("ts", 0, "unix_ms override (default: now)")
	useTLS := flag.Bool("tls", grpcauth.TLSEnabled(), "use mTLS (default from PAIL_GRPC_TLS; ignored for unix: addr)")
	caPath := flag.String("ca", "", "CA cert path (default PAIL_GRPC_CA or /etc/pail/grpc_certs/ca.crt)")
	certPath := flag.String("cert", "", "client cert path (default PAIL_GRPC_CERT or /etc/pail/grpc_certs/client.crt)")
	keyPath := flag.String("key", "", "client key path (default PAIL_GRPC_KEY or /etc/pail/grpc_certs/client.key)")
	flag.Parse()

	// `S17` (§3.7). 인자 검사는 **키 파일을 만지기 전에** 한다 — 뒤에 두면 인자를
	// 빠뜨린 실행이 먼저 키 파일을 생성하고 나서 거부된다.
	if *mode == "revoke" {
		if err := deploysec.RequireIssuerKeyID(*issuerKeyID, "-issuer-key-id"); err != nil {
			deploysec.RefuseConfig("operator_cli", err)
		}
	}

	// Provisioning tool: use the existing operator key, and mint one explicitly
	// only when absent. The operator identity must be stable across runs (the
	// server trusts a fixed operator pubkey), so this is load-first, generate-
	// on-absence — never an unconditional (re)generate.
	kp, err := devcrypto.LoadEd25519KeypairJSON(*keyfile, *keyID)
	if errors.Is(err, devcrypto.ErrKeyFileNotFound) {
		kp, err = devcrypto.GenerateEd25519KeypairJSON(*keyfile, *keyID)
	}
	if err != nil {
		log.Fatalf("operator key: %v", err)
	}

	if *mode == "print-pubkey" {
		log.Printf("OPERATOR_KEY_ID=%s", kp.KeyID)
		log.Printf("OPERATOR_PUBKEY_B64=%s", devcrypto.PublicKeyBase64(kp.Public))
		return
	}

	var nonce []byte
	if *nonceB64 != "" {
		nonce, err = base64.StdEncoding.DecodeString(*nonceB64)
		if err != nil {
			log.Fatalf("nonce decode: %v", err)
		}
	} else {
		nonce = make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			log.Fatalf("nonce: %v", err)
		}
	}
	unixMs := *ts
	if unixMs == 0 {
		unixMs = time.Now().UnixMilli()
	}

	dialOpts, err := grpcauth.ToolDialOptions(*addr, *useTLS, *caPath, *certPath, *keyPath)
	if err != nil {
		log.Fatalf("grpc credentials: %v", err)
	}
	conn, err := grpc.Dial(*addr, dialOpts...)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	oc := operatorpb.NewOperatorServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch *mode {
	case "unlock":
		c, err := operator.UnlockCanon(*robot, unixMs, nonce, kp.KeyID)
		if err != nil {
			log.Fatalf("unlock canon: %v", err)
		}
		sig := ed25519.Sign(kp.Private, c)
		resp, err := oc.Unlock(ctx, &operatorpb.UnlockRequest{
			RobotId:       *robot,
			UnixMs:        unixMs,
			Nonce:         nonce,
			OperatorSig:   sig,
			OperatorKeyId: kp.KeyID,
		})
		if err != nil {
			log.Fatalf("Unlock: %v", err)
		}
		log.Printf("unlock accepted=%v detail=%q nonce_b64=%s ts=%d", resp.Accepted, resp.Detail, base64.StdEncoding.EncodeToString(nonce), unixMs)
	case "revoke":
		c, err := operator.RevokeCanon(*issuerKeyID, unixMs, nonce, kp.KeyID)
		if err != nil {
			log.Fatalf("revoke canon: %v", err)
		}
		sig := ed25519.Sign(kp.Private, c)
		resp, err := oc.RevokeIssuerKey(ctx, &operatorpb.RevokeKeyRequest{
			IssuerKeyId:   *issuerKeyID,
			UnixMs:        unixMs,
			Nonce:         nonce,
			OperatorSig:   sig,
			OperatorKeyId: kp.KeyID,
		})
		if err != nil {
			log.Fatalf("RevokeIssuerKey: %v", err)
		}
		log.Printf("revoke accepted=%v detail=%q nonce_b64=%s ts=%d", resp.Accepted, resp.Detail, base64.StdEncoding.EncodeToString(nonce), unixMs)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}
