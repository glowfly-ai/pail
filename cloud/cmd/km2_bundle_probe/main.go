// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Command km2_bundle_probe is the KM2-3 FAIL-first battery probe (KM LLD §8).
//
// It answers the KM2 question at the trust-anchor layer: can an attacker who
// controls the *transport* (the file that carries the keyring) get the gate to
// trust a key the offline root never signed?
//
//	-mode forge-unsigned  (F1): the pre-KM2 status quo. In unsigned-dev mode
//	  the keyring.json IS the trust anchor, so an attacker who swaps it for one
//	  carrying their own pubkey has the gate accept their forged token. Exit 0
//	  == swap succeeded (expected FAIL — this is vulnerability W2 that KM2
//	  bundle mode closes).
//
//	-mode load  (F2..F5): the KM2 posture. LoadKeyringBundle is the ONLY
//	  trusted path; authenticity comes solely from the offline root signature
//	  over the exact payload bytes — never from the file that delivered it.
//	  Give it a bundle and -expect accept|reject. A rejected bundle returns an
//	  error and NO keyring, so the running process keeps the keyring it already
//	  had (fail-closed). This one mode covers self-signed/unsigned swap (F2),
//	  rollback (F3), tamper/truncation (F4) and expiry (F5) — the reject reason
//	  is printed so the evidence names which defense fired.
//
// The forge in F1 signs over the marshaled ActionToken bytes exactly as the
// issuer does (action_token_bytes canon), so a PASS is the same trust decision
// the live gate makes.
package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/protobuf/proto"

	pailcrypto "github.com/glowfly/pail/services/internal/crypto"
	pb "github.com/glowfly/pail/services/proto/pailv1"
)

func forgedTokenBytes(robot, target, keyID string) []byte {
	now := time.Now().UnixMilli()
	tok := &pb.ActionToken{
		TokenId:         "forged-token-km2",
		ChainId:         "forged-chain-km2",
		SequenceIndex:   1,
		RobotId:         robot,
		PlanId:          "attacker-plan",
		StepId:          "s1",
		TargetObjectId:  target,
		SchemaVersion:   2,
		ActionType:      pb.ActionType_ACTION_MOVE,
		Constraints:     &pb.TokenConstraints{MaxLinearSpeedMps: 1.0, MaxAngularSpeedRps: 1.0, MaxDurationSec: 5.0},
		IssuedAtUnixMs:  now,
		NotBeforeUnixMs: now - 1000,
		NotAfterUnixMs:  now + 60_000,
	}
	raw, err := proto.Marshal(tok)
	if err != nil {
		log.Fatalf("marshal forged token: %v", err)
	}
	return raw
}

func main() {
	mode := flag.String("mode", "load", "forge-unsigned (F1) | load (F2..F5)")
	keyring := flag.String("keyring", "", "unsigned keyring.json to write/swap (forge-unsigned)")
	keyID := flag.String("key-id", "issuer-a", "issuer key_id the gate looks up")
	robot := flag.String("robot", "robot-1", "robot_id to embed (forge-unsigned)")
	target := flag.String("target", "880123", "target_object_id to embed (forge-unsigned)")
	bundle := flag.String("bundle", "", "keyring bundle to load (load)")
	rootPubFile := flag.String("root-pub", "", "base64 root public key file (load)")
	statePath := flag.String("state", "", "bundle version state file (load)")
	expect := flag.String("expect", "accept", "load: accept|reject")
	flag.Parse()

	switch *mode {
	case "forge-unsigned":
		if *keyring == "" {
			log.Fatalf("forge-unsigned needs -keyring")
		}
		// The attacker mints their own keypair and writes an unsigned keyring
		// that names it as the trusted issuer under the key_id the gate uses.
		attackerPub, attackerPriv, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatalf("gen attacker key: %v", err)
		}
		pubB64 := pailcrypto.PublicKeyBase64(attackerPub)
		krJSON := fmt.Sprintf(`{"keys":[{"key_id":%q,"ed25519_public_key_base64":%q,"role":"issuer"}]}`, *keyID, pubB64)
		if err := os.WriteFile(*keyring, []byte(krJSON), 0644); err != nil {
			log.Fatalf("write swapped keyring: %v", err)
		}
		// Forge a token and sign it with the attacker private key.
		raw := forgedTokenBytes(*robot, *target, *keyID)
		sig := ed25519.Sign(attackerPriv, raw)
		// The gate trusts issuer pubkeys from this (swapped) keyring, by key_id.
		kr, err := pailcrypto.LoadKeyring(*keyring)
		if err != nil {
			log.Fatalf("load swapped keyring: %v", err)
		}
		issuers, err := kr.PublicKeysByRole("issuer")
		if err != nil {
			log.Fatalf("keyring issuer role: %v", err)
		}
		pub, ok := issuers[*keyID]
		if !ok {
			log.Fatalf("swapped keyring has no issuer entry for key_id=%s", *keyID)
		}
		if ed25519.Verify(pub, raw, sig) {
			fmt.Printf("KM2-3 F1 RESULT: SWAP SUCCEEDED — unsigned-dev keyring swapped to attacker pubkey (key_id=%s); the gate verifier accepts the attacker's forged token. This is vulnerability W2 that KM2 bundle mode (root-signed keyring) closes.\n", *keyID)
			os.Exit(0)
		}
		log.Fatalf("KM2-3 F1 UNEXPECTED: attacker token did not verify against its own swapped keyring — probe is broken")

	case "load":
		if *bundle == "" || *rootPubFile == "" || *statePath == "" {
			log.Fatalf("load needs -bundle -root-pub -state")
		}
		rootPub, err := pailcrypto.ReadRootPubFile(*rootPubFile)
		if err != nil {
			log.Fatalf("read root pub: %v", err)
		}
		// 정책을 플래그로 받지 않고 환경에서 읽는다. 플래그면 이 탐침은 배포가
		// 재는 것과 **다른 상한**을 재게 되고, 그 차이는 탐침이 초록인 날에도
		// 남아 있다.
		pol, err := pailcrypto.BundlePolicyFromEnv()
		if err != nil {
			log.Fatalf("bundle policy: %v", err)
		}
		kr, err := pailcrypto.LoadKeyringBundle(*bundle, rootPub, *statePath, pol)
		switch *expect {
		case "accept":
			if err != nil {
				log.Fatalf("KM2-3 load FAIL: expected ACCEPT but bundle was rejected: %v", err)
			}
			issuers, _ := kr.PublicKeysByRole("issuer")
			ids := make([]string, 0, len(issuers))
			for id := range issuers {
				ids = append(ids, id)
			}
			fmt.Printf("KM2-3 load RESULT: ACCEPTED — bundle root-signature valid, version+expiry OK; trusted issuers=%v\n", ids)
			os.Exit(0)
		case "reject":
			if err == nil {
				log.Fatalf("KM2-3 load FAIL: expected REJECT but bundle loaded (trust anchor bypassed!)")
			}
			fmt.Printf("KM2-3 load RESULT: REJECTED (fail-closed, existing keyring kept) — %v\n", err)
			os.Exit(0)
		default:
			log.Fatalf("unknown -expect %q (want accept|reject)", *expect)
		}

	default:
		log.Fatalf("unknown -mode %q (want forge-unsigned|load)", *mode)
	}
}
