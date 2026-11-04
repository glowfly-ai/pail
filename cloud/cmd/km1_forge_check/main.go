// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Command km1_forge_check is the KM1-4 FAIL-first forge probe (KM LLD §5).
//
// It answers one question at the cryptographic layer: does possession of the
// on-disk issuer material let an attacker mint a token that the gate's
// verifier accepts?
//
//	-mode forge-local  (F1): loads a (stolen) local issuer keyfile, forges a
//	  token over attacker-chosen bytes, and verifies it against the issuer
//	  public key from the keyring — the SAME check the gate does. With a
//	  local keyfile the forge SUCCEEDS: this is the pre-KM1 status quo the
//	  milestone exists to close. Exit 0 == forge succeeded (expected FAIL).
//
//	-mode forge-vault  (F2): the KM1 (vault) posture. There is no private key
//	  on disk to steal; signing must go through the vault. This mode builds
//	  the vault signer from the stolen env/disk and attempts one Sign. With
//	  the vault unreachable or the delegated token absent, the forge is
//	  BLOCKED (Sign errors, fail-closed). Exit 0 == forge blocked (expected).
//
//	-mode gen-local: harness helper — create a local issuer keyfile (-key,
//	  key_id -key-id) and write a matching issuer keyring (-keyring). Used to
//	  set up F1 so the "stolen" keyfile and the gate's trusted keyring agree.
//
// The token bytes are marshaled and signed exactly as the issuer does
// (signature over the marshaled ActionToken bytes = action_token_bytes canon),
// so a PASS here is the same trust decision the live gate would make.
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
	"github.com/glowfly/pail/services/internal/signer"
	pb "github.com/glowfly/pail/services/proto/pailv1"
)

func forgedTokenBytes(robot, target string) []byte {
	now := time.Now().UnixMilli()
	tok := &pb.ActionToken{
		TokenId:         "forged-token-1",
		ChainId:         "forged-chain-1",
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
	mode := flag.String("mode", "forge-local", "forge-local (F1) | forge-vault (F2)")
	key := flag.String("key", "", "stolen local issuer keyfile (forge-local)")
	keyring := flag.String("keyring", "", "keyring.json the gate trusts (issuer role)")
	keyID := flag.String("key-id", "vault-issuer-1", "issuer key_id (forge-vault)")
	robot := flag.String("robot", "robot-1", "robot_id to embed")
	target := flag.String("target", "880123", "target_object_id to embed")
	flag.Parse()

	switch *mode {
	case "gen-local":
		if *key == "" || *keyring == "" {
			log.Fatalf("gen-local needs -key and -keyring")
		}
		kp, err := pailcrypto.GenerateEd25519KeypairJSON(*key, *keyID)
		if err != nil {
			log.Fatalf("create keyfile: %v", err)
		}
		pubB64 := pailcrypto.PublicKeyBase64(kp.Public)
		krJSON := fmt.Sprintf(`{"keys":[{"key_id":%q,"ed25519_public_key_base64":%q,"role":"issuer"}]}`, kp.KeyID, pubB64)
		if err := os.WriteFile(*keyring, []byte(krJSON), 0644); err != nil {
			log.Fatalf("write keyring: %v", err)
		}
		fmt.Printf("gen-local: keyfile=%s keyring=%s key_id=%s pub=%s\n", *key, *keyring, kp.KeyID, pubB64)
		return

	case "forge-local":
		if *key == "" || *keyring == "" {
			log.Fatalf("forge-local needs -key and -keyring")
		}
		// The attacker holds a copy of the issuer keyfile.
		kp, err := pailcrypto.LoadEd25519KeypairJSON(*key, "")
		if err != nil {
			log.Fatalf("load stolen keyfile: %v", err)
		}
		raw := forgedTokenBytes(*robot, *target)
		sig := pailcrypto.Sign(kp.Private, raw)

		// The gate trusts the issuer public key from the keyring, keyed by key_id.
		kr, err := pailcrypto.LoadKeyring(*keyring)
		if err != nil {
			log.Fatalf("load keyring: %v", err)
		}
		issuers, err := kr.PublicKeysByRole("issuer")
		if err != nil {
			log.Fatalf("keyring issuer role: %v", err)
		}
		pub, ok := issuers[kp.KeyID]
		if !ok {
			log.Fatalf("keyring has no issuer entry for key_id=%s", kp.KeyID)
		}
		if ed25519.Verify(pub, raw, sig) {
			fmt.Printf("KM1-4 F1 RESULT: FORGE SUCCEEDED — stolen keyfile (key_id=%s) mints a token the gate verifier accepts. This is the pre-KM1 vulnerability (W1) that KM1-2 (vault custody) closes.\n", kp.KeyID)
			os.Exit(0)
		}
		log.Fatalf("KM1-4 F1 UNEXPECTED: forged token did not verify — probe is broken (F1 must reproduce the forge)")

	case "forge-vault":
		// KM1 posture: no private key on disk. The attacker who stole the
		// filesystem+env can only point at the vault. Off the vault network
		// (or without the delegated token) signing must fail — fail-closed.
		sg, err := signer.NewVaultFromEnv(*keyID)
		if err != nil {
			fmt.Printf("KM1-4 F2 RESULT: FORGE BLOCKED at signer init — vault signer cannot be constructed from stolen state (%v). No private key on disk; nothing to sign with.\n", err)
			os.Exit(0)
		}
		raw := forgedTokenBytes(*robot, *target)
		if _, err := sg.Sign(raw); err != nil {
			fmt.Printf("KM1-4 F2 RESULT: FORGE BLOCKED at sign — %v. The private key never left the vault; a disk/env copy cannot forge.\n", err)
			os.Exit(0)
		}
		log.Fatalf("KM1-4 F2 FAIL: vault signer produced a signature from stolen state — private key custody is broken")

	default:
		log.Fatalf("unknown -mode %q (want forge-local|forge-vault)", *mode)
	}
}
