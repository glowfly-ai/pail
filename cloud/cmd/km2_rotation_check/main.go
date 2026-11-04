// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Command km2_rotation_check is the §7.2 rotation-rehearsal probe (KM LLD).
//
// Live mode (default): submits a one-step plan through the robot-agent front
// door, takes the issued SignedToken and verifies its signature against the
// keyring loaded FROM THE PULLED BUNDLE (root-signature trust path) — the
// same trust anchor the gate uses. Optionally saves the SignedToken bytes.
//
// -check-file mode: re-verifies a previously saved SignedToken against the
// (possibly rotated) bundle. With -expect fail it PASSES only when the old
// token no longer verifies — the revoked-key policy check of §7.2.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/grpcauth"
	pb "github.com/glowfly/pail/services/proto/pailv1"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "robot-agent front door")
	robot := flag.String("robot", "robot-1", "robot_id")
	planID := flag.String("plan", "km2-rotation-check", "plan_id")
	target := flag.String("target", "880123", "target_object_id")
	bundle := flag.String("bundle", "", "pulled keyring_bundle.json (trust source)")
	rootPub := flag.String("root-pub", "", "offline root public key file")
	state := flag.String("state", "", "bundle rollback state file")
	expectKey := flag.String("expect-key", "", "required issuer key_id on the token")
	save := flag.String("save", "", "write the SignedToken bytes here")
	checkFile := flag.String("check-file", "", "verify a saved SignedToken instead of issuing")
	expect := flag.String("expect", "pass", "check-file expectation: pass|fail")
	flag.Parse()

	if *bundle == "" || *rootPub == "" || *state == "" {
		log.Fatalf("-bundle, -root-pub and -state are required")
	}
	root, err := crypto.ReadRootPubFile(*rootPub)
	if err != nil {
		log.Fatalf("root pub: %v", err)
	}
	pol, err := crypto.BundlePolicyFromEnv()
	if err != nil {
		log.Fatalf("bundle policy: %v", err)
	}
	kr, err := crypto.LoadKeyringBundle(*bundle, root, *state, pol)
	if err != nil {
		log.Fatalf("bundle load: %v", err)
	}
	issuers, err := kr.PublicKeysByRole("issuer")
	if err != nil {
		log.Fatalf("issuer keys: %v", err)
	}

	if *checkFile != "" {
		raw, err := os.ReadFile(*checkFile)
		if err != nil {
			log.Fatalf("read %s: %v", *checkFile, err)
		}
		var st pb.SignedToken
		if err := proto.Unmarshal(raw, &st); err != nil {
			log.Fatalf("unmarshal saved token: %v", err)
		}
		ok := verifySigned(issuers, &st)
		keyID := string(st.GetKeyId())
		switch *expect {
		case "fail":
			if ok {
				log.Fatalf("ROTATION_CHECK FAIL: saved token (key_id=%s) STILL verifies against the rotated bundle", keyID)
			}
			fmt.Printf("ROTATION_CHECK PASS: old-key token rejected against rotated bundle (key_id=%s no longer a trust anchor)\n", keyID)
		case "pass":
			if !ok {
				log.Fatalf("ROTATION_CHECK FAIL: saved token (key_id=%s) does not verify", keyID)
			}
			fmt.Printf("ROTATION_CHECK PASS: saved token verifies (key_id=%s)\n", keyID)
		default:
			log.Fatalf("-expect must be pass|fail")
		}
		return
	}

	dialOpts, err := grpcauth.ToolDialOptions(*addr, grpcauth.TLSEnabled(), "", "", "")
	if err != nil {
		log.Fatalf("grpc credentials: %v", err)
	}
	conn, err := grpc.Dial(*addr, dialOpts...)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := pb.NewPailNorthboundClient(conn).SubmitActionPlan(ctx, &pb.SubmitActionPlanRequest{
		SessionId: "km2-rehearsal",
		RobotId:   *robot,
		Plan: &pb.ActionPlan{
			PlanId: *planID,
			Steps: []*pb.PlanStep{{
				StepId: "s1", Type: pb.StepType_STEP_TWIST, TargetObjectId: *target,
				Twist: &pb.TwistCommand{LinearX: 0.1, DurationSec: 1.0},
			}},
		},
	})
	if err != nil {
		log.Fatalf("SubmitActionPlan: %v", err)
	}
	if resp.Status != pb.SubmitStatus_ACCEPTED || len(resp.Tokens) == 0 {
		log.Fatalf("plan not accepted: status=%v rejected=%s tokens=%d", resp.Status, resp.RejectedReason, len(resp.Tokens))
	}
	st := resp.Tokens[0]
	keyID := string(st.GetKeyId())
	if !verifySigned(issuers, st) {
		log.Fatalf("ROTATION_CHECK FAIL: issued token (key_id=%s) does not verify against the pulled bundle", keyID)
	}
	if *expectKey != "" && keyID != *expectKey {
		log.Fatalf("ROTATION_CHECK FAIL: token signed by key_id=%s, expected %s", keyID, *expectKey)
	}
	if *save != "" {
		raw, err := proto.Marshal(st)
		if err != nil {
			log.Fatalf("marshal token: %v", err)
		}
		if err := os.WriteFile(*save, raw, 0644); err != nil {
			log.Fatalf("save token: %v", err)
		}
	}
	fmt.Printf("ROTATION_CHECK PASS: token_id=%s key_id=%s verified against pulled bundle (issuer trust anchors=%d)\n",
		st.GetToken().GetTokenId(), keyID, len(issuers))
}

// verifySigned checks the signature over the exact action_token_bytes (the
// canon — never a re-serialization) with the bundle issuer key named by key_id.
func verifySigned(issuers map[string]ed25519.PublicKey, st *pb.SignedToken) bool {
	pub, ok := issuers[string(st.GetKeyId())]
	if !ok {
		return false
	}
	if len(st.GetActionTokenBytes()) == 0 {
		return false
	}
	return ed25519.Verify(pub, st.GetActionTokenBytes(), st.GetSignature())
}
