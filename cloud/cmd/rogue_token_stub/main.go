// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// rogue_token_stub is a TEST HARNESS for M2 completion criterion (2)
// (LLD-v2 §1.1 old-stub bypass prevention). It impersonates TokenService
// and serves tokens that a v2 PEP verifier MUST reject:
//
//	-mode v1          : schema_version=0, no action_type   -> expect ERR_SCHEMA
//	-mode v1_nobytes  : SignedToken without action_token_bytes (real old stub)
//	                    -> expect ERR_TOKEN_VIEW_INCOMPLETE
//	-mode unknownfield: valid v2 token bytes + appended unknown field 61
//	                    -> expect ERR_SCHEMA
//	-mode unspecified : schema_version=2, action_type UNSPECIFIED
//	                    -> expect ERR_BAD_TOKEN
//	-mode replay      : valid v2 MOVE token with fixed token_id, short
//	                    max_duration (1s), served forever even after the PEP
//	                    consumes it -> expect PERMIT, then step completion,
//	                    then BLOCK/ERR_TOKEN_CONSUMED on re-presentation (M3)
//
// Tokens are correctly ed25519-signed with the real dev issuer key, so the
// only reason for rejection is the schema/action rule under test.
// If the PEP gate ever answers PERMIT while pointed at this stub, M2 FAILED.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"time"

	"github.com/glowfly/pail/services/internal/grpclive"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	pailcrypto "github.com/glowfly/pail/services/internal/crypto"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

type server struct {
	tokenpb.UnimplementedTokenServiceServer
	kp     *pailcrypto.Keypair
	mode   string
	robot  string
	target string
}

func (s *server) GetActiveToken(ctx context.Context, req *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	// This executable is the synthetic peer, not a transparent proxy.
	if err := grpclive.EchoFixtureExecution(ctx); err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	tok := &pb.ActionToken{
		TokenId:         "rogue-token-1",
		ChainId:         "rogue-chain-1",
		SequenceIndex:   1,
		RobotId:         s.robot,
		PlanId:          "rogue-plan",
		StepId:          "s1",
		TargetObjectId:  s.target,
		IssuedAtUnixMs:  now,
		NotBeforeUnixMs: now - 1000,
		NotAfterUnixMs:  now + 60_000,
	}

	switch s.mode {
	case "v1", "v1_nobytes":
		// v1-era token: schema_version=0, no action_type/constraints.
	case "unknownfield", "unspecified":
		tok.SchemaVersion = 2
		if s.mode == "unknownfield" {
			tok.ActionType = pb.ActionType_ACTION_MOVE
			tok.Constraints = &pb.TokenConstraints{MaxLinearSpeedMps: 1.0, MaxAngularSpeedRps: 1.0}
		}
	case "replay":
		tok.SchemaVersion = 2
		tok.ActionType = pb.ActionType_ACTION_MOVE
		tok.Constraints = &pb.TokenConstraints{
			MaxLinearSpeedMps:  1.0,
			MaxAngularSpeedRps: 1.0,
			MaxDurationSec:     1.0,
		}
	default:
		log.Fatalf("unknown mode %q", s.mode)
	}

	raw, err := proto.Marshal(tok)
	if err != nil {
		return nil, err
	}
	if s.mode == "unknownfield" {
		// Append unknown field 61 (varint, value 1): tag=(61<<3)|0=488 -> 0xE8 0x03.
		raw = append(raw, 0xE8, 0x03, 0x01)
	}

	st := &pb.SignedToken{
		Token:     tok,
		Signature: pailcrypto.Sign(s.kp.Private, raw),
		KeyId:     []byte(s.kp.KeyID),
	}
	if s.mode != "v1_nobytes" {
		st.ActionTokenBytes = raw
	}

	log.Printf("served %s token to robot=%s (mode=%s)", tok.TokenId, req.RobotId, s.mode)
	return &tokenpb.GetActiveTokenResponse{
		Status:                tokenpb.ActiveTokenStatus_OK,
		ChainId:               tok.ChainId,
		ExpectedSequenceIndex: 1,
		Token:                 st,
	}, nil
}

func (s *server) ReportDecision(_ context.Context, req *tokenpb.ReportDecisionRequest) (*tokenpb.ReportDecisionResponse, error) {
	log.Printf("ReportDecision robot=%s token=%s decision=%v reason=%s", req.RobotId, req.TokenId, req.Decision, req.ReasonCode)
	return &tokenpb.ReportDecisionResponse{Accepted: true}, nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:50052", "listen addr")
	key := flag.String("key", "/etc/pail/keys/issuer_ed25519.json", "issuer keyfile (must match PEP keyring)")
	robot := flag.String("robot", "robot-1", "robot_id to embed")
	target := flag.String("target", "", "target_object_id to embed")
	mode := flag.String("mode", "v1", "v1|v1_nobytes|unknownfield|unspecified|replay")
	flag.Parse()

	kp, err := pailcrypto.LoadEd25519KeypairJSON(*key, "")
	if err != nil {
		log.Fatalf("load key: %v", err)
	}
	log.Printf("rogue stub: mode=%s key_id=%s addr=%s", *mode, kp.KeyID, *addr)

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	g := grpc.NewServer(grpclive.ServerKeepalive()) // the agent pings its upstream (P8-M1)
	tokenpb.RegisterTokenServiceServer(g, &server{kp: kp, mode: *mode, robot: *robot, target: *target})
	if err := g.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
