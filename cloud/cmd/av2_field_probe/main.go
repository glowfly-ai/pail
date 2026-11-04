// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// av2_field_probe is a TEST HARNESS for AV LLD §7 risk #5: "proto 필드 추가 후
// C++ 미재생성 가정".
//
// AV2 adds lease_tokens(7) / lease_max_index(8) / issuer_epoch(9) to
// GetActiveTokenResponse. The design deliberately does NOT regenerate the
// gate's C++ stubs, because the robot-side gateway reconstructs the response it
// hands to the gate (§3.2). That leaves an assumption to verify rather than
// assume: a gate built from the OLD proto must treat 7~9 as unknown fields and
// keep behaving exactly as before.
//
// This proxy sits between the gate and its real token source, forwards every
// RPC untouched, and injects fields 7~9 into GetActiveToken responses. Point an
// UNMODIFIED gate image at it: if the gate still PERMITs, the assumption holds.
// If it errors or blocks, §3.2 already contains the blast radius — but we would
// then know it instead of guessing.
package main

import (
	"context"
	"flag"
	"log"
	"net"

	"github.com/glowfly/pail/services/internal/grpclive"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

type proxy struct {
	tokenpb.UnimplementedTokenServiceServer
	up tokenpb.TokenServiceClient
}

func (p *proxy) GetActiveToken(ctx context.Context, req *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	resp, _, err := grpclive.TokenCall(ctx, p.up, req)
	if err != nil {
		return nil, err
	}
	// Inject the AV2 fields. lease_tokens carries a real SignedToken so the
	// unknown field is a nested message, not just a varint — the harder case.
	if resp.Token != nil {
		resp.LeaseTokens = []*pb.SignedToken{resp.Token}
	}
	resp.LeaseMaxIndex = resp.ExpectedSequenceIndex + 5
	resp.IssuerEpoch = 7
	log.Printf("inject: lease_tokens=%d lease_max_index=%d issuer_epoch=%d (upstream status=%v idx=%d)",
		len(resp.LeaseTokens), resp.LeaseMaxIndex, resp.IssuerEpoch, resp.Status, resp.ExpectedSequenceIndex)
	return resp, nil
}

func (p *proxy) ReportDecision(ctx context.Context, req *tokenpb.ReportDecisionRequest) (*tokenpb.ReportDecisionResponse, error) {
	return p.up.ReportDecision(ctx, req)
}

func (p *proxy) Attest(ctx context.Context, req *tokenpb.AttestRequest) (*tokenpb.AttestResponse, error) {
	return p.up.Attest(ctx, req)
}

func (p *proxy) SealConfig(ctx context.Context, req *tokenpb.SealConfigRequest) (*tokenpb.SealConfigResponse, error) {
	return p.up.SealConfig(ctx, req)
}

func main() {
	listen := flag.String("listen", ":50184", "listen address for the gate")
	upstream := flag.String("upstream", "127.0.0.1:50183", "matching robot gateway, not a raw Issuer")
	flag.Parse()

	cc, err := grpc.Dial(*upstream, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial upstream: %v", err)
	}
	defer cc.Close()

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	s := grpc.NewServer(grpclive.ServerKeepalive()) // the agent pings its upstream (P8-M1)
	tokenpb.RegisterTokenServiceServer(s, &proxy{up: tokenpb.NewTokenServiceClient(cc)})
	log.Printf("av2_field_probe listening on %s -> %s (injecting fields 7/8/9)", *listen, *upstream)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
