// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// report_decision: test CLI that sends a TokenService.ReportDecision, e.g. to
// simulate the PEP reporting a forged token (M9 §9: BLOCK/ERR_BAD_TOKEN must
// trip the issuer into SAFE_STOP).
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"google.golang.org/grpc"

	"github.com/glowfly/pail/services/internal/grpcauth"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "pail-services gRPC addr")
	robot := flag.String("robot", "robot-1", "robot_id")
	chain := flag.String("chain", "", "chain_id")
	tokenID := flag.String("token", "", "token_id")
	decision := flag.String("decision", "BLOCK", "PERMIT|BLOCK|ESTOP")
	reason := flag.String("reason", "ERR_BAD_TOKEN", "reason_code")
	stepComplete := flag.Bool("step-complete", false, "step_complete flag")
	fatal := flag.Bool("fatal", false, "fatal flag")
	useTLS := flag.Bool("tls", grpcauth.TLSEnabled(), "use mTLS (default from PAIL_GRPC_TLS; ignored for unix: addr)")
	caPath := flag.String("ca", "", "CA cert path")
	certPath := flag.String("cert", "", "client cert path")
	keyPath := flag.String("key", "", "client key path")
	flag.Parse()

	d, ok := tokenpb.Decision_value[*decision]
	if !ok {
		log.Fatalf("unknown decision %q", *decision)
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := tokenpb.NewTokenServiceClient(conn).ReportDecision(ctx, &tokenpb.ReportDecisionRequest{
		RobotId:      *robot,
		ChainId:      *chain,
		TokenId:      *tokenID,
		Decision:     tokenpb.Decision(d),
		ReasonCode:   *reason,
		StepComplete: *stepComplete,
		Fatal:        *fatal,
	})
	if err != nil {
		log.Fatalf("ReportDecision: %v", err)
	}
	log.Printf("accepted=%v", resp.Accepted)
}
