// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// AV3 (AV LLD §4.6): send one gateway census declaration. The gateway does this
// itself on every stream recovery; this tool exists so the integration harness
// can declare a SPECIFIC position — including one the issuer cannot explain —
// without having to make a real robot misbehave.

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
	chain := flag.String("chain", "", "chain_id the gateway holds (empty = holds nothing)")
	consumed := flag.Int("consumed", 0, "last_consumed_index")
	leaseMax := flag.Int("lease-max", 0, "held_lease_max_index")
	epoch := flag.Uint64("epoch", 0, "seen_issuer_epoch")
	useTLS := flag.Bool("tls", grpcauth.TLSEnabled(), "use mTLS (default from PAIL_GRPC_TLS)")
	caPath := flag.String("ca", "", "CA cert path")
	certPath := flag.String("cert", "", "client cert path")
	keyPath := flag.String("key", "", "client key path")
	flag.Parse()

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
	resp, err := tokenpb.NewTokenServiceClient(conn).ReportGatewayCensus(ctx, &tokenpb.GatewayCensusRequest{
		RobotId:           *robot,
		ChainId:           *chain,
		LastConsumedIndex: int32(*consumed),
		HeldLeaseMaxIndex: int32(*leaseMax),
		SeenIssuerEpoch:   *epoch,
	})
	if err != nil {
		log.Fatalf("ReportGatewayCensus: %v", err)
	}
	log.Printf("accepted=%v verdict=%s issuer_epoch=%d", resp.Accepted, resp.Verdict, resp.IssuerEpoch)
}
