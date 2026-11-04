// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"

	"github.com/glowfly/pail/services/internal/grpcauth"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "pail-services gRPC addr")
	robot := flag.String("robot", "robot-1", "robot_id")
	useTLS := flag.Bool("tls", grpcauth.TLSEnabled(), "use mTLS (default from PAIL_GRPC_TLS; ignored for unix: addr)")
	caPath := flag.String("ca", "", "CA cert path (default PAIL_GRPC_CA or /etc/pail/grpc_certs/ca.crt)")
	certPath := flag.String("cert", "", "client cert path (default PAIL_GRPC_CERT or /etc/pail/grpc_certs/client.crt)")
	keyPath := flag.String("key", "", "client key path (default PAIL_GRPC_KEY or /etc/pail/grpc_certs/client.key)")
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

	tc := tokenpb.NewTokenServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := tc.GetActiveToken(ctx, &tokenpb.GetActiveTokenRequest{RobotId: *robot})
	if err != nil {
		log.Fatalf("GetActiveToken: %v", err)
	}

	tokenID := ""
	ttl := ""
	if resp.Token != nil && resp.Token.Token != nil {
		t := resp.Token.Token
		tokenID = t.TokenId
		nowMs := time.Now().UnixMilli()
		ttl = fmt.Sprintf(" issued_at=%d not_after=%d remain_ms=%d", t.IssuedAtUnixMs, t.NotAfterUnixMs, t.NotAfterUnixMs-nowMs)
	}

	log.Printf("status=%v chain_id=%s expected_index=%d token_id=%s%s issuer_epoch=%d lease_max_index=%d lease_tokens=%d",
		resp.Status, resp.ChainId, resp.ExpectedSequenceIndex, tokenID, ttl,
		resp.IssuerEpoch, resp.LeaseMaxIndex, len(resp.LeaseTokens))
}
