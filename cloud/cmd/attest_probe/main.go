// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// attest_probe issues a single TokenService.Attest call.
//
// The gateway's tokenProxy.Attest runs `defer p.m.Invalidate()` — attestation
// is the one RPC that drops the mirror's cached token AND its lease. Every
// other tool in cmd/ can reach the issuer but none can exercise that path, so
// AV-L1 (an unconsumed lease dropped at startup attest) had no repro handle.
package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"log"
	"time"

	"google.golang.org/grpc"

	"github.com/glowfly/pail/services/internal/grpcauth"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "token service addr")
	robot := flag.String("robot", "robot-1", "robot_id")
	component := flag.String("component", "pep_gate", "component name")
	measure := flag.String("measurement", "av7-red", "string hashed to the 32B measurement")
	build := flag.String("build", "av7-red-probe", "build_info stamp")
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

	sum := sha256.Sum256([]byte(*measure))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := tokenpb.NewTokenServiceClient(conn).Attest(ctx, &tokenpb.AttestRequest{
		RobotId:           *robot,
		Component:         *component,
		MeasurementSha256: sum[:],
		BuildInfo:         *build,
	})
	if err != nil {
		log.Fatalf("Attest: %v", err)
	}
	log.Printf("attest status=%s ttl_s=%d", resp.Status, resp.TtlS)
}
