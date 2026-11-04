// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// replay_seam is a TEST HARNESS for the live single-use check (실기브링업 B4 4-e).
//
// It is the live analogue of PVS's _RogueTokenService (pvs/runner/live/
// backend_live.py): a transparent TokenService proxy that CAPTURES the first
// OK GetActiveToken response and then serves that same response forever. The
// gate therefore sees a token it has already consumed re-presented, which is
// exactly the replay the single-use cache exists to refuse.
//
// Every other RPC is forwarded verbatim, so the issuer still advances its
// sequence when the gate reports step completion — the replay is the seam's
// doing, not the issuer's.
//
// The pinned response is passed through as the upstream message, so
// action_token_bytes (the consumption key preimage) is byte-identical.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"
	"os"
	"sync"

	"github.com/glowfly/pail/services/internal/grpclive"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

type seam struct {
	tokenpb.UnimplementedTokenServiceServer
	up tokenpb.TokenServiceClient

	mu      sync.Mutex
	pinned  *tokenpb.GetActiveTokenResponse
	headers metadata.MD
	serves  int
}

func (s *seam) GetActiveToken(ctx context.Context, req *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	s.mu.Lock()
	pinned := s.pinned
	headers := s.headers.Copy()
	if pinned != nil {
		s.serves++
		n := s.serves
		s.mu.Unlock()
		if n == 1 || n%50 == 0 {
			log.Printf("REPLAY serve #%d (pinned token %s)", n, pinned.GetToken().GetToken().GetTokenId())
		}
		if err := grpclive.SendExecutionHeaders(ctx, headers); err != nil {
			return nil, err
		}
		return pinned, nil
	}
	s.mu.Unlock()

	resp, headers, err := grpclive.TokenCall(ctx, s.up, req)
	if err != nil {
		log.Printf("upstream GetActiveToken error: %v", err)
		return nil, err
	}
	if resp.GetStatus() == tokenpb.ActiveTokenStatus_OK && resp.GetToken() != nil {
		s.mu.Lock()
		if s.pinned == nil {
			s.pinned = resp
			s.headers = headers.Copy()
			log.Printf("PINNED chain=%s idx=%d token=%s bytes=%d",
				resp.GetChainId(), resp.GetExpectedSequenceIndex(),
				resp.GetToken().GetToken().GetTokenId(),
				len(resp.GetToken().GetActionTokenBytes()))
		}
		s.mu.Unlock()
	}
	return resp, nil
}

func (s *seam) ReportDecision(ctx context.Context, req *tokenpb.ReportDecisionRequest) (*tokenpb.ReportDecisionResponse, error) {
	log.Printf("ReportDecision token=%s decision=%v reason=%s step_complete=%v",
		req.GetTokenId(), req.GetDecision(), req.GetReasonCode(), req.GetStepComplete())
	return s.up.ReportDecision(ctx, req)
}

func (s *seam) Attest(ctx context.Context, req *tokenpb.AttestRequest) (*tokenpb.AttestResponse, error) {
	return s.up.Attest(ctx, req)
}

func (s *seam) ReportGatewayCensus(ctx context.Context, req *tokenpb.GatewayCensusRequest) (*tokenpb.GatewayCensusResponse, error) {
	return s.up.ReportGatewayCensus(grpclive.ExecutionContext(ctx), req)
}

func (s *seam) SealConfig(ctx context.Context, req *tokenpb.SealConfigRequest) (*tokenpb.SealConfigResponse, error) {
	return s.up.SealConfig(ctx, req)
}

func mustRead(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		log.Fatalf("read %s: %v", p, err)
	}
	return b
}

func main() {
	addr := flag.String("addr", "127.0.0.1:50052", "listen addr")
	upstream := flag.String("upstream", "127.0.0.1:50051", "matching robot gateway TokenService addr")
	caPath := flag.String("ca", "/etc/pail/grpc_certs/ca.crt", "CA cert")
	srvCert := flag.String("server-cert", "/etc/pail/grpc_certs/server.crt", "seam server cert")
	srvKey := flag.String("server-key", "/etc/pail/grpc_certs/server.key", "seam server key")
	cliCert := flag.String("client-cert", "/etc/pail/grpc_certs/robot-1/client.crt", "upstream client cert")
	cliKey := flag.String("client-key", "/etc/pail/grpc_certs/robot-1/client.key", "upstream client key")
	flag.Parse()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mustRead(*caPath)) {
		log.Fatalf("bad CA %s", *caPath)
	}

	sc, err := tls.LoadX509KeyPair(*srvCert, *srvKey)
	if err != nil {
		log.Fatalf("server keypair: %v", err)
	}
	cc, err := tls.LoadX509KeyPair(*cliCert, *cliKey)
	if err != nil {
		log.Fatalf("client keypair: %v", err)
	}

	conn, err := grpc.Dial(*upstream, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cc},
		RootCAs:      pool,
	})))
	if err != nil {
		log.Fatalf("dial upstream: %v", err)
	}
	defer conn.Close()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{sc},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	})), grpclive.ServerKeepalive()) // the agent pings its upstream (P8-M1)
	tokenpb.RegisterTokenServiceServer(g, &seam{up: tokenpb.NewTokenServiceClient(conn)})
	log.Printf("replay_seam listening on %s (mTLS), upstream %s", *addr, *upstream)
	if err := g.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
