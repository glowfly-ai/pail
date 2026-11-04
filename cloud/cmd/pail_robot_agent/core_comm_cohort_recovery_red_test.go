// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

// This file uses only the API that existed in preview.37 (cohortGuard, tokenMirror.cohort, newReportQueue,
// tokenProxy), so it compiles against the preview.37 sources and fails there: the fail-first proof of the P37-M1
// correction (the cohort hold clears when the Issuer answers v1 again; the storage fault is a separate state).

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// cohortIssuer is a real gRPC TokenService on bufconn whose census header, epoch, verdict and C1 acceptance the test
// controls per call. It is the Issuer side of the handshake, not a model of the agent.
type cohortIssuer struct {
	tokenpb.UnimplementedTokenServiceServer
	mu       sync.Mutex
	header   []string // census response header values; nil = none (an Issuer older than the handshake)
	epoch    uint64
	verdict  string
	legacyC1 bool          // refuse C1 reports the way a legacy Issuer does
	gate     chan struct{} // when set, a census blocks here after signalling started
	started  chan struct{}
	census   atomic.Int64
	reports  atomic.Int64
}

func newCohortIssuer(t *testing.T) (*cohortIssuer, tokenpb.TokenServiceClient) {
	t.Helper()
	iss := &cohortIssuer{header: []string{"v1"}, epoch: 1, verdict: "OK"}
	conn := bufServer(t, func(g *grpc.Server) { tokenpb.RegisterTokenServiceServer(g, iss) })
	return iss, tokenpb.NewTokenServiceClient(conn)
}

func (f *cohortIssuer) set(header []string, epoch uint64, verdict string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.header, f.epoch, f.verdict = header, epoch, verdict
}

func (f *cohortIssuer) ReportGatewayCensus(ctx context.Context, req *tokenpb.GatewayCensusRequest) (*tokenpb.GatewayCensusResponse, error) {
	f.census.Add(1)
	f.mu.Lock()
	hdr, epoch, verdict, gate, started := f.header, f.epoch, f.verdict, f.gate, f.started
	f.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		<-gate
	}
	for _, h := range hdr {
		_ = grpc.SetHeader(ctx, metadata.Pairs(cohortHeader, h)) // SetHeader appends: two values arrive as two
	}
	return &tokenpb.GatewayCensusResponse{Accepted: true, Verdict: verdict, IssuerEpoch: epoch}, nil
}

func (f *cohortIssuer) ReportDecision(ctx context.Context, r *tokenpb.ReportDecisionRequest) (*tokenpb.ReportDecisionResponse, error) {
	f.reports.Add(1)
	f.mu.Lock()
	legacy := f.legacyC1
	f.mu.Unlock()
	if legacy && r.GetReceiptContractVersion() == 1 {
		return nil, status.Error(codes.FailedPrecondition, cohortMismatchMsg)
	}
	return &tokenpb.ReportDecisionResponse{Accepted: true}, nil
}

func (f *cohortIssuer) GetActiveToken(ctx context.Context, r *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	return &tokenpb.GetActiveTokenResponse{ChainId: "chain-1", IssuerEpoch: 1}, nil
}

// cohortRig is a C1 report queue, a mirror and the token proxy in front of the bufconn Issuer — the agent's real
// code on the authority path.
func cohortRig(t *testing.T, tc tokenpb.TokenServiceClient, interval time.Duration) (*reportQueue, *tokenMirror, *tokenProxy) {
	t.Helper()
	q, err := newReportQueue(tc, reportQueueOptions{RobotID: "robot-1", ReceiptVersion: 1, Dir: t.TempDir(), RetryMax: 20 * time.Millisecond, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(q.close)
	m := newTokenMirror(tc, "robot-1", interval)
	m.cohort = q.cohort
	return q, m, &tokenProxy{c: tc, m: m, f: q}
}

func authority(p *tokenProxy) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := p.GetActiveToken(ctx, &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
	return err
}

// preview.37 hardware evaluation P37-M1: after the Issuer was swapped to legacy and back to v1, the agent kept
// withholding authority (the fault it raised had no release) until a restart. Now the mismatch is a hold that the
// next verified v1 census clears; the storage fault is a different state and stays healthy throughout.
func TestCohortTransitionClearsOnlyTheCohortHold(t *testing.T) {
	iss, tc := newCohortIssuer(t)
	q, m, p := cohortRig(t, tc, 0)
	m.census() // first census: v1 — no refusal
	if err := authority(p); err != nil {
		t.Fatalf("v1 cohort: authority must be served: %v", err)
	}
	iss.set([]string{"legacy"}, 1, "OK") // the Issuer was replaced by a legacy one while running
	m.census()
	if err := authority(p); status.Code(err) != codes.Unavailable {
		t.Fatalf("legacy Issuer: authority must be withheld (Unavailable), got %v", err)
	}
	iss.set([]string{"v1"}, 1, "OK") // and switched back
	m.census()
	if err := authority(p); err != nil {
		t.Fatalf("the Issuer answers v1 again: authority must be served without a restart, got %v", err)
	}
	if !q.core.healthy() {
		t.Fatal("a cohort mismatch is not a storage fault: the critical outbox must stay healthy")
	}
}
