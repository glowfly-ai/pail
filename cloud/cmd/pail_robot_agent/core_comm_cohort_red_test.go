// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

// This file used only the API that existed before the cohort guard (its fail-first proof against the preview.36
// sources, preview.37). Since preview.38 the mismatch is the guard's own hold, not the outbox's storage fault
// (P37-M1), so the assertions read the guard.

import (
	"bytes"
	"context"
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/corecomm"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// legacyIssuerForC1 answers the way a legacy Issuer answers a C1 report (core_comm.go): FailedPrecondition.
type legacyIssuerForC1 struct {
	fakeTokenClient
	received atomic.Int64
}

func (f *legacyIssuerForC1) ReportDecision(ctx context.Context, r *tp.ReportDecisionRequest, o ...grpc.CallOption) (*tp.ReportDecisionResponse, error) {
	f.received.Add(1)
	return nil, status.Error(codes.FailedPrecondition, "core-comm receipt version unsupported")
}

func c1Report(id string) *tp.ReportDecisionRequest {
	r := blockReport(1)
	r.ReportId = id
	r.ReceiptContractVersion = 1
	r.ReportDigest, _ = corecomm.ReportDigest(r)
	return r
}

// preview.36 hardware evaluation P36-M1, running mismatch: the Issuer refuses every C1 report, the queue used to
// retry the head as a transport error, the critical outbox retried in silence, and nothing told the operator.
// Now the refusal is a cohort mismatch: the critical fault is raised (authority withheld), the head is kept
// (never downgraded, never dropped), and the warning repeats at most every 30 s.
func TestLegacyIssuerRefusalOfC1ReportIsAFault(t *testing.T) {
	dir := t.TempDir()
	f := &legacyIssuerForC1{}
	q, err := newReportQueue(f, reportQueueOptions{RobotID: "robot-1", ReceiptVersion: 1, Dir: dir, RetryMax: 20 * time.Millisecond, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)
	q.push(c1Report("obs-1"))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && f.received.Load() < 3 {
		time.Sleep(time.Millisecond)
	}
	if f.received.Load() < 3 {
		t.Fatalf("the refused report was presented %d times; it must stay at the head and be retried", f.received.Load())
	}
	if !q.cohort.mismatched() {
		t.Fatal("a legacy Issuer refusing C1 reports must enter the cohort hold (new authority withheld)")
	}
	if !q.core.healthy() {
		t.Fatal("the hold is not a storage fault: the critical outbox stays healthy (P37-M1)")
	}
	if q.sent.Load() != 0 || q.refused.Load() != 0 {
		t.Fatalf("sent=%d refused=%d: the report is neither delivered nor quarantined", q.sent.Load(), q.refused.Load())
	}
	if n := strings.Count(logs.String(), "CORE_COMM_COHORT_MISMATCH"); n != 1 {
		t.Fatalf("mismatch warned %d times within 3 s; want exactly one (30 s cadence): %s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "1 decision reports and 0 critical reports are held") {
		t.Fatalf("the warning must count the held reports: %s", logs.String())
	}
}
