// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
)

// legacyRefuser answers a legacy (C0) decision report the way the Issuer does: a report it cannot attribute
// (no token) is refused every time it is presented — the RPC succeeds and accepted=false, definitively —
// and an attributable report is accepted. It records which tokens it was asked about.
type legacyRefuser struct {
	fakeTokenClient
	calls  atomic.Int64
	mu     sync.Mutex
	tokens []string
}

func (f *legacyRefuser) ReportDecision(ctx context.Context, r *tokenpb.ReportDecisionRequest, o ...grpc.CallOption) (*tokenpb.ReportDecisionResponse, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.tokens = append(f.tokens, r.TokenId)
	f.mu.Unlock()
	return &tokenpb.ReportDecisionResponse{Accepted: r.TokenId != ""}, nil
}

func (f *legacyRefuser) seen(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t == token {
			return true
		}
	}
	return false
}

// preview.35 pre-seal on the built images (test-supersede 2/8): the readiness probe's BLOCK ERR_NO_TOKEN
// was refused by the Issuer (no chain to attribute it to — journaled unattributed, accepted=false) and the
// agent, which no longer counts accepted=false as delivery, retried that head report for the whole run.
// Every later decision stayed behind it in the FIFO and never reached the journal. A definitive refusal
// must be retained as rejected and the queue must move on; the retry stays for transport errors and nil.
func TestLegacyRefusalDoesNotBlockTheQueue(t *testing.T) {
	for _, tc := range []struct {
		name string
		dir  string
	}{{"durable", t.TempDir()}, {"memory-only", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &legacyRefuser{}
			q, err := newReportQueue(f, reportQueueOptions{RobotID: "robot-1", Dir: tc.dir, RetryMax: time.Millisecond, NoJitter: true})
			if err != nil {
				t.Fatal(err)
			}
			defer q.close()
			first := blockReport(1)
			first.TokenId = ""
			first.ReasonCode = "ERR_NO_TOKEN"
			q.push(first)
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) && !f.seen("") {
				time.Sleep(time.Millisecond)
			}
			if !f.seen("") {
				t.Fatal("refused report never reached the receiver")
			}
			second := blockReport(2)
			second.TokenId = "tok-after-refusal"
			q.push(second)
			deadline = time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) && !f.seen(second.TokenId) {
				time.Sleep(time.Millisecond)
			}
			if !f.seen(second.TokenId) {
				t.Fatal("the report behind a refused one was never delivered: the refusal blocked the queue")
			}
			if q.sent.Load() != 1 {
				t.Fatalf("sent=%d: the refused report must not count as delivered", q.sent.Load())
			}
			if n := f.calls.Load(); n != 2 {
				t.Fatalf("%d calls: a definitive refusal is presented once, not retried", n)
			}
			if q.refused.Load() != 1 {
				t.Fatalf("refused=%d: exactly one definitive refusal", q.refused.Load())
			}
			if tc.dir != "" {
				files, _ := filepath.Glob(filepath.Join(tc.dir, "rejected-*.json")) // quarantine() writes beside the report log
				if len(files) != 1 {
					t.Fatalf("durable queue must retain the refusal as rejected evidence, found %v", files)
				}
			}
		})
	}
}
