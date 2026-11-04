// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// OI-01 rules (design §8): each test is the one shape its rule decides alone.
//
//	R1 reports queued while the upstream fails all arrive, in order, after recovery
//	R2 the first attempt is "live", every later attempt is "replayed"
//	R3 a restarted agent sends what the disk log still holds (original run id kept)
//	R4 overflow drops the OLDEST and a single ERR_REPORT_GAP summary goes first
//	R5 a mutating report waits for the attempt in flight only, not for the queue
//	R6 beacon-stream recovery (kickNow) retries at once instead of waiting out backoff
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

func blockReport(i int) *tokenpb.ReportDecisionRequest {
	return &tokenpb.ReportDecisionRequest{RobotId: "robot-1", ChainId: "chain-1", TokenId: "tok-" + strings.Repeat("x", i%3),
		Decision: tokenpb.Decision_BLOCK, ReasonCode: "ERR_NO_TOKEN", Detail: "n=" + string(rune('a'+i%26))}
}

func waitReports(t *testing.T, f *fakeTokenClient, n int, within time.Duration) []*tokenpb.ReportDecisionRequest {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		f.mu.Lock()
		got := append([]*tokenpb.ReportDecisionRequest(nil), f.reports...)
		f.mu.Unlock()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("want %d upstream reports, got %d", n, len(got))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func newTestQueue(t *testing.T, f *fakeTokenClient, o reportQueueOptions) *reportQueue {
	t.Helper()
	o.RobotID = "robot-1"
	if o.RetryMax == 0 {
		o.RetryMax = 20 * time.Millisecond
	}
	if o.Attempt == 0 {
		o.Attempt = 200 * time.Millisecond
	}
	q, err := newReportQueue(f, o)
	if err != nil {
		t.Fatalf("queue: %v", err)
	}
	t.Cleanup(q.close)
	return q
}

// R1
func TestOI01_ReportsSurviveOutageInOrder(t *testing.T) {
	f := &fakeTokenClient{}
	f.reportFail.Store(true)
	q := newTestQueue(t, f, reportQueueOptions{})
	for i := 0; i < 50; i++ {
		q.push(blockReport(i))
	}
	time.Sleep(60 * time.Millisecond) // attempts fail, nothing may be dropped
	if n := q.pending(); n != 50 {
		t.Fatalf("pending during outage = %d, want 50 (nothing dropped)", n)
	}
	f.reportFail.Store(false)
	got := waitReports(t, f, 50, 3*time.Second)
	for i, r := range got {
		if r.GetAgentSeq() != uint64(i+1) {
			t.Fatalf("order broken at %d: seq %d", i, r.GetAgentSeq())
		}
		if r.GetAgentRunId() != q.RunID() || r.GetDecidedUnixMs() == 0 {
			t.Fatalf("delivery metadata missing on %d: %v", i, r)
		}
		if r.GetDelivery() != reportDeliveryReplayed {
			t.Fatalf("report %d waited through the outage and must say replayed, got %q", i, r.GetDelivery())
		}
	}
	if q.pending() != 0 {
		t.Fatalf("queue not empty after recovery: %d", q.pending())
	}
	// the outage is over and the queue drained: the next report is live again
	q.push(blockReport(99))
	got = waitReports(t, f, 51, 2*time.Second)
	if got[50].GetDelivery() != reportDeliveryLive {
		t.Fatalf("after the queue drained a new report must be live, got %q", got[50].GetDelivery())
	}
}

// R2
func TestOI01_FirstAttemptLiveLaterAttemptsReplayed(t *testing.T) {
	f := &fakeTokenClient{}
	q := newTestQueue(t, f, reportQueueOptions{})
	q.push(blockReport(0))
	live := waitReports(t, f, 1, time.Second)
	if live[0].GetDelivery() != reportDeliveryLive {
		t.Fatalf("first attempt delivery = %q, want live", live[0].GetDelivery())
	}
	f.reportFail.Store(true)
	q.push(blockReport(1))
	time.Sleep(60 * time.Millisecond)
	f.reportFail.Store(false)
	got := waitReports(t, f, 2, 2*time.Second)
	if got[1].GetDelivery() != reportDeliveryReplayed {
		t.Fatalf("retried attempt delivery = %q, want replayed", got[1].GetDelivery())
	}
}

// R3
func TestOI01_DiskLogSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	f := &fakeTokenClient{}
	f.reportFail.Store(true)
	q := newTestQueue(t, f, reportQueueOptions{Dir: dir, MaxBytes: 1 << 20})
	for i := 0; i < 20; i++ {
		q.push(blockReport(i))
	}
	time.Sleep(50 * time.Millisecond)
	firstRun := q.RunID()
	q.close() // "crash": the sender stops, the log stays
	if st, err := os.Stat(filepath.Join(dir, reportLogFile)); err != nil || st.Size() == 0 {
		t.Fatalf("disk log missing or empty: %v", err)
	}

	f2 := &fakeTokenClient{}
	q2 := newTestQueue(t, f2, reportQueueOptions{Dir: dir, MaxBytes: 1 << 20})
	if q2.RunID() == firstRun {
		t.Fatal("restart must mint a new run id")
	}
	got := waitReports(t, f2, 20, 3*time.Second)
	for i, r := range got {
		if r.GetAgentRunId() != firstRun || r.GetAgentSeq() != uint64(i+1) {
			t.Fatalf("replayed record %d lost its identity: run=%s seq=%d", i, r.GetAgentRunId(), r.GetAgentSeq())
		}
		if r.GetDelivery() != reportDeliveryReplayed {
			t.Fatalf("record from a previous run must be replayed, got %q", r.GetDelivery())
		}
	}
	if q2.pending() != 0 {
		t.Fatalf("pending after replay: %d", q2.pending())
	}
}

// R4
func TestOI01_OverflowDropsOldestAndSendsOneGapFirst(t *testing.T) {
	f := &fakeTokenClient{}
	f.reportFail.Store(true)
	q := newTestQueue(t, f, reportQueueOptions{MemCap: 10})
	// Gap attempts share the sequence allocator. Capture each original
	// report's assigned identity instead of assuming gap-free numbering.
	var submitted []*tokenpb.ReportDecisionRequest
	for i := 0; i < 25; i++ {
		req := blockReport(i)
		q.push(req)
		submitted = append(submitted, req)
	}
	time.Sleep(30 * time.Millisecond)
	if q.pending() != 11 { // 10 kept + 1 gap summary
		t.Fatalf("pending = %d, want 11", q.pending())
	}
	f.reportFail.Store(false)
	got := waitReports(t, f, 11, 3*time.Second)
	gap := got[0]
	if gap.GetReasonCode() != reportGapReason || gap.GetDecision() != tokenpb.Decision_BLOCK || gap.GetDelivery() != reportDeliveryReplayed {
		t.Fatalf("first upstream report is not the gap summary: %v", gap)
	}
	for _, want := range []string{"dropped=15", fmt.Sprintf("first_seq=%d", submitted[0].AgentSeq), fmt.Sprintf("last_seq=%d", submitted[14].AgentSeq), "reasons=ERR_NO_TOKEN:15", "durable=false"} {
		if !strings.Contains(gap.GetDetail(), want) {
			t.Fatalf("gap detail %q lacks %q", gap.GetDetail(), want)
		}
	}
	for i, req := range got[1:11] {
		want := submitted[15+i]
		if req.AgentSeq != want.AgentSeq || req.AgentRunId != want.AgentRunId || req.Detail != want.Detail || req.TokenId != want.TokenId {
			t.Fatalf("kept report %d: seq=%d detail=%q; want seq=%d detail=%q", i, req.AgentSeq, req.Detail, want.AgentSeq, want.Detail)
		}
	}
	if len(waitReports(t, f, 11, 100*time.Millisecond)) != 11 {
		t.Fatal("more than one gap summary or stray reports")
	}
}

// R4 on disk: the cap is in bytes, the oldest records go, the gap is persisted.
func TestOI01_DiskOverflowKeepsGapAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	f := &fakeTokenClient{reportDelay: 200 * time.Millisecond} // a slow, failing upstream: 200 pushes outrun any sender
	f.reportFail.Store(true)
	q := newTestQueue(t, f, reportQueueOptions{Dir: dir, MaxBytes: 2048})
	for i := 0; i < 200; i++ {
		q.push(blockReport(i))
	}
	time.Sleep(30 * time.Millisecond)
	if q.dropped.Load() == 0 {
		t.Fatal("2 KiB cap with 200 reports must drop")
	}
	q.close()
	if _, err := os.Stat(filepath.Join(dir, reportGapFile)); err != nil {
		t.Fatalf("gap summary not persisted: %v", err)
	}
	f2 := &fakeTokenClient{}
	q2 := newTestQueue(t, f2, reportQueueOptions{Dir: dir, MaxBytes: 2048})
	got := waitReports(t, f2, 1, 2*time.Second)
	if got[0].GetReasonCode() != reportGapReason || !strings.Contains(got[0].GetDetail(), "durable=true") {
		t.Fatalf("gap summary not first after restart: %v", got[0])
	}
	_ = q2
}

// R5
func TestOI01_MutatingReportWaitsForOneAttemptOnly(t *testing.T) {
	f := &fakeTokenClient{}
	f.reportFail.Store(true)
	// A long attempt timeout: the wait must end on the first FAILED attempt, not on the timeout.
	q := newTestQueue(t, f, reportQueueOptions{Attempt: 2 * time.Second, RetryMax: 2 * time.Second})
	m := newTokenMirror(f, "robot-1", 0)
	p := &tokenProxy{c: f, m: m, f: q}
	for i := 0; i < 100; i++ {
		q.push(blockReport(i))
	}
	start := time.Now()
	_, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{
		RobotId: "robot-1", Decision: tokenpb.Decision_PERMIT, ReasonCode: "OK", StepComplete: true})
	if err == nil {
		t.Fatal("mutating report on a dead link must fail, not be acked")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("mutating report waited %v — it must not wait for the queue to drain", el)
	}
}

// R6. Without jitter the waits are 200, 400, 800, 1600 ms …: at 1.5 s the sender is inside the
// 1600 ms wait that ends at 3.0 s. A kick must deliver long before that; without the hook the
// report arrives only at 3.0 s.
func TestOI01_KickRetriesImmediately(t *testing.T) {
	f := &fakeTokenClient{}
	f.reportFail.Store(true)
	q := newTestQueue(t, f, reportQueueOptions{RetryMax: 3 * time.Second, NoJitter: true})
	q.push(blockReport(0))
	time.Sleep(1500 * time.Millisecond)
	f.reportFail.Store(false)
	q.kickNow()
	got := waitReports(t, f, 1, 500*time.Millisecond) // the next scheduled attempt is ~1.5 s away
	if got[0].GetDelivery() != reportDeliveryReplayed {
		t.Fatalf("delivery = %q", got[0].GetDelivery())
	}
}

// The pre-OI-01 contract holds: a non-mutating report is acked at once and a
// mutating one does not overtake queued telemetry while the link is up.
func TestOI01_LiveLinkOrderAndAckUnchanged(t *testing.T) {
	f := &fakeTokenClient{reportDelay: 10 * time.Millisecond}
	q := newTestQueue(t, f, reportQueueOptions{})
	m := newTokenMirror(f, "robot-1", 0)
	p := &tokenProxy{c: f, m: m, f: q}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		start := time.Now()
		if _, err := p.ReportDecision(context.Background(), blockReport(i)); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) > 5*time.Millisecond {
			t.Fatal("non-mutating report blocked on the round trip")
		}
	}
	wg.Wait()
	if _, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{
		RobotId: "robot-1", Decision: tokenpb.Decision_PERMIT, ReasonCode: "OK", StepComplete: true}); err != nil {
		t.Fatal(err)
	}
	got := waitReports(t, f, 4, time.Second)
	if !got[3].GetStepComplete() || got[3].GetAgentSeq() != 4 {
		t.Fatalf("mutating report overtook queued telemetry or lost its seq: %v", got)
	}
}
