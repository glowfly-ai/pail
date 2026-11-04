// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/protobuf/proto"

	"google.golang.org/grpc"
)

type fakeTokenClient struct {
	calls atomic.Int64
	fail  atomic.Bool

	reportDelay time.Duration
	reportFail  atomic.Bool // OI-01 tests: upstream refuses decision reports
	mu          sync.Mutex
	reports     []*tokenpb.ReportDecisionRequest
}

func (f *fakeTokenClient) GetActiveToken(ctx context.Context, in *tokenpb.GetActiveTokenRequest, opts ...grpc.CallOption) (*tokenpb.GetActiveTokenResponse, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return nil, errors.New("upstream down")
	}
	return &tokenpb.GetActiveTokenResponse{ChainId: "chain-1"}, nil
}

func (f *fakeTokenClient) Attest(ctx context.Context, in *tokenpb.AttestRequest, opts ...grpc.CallOption) (*tokenpb.AttestResponse, error) {
	return &tokenpb.AttestResponse{Status: "OK"}, nil
}

func (f *fakeTokenClient) SealConfig(ctx context.Context, in *tokenpb.SealConfigRequest, opts ...grpc.CallOption) (*tokenpb.SealConfigResponse, error) {
	return &tokenpb.SealConfigResponse{Status: "OK"}, nil
}

func (f *fakeTokenClient) ReportGatewayCensus(ctx context.Context, in *tokenpb.GatewayCensusRequest, opts ...grpc.CallOption) (*tokenpb.GatewayCensusResponse, error) {
	return &tokenpb.GatewayCensusResponse{Accepted: true, Verdict: "OK"}, nil
}

func (f *fakeTokenClient) ReportDecision(ctx context.Context, in *tokenpb.ReportDecisionRequest, opts ...grpc.CallOption) (*tokenpb.ReportDecisionResponse, error) {
	if f.reportDelay > 0 {
		time.Sleep(f.reportDelay) // simulated WAN round trip
	}
	if f.reportFail.Load() {
		return nil, errors.New("upstream down")
	}
	f.mu.Lock()
	f.reports = append(f.reports, proto.Clone(in).(*tokenpb.ReportDecisionRequest))
	f.mu.Unlock()
	return &tokenpb.ReportDecisionResponse{Accepted: true}, nil
}

func req() *tokenpb.GetActiveTokenRequest {
	return &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}
}

// seqTokenClient stamps every upstream answer with its call number, so a test
// can tell a fresh answer from a mirrored one by the answer itself. Counting
// calls alone cannot: get() starts the poller, whose first refresh may join
// get()'s call or follow it depending on scheduling (HW-A1 moved the RPC onto
// its own goroutine, which made the "follow" order common against an instant
// fake). What these tests guard is whether a READ was served from the mirror.
type seqTokenClient struct{ fakeTokenClient }

func (f *seqTokenClient) GetActiveToken(ctx context.Context, in *tokenpb.GetActiveTokenRequest, opts ...grpc.CallOption) (*tokenpb.GetActiveTokenResponse, error) {
	n := f.calls.Add(1)
	return &tokenpb.GetActiveTokenResponse{ChainId: fmt.Sprintf("chain-%d", n)}, nil
}

// settle lets the poller's start-up refresh land before a test counts calls.
func settle() { time.Sleep(50 * time.Millisecond) }

// interval=0 disables the mirror: every read must go upstream.
func TestMirrorDisabledPassthrough(t *testing.T) {
	f := &fakeTokenClient{}
	m := newTokenMirror(f, "robot-1", 0)
	for i := 0; i < 3; i++ {
		if _, err := m.get(context.Background(), req()); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.calls.Load(); got != 3 {
		t.Fatalf("want 3 upstream calls, got %d", got)
	}
}

// While the beacon stream is up and the entry is fresh, repeat reads are
// served from the mirror (single upstream fetch).
func TestMirrorCacheHitWhileStreamUp(t *testing.T) {
	f := &seqTokenClient{}
	m := newTokenMirror(f, "robot-1", time.Hour) // huge interval: poller never fires again mid-test
	m.setStream(true)
	if _, err := m.get(context.Background(), req()); err != nil {
		t.Fatal(err)
	}
	settle()
	before := f.calls.Load()
	for i := 0; i < 4; i++ {
		if _, err := m.get(context.Background(), req()); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.calls.Load(); got != before {
		t.Fatalf("want repeat reads served from the mirror (no upstream call), got %d calls after %d", got-before, before)
	}
}

// Stream down ⇒ fail-closed: the mirror is never served, every read is a
// synchronous upstream call.
func TestMirrorStreamDownGoesUpstream(t *testing.T) {
	f := &seqTokenClient{}
	m := newTokenMirror(f, "robot-1", time.Hour)
	m.setStream(true)
	if _, err := m.get(context.Background(), req()); err != nil {
		t.Fatal(err)
	}
	settle()
	m.setStream(false)
	settle() // stream loss kicks the poller; let that refresh land first
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		before := f.calls.Load()
		resp, err := m.get(context.Background(), req())
		if err != nil {
			t.Fatal(err)
		}
		if f.calls.Load() == before || seen[resp.GetChainId()] {
			t.Fatalf("read %d served without a fresh upstream answer (%s) — the mirror must not serve while the stream is down", i, resp.GetChainId())
		}
		seen[resp.GetChainId()] = true
	}
}

// Invalidate (mutation or beacon event) forces the next read upstream.
func TestMirrorInvalidateForcesRefetch(t *testing.T) {
	f := &seqTokenClient{}
	m := newTokenMirror(f, "robot-1", time.Hour)
	m.setStream(true)
	if _, err := m.get(context.Background(), req()); err != nil {
		t.Fatal(err)
	}
	settle()
	cached, err := m.get(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	m.Invalidate()
	resp, err := m.get(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetChainId() == cached.GetChainId() {
		t.Fatalf("read after Invalidate returned the mirrored answer %s — want a fresh upstream answer", resp.GetChainId())
	}
}

// Hard age cap: an entry older than 3× interval is never served even with the
// stream up (bounds staleness if the poller wedges).
func TestMirrorAgeCap(t *testing.T) {
	f := &fakeTokenClient{}
	m := newTokenMirror(f, "robot-1", 10*time.Millisecond)
	m.streamUp.Store(true) // bypass setStream to avoid poller interplay
	if _, err := m.get(context.Background(), req()); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.at = time.Now().Add(-31 * time.Millisecond) // > 3×10ms
	m.mu.Unlock()
	if _, err := m.get(context.Background(), req()); err != nil {
		t.Fatal(err)
	}
	if got := f.calls.Load(); got < 2 {
		t.Fatalf("want over-age refetch (>=2 upstream calls), got %d", got)
	}
}

// Requests for a different robot are always passthrough (never cached).
func TestMirrorOtherRobotPassthrough(t *testing.T) {
	f := &fakeTokenClient{}
	m := newTokenMirror(f, "robot-1", time.Hour)
	m.setStream(true)
	other := &tokenpb.GetActiveTokenRequest{RobotId: "robot-2"}
	for i := 0; i < 3; i++ {
		if _, err := m.get(context.Background(), other); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.calls.Load(); got != 3 {
		t.Fatalf("want 3 upstream calls for foreign robot, got %d", got)
	}
}

// AV1 (AV LLD §1.3): a failed background refresh must NOT destroy the cache.
// Pre-AV1 the poller set resp=nil on any error, so one WAN hiccup discarded a
// token that was still signed, unexpired and unrevoked (AV0-1 threw away 28.9s
// of remaining validity over a 600ms stall). Staleness stays bounded by the age
// cap (TestMirrorAgeCap) and by the gate's own not_after check.
func TestMirrorFailedRefreshKeepsCache(t *testing.T) {
	f := &fakeTokenClient{}
	m := newTokenMirror(f, "robot-1", 10*time.Millisecond)
	m.setStream(true)
	if _, err := m.get(context.Background(), req()); err != nil {
		t.Fatal(err)
	}

	f.fail.Store(true)
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		failed := m.refreshErr != nil
		m.mu.Unlock()
		if failed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background refresh never failed — test did not exercise the error path")
		}
		time.Sleep(2 * time.Millisecond)
	}

	m.mu.Lock()
	cached := m.resp
	m.mu.Unlock()
	if cached == nil {
		t.Fatal("failed refresh destroyed the cache (pre-AV1 self-destruct)")
	}
}

// A failed refresh keeps the cache, but losing the beacon stream still clears
// it — the two must not be confused.
func TestMirrorStreamLossStillClearsCache(t *testing.T) {
	f := &fakeTokenClient{}
	m := newTokenMirror(f, "robot-1", time.Hour)
	m.setStream(true)
	if _, err := m.get(context.Background(), req()); err != nil {
		t.Fatal(err)
	}
	m.setStream(false)
	m.mu.Lock()
	cached := m.resp
	m.mu.Unlock()
	if cached != nil {
		t.Fatal("stream loss must invalidate the mirror")
	}
}

// Non-mutating telemetry reports are acked locally (no WAN wait) and still
// reach the upstream in the background.
func TestReportAsyncAck(t *testing.T) {
	f := &fakeTokenClient{reportDelay: 50 * time.Millisecond}
	m := newTokenMirror(f, "robot-1", 0)
	p := &tokenProxy{c: f, m: m, f: newReportForwarder(f)}
	start := time.Now()
	resp, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{
		RobotId: "robot-1", Decision: tokenpb.Decision_PERMIT, ReasonCode: "OK",
	})
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("want local ack, got resp=%v err=%v", resp, err)
	}
	if el := time.Since(start); el > 20*time.Millisecond {
		t.Fatalf("telemetry report blocked %v (must not wait the WAN round trip)", el)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		n := len(f.reports)
		f.mu.Unlock()
		if n == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("report never forwarded upstream")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A mutating report (step_complete/fatal) is synchronous and never overtakes
// previously queued telemetry at the upstream (audit order preserved).
func TestReportMutatingSyncAndOrdered(t *testing.T) {
	f := &fakeTokenClient{reportDelay: 20 * time.Millisecond}
	m := newTokenMirror(f, "robot-1", 0)
	p := &tokenProxy{c: f, m: m, f: newReportForwarder(f)}
	for i := 0; i < 3; i++ {
		if _, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{
			RobotId: "robot-1", Decision: tokenpb.Decision_PERMIT, ReasonCode: "OK",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{
		RobotId: "robot-1", Decision: tokenpb.Decision_PERMIT, ReasonCode: "OK", StepComplete: true,
	}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) != 4 {
		t.Fatalf("want 4 upstream reports after mutating sync return, got %d", len(f.reports))
	}
	if !f.reports[3].GetStepComplete() {
		t.Fatal("mutating report overtook queued telemetry (audit order broken)")
	}
}

// Poller fail-closed: an errored refresh clears the mirror, so the next read
// surfaces the upstream error instead of serving stale state.
func TestMirrorPollerFailClosed(t *testing.T) {
	f := &fakeTokenClient{}
	m := newTokenMirror(f, "robot-1", 5*time.Millisecond)
	m.setStream(true)
	if _, err := m.get(context.Background(), req()); err != nil {
		t.Fatal(err)
	}
	f.fail.Store(true)
	m.Invalidate() // kick the poller into the failing refresh immediately
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := m.get(context.Background(), req())
		if err != nil {
			return // fail-closed surfaced
		}
		if time.Now().After(deadline) {
			t.Fatal("mirror kept serving after upstream started failing")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
