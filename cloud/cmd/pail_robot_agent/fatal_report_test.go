// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// P15-H1 (preview.15 evaluation, TB3 judge2 scene 8, 2026-10-16): the ESTOP's
// fatal report never reached the issuer — it waited behind 13 queued PERMIT
// reports, then went upstream under the gate's 50 ms context, failed once, and
// was never retried. These tests pin the three properties of the fix: a fatal
// jumps the telemetry queue, runs under its own timeout detached from the gate's
// context, and is retried durably until the issuer confirms it.

// fatalLinkClient models a WAN link: every upstream call takes `delay` and honours
// the caller's context (a gRPC deadline fails the call), and the first
// `failFatal` fatal reports fail with UNAVAILABLE (the lost RPC). `arrivals`
// records every call in completion order — "permit", "fatal" (confirmed) or
// "fatal-dropped" (the attempt the link lost).
type fatalLinkClient struct {
	fakeTokenClient
	delay     time.Duration
	mu        sync.Mutex
	failFatal int
	arrivals  []string
}

func (f *fatalLinkClient) ReportDecision(ctx context.Context, in *tokenpb.ReportDecisionRequest, opts ...grpc.CallOption) (*tokenpb.ReportDecisionResponse, error) {
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return nil, status.Error(codes.DeadlineExceeded, ctx.Err().Error())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if in.GetFatal() {
		if f.failFatal > 0 {
			f.failFatal--
			f.arrivals = append(f.arrivals, "fatal-dropped")
			return nil, status.Error(codes.Unavailable, "link dropped")
		}
		f.arrivals = append(f.arrivals, "fatal")
	} else {
		f.arrivals = append(f.arrivals, "permit")
	}
	f.reports = append(f.reports, in)
	return &tokenpb.ReportDecisionResponse{Accepted: true}, nil
}

func (f *fatalLinkClient) count(kind string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.arrivals {
		if a == kind {
			n++
		}
	}
	return n
}

func (f *fatalLinkClient) fatalCount() int { return f.count("fatal") }

// index of the first fatal attempt (dropped or confirmed) among all arrivals.
func (f *fatalLinkClient) firstFatalAttemptIndex() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, a := range f.arrivals {
		if a == "fatal" || a == "fatal-dropped" {
			return i
		}
	}
	return -1
}

func fatalReq() *tokenpb.ReportDecisionRequest {
	return &tokenpb.ReportDecisionRequest{RobotId: "robot-1", ChainId: "chain-1", TokenId: "tok-1",
		Decision: tokenpb.Decision_ESTOP, ReasonCode: "ERR_SAFETY_UNSAFE", Fatal: true}
}

func permitReq(i int) *tokenpb.ReportDecisionRequest {
	return &tokenpb.ReportDecisionRequest{RobotId: "robot-1", ChainId: "chain-1", TokenId: "tok-1",
		Decision: tokenpb.Decision_PERMIT, ReasonCode: "OK"}
}

// The judge2 shape: 13 PERMIT reports are queued on a slow link, the fatal
// report's first attempt is lost. Before the fix the proxy returned the error and
// forgot the report; the issuer never revoked the chain. Now the issuer sees the
// fatal (retried from the durable queue) and sees it before the telemetry backlog
// has drained.
func TestFatalReportJumpsQueueAndIsRetriedUntilConfirmed(t *testing.T) {
	f := &fatalLinkClient{delay: 30 * time.Millisecond, failFatal: 1}
	q, err := newReportQueue(f, reportQueueOptions{Attempt: time.Second, RetryMax: 50 * time.Millisecond, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	m := newTokenMirror(f, "robot-1", 0)
	p := &tokenProxy{c: f, m: m, f: q}
	for i := 0; i < 13; i++ {
		if _, err := p.ReportDecision(context.Background(), permitReq(i)); err != nil {
			t.Fatal(err)
		}
	}
	gateCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = p.ReportDecision(gateCtx, fatalReq())
	if err == nil {
		t.Fatal("the first fatal attempt was dropped by the link: the gate must be told, not handed a false confirmation")
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.fatalCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.fatalCount() == 0 {
		t.Fatal("fatal report never reached the issuer: not retried after the lost attempt (P15-H1)")
	}
	if f.count("fatal-dropped") != 1 {
		t.Fatalf("the link should have dropped exactly one fatal attempt, saw %d", f.count("fatal-dropped"))
	}
	if idx := f.firstFatalAttemptIndex(); idx < 0 || idx >= 13 {
		t.Fatalf("first fatal attempt reached the issuer at index %d: it must not wait behind the 13 queued PERMITs", idx)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("fatal confirmation took %v", took)
	}
}

// The gate's context is shorter than the issuer round trip. Before the fix the
// upstream call inherited it and failed at 50 ms; the report is now sent under
// its own timeout and the gate receives the confirmation.
func TestFatalReportDetachedFromGateDeadline(t *testing.T) {
	f := &fatalLinkClient{delay: 120 * time.Millisecond}
	q, err := newReportQueue(f, reportQueueOptions{Attempt: time.Second, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	m := newTokenMirror(f, "robot-1", 0)
	p := &tokenProxy{c: f, m: m, f: q}
	gateCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	resp, err := p.ReportDecision(gateCtx, fatalReq())
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("fatal report must be confirmed under its own timeout, got resp=%v err=%v", resp, err)
	}
	if f.fatalCount() != 1 {
		t.Fatalf("issuer saw %d fatal reports, want 1", f.fatalCount())
	}
}

// P16-L1 (preview.16 evaluation, TB3 fault injection 2026-10-17): one injected
// outage put the same ESTOP seven times in the Issuer ledger — the gate worker
// retried every 200 ms..2 s and each retry was forwarded upstream while the
// durable queue carried its own copy. Now a repeat of a fatal that is still
// queued is refused without an upstream call, and a repeat of a confirmed fatal
// is accepted locally; the issuer confirms the report exactly once.
func TestFatalRepeatsAreNotForwardedWhileQueued(t *testing.T) {
	f := &fatalLinkClient{delay: 10 * time.Millisecond, failFatal: 3}
	q, err := newReportQueue(f, reportQueueOptions{Attempt: time.Second, RetryMax: 40 * time.Millisecond, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	m := newTokenMirror(f, "robot-1", 0)
	p := &tokenProxy{c: f, m: m, f: q}
	if _, err := p.ReportDecision(context.Background(), fatalReq()); err == nil {
		t.Fatal("first attempt was dropped by the link; the gate must see the failure")
	}
	// The gate worker's retries while the queue still carries the report.
	for i := 0; i < 5; i++ {
		time.Sleep(10 * time.Millisecond)
		if f.fatalCount() > 0 {
			break
		}
		if _, err := p.ReportDecision(context.Background(), fatalReq()); err == nil {
			t.Fatal("a repeat of a queued fatal must not be confirmed before the issuer confirmed it")
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.fatalCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.fatalCount() != 1 {
		t.Fatalf("issuer confirmed %d fatal reports, want exactly 1", f.fatalCount())
	}
	// The fake issuer increments arrivals before returning its response. Wait
	// for that response to reach the tracker; observing server arrival alone
	// is not proof that the asynchronous client already confirmed it.
	for !p.fatals.confirmed(fatalKey(fatalReq())) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !p.fatals.confirmed(fatalKey(fatalReq())) {
		t.Fatal("confirmation did not reach the tracker")
	}
	// Repeats after confirmation: accepted locally, nothing more upstream.
	for i := 0; i < 3; i++ {
		resp, err := p.ReportDecision(context.Background(), fatalReq())
		if err != nil || !resp.GetAccepted() {
			t.Fatalf("repeat of a confirmed fatal must be accepted locally, got resp=%v err=%v", resp, err)
		}
	}
	if f.fatalCount() != 1 {
		t.Fatalf("issuer saw %d confirmed fatal reports after the repeats, want 1 (P16-L1 duplicates)", f.fatalCount())
	}
	// A different fatal (another token) is still forwarded.
	other := fatalReq()
	other.TokenId = "tok-2"
	if resp, err := p.ReportDecision(context.Background(), other); err != nil || !resp.GetAccepted() {
		t.Fatalf("a fatal for another token must still reach the issuer, got resp=%v err=%v", resp, err)
	}
	if f.fatalCount() != 2 {
		t.Fatalf("issuer saw %d confirmed fatal reports, want 2", f.fatalCount())
	}
}

// P17-L1 (preview.17 evaluation, 30 s Issuer pause on the TB3): `docker pause` delays the
// Issuer, it does not drop requests. The agent's first attempt ran for its 3 s window; a
// gate retry that arrived inside that window was forwarded as a SECOND RPC, and the
// resumed Issuer processed both, plus the queued copy: three ledger lines. heldLinkClient
// models that link — a call blocks until `release`, a caller whose context expires gets
// an error, and the paused side still processes the request once released.
type heldLinkClient struct {
	fakeTokenClient
	release   chan struct{}
	calls     atomic.Int64 // distinct upstream fatal RPCs opened
	delivered atomic.Int64 // fatal reports the issuer eventually processed
}

func (f *heldLinkClient) ReportDecision(ctx context.Context, in *tokenpb.ReportDecisionRequest, opts ...grpc.CallOption) (*tokenpb.ReportDecisionResponse, error) {
	if !in.GetFatal() {
		return &tokenpb.ReportDecisionResponse{Accepted: true}, nil
	}
	f.calls.Add(1)
	select {
	case <-f.release:
		f.delivered.Add(1)
		return &tokenpb.ReportDecisionResponse{Accepted: true}, nil
	case <-ctx.Done():
		go func() { <-f.release; f.delivered.Add(1) }() // the paused issuer still has the bytes
		return nil, status.Error(codes.DeadlineExceeded, ctx.Err().Error())
	}
}

func TestFatalRepeatsJoinTheInFlightAttempt(t *testing.T) {
	f := &heldLinkClient{release: make(chan struct{})}
	q, err := newReportQueue(f, reportQueueOptions{Attempt: 2 * time.Second, RetryMax: 100 * time.Millisecond, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	m := newTokenMirror(f, "robot-1", 0)
	p := &tokenProxy{c: f, m: m, f: q}
	leaderDone := make(chan error, 1)
	go func() {
		gateCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // the gate's PAIL_FATAL_REPORT_DEADLINE_MS
		defer cancel()
		_, err := p.ReportDecision(gateCtx, fatalReq())
		leaderDone <- err
	}()
	time.Sleep(50 * time.Millisecond)
	// The gate worker's retries while the first attempt is still in flight (agent window 3 s > gate 2 s).
	for i := 0; i < 6; i++ {
		gateCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		resp, err := p.ReportDecision(gateCtx, fatalReq())
		cancel()
		if err == nil || resp.GetAccepted() {
			t.Fatal("a repeat must not be confirmed while the issuer has not answered")
		}
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("repeats during the in-flight attempt opened %d upstream RPCs, want 1 (P17-L1)", n)
	}
	if err := <-leaderDone; err == nil {
		t.Fatal("the first attempt must fail at the agent's window while the issuer is paused")
	}
	// Now the report is queued: a repeat is refused at once, without a new RPC.
	if _, err := p.ReportDecision(context.Background(), fatalReq()); err == nil {
		t.Fatal("a repeat of a queued fatal must be refused until the issuer confirms it")
	}
	time.Sleep(150 * time.Millisecond) // the queue's attempt is on the wire (held)
	close(f.release)                   // the issuer resumes
	deadline := time.Now().Add(5 * time.Second)
	for !p.fatals.confirmed(fatalKey(fatalReq())) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	resp, err := p.ReportDecision(context.Background(), fatalReq())
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("after the queued copy was confirmed a repeat must be accepted locally, got resp=%v err=%v", resp, err)
	}
	if n := f.calls.Load(); n != 2 {
		t.Fatalf("upstream fatal RPCs opened: %d, want 2 (the first attempt and the queued copy)", n)
	}
	time.Sleep(50 * time.Millisecond)
	if n := f.delivered.Load(); n != 2 {
		t.Fatalf("the resumed issuer processed %d fatal reports, want 2 — the ledger bound the publisher states", n)
	}
}

// P18-H1 (preview.18 evaluation, E-wb4.0): the gate reported an E-STOP with no chain and no
// token (no live permit, Issuer unreachable). The tracker key of such a report is the same
// every time, so the second one was answered as "already confirmed" and never reached the
// Issuer — the Issuer never revoked the robot's current chain, and the plan resumed.
func TestAnonymousFatalIsForwardedEveryTime(t *testing.T) {
	f := &fatalLinkClient{delay: 5 * time.Millisecond}
	q, err := newReportQueue(f, reportQueueOptions{Attempt: time.Second, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	m := newTokenMirror(f, "robot-1", 0) // serves no chain: nothing to attribute to
	p := &tokenProxy{c: f, m: m, f: q}
	anon := func() *tokenpb.ReportDecisionRequest {
		return &tokenpb.ReportDecisionRequest{RobotId: "robot-1", Decision: tokenpb.Decision_ESTOP, ReasonCode: "ERR_SAFETY_UNSAFE", Fatal: true}
	}
	for i := 1; i <= 3; i++ {
		resp, err := p.ReportDecision(context.Background(), anon())
		if err != nil || !resp.GetAccepted() {
			t.Fatalf("E-STOP %d: resp=%v err=%v", i, resp, err)
		}
		if n := f.fatalCount(); n != i {
			t.Fatalf("after E-STOP %d the issuer saw %d fatal reports, want %d — an anonymous fatal must never be answered from memory (P18-H1)", i, n, i)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.reports {
		if r.GetChainId() != "" {
			t.Fatalf("no chain was served, yet the forwarded report names %q", r.GetChainId())
		}
	}
}

// P18-H1: when the agent is serving a chain, a fatal that names nothing is attributed to it
// before it goes upstream — the Issuer then revokes by name, and the dedup key is specific.
func TestAnonymousFatalIsAttributedToTheServedChain(t *testing.T) {
	f := &fatalLinkClient{delay: 5 * time.Millisecond}
	q, err := newReportQueue(f, reportQueueOptions{Attempt: time.Second, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	m := newTokenMirror(f, "robot-1", 0)
	m.chainID = "chain-served"
	p := &tokenProxy{c: f, m: m, f: q}
	anon := &tokenpb.ReportDecisionRequest{RobotId: "robot-1", Decision: tokenpb.Decision_ESTOP, ReasonCode: "ERR_SAFETY_UNSAFE", Fatal: true}
	if _, err := p.ReportDecision(context.Background(), anon); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	got := f.reports[len(f.reports)-1].GetChainId()
	f.mu.Unlock()
	if got != "chain-served" {
		t.Fatalf("forwarded chain_id=%q, want the served chain", got)
	}
	// Attributed, it is a named fatal: a repeat is deduplicated as before (P16-L1).
	if _, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{RobotId: "robot-1", ChainId: "chain-served",
		Decision: tokenpb.Decision_ESTOP, ReasonCode: "ERR_SAFETY_UNSAFE", Fatal: true}); err != nil {
		t.Fatal(err)
	}
	if n := f.fatalCount(); n != 1 {
		t.Fatalf("the attributed repeat opened another RPC: %d fatal reports upstream, want 1", n)
	}
}

// A step-complete report keeps the pre-P15 path (drain, lease) — the fatal
// special case must not have widened it.
func TestStepCompleteStillDrainsBehindTelemetry(t *testing.T) {
	f := &fatalLinkClient{delay: 20 * time.Millisecond}
	q, err := newReportQueue(f, reportQueueOptions{Attempt: time.Second, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	m := newTokenMirror(f, "robot-1", 0)
	p := &tokenProxy{c: f, m: m, f: q}
	for i := 0; i < 3; i++ {
		if _, err := p.ReportDecision(context.Background(), permitReq(i)); err != nil {
			t.Fatal(err)
		}
	}
	done := &tokenpb.ReportDecisionRequest{RobotId: "robot-1", ChainId: "chain-1", TokenId: "tok-1",
		Decision: tokenpb.Decision_PERMIT, ReasonCode: "OK", StepComplete: true}
	if _, err := p.ReportDecision(context.Background(), done); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.arrivals) != 4 || f.arrivals[3] != "permit" {
		t.Fatalf("arrivals %v: the step-complete report must still follow the drained telemetry", f.arrivals)
	}
	last := f.reports[len(f.reports)-1]
	if !last.GetStepComplete() {
		t.Fatalf("last report must be the step-complete one, got %v", last)
	}
}

// P25-M2 (preview.25 evaluation, 2026-10-21): the report queue degraded to memory
// when its directory was unusable and the fatal path still logged "queued
// durably"; an agent+gate crash after an E-STOP then lost the ESTOP from the
// signed ledger (6 of 8 injected runs on the TB3 software demo, whose compose set
// no queue directory). Two properties pinned here: a queue that cannot be durable
// refuses to open (the agent exits instead of running non-durably), and a fatal is
// written ahead of its upstream attempt so a process that dies inside the attempt
// window still hands the E-STOP to the next run.
func TestReportQueueRefusesAnUnusableDirectory(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fatalLinkClient{}
	q, err := newReportQueue(f, reportQueueOptions{Dir: filepath.Join(blocker, "report_queue"), MaxBytes: 1 << 20})
	if err == nil {
		q.close()
		t.Fatal("a report queue whose directory cannot be created must refuse to open, not run memory-only")
	}
	if !strings.Contains(err.Error(), "REPORT_QUEUE_NOT_DURABLE") {
		t.Fatalf("refusal must name REPORT_QUEUE_NOT_DURABLE: %v", err)
	}
	// memory only remains available, but only when asked for (Dir == "")
	q2, err := newReportQueue(f, reportQueueOptions{})
	if err != nil || q2.isDurable() {
		t.Fatalf("explicit memory-only queue: err=%v durable=%v", err, q2 != nil && q2.isDurable())
	}
	q2.close()
}

// alwaysDownClient: every upstream call fails at once (the Issuer is stopped).
type alwaysDownClient struct{ fakeTokenClient }

func (*alwaysDownClient) ReportDecision(ctx context.Context, in *tokenpb.ReportDecisionRequest, opts ...grpc.CallOption) (*tokenpb.ReportDecisionResponse, error) {
	// a stopped Issuer (SIGSTOP, the evaluator's injection) holds the call until the deadline rather than refusing at once
	select {
	case <-time.After(300 * time.Millisecond):
	case <-ctx.Done():
	}
	return nil, status.Error(codes.Unavailable, "issuer stopped")
}

func TestFatalIsWrittenAheadAndReplayedByTheNextRun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "report_queue")
	down := &alwaysDownClient{}
	q, err := newReportQueue(down, reportQueueOptions{Dir: dir, MaxBytes: 1 << 20, Attempt: 100 * time.Millisecond, RetryMax: time.Hour, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	m := newTokenMirror(down, "robot-1", 0)
	p := &tokenProxy{c: down, m: m, f: q}
	// the write-ahead record exists during the attempt: observe it from a second goroutine while the attempt runs
	req := fatalReq()
	seen := make(chan bool, 1)
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(dir, fatalWALName(req))); err == nil {
				seen <- true
				return
			}
			time.Sleep(time.Millisecond)
		}
		seen <- false
	}()
	if _, err := p.ReportDecision(context.Background(), req); err == nil {
		t.Fatal("the issuer is down: the gate must be told")
	}
	if !<-seen {
		t.Fatal("no write-ahead record appeared before/while the upstream attempt ran (P25-M2)")
	}
	// the process dies here: the queue is not closed, its log holds the pushed copy and the WAL is already cleared
	// (the queue log took over). Simulate the worse case too — death before the push: leave a WAL behind by hand.
	if err := os.WriteFile(filepath.Join(dir, fatalWALName(req)), mustMarshal(t, req), 0o600); err != nil {
		t.Fatal(err)
	}
	up := &fatalLinkClient{}
	q2, err := newReportQueue(up, reportQueueOptions{Dir: dir, MaxBytes: 1 << 20, Attempt: time.Second, RetryMax: 20 * time.Millisecond, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q2.close()
	deadline := time.Now().Add(5 * time.Second)
	for up.fatalCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if up.fatalCount() < 1 {
		t.Fatal("the next run did not deliver the fatal left behind by the previous one (P25-M2)")
	}
	if _, err := os.Stat(filepath.Join(dir, fatalWALName(req))); err == nil {
		t.Fatal("the write-ahead record must be removed once re-queued")
	}
}

func mustMarshal(t *testing.T, req *tokenpb.ReportDecisionRequest) []byte {
	t.Helper()
	b, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
