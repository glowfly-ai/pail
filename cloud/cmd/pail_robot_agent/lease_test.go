// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// AV2 (AV LLD §3): gateway-side edge lease.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// leaseClient serves a fixed lease window and can be taken offline.
type leaseClient struct {
	mu       sync.Mutex
	down     atomic.Bool
	getDown  atomic.Bool
	getCalls atomic.Int64
	reports  []string
	census   []*tokenpb.GatewayCensusRequest
	accept   bool

	first    int32
	epoch    uint64
	tokenIDs []string
	notAfter int64  // informational copy's not_after_unix_ms (0 = none)
	signedNA int64  // not_after_unix_ms encoded in the signed bytes (0 = no signed bytes)
	chain    string // chain id served (empty = "chain-1")
	verdict  string // census verdict answered (empty = "OK")
}

func newLeaseClient(first int32, ids ...string) *leaseClient {
	return &leaseClient{first: first, tokenIDs: ids, accept: true}
}

// window builds the tokens the fake issuer currently delegates. Called under c.mu: the poller goroutine reads
// these fields while a test rewrites them (set), and the race detector sees it.
func (c *leaseClient) window() []*pb.SignedToken {
	out := make([]*pb.SignedToken, 0, len(c.tokenIDs))
	for _, id := range c.tokenIDs {
		tok := &pb.SignedToken{Token: &pb.ActionToken{TokenId: id, NotAfterUnixMs: c.notAfter}}
		if c.signedNA != 0 {
			raw, err := proto.Marshal(&pb.ActionToken{TokenId: id, NotAfterUnixMs: c.signedNA})
			if err != nil {
				panic(err)
			}
			tok.ActionTokenBytes = raw
		}
		out = append(out, tok)
	}
	return out
}

// set replaces what the fake issuer serves next (the chain's position, validity and tokens).
func (c *leaseClient) set(first int32, notAfter int64, ids ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.first, c.notAfter, c.tokenIDs = first, notAfter, ids
}

func (c *leaseClient) GetActiveToken(ctx context.Context, in *tokenpb.GetActiveTokenRequest, opts ...grpc.CallOption) (*tokenpb.GetActiveTokenResponse, error) {
	c.getCalls.Add(1)
	if c.down.Load() || c.getDown.Load() {
		return nil, errors.New("cloud unreachable")
	}
	c.mu.Lock()
	toks := c.window()
	first, epoch, chain := c.first, c.epoch, c.chain
	c.mu.Unlock()
	if chain == "" {
		chain = "chain-1"
	}
	return &tokenpb.GetActiveTokenResponse{
		Status:                tokenpb.ActiveTokenStatus_OK,
		ChainId:               chain,
		ExpectedSequenceIndex: first,
		Token:                 toks[0],
		CurrentSubgraphHash:   []byte("world-hash"),
		LeaseTokens:           toks,
		LeaseMaxIndex:         first + int32(len(toks)) - 1,
		IssuerEpoch:           epoch,
	}, nil
}

func (c *leaseClient) Attest(ctx context.Context, in *tokenpb.AttestRequest, opts ...grpc.CallOption) (*tokenpb.AttestResponse, error) {
	return &tokenpb.AttestResponse{Status: "OK"}, nil
}

func (c *leaseClient) SealConfig(ctx context.Context, in *tokenpb.SealConfigRequest, opts ...grpc.CallOption) (*tokenpb.SealConfigResponse, error) {
	return &tokenpb.SealConfigResponse{Status: "OK"}, nil
}

func (c *leaseClient) ReportDecision(ctx context.Context, in *tokenpb.ReportDecisionRequest, opts ...grpc.CallOption) (*tokenpb.ReportDecisionResponse, error) {
	if c.down.Load() {
		return nil, errors.New("cloud unreachable")
	}
	c.mu.Lock()
	c.reports = append(c.reports, in.GetTokenId())
	accepted := c.accept
	c.mu.Unlock()
	return &tokenpb.ReportDecisionResponse{Accepted: accepted}, nil
}

func (c *leaseClient) ReportGatewayCensus(ctx context.Context, in *tokenpb.GatewayCensusRequest, opts ...grpc.CallOption) (*tokenpb.GatewayCensusResponse, error) {
	if c.down.Load() {
		return nil, errors.New("cloud unreachable")
	}
	c.mu.Lock()
	c.census = append(c.census, in)
	verdict := c.verdict
	c.mu.Unlock()
	if verdict == "" {
		verdict = "OK"
	}
	return &tokenpb.GatewayCensusResponse{Accepted: true, Verdict: verdict, IssuerEpoch: c.epoch}, nil
}

func (c *leaseClient) declared() []*tokenpb.GatewayCensusRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*tokenpb.GatewayCensusRequest(nil), c.census...)
}

func (c *leaseClient) reported() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.reports...)
}

func leasedProxy(t *testing.T, c *leaseClient) (*tokenProxy, *tokenMirror) {
	t.Helper()
	m := newTokenMirror(c, "robot-1", time.Hour) // poller never fires mid-test
	m.setStream(true)
	return &tokenProxy{c: c, m: m, f: newReportForwarder(c)}, m
}

func serve(t *testing.T, p *tokenProxy) *tokenpb.GetActiveTokenResponse {
	t.Helper()
	resp, err := p.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
	if err != nil {
		t.Fatalf("GetActiveToken: %v", err)
	}
	return resp
}

func step(t *testing.T, p *tokenProxy, tokenID string) {
	t.Helper()
	if _, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{
		RobotId: "robot-1", ChainId: "chain-1", TokenId: tokenID,
		Decision: tokenpb.Decision_PERMIT, ReasonCode: "OK", StepComplete: true,
	}); err != nil {
		t.Fatalf("ReportDecision(%s): %v", tokenID, err)
	}
}

// d5Client models the issuer's serving rule (D-5, cloud-side leaseServeIndex):
// every GetActiveToken inside an outstanding window reads as "the window is
// spent", so the next grant starts past lease_max_index. Against this rule a
// DUPLICATED request is not merely wasteful — it doubles the delegated depth.
//
// The first call parks until a second one arrives (or a short grace elapses),
// which makes the 1ms overlap seen in the live AV2 run deterministic here.
type d5Client struct {
	leaseClient
	steps int32

	gmu     sync.Mutex
	calls   int
	next    int32
	max     int32
	granted []int32

	second   chan struct{}
	overlap  sync.Once
	graceDur time.Duration
}

func newD5Client(steps int32) *d5Client {
	return &d5Client{steps: steps, next: 1, second: make(chan struct{}), graceDur: 300 * time.Millisecond}
}

func (c *d5Client) GetActiveToken(ctx context.Context, in *tokenpb.GetActiveTokenRequest, opts ...grpc.CallOption) (*tokenpb.GetActiveTokenResponse, error) {
	c.gmu.Lock()
	c.calls++
	n := c.calls
	c.gmu.Unlock()

	if n == 1 {
		select {
		case <-c.second:
		case <-time.After(c.graceDur):
		}
	} else {
		c.overlap.Do(func() { close(c.second) })
	}

	c.gmu.Lock()
	defer c.gmu.Unlock()
	first := c.next
	if c.max >= first {
		first = c.max + 1 // leaseServeIndex: silence means the window was spent
	}
	last := first + c.steps - 1
	c.max = last
	c.granted = append(c.granted, last)

	toks := make([]*pb.SignedToken, 0, c.steps)
	for i := first; i <= last; i++ {
		toks = append(toks, &pb.SignedToken{Token: &pb.ActionToken{TokenId: fmt.Sprintf("t%d", i)}})
	}
	return &tokenpb.GetActiveTokenResponse{
		Status:                tokenpb.ActiveTokenStatus_OK,
		ChainId:               "chain-1",
		ExpectedSequenceIndex: first,
		Token:                 toks[0],
		CurrentSubgraphHash:   []byte("world-hash"),
		LeaseTokens:           toks,
		LeaseMaxIndex:         last,
	}, nil
}

func (c *d5Client) stats() (int, []int32) {
	c.gmu.Lock()
	defer c.gmu.Unlock()
	return c.calls, append([]int32(nil), c.granted...)
}

// §3.5 (HLD D-11): the gateway must never have two GetActiveToken calls in
// flight at once. Under D-5 the second is read as "the first window is spent",
// so the issuer delegates 2×MAX_STEPS while the gateway can only serve one
// window — the OVER_LEASE ceiling opens to twice the policy.
//
// This is the drive-start path exactly as it runs in production: get() starts
// the poller, and the poller's first iteration finds no lease and goes upstream
// while get()'s own call is still out.
func TestFirstServeGrantsExactlyOneLease(t *testing.T) {
	c := newD5Client(5)
	m := newTokenMirror(c, "robot-1", time.Hour)
	m.setStream(true)
	p := &tokenProxy{c: c, m: m, f: newReportForwarder(c)}

	resp := serve(t, p)
	time.Sleep(500 * time.Millisecond) // let any second call land

	calls, granted := c.stats()
	if calls != 1 {
		t.Fatalf("upstream GetActiveToken calls=%d (grants=%v), want 1 — a duplicate request doubles the delegation", calls, granted)
	}
	if got := resp.GetExpectedSequenceIndex(); got != 1 {
		t.Fatalf("served index=%d, want 1", got)
	}
	m.mu.Lock()
	leaseMax := m.leaseMax
	m.mu.Unlock()
	if leaseMax != 5 {
		t.Fatalf("gateway leaseMax=%d, want 5", leaseMax)
	}
	if len(granted) != 1 || granted[0] != 5 {
		t.Fatalf("issuer delegated %v, want one grant up to index 5", granted)
	}
}

// §3.5: the same rule under concurrent gate reads — the 20Hz recheck and the
// poller can collide on any refresh, not just the first.
func TestConcurrentServesShareOneGrant(t *testing.T) {
	c := newD5Client(5)
	m := newTokenMirror(c, "robot-1", time.Hour)
	m.setStream(true)
	p := &tokenProxy{c: c, m: m, f: newReportForwarder(c)}

	var wg sync.WaitGroup
	got := make([]int32, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := p.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
			if err != nil {
				t.Errorf("GetActiveToken: %v", err)
				return
			}
			got[i] = resp.GetExpectedSequenceIndex()
		}(i)
	}
	wg.Wait()
	time.Sleep(500 * time.Millisecond)

	calls, granted := c.stats()
	if calls != 1 {
		t.Fatalf("upstream calls=%d (grants=%v), want 1", calls, granted)
	}
	if got[0] != 1 || got[1] != 1 {
		t.Fatalf("served indices=%v, want both 1 — no caller may be handed a step out of order", got)
	}
}

// §3.2/§3.3: with the cloud gone, the whole leased window is still served, one
// step at a time, without a single upstream call.
func TestLeaseServesWholeWindowOffline(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2", "t3")
	p, m := leasedProxy(t, c)

	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "t1" {
		t.Fatalf("first serve=%s, want t1", got)
	}
	c.down.Store(true)
	m.setStream(false) // the outage the lease exists to survive
	before := c.getCalls.Load()

	for _, id := range []string{"t1", "t2"} {
		step(t, p, id)
		next := serve(t, p)
		if next.Status != tokenpb.ActiveTokenStatus_OK {
			t.Fatalf("after consuming %s: status=%v, want OK", id, next.Status)
		}
		if string(next.CurrentSubgraphHash) != "world-hash" {
			t.Fatalf("lease serving must reuse the last world hash, got %q", next.CurrentSubgraphHash)
		}
		// The gate must not see the issuer-gateway lease fields (§3.2).
		if len(next.LeaseTokens) != 0 || next.LeaseMaxIndex != 0 || next.IssuerEpoch != 0 {
			t.Fatal("lease fields must not be handed to the gate")
		}
	}
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "t3" {
		t.Fatalf("third serve=%s, want t3", got)
	}
	if c.getCalls.Load() != before {
		t.Fatalf("lease serving hit the cloud %d times", c.getCalls.Load()-before)
	}
}

// §3.3: the lease depth IS the stopping distance. Past lease_max_index the
// gateway falls back to the cloud, and with the cloud gone the gate gets an
// error and blocks.
func TestLeaseExhaustionStopsAtTheCloud(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	p, m := leasedProxy(t, c)
	serve(t, p)
	c.down.Store(true)
	m.setStream(false)

	step(t, p, "t1")
	step(t, p, "t2") // window spent

	if _, err := p.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}); err == nil {
		t.Fatal("past the lease the gateway must fall back to the cloud and fail")
	}
}

// §3.3: consumption reported while offline is queued in order and replayed on
// stream recovery; remaining unspent authority is retained without re-fetching.
func TestLeaseReportsReplayedInOrderOnReconcile(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2", "t3")
	p, m := leasedProxy(t, c)
	serve(t, p)
	c.down.Store(true)
	m.setStream(false)

	step(t, p, "t1")
	step(t, p, "t2")
	if got := len(c.reported()); got != 0 {
		t.Fatalf("cloud saw %d reports while down", got)
	}
	m.mu.Lock()
	pending := len(m.pendingRep)
	m.mu.Unlock()
	if pending != 2 {
		t.Fatalf("pendingRep=%d, want 2", pending)
	}

	c.down.Store(false)
	before := c.getCalls.Load()
	m.reconcile()

	if got := c.reported(); len(got) != 2 || got[0] != "t1" || got[1] != "t2" {
		t.Fatalf("replayed reports=%v, want [t1 t2] in order", got)
	}
	m.mu.Lock()
	pending = len(m.pendingRep)
	m.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pendingRep=%d after reconcile, want 0", pending)
	}
	if c.getCalls.Load() != before {
		t.Fatalf("reconcile must preserve the remaining unspent t3 grant, extra calls=%d", c.getCalls.Load()-before)
	}
	resp := serve(t, p)
	if resp.GetToken().GetToken().GetTokenId() != "t3" || resp.GetExpectedSequenceIndex() != 3 {
		t.Fatalf("replayed completions must not rewind t1/t2 or discard t3: %v", resp)
	}
}

// §3.3 + D-5: a stream flap with nothing consumed has nothing to reconcile.
// The forced refresh must be skipped — inside our own live window the issuer
// reads a second call as "the window is spent" and serves past it, so a
// reconnect would silently throw away the steps we still hold.
func TestReconcileWithoutPendingKeepsWindow(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2", "t3")
	p, m := leasedProxy(t, c)
	serve(t, p)

	m.setStream(false) // a flap, not an outage: nothing was consumed
	before := c.getCalls.Load()
	m.setStream(true)
	m.reconcile()

	if c.getCalls.Load() != before {
		t.Fatalf("reconcile with an intact window hit the cloud %d times", c.getCalls.Load()-before)
	}
	if !m.leaseHeld() {
		t.Fatal("the window must survive a stream flap")
	}
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "t1" {
		t.Fatalf("serving %s after the flap, want t1 — no step was consumed", got)
	}
}

// §3.3: an issuer refusal during reconcile (over-lease, revoked chain) drops
// the window — the verdict is the issuer's to enforce.
func TestLeaseRefusalOnReconcileDropsWindow(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2", "t3")
	p, m := leasedProxy(t, c)
	serve(t, p)
	c.down.Store(true)
	m.setStream(false)
	step(t, p, "t1")

	c.mu.Lock()
	c.accept = false
	c.mu.Unlock()
	c.down.Store(false)
	c.getDown.Store(true) // no fresh window to mask the drop
	m.reconcile()

	if m.leaseHeld() {
		t.Fatal("an issuer refusal during reconcile must drop the lease")
	}
	if _, err := p.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}); err == nil {
		t.Fatal("after the drop the gateway must go to the cloud")
	}
}

// §3.3/§4.5: a response from an older generation is refused and everything the
// gateway was serving from is dropped.
func TestEpochRegressionRefused(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	c.epoch = 7
	p, m := leasedProxy(t, c)
	serve(t, p)

	c.epoch = 6 // a demoted issuer answering from the past
	m.Invalidate()
	if _, err := p.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}); !errors.Is(err, errEpochRegression) {
		t.Fatalf("err=%v, want epoch regression refusal", err)
	}
	if m.leaseHeld() {
		t.Fatal("an epoch regression must drop the lease")
	}
}

// Safety: everything that invalidated before AV2 still purges the lease; only
// stream loss preserves it.
func TestInvalidateDropsLeaseStreamLossDoesNot(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	p, m := leasedProxy(t, c)
	serve(t, p)

	m.setStream(false)
	if !m.leaseHeld() {
		t.Fatal("stream loss must NOT drop the lease")
	}
	// Invalidate kicks the poller, and this fixture re-grants the same window
	// on any refresh (a real issuer does not re-serve a revoked chain) — a
	// refresh landing before the check re-absorbed it (flake, see
	// TestRevokingBeaconsReleaseTheDelegatedWindow).
	c.getDown.Store(true)
	m.Invalidate() // what a revocation beacon does
	if m.leaseHeld() {
		t.Fatal("Invalidate must drop the lease")
	}
	c.down.Store(true)
	if _, err := p.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}); err == nil {
		t.Fatal("after invalidation the gateway must go to the cloud")
	}
}

// An expired window is not a window. The lease delegates the not_after judgement to the gate; once the gate
// has reported ERR_EXPIRED on the very token this gateway is serving from its lease, holding the grant only
// hands the same dead token to every later recheck — while the issuer may already have accepted the next
// plan. Measured 2026-10-09 on the software rig: an adapter judged one command (PERMIT, step never
// completed), the plan expired, a new plan was ACCEPTED, and the gateway kept serving the old token
// (BLOCK ERR_EXPIRED) for 15 minutes. Only the console's cancel beacon ever released it.
func TestExpiredLeasedTokenReleasesTheWindow(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	p, m := leasedProxy(t, c)
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "t1" {
		t.Fatalf("first serve: %s", got)
	}
	if !m.leaseHeld() {
		t.Fatal("lease not held after the first serve")
	}
	// A BLOCK for another reason on the leased token keeps the window (the token is untouched).
	if _, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{
		RobotId: "robot-1", ChainId: "chain-1", TokenId: "t1", Decision: tokenpb.Decision_BLOCK, ReasonCode: "ERR_CONSTRAINT",
	}); err != nil {
		t.Fatal(err)
	}
	if !m.leaseHeld() {
		t.Fatal("a non-expiry BLOCK released the window")
	}
	// ERR_EXPIRED on a token this gateway is NOT serving (another chain) changes nothing.
	if _, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{
		RobotId: "robot-1", ChainId: "chain-old", TokenId: "t0", Decision: tokenpb.Decision_BLOCK, ReasonCode: "ERR_EXPIRED",
	}); err != nil {
		t.Fatal(err)
	}
	if !m.leaseHeld() {
		t.Fatal("an expiry report for another chain released the window")
	}
	// From here the cloud answers no token read. Before the fix the gateway did not need the cloud: it
	// kept answering t1 from its lease. After the fix the window is gone, so a read must go upstream —
	// and with the cloud unreachable it fails closed instead of handing out the dead token. (The poller
	// may also refresh after the drop; taking the cloud away makes the outcome independent of that race.)
	c.getDown.Store(true)
	// ERR_EXPIRED on the leased token: the window is spent and the drop is declared.
	if _, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{
		RobotId: "robot-1", ChainId: "chain-1", TokenId: "t1", Decision: tokenpb.Decision_BLOCK, ReasonCode: "ERR_EXPIRED",
	}); err != nil {
		t.Fatal(err)
	}
	if resp, err := p.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}); err == nil {
		t.Fatalf("the dead leased token was still served after the gate reported it expired: %v", resp.GetToken().GetToken().GetTokenId())
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(c.declared()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if d := c.declared(); len(d) == 0 || d[len(d)-1].GetHeldLeaseMaxIndex() != 0 || d[len(d)-1].GetChainId() != "chain-1" {
		t.Fatalf("the drop was not declared to the issuer: %v", d)
	}
}

// A lease cannot outlive its tokens. Past the current token's not_after every recheck served from the
// window is refused by the gate anyway, while the issuer may already hold the next plan — which this
// gateway never asks about while it believes it holds a usable window. So the window is released on the
// gateway's own clock (a liveness decision; validity is still the gate's), declared, and the next read
// goes to the issuer. With the cloud away the read fails closed instead of handing out the dead token.
func TestLeaseDoesNotOutliveItsToken(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	c.notAfter = 1_000_000
	p, m := leasedProxy(t, c)
	var clock atomic.Int64 // the poller reads the clock too
	clock.Store(999_000)
	m.nowFn = func() time.Time { return time.UnixMilli(clock.Load()) }
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "t1" {
		t.Fatalf("first serve: %s", got)
	}
	clock.Store(1_000_000) // not_after itself is still inside the window
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "t1" || !m.leaseHeld() {
		t.Fatalf("at not_after the window must still serve: %s held=%v", got, m.leaseHeld())
	}
	before := c.getCalls.Load()
	clock.Store(1_000_001)
	c.getDown.Store(true)
	if resp, err := p.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}); err == nil {
		t.Fatalf("a token past its not_after was still served from the lease: %v", resp.GetToken().GetToken().GetTokenId())
	}
	if m.leaseHeld() {
		t.Fatal("the window survived its token")
	}
	// At least one: the poller reads the same clock and may refresh concurrently (2 of 20 -race runs
	// counted 1 -> 3), so an exact +1 measured the scheduler, not this read.
	if c.getCalls.Load() <= before {
		t.Fatalf("the read after the release did not go to the issuer (calls %d -> %d)", before, c.getCalls.Load())
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(c.declared()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if d := c.declared(); len(d) == 0 || d[len(d)-1].GetHeldLeaseMaxIndex() != 0 || d[len(d)-1].GetChainId() != "chain-1" {
		t.Fatalf("the release was not declared to the issuer: %v", d)
	}
	// The issuer is back with the next plan: the very next read serves it — no refusal in between.
	c.getDown.Store(false)
	c.set(7, 2_000_000, "n1")
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "n1" {
		t.Fatalf("the next plan's token was not served after the release: %s", got)
	}
	if !m.leaseHeld() {
		t.Fatal("the new window was not taken")
	}
}

// The expiry is read from the signed bytes — the bytes the gate judges — not from the informational copy.
func TestLeaseExpiryReadsTheSignedBytes(t *testing.T) {
	c := newLeaseClient(1, "t1")
	c.notAfter, c.signedNA = 2_000_000, 1_000_000
	p, m := leasedProxy(t, c)
	m.nowFn = func() time.Time { return time.UnixMilli(1_500_000) }
	// The first read takes the window from the issuer's answer; the window is judged when it is next served.
	if _, err := p.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}); err != nil {
		t.Fatalf("first read: %v", err)
	}
	c.getDown.Store(true)
	// The informational copy says 2_000_000 (valid); the signed bytes say 1_000_000 (past) — the signed bytes win.
	if resp, err := p.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}); err == nil {
		t.Fatalf("the window was served on the strength of the informational not_after: %v", resp.GetToken().GetToken().GetTokenId())
	}
	if m.leaseHeld() {
		t.Fatal("the window was kept on the strength of the informational not_after")
	}
}

// A token without any not_after (none in the signed bytes, none in the copy) gives the window no expiry
// of its own: the gate alone judges, and expiredLeased releases on its ERR_EXPIRED report.
func TestLeaseWithoutNotAfterHasNoClockOfItsOwn(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	p, m := leasedProxy(t, c)
	m.nowFn = func() time.Time { return time.UnixMilli(1 << 50) }
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "t1" || !m.leaseHeld() {
		t.Fatalf("a window without not_after must be served: %s held=%v", got, m.leaseHeld())
	}
}

// Within one chain the window holds consecutive tokens with their own validity. When the token being served runs
// out while the next one is still valid, the window is released as a whole (the gateway does not pick the next
// token itself: which step is current is the issuer's judgement) and the very next read fetches the issuer's
// answer for the chain — here the next token — without a refusal in between. The drop is declared.
func TestExpiredTokenOfAChainRefetchesTheNextOne(t *testing.T) {
	c := newLeaseClient(1, "k1", "k2")
	c.notAfter = 1_000_000
	p, m := leasedProxy(t, c)
	var clock atomic.Int64
	clock.Store(900_000)
	m.nowFn = func() time.Time { return time.UnixMilli(clock.Load()) }
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "k1" {
		t.Fatalf("first serve: %s", got)
	}
	// the issuer now answers with the next step of the same chain, valid for longer
	c.set(2, 2_000_000, "k2")
	before := c.getCalls.Load()
	clock.Store(1_000_001)
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "k2" {
		t.Fatalf("after k1 ran out the next read must serve the issuer's next token, got %s", got)
	}
	// At least one: the poller reads the same clock and may refresh concurrently (2 of 20 -race runs
	// counted 1 -> 3), so an exact +1 measured the scheduler, not this read.
	if c.getCalls.Load() <= before {
		t.Fatalf("the read did not go to the issuer (calls %d -> %d)", before, c.getCalls.Load())
	}
	if !m.leaseHeld() {
		t.Fatal("the new window was not taken")
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(c.declared()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if d := c.declared(); len(d) == 0 || d[0].GetChainId() != "chain-1" {
		t.Fatalf("the release was not declared: %v", d)
	}
}
