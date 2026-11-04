// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// HW-A1 (TB3 hardware run, 2026-09-14): the gate asks for its token with a
// 50 ms deadline. The first upstream call to the issuer is slower than that
// (TLS handshake, WAN). Observed: ERR_ISSUER_UNREACHABLE once, then
// ERR_NO_TOKEN for good, while the issuer's journal shows the lease granted.
//
// The mechanism: the mirror ran the upstream GetActiveToken on the CALLER's
// context. The gate's deadline cancelled the RPC, the answer was thrown away,
// but the issuer had already recorded the lease (record-first). Under D-5 the
// next call reads as "that window was spent" and is served past it — for a
// one-step chain, NO_TOKEN, and nothing the gateway does afterwards can walk
// it back, because it never learned the chain it would have to declare.
//
// The grant is the issuer's once it is recorded; the gateway must receive it
// regardless of how patient the first asker happened to be.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"

	"google.golang.org/grpc"
)

// slowGrantIssuer models the issuer side exactly where it matters: the lease
// is recorded BEFORE the response travels (auditLeaseGrantedStrict, then
// LeaseMaxIndex = last), the travel takes `delay`, and a caller whose context
// ends first gets its context error — the recorded grant stays recorded.
// Serving follows leaseServeIndex (D-5) over a chain of `steps` tokens.
type slowGrantIssuer struct {
	leaseClient
	steps   int32
	delay   time.Duration
	revoked atomic.Bool // once set, the issuer answers REVOKED (the chain was revoked)

	gmu      sync.Mutex
	calls    int
	leaseMax int32
	grants   []int32
}

func (c *slowGrantIssuer) GetActiveToken(ctx context.Context, in *tokenpb.GetActiveTokenRequest, opts ...grpc.CallOption) (*tokenpb.GetActiveTokenResponse, error) {
	c.gmu.Lock()
	c.calls++
	if c.calls > 1 && c.revoked.Load() {
		c.gmu.Unlock()
		return &tokenpb.GetActiveTokenResponse{Status: tokenpb.ActiveTokenStatus_REVOKED, ChainId: "chain-1"}, nil
	}
	idx := int32(1) // nothing is ever reported in this test
	if c.leaseMax >= idx {
		idx = c.leaseMax + 1 // D-5: an unreported window reads as spent
	}
	var resp *tokenpb.GetActiveTokenResponse
	if idx > c.steps {
		resp = &tokenpb.GetActiveTokenResponse{Status: tokenpb.ActiveTokenStatus_NO_TOKEN}
	} else {
		last := c.steps
		toks := make([]*pb.SignedToken, 0, last-idx+1)
		for i := idx; i <= last; i++ {
			toks = append(toks, &pb.SignedToken{Token: &pb.ActionToken{TokenId: tokenName(i)}})
		}
		c.leaseMax = last // record-first: the grant exists before the reply leaves
		c.grants = append(c.grants, last)
		resp = &tokenpb.GetActiveTokenResponse{
			Status: tokenpb.ActiveTokenStatus_OK, ChainId: "chain-1", ExpectedSequenceIndex: idx,
			Token: toks[0], CurrentSubgraphHash: []byte("world-hash"),
			LeaseTokens: toks, LeaseMaxIndex: last,
		}
	}
	first := c.calls == 1
	c.gmu.Unlock()

	if first {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return nil, ctx.Err() // what a cancelled unary RPC looks like to the client
		}
	}
	return resp, nil
}

func tokenName(i int32) string { return "t" + string(rune('0'+i)) }

func (c *slowGrantIssuer) stats() (int, []int32) {
	c.gmu.Lock()
	defer c.gmu.Unlock()
	return c.calls, append([]int32(nil), c.grants...)
}

// gateAsk is the gate's recheck: a 50 ms deadline, as token_provider_grpc.cpp sets it.
func gateAsk(p *tokenProxy) (*tokenpb.GetActiveTokenResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	return p.GetActiveToken(ctx, &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
}

// The rig's shape: mirror refresh 200 ms (PAIL_TOKEN_MIRROR_MS), stream up, a
// one-step chain, and a first reply that takes 120 ms — longer than the gate's
// 50 ms, far shorter than anything that should count as "unreachable".
func TestSlowFirstReplyStillDeliversTheGrant(t *testing.T) {
	c := &slowGrantIssuer{steps: 1, delay: 120 * time.Millisecond}
	m := newTokenMirror(c, "robot-1", 200*time.Millisecond)
	m.setStream(true)
	p := &tokenProxy{c: c, m: m, f: newReportForwarder(c)}

	if resp, err := gateAsk(p); err == nil && resp.GetStatus() == tokenpb.ActiveTokenStatus_OK {
		t.Fatalf("first ask answered OK inside 50 ms — the fixture did not model a slow first reply")
	}

	deadline := time.Now().Add(2 * time.Second)
	var last *tokenpb.GetActiveTokenResponse
	var lastErr error
	for time.Now().Before(deadline) {
		last, lastErr = gateAsk(p)
		if lastErr == nil && last.GetStatus() == tokenpb.ActiveTokenStatus_OK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	calls, grants := c.stats()
	if lastErr != nil || last.GetStatus() != tokenpb.ActiveTokenStatus_OK {
		t.Fatalf("after a slow first reply the gate never got its token: status=%v err=%v (issuer calls=%d grants=%v) — the recorded grant was thrown away and D-5 served past it",
			last.GetStatus(), lastErr, calls, grants)
	}
	if got := last.GetToken().GetToken().GetTokenId(); got != "t1" || last.GetExpectedSequenceIndex() != 1 {
		t.Fatalf("served %s at index %d, want t1 at 1", got, last.GetExpectedSequenceIndex())
	}
	// D-11 still holds: the recovery is receiving the one grant, not asking twice.
	if len(grants) != 1 {
		t.Fatalf("issuer granted %v — recovery must not come from a second delegation", grants)
	}
}

// The caller's patience still bounds the caller: a gate with a short deadline
// gets its own deadline back promptly instead of waiting out the slow reply.
func TestSlowReplyDoesNotHoldTheGatePastItsDeadline(t *testing.T) {
	c := &slowGrantIssuer{steps: 1, delay: 400 * time.Millisecond}
	m := newTokenMirror(c, "robot-1", time.Hour)
	m.setStream(true)
	p := &tokenProxy{c: c, m: m, f: newReportForwarder(c)}

	start := time.Now()
	_, err := gateAsk(p)
	if waited := time.Since(start); waited > 150*time.Millisecond {
		t.Fatalf("gate waited %v on a 50 ms deadline — detaching the call must not detach the caller", waited)
	}
	if err == nil {
		t.Fatalf("a 50 ms ask against a 400 ms reply returned no error")
	}
}

// Detaching the call widens a window that was already there: a reply computed
// BEFORE a revocation can land AFTER the beacon's Invalidate. Before HW-A1 a
// slow reply to the gate was cancelled at 50 ms; now it completes, so without
// a guard a revoked chain's window would be re-installed by the reply that
// raced the beacon. The reply must not restore authority Invalidate removed —
// but its chain must still be learned and declared, or the issuer keeps the
// recorded grant open under D-5 with nobody able to walk it back (AV7).
func TestReplyThatRacedAnInvalidateRestoresNothing(t *testing.T) {
	c := &slowGrantIssuer{steps: 2, delay: 200 * time.Millisecond}
	m := newTokenMirror(c, "robot-1", time.Hour)
	m.setStream(true)
	p := &tokenProxy{c: c, m: m, f: newReportForwarder(c)}

	go func() { _, _ = gateAsk(p) }() // starts the slow call
	time.Sleep(60 * time.Millisecond)
	c.revoked.Store(true)
	m.Invalidate() // the revocation beacon arrives while the reply is in flight
	time.Sleep(300 * time.Millisecond)

	if m.leaseHeld() {
		t.Fatalf("a reply computed before the revocation re-installed the window after Invalidate")
	}
	resp, err := gateAsk(p)
	if err == nil && resp.GetStatus() == tokenpb.ActiveTokenStatus_OK {
		t.Fatalf("gate was served %s after the revocation — want a fresh upstream answer", resp.GetToken().GetToken().GetTokenId())
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, d := range c.declared() {
			if d.GetChainId() == "chain-1" && d.GetHeldLeaseMaxIndex() == 0 {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the discarded grant was never declared (census=%v) — the issuer keeps a window nobody holds", c.declared())
}

// M3 (TB3 raised wheels, 2026-09-15): the step-2 completion report advances the gateway to
// index 3 and kicks the poller BEFORE the report is forwarded. The poller's refresh reaches
// the issuer first, is answered from index 2 (its lease for step 2 still counts as live),
// and absorbing that answer walked the gateway back to index 2 with the consumed step-2
// token as a usable lease. The next plan's gate then read the old chain's consumed token
// (ERR_TOKEN_CONSUMED, then ERR_EXPIRED) until the stale lease expired.
//
// For one chain the issuer's serving position never moves below what the gateway has
// already reported consumed; an answer that does was computed before the report landed.
type heldIssuer struct {
	leaseClient
	release chan struct{}
}

func (c *heldIssuer) GetActiveToken(ctx context.Context, in *tokenpb.GetActiveTokenRequest, opts ...grpc.CallOption) (*tokenpb.GetActiveTokenResponse, error) {
	<-c.release // computed now (index 2), delivered after the gateway consumed step 2
	t2 := &pb.SignedToken{Token: &pb.ActionToken{TokenId: "t2"}}
	return &tokenpb.GetActiveTokenResponse{Status: tokenpb.ActiveTokenStatus_OK, ChainId: "chain-1", ExpectedSequenceIndex: 2,
		Token: t2, CurrentSubgraphHash: []byte("world-hash"), LeaseTokens: []*pb.SignedToken{t2}, LeaseMaxIndex: 2}, nil
}

func TestAnswerFromBeforeAConsumptionReportDoesNotRewind(t *testing.T) {
	c := &heldIssuer{release: make(chan struct{})}
	m := newTokenMirror(c, "robot-1", time.Hour)
	m.setStream(true)
	m.mu.Lock()
	m.chainID, m.servingIdx = "chain-1", 3 // steps 1 and 2 consumed; the two-step window is spent
	m.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.mu.Lock()
		_, _ = m.upstream(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}) // releases m.mu
	}()
	time.Sleep(20 * time.Millisecond)
	close(c.release)
	<-done

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.servingIdx != 3 || m.leaseUsableLocked() {
		t.Fatalf("a stale answer rewound the gateway: servingIdx=%d usable=%v lease=%v — the consumed step would be served again", m.servingIdx, m.leaseUsableLocked(), m.lease)
	}
	if m.resp != nil && m.resp.GetExpectedSequenceIndex() < 3 {
		t.Fatalf("the stale answer was cached: %+v", m.resp)
	}
}
