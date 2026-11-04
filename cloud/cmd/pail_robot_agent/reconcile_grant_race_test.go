// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"context"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"testing"
	"time"
)

// A command may receive the new plan between reconcile's no-window check and
// its forced refresh. D-5 makes a second fetch consume the just-issued window.
func TestReconcileRefreshPreservesConcurrentUnspentGrant(t *testing.T) {
	c := newLeaseClient(1, "b1")
	c.chain = "chain-B"
	m := newTokenMirror(c, "robot-1", time.Hour)
	resp, err := c.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	err = m.absorbLocked(resp)
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	before := c.getCalls.Load()
	got, err := m.upstreamFresh(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
	if err != nil || got.GetChainId() != "chain-B" {
		t.Fatalf("got=%v err=%v", got, err)
	}
	if c.getCalls.Load() != before {
		t.Fatal("forced refresh fetched again over an unspent grant (D-5 loses the new plan)")
	}
}

func TestOldChainCensusDoesNotDiscardNewChainGrantInFlight(t *testing.T) {
	c := newLeaseClient(1, "a1")
	c.chain = "chain-A"
	c.verdict = "CHAIN_ENDED"
	m := newTokenMirror(c, "robot-1", time.Hour)
	a, _ := c.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
	m.mu.Lock()
	if err := m.absorbLocked(a); err != nil {
		t.Fatal(err)
	}
	call, _ := m.beginUpstreamLocked()
	m.mu.Unlock()
	c.mu.Lock()
	c.chain = "chain-B"
	c.tokenIDs = []string{"b1"}
	c.mu.Unlock()
	b, _ := c.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
	m.census() // A ended, while B is already issued but its reply is pending.
	m.finishUpstream(call, b, nil)
	if call.err != nil || call.resp.GetChainId() != "chain-B" {
		t.Fatalf("new B grant discarded by old A census: %v", call.err)
	}
}

func TestCensusScopedReplyCannotCrossOtherBoundaries(t *testing.T) {
	for _, kind := range []string{"same-chain", "global-before", "global-after", "epoch-regression", "consumed"} {
		t.Run(kind, func(t *testing.T) {
			c := newLeaseClient(1, "a1")
			c.chain = "chain-A"
			c.verdict = "CHAIN_ENDED"
			m := newTokenMirror(c, "robot-1", time.Hour)
			a, _ := c.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
			m.mu.Lock()
			if err := m.absorbLocked(a); err != nil {
				t.Fatal(err)
			}
			call, _ := m.beginUpstreamLocked()
			if kind == "global-before" {
				m.gen++
			}
			m.mu.Unlock()
			c.mu.Lock()
			if kind != "same-chain" {
				c.chain = "chain-B"
			}
			c.tokenIDs = []string{"b1"}
			c.mu.Unlock()
			b, _ := c.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
			m.census()
			m.mu.Lock()
			switch kind {
			case "global-after":
				m.gen++
			case "epoch-regression":
				m.epoch = 1
			case "consumed":
				m.chainID = "chain-B"
				m.servingIdx = 2
			}
			m.mu.Unlock()
			m.finishUpstream(call, b, nil)
			if call.err == nil {
				t.Fatalf("%s boundary accepted stale authority", kind)
			}
			if m.leaseHeld() {
				t.Fatalf("%s left authority usable", kind)
			}
		})
	}
}

func TestReconcileWaitHonorsDeadline(t *testing.T) {
	c := newLeaseClient(1, "a1")
	m := newTokenMirror(c, "robot-1", time.Hour)
	m.mu.Lock()
	call, _ := m.beginUpstreamLocked()
	m.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		_, err := m.upstreamFresh(ctx, &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"})
		done <- err
	}()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(call.done)
		t.Fatal("reconcile ignored cancellation")
	}
}
