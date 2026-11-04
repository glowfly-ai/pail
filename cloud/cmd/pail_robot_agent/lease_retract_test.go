// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// AV7 (AV LLD §9.3): the gateway half of unconsumed-lease retraction.
//
// Dropping a window the gateway never spent is invisible to the issuer, whose
// walk-back needs a consumption report that will never come. So the drop is
// declared. These tests pin the two things that make the declaration usable:
// it happens at all, and it states a true position.

import (
	"testing"
	"time"

	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

// waitDeclared polls for n declarations (the census runs off the caller's
// goroutine so Invalidate never blocks an RPC handler).
func waitDeclared(t *testing.T, c *leaseClient, n int) []*tokenpb.GatewayCensusRequest {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := c.declared()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("declarations=%d, want %d", len(got), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// AV7-1: an Invalidate that kills a live window declares it, and the
// declaration says the gateway holds nothing — which is what lets the issuer
// take the delegation back.
func TestDroppedLeaseIsDeclared(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	p, m := leasedProxy(t, c)
	serve(t, p)
	if !m.leaseHeld() {
		t.Fatal("setup: no lease to drop")
	}
	// The mirror's poller would re-absorb a fresh window and mask the drop.
	// That is correct behaviour and not what this test is about.
	c.getDown.Store(true)

	m.Invalidate()
	if m.leaseHeld() {
		t.Fatal("Invalidate must still drop the lease")
	}
	last := waitDeclared(t, c, 1)[0]
	if last.GetChainId() != "chain-1" {
		t.Fatalf("declared chain=%q, want chain-1", last.GetChainId())
	}
	if last.GetHeldLeaseMaxIndex() != 0 {
		t.Fatalf("declared held_lease_max=%d, want 0 — the window is gone", last.GetHeldLeaseMaxIndex())
	}
	// AV-L1b: dropLeaseLocked used to zero servingIdx, which made this -1 —
	// a false claim, and one the issuer refuses to act on.
	if last.GetLastConsumedIndex() != 0 {
		t.Fatalf("declared last_consumed=%d, want 0 (nothing was consumed)", last.GetLastConsumedIndex())
	}
}

// The position in the declaration is the gateway's, not the lease's: dropping
// a window must not disturb it. Without this the issuer's condition (2) would
// read a consumed step as unconsumed and reopen it.
func TestDeclarationStatesTheConsumedPosition(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	_, m := leasedProxy(t, c)
	m.mu.Lock()
	m.chainID, m.servingIdx = "chain-1", 3
	dropped := m.dropLeaseLocked()
	idx := m.servingIdx
	m.mu.Unlock()
	if dropped {
		t.Fatal("dropLeaseLocked reported a window that was never held")
	}
	if idx != 3 {
		t.Fatalf("servingIdx=%d after drop, want 3 (the position is not part of the grant)", idx)
	}

	m.census()
	last := waitDeclared(t, c, 1)[0]
	if last.GetLastConsumedIndex() != 2 {
		t.Fatalf("declared last_consumed=%d, want 2", last.GetLastConsumedIndex())
	}
	if last.GetHeldLeaseMaxIndex() != 0 {
		t.Fatalf("declared held_lease_max=%d, want 0", last.GetHeldLeaseMaxIndex())
	}
}

// Declaring is bounded to windows that actually died. Invalidate runs on every
// mutating northbound RPC and every beacon; declaring unconditionally would put
// a 5s-deadline round trip behind each of them.
func TestInvalidateWithoutLeaseDeclaresNothing(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	_, m := leasedProxy(t, c)
	for i := 0; i < 4; i++ {
		m.Invalidate()
	}
	time.Sleep(150 * time.Millisecond)
	if got := c.declared(); len(got) != 0 {
		t.Fatalf("declarations=%d with no lease ever held, want 0", len(got))
	}
}
