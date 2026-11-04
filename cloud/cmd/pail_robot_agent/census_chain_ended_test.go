// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// P7-H1 (seventh evaluation of 0.2.0-preview.7): a gateway holding an unspent window of plan A kept
// permitting under A after plan B was accepted. The issuer now beacons the superseded chain; a gateway
// that was cut from the relay when that beacon went out (the relay keeps a backlog only while nobody at
// all is subscribed) learns it from the census answer instead: CHAIN_ENDED for the chain it declared.
// Before this, the reconnect reconcile kept the window (a refresh inside our own window reads as
// "spent", D-5) and the robot stayed on A until that token's not_after.

import (
	"testing"
)

func TestCensusChainEndedDropsTheDeclaredWindow(t *testing.T) {
	c := newLeaseClient(1, "a1", "a2")
	p, m := leasedProxy(t, c)
	serve(t, p)
	if !m.leaseHeld() {
		t.Fatal("setup: no window held")
	}
	c.getDown.Store(true) // the poller must not re-absorb a window and mask the drop
	c.mu.Lock()
	c.verdict = "CHAIN_ENDED"
	c.mu.Unlock()
	m.census()
	if m.leaseHeld() {
		t.Fatal("the issuer answered CHAIN_ENDED for the declared chain and the gateway still holds its window: the robot keeps permitting under the ended plan")
	}
}

func TestCensusOKKeepsTheWindow(t *testing.T) {
	c := newLeaseClient(1, "a1", "a2")
	p, m := leasedProxy(t, c)
	serve(t, p)
	c.getDown.Store(true)
	m.census()
	if !m.leaseHeld() {
		t.Fatal("an OK census dropped a live window: the declaration is a claim, it must not cost the robot its offline authority")
	}
}

// The reconnect path end to end: the gateway missed the beacon, reconciles on stream recovery, is told
// CHAIN_ENDED, and its next read takes the issuer's current chain instead of serving the old window.
func TestReconcileAfterMissedSupersedeFetchesTheCurrentChain(t *testing.T) {
	c := newLeaseClient(1, "a1", "a2")
	p, m := leasedProxy(t, c)
	serve(t, p)
	c.mu.Lock()
	c.verdict, c.chain, c.tokenIDs = "CHAIN_ENDED", "chain-2", []string{"b1"}
	c.mu.Unlock()
	m.reconcile()
	resp := serve(t, p)
	if resp.GetChainId() != "chain-2" || resp.GetToken().GetToken().GetTokenId() != "b1" {
		t.Fatalf("after reconcile the gateway serves chain=%s token=%s, want chain-2/b1 (the plan the issuer accepted while we were cut off)",
			resp.GetChainId(), resp.GetToken().GetToken().GetTokenId())
	}
}
