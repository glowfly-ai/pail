// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// AV2/AV7: what a beacon does to the delegated window.
//
// These are written against the MIRROR'S OWN STATE (`leaseHeld`) and against
// what it then declares to the issuer, not against what a fake issuer would
// answer next. That choice is the point: an earlier attempt at this defect was
// judged by whether a fake client re-served a token, and the fake re-served
// unconditionally — so the test was green while the rig was unchanged. The
// window is the gateway's own fact; ask the gateway.

import (
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/burst"
	agentpb "github.com/glowfly/pail/services/proto/agentv1"
)

// beaconArrives is what subscribeBeacons does per event addressed to this
// robot, with nothing else of the stream loop in the way (main.go,
// applyBeacon). The event names the mirror's own robot: these tests are about
// what each event KIND does to the window; beacon_scope_test.go is about
// whose events count at all (OI-02).
func beaconArrives(m *tokenMirror, event byte) {
	applyBeacon(m, m.robotID, &agentpb.BeaconEvent{Event: uint32(event), RobotId: m.robotID})
}

// A BLOCK beacon says one command was refused. It says nothing about the
// tokens, so the window must survive it — and, because the window survives,
// the next census must still declare it. The pre-fix code dropped the window
// here, declared held_lease_max=0, and the issuer retracted the lease out from
// under a live permit (measured on the Viam rig, 2026-09-10).
func TestBlockBeaconKeepsTheDelegatedWindow(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2", "t3")
	p, m := leasedProxy(t, c)
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "t1" {
		t.Fatalf("first serve=%s, want t1", got)
	}
	if !m.leaseHeld() {
		t.Fatalf("no window to begin with — this test cannot measure anything")
	}

	beaconArrives(m, burst.EventBlock)

	if !m.leaseHeld() {
		t.Fatalf("a BLOCK beacon released the delegated window")
	}
	// The cached answer is still dropped: the freshness bet is what a beacon
	// invalidates. Serving must therefore reach the client again and still
	// come back inside the window.
	if got := serve(t, p).GetToken().GetToken().GetTokenId(); got != "t1" {
		t.Fatalf("after BLOCK beacon: serve=%s, want t1 (still inside the window)", got)
	}

	m.census()
	decl := c.declared()
	if len(decl) == 0 {
		t.Fatalf("no census declaration reached the issuer")
	}
	last := decl[len(decl)-1]
	if last.GetHeldLeaseMaxIndex() != 3 {
		t.Fatalf("declared held_lease_max=%d, want 3 — the issuer reads 0 as its cue to retract",
			last.GetHeldLeaseMaxIndex())
	}
}

// A CHECKPOINT beacon is a ledger marker. It is not about authorization at all.
func TestCheckpointBeaconKeepsTheDelegatedWindow(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	p, m := leasedProxy(t, c)
	serve(t, p)

	beaconArrives(m, burst.EventCheckpoint)

	if !m.leaseHeld() {
		t.Fatalf("a CHECKPOINT beacon released the delegated window")
	}
}

// The mirror image, and it is what keeps the fix from being a hole: an event
// that DOES take authority away must still take the window with it. Without
// this case, "never drop the lease on a beacon" would pass the case above and
// leave a revoked chain driving off an offline grant.
func TestRevokingBeaconsReleaseTheDelegatedWindow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event byte
	}{
		{"chain revoked", burst.EventChainRevoked},
		{"estop", burst.EventEstop},
		{"unknown event code", 0x7f}, // a build that cannot read it must not keep authority
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newLeaseClient(1, "t1", "t2")
			p, m := leasedProxy(t, c)
			serve(t, p)
			if !m.leaseHeld() {
				t.Fatalf("no window to begin with")
			}
			// The fixture re-grants the same window on every GetActiveToken; a
			// real issuer does not re-serve a revoked chain. Invalidate kicks the
			// poller, and a refresh landing before the check below re-absorbed
			// the fixture's window — a flake measured at 4/80 under -race before
			// HW-A1 and 8/80 after. Refusing the refresh keeps the test about
			// what the beacon does, not about what the fixture hands back.
			c.getDown.Store(true)

			beaconArrives(m, tc.event)

			if m.leaseHeld() {
				t.Fatalf("%s beacon left the delegated window in place", tc.name)
			}
			// Releasing it is also what tells the issuer to walk its serving
			// position back (AV7) — the declaration is the signal, so it must
			// actually go out.
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if len(c.declared()) > 0 {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatalf("%s beacon dropped the window without declaring it to the issuer", tc.name)
		})
	}
}

// The vocabulary itself, stated once so a new event code has to answer this
// question deliberately rather than inherit an answer from a `default`.
func TestBeaconAuthorityVocabulary(t *testing.T) {
	for _, tc := range []struct {
		event byte
		want  bool
	}{
		{burst.EventBlock, false},
		{burst.EventCheckpoint, false},
		{burst.EventChainRevoked, true},
		{burst.EventEstop, true},
		{burst.EventAuthorityWithheld, true}, // OI-04: serving withheld -> the window goes
		{0x00, true},
		{0xff, true},
	} {
		if got := beaconRevokesAuthority(tc.event); got != tc.want {
			t.Fatalf("beaconRevokesAuthority(%s/0x%02x)=%v, want %v",
				burst.EventName(tc.event), tc.event, got, tc.want)
		}
	}
}
