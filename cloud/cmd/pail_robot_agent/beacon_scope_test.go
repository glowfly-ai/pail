// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// OI-02: whose beacons this gateway acts on.
//
// The relay used to fan every robot's events to every subscribed agent, and
// the agent used to act on all of them: one robot's CHAIN_REVOKED or ESTOP
// dropped every other robot's delegated window, declared a census for each,
// and was re-signed by each as if it were its own. These tests are written
// against the mirror's own state and against what reaches the issuer, the
// same way beacon_lease_test.go is — the window is the gateway's fact.

import (
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/burst"
	agentpb "github.com/glowfly/pail/services/proto/agentv1"
)

// A revoking event about ANOTHER robot must leave this gateway untouched:
// window kept, generation unchanged, nothing declared to the issuer, and the
// event not re-broadcast under this robot's key (applyBeacon says false).
func TestOI02_ForeignRobotBeaconLeavesTheWindowAlone(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event byte
	}{
		{"chain revoked", burst.EventChainRevoked},
		{"estop", burst.EventEstop},
		{"unknown event code", 0x7f},
		{"block", burst.EventBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newLeaseClient(1, "t1", "t2")
			p, m := leasedProxy(t, c)
			serve(t, p)
			if !m.leaseHeld() {
				t.Fatalf("no window to begin with")
			}
			c.getDown.Store(true)
			m.mu.Lock()
			gen0 := m.gen
			cached := m.resp != nil
			m.mu.Unlock()
			if !cached {
				t.Fatalf("no cached answer to begin with — the cache half of this test cannot measure anything")
			}

			ours := applyBeacon(m, m.robotID, &agentpb.BeaconEvent{Event: uint32(tc.event), RobotId: "robot-2"})

			if ours {
				t.Fatalf("%s for robot-2 was taken as this gateway's (robot-1) own event", tc.name)
			}
			if !m.leaseHeld() {
				t.Fatalf("%s for robot-2 released robot-1's delegated window", tc.name)
			}
			m.mu.Lock()
			gen1, stillCached := m.gen, m.resp != nil
			m.mu.Unlock()
			if gen1 != gen0 {
				t.Fatalf("%s for robot-2 bumped robot-1's invalidation generation %d -> %d", tc.name, gen0, gen1)
			}
			if !stillCached {
				t.Fatalf("%s for robot-2 dropped robot-1's cached answer", tc.name)
			}
			// A dropped window is declared asynchronously; give a wrong
			// implementation time to send it before concluding it did not.
			time.Sleep(150 * time.Millisecond)
			if n := len(c.declared()); n != 0 {
				t.Fatalf("%s for robot-2 made robot-1 declare a census (%d declarations)", tc.name, n)
			}
		})
	}
}

// The mirror image: an event that names THIS robot, or names no robot at all
// (fleet-wide), still does what beacon_lease_test.go says it does. Without
// this the scoping could be "ignore every beacon" and still pass above.
func TestOI02_OwnAndFleetWideBeaconsStillApply(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
	}{
		{"names this robot", "robot-1"},
		{"names no robot (fleet-wide)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newLeaseClient(1, "t1", "t2")
			p, m := leasedProxy(t, c)
			serve(t, p)
			if !m.leaseHeld() {
				t.Fatalf("no window to begin with")
			}
			c.getDown.Store(true)

			ours := applyBeacon(m, m.robotID, &agentpb.BeaconEvent{Event: uint32(burst.EventChainRevoked), RobotId: tc.target})

			if !ours {
				t.Fatalf("CHAIN_REVOKED that %s was not taken as this gateway's event", tc.name)
			}
			if m.leaseHeld() {
				t.Fatalf("CHAIN_REVOKED that %s left the delegated window in place", tc.name)
			}
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if len(c.declared()) > 0 {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatalf("CHAIN_REVOKED that %s dropped the window without declaring it", tc.name)
		})
	}
}

// CHECKPOINT carries the issuer's own robot tag (a single-robot default), so
// the tag is not a scope: every gateway takes it and re-broadcasts it for its
// local observers. It never touches the window either way.
func TestOI02_CheckpointIsFleetWideWhateverItsTag(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	p, m := leasedProxy(t, c)
	serve(t, p)

	ours := applyBeacon(m, m.robotID, &agentpb.BeaconEvent{Event: uint32(burst.EventCheckpoint), RobotId: "robot-2"})

	if !ours {
		t.Fatalf("a CHECKPOINT tagged robot-2 was not taken by robot-1 — its observers would miss the ledger marker")
	}
	if !m.leaseHeld() {
		t.Fatalf("a CHECKPOINT released the delegated window")
	}
}

// OI-04: AUTHORITY_WITHHELD says the issuer stopped serving this robot. The
// window it granted earlier must not outlive that, and the drop is declared.
func TestOI04_AuthorityWithheldBeaconReleasesTheWindow(t *testing.T) {
	c := newLeaseClient(1, "t1", "t2")
	p, m := leasedProxy(t, c)
	serve(t, p)
	if !m.leaseHeld() {
		t.Fatalf("no window to begin with")
	}
	c.getDown.Store(true)

	beaconArrives(m, burst.EventAuthorityWithheld)

	if m.leaseHeld() {
		t.Fatalf("AUTHORITY_WITHHELD left the delegated window in place")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(c.declared()) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("AUTHORITY_WITHHELD dropped the window without declaring it to the issuer")
}
