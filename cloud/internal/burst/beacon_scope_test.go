// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package burst

import "testing"

// The scoping vocabulary, stated once (OI-02). A new event code or a new
// emitter has to answer "whom does this address" here, deliberately.
func TestOI02_BeaconAddresses(t *testing.T) {
	for _, tc := range []struct {
		name         string
		event        byte
		target, self string
		want         bool
	}{
		{"revoke names this robot", EventChainRevoked, "robot-1", "robot-1", true},
		{"revoke names another robot", EventChainRevoked, "robot-2", "robot-1", false},
		{"estop names another robot", EventEstop, "robot-2", "robot-1", false},
		{"block names another robot", EventBlock, "robot-2", "robot-1", false},
		{"unknown code names another robot", 0x7f, "robot-2", "robot-1", false},
		{"revoke names no robot (fleet-wide)", EventChainRevoked, "", "robot-1", true},
		{"unknown code names no robot (fleet-wide)", 0x7f, "", "robot-1", true},
		{"checkpoint tagged another robot", EventCheckpoint, "robot-2", "robot-1", true},
		{"checkpoint tagged this robot", EventCheckpoint, "robot-1", "robot-1", true},
	} {
		if got := BeaconAddresses(tc.event, tc.target, tc.self); got != tc.want {
			t.Errorf("%s: BeaconAddresses(0x%02x, %q, %q)=%v, want %v", tc.name, tc.event, tc.target, tc.self, got, tc.want)
		}
	}
}

// OI-04: the new code has a name on every receiver that prints one.
func TestOI04_EventNameAuthorityWithheld(t *testing.T) {
	if got := EventName(EventAuthorityWithheld); got != "AUTHORITY_WITHHELD" {
		t.Fatalf("EventName(%d)=%q, want AUTHORITY_WITHHELD", EventAuthorityWithheld, got)
	}
	if EventAuthorityWithheld != 5 {
		t.Fatalf("EventAuthorityWithheld=%d, want 5 (the wire value receivers map)", EventAuthorityWithheld)
	}
}
