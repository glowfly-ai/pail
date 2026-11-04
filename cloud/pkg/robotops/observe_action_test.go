// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package robotops

import "testing"

// The observe action exists for observation attestations and maps only to the
// observe role: an observer key never satisfies a management action, and a
// management key without the observe role never attests an observation.
func TestObserveActionMapsOnlyToObserveRole(t *testing.T) {
	if roleForAction["observe"] != "observe" {
		t.Fatal("observe action must map to the observe role")
	}
	for action, role := range roleForAction {
		if action != "observe" && role == "observe" {
			t.Fatal("no management action may map to the observe role:", action)
		}
	}
	if !knownRoles["observe"] {
		t.Fatal("observe must be a known trust role")
	}
}
