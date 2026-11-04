// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package util

import (
	"regexp"
	"testing"
)

func TestNewUUIDv4_Format(t *testing.T) {
	id, err := NewUUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !re.MatchString(id) {
		t.Fatalf("UUID %q does not match v4 pattern", id)
	}
}

func TestNewUUIDv4_Unique(t *testing.T) {
	a, _ := NewUUIDv4()
	b, _ := NewUUIDv4()
	if a == b {
		t.Fatal("two UUIDs should not be equal")
	}
}

func TestReasonStringToUint16(t *testing.T) {
	cases := []struct {
		reason string
		want   uint16
	}{
		{"OK", 0x00},
		{"ERR_TARGET_MISMATCH", 0x10},
		{"ERR_GEO_FENCE", 0x11},
		{"ERR_HUMAN_DETECT", 0x12},
		{"ERR_SAFETY_UNSAFE", 0x13},
		{"ERR_WORLD_CHANGED", 0x14},
		{"ERR_CHAIN_BROKEN", 0x20},
		{"ERR_TAMPERED", 0x99},
		{"UNKNOWN_REASON", 0xFF},
		{"", 0xFF},
	}
	for _, tc := range cases {
		got := ReasonStringToUint16(tc.reason)
		if got != tc.want {
			t.Errorf("ReasonStringToUint16(%q) = 0x%02x, want 0x%02x", tc.reason, got, tc.want)
		}
	}
}
