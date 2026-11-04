// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build linux

package robotops

import "testing"

func TestSameClockOffsetTables(t *testing.T) {
	zero := "monotonic           0         0\nboottime            0         0\n"
	cases := []struct {
		name         string
		mine, theirs string
		want         bool
	}{
		{"identical zero offsets (container time namespace, same clock)", zero, zero, true},
		{"identical nonzero offsets", "monotonic 5 0\nboottime 5 0\n", "monotonic 5 0\nboottime 5 0", true},
		{"whitespace only differs", zero, "monotonic 0 0\nboottime 0 0", true},
		{"peer monotonic shifted", zero, "monotonic 1 0\nboottime 0 0\n", false},
		{"peer boottime nanoseconds shifted", zero, "monotonic 0 0\nboottime 0 7\n", false},
		{"peer table truncated", zero, "monotonic 0 0\n", false},
		{"peer table empty", zero, "", false},
		{"unknown clock row", zero, zero + "realtime 0 0\n", false},
		{"duplicate row", zero, "monotonic 0 0\nmonotonic 0 0\n", false},
		{"non-numeric offset", zero, "monotonic 0 0\nboottime x 0\n", false},
		{"mine unreadable shape", "", zero, false},
	}
	for _, c := range cases {
		if got := sameClock(c.mine, c.theirs); got != c.want {
			t.Fatalf("%s: sameClock=%v want %v", c.name, got, c.want)
		}
	}
}
