// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build linux

package observability

import (
	"syscall"
	"unsafe"
)

const clockMonotonic = 1

// monotonicNS reads CLOCK_MONOTONIC itself, the clock a producer stamps its
// records with. The runtime's own monotonic reading has no comparable origin.
func monotonicNS() (int64, bool) {
	var ts syscall.Timespec
	if _, _, e := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonic, uintptr(unsafe.Pointer(&ts)), 0); e != 0 {
		return 0, false
	}
	n := ts.Nano()
	return n, n > 0
}
