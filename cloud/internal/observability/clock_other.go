// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build !linux

package observability

// Without a kernel clock that a producer could share there is nothing to
// compare: every declared binding stays CLOCK_BINDING_UNAVAILABLE.
func monotonicNS() (int64, bool) { return 0, false }
