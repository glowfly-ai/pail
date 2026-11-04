// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build !linux

package deploysec

// statfs magics are Linux's. Elsewhere only the prefix rule (S9-b) applies —
// the robot targets are Linux, and a developer's laptop must not be refused for
// a filesystem type this build cannot name.
func fsMagic(string) (int64, bool) { return 0, false }
