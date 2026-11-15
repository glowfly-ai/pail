// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build unix

package ledgerq

import (
	"path/filepath"
	"syscall"
)

// statfsUsage reports the space of the filesystem that holds path: what an
// unprivileged process may still use, and the size of the whole filesystem.
func statfsUsage(path string) (free, total int64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(path), &st); err != nil {
		return 0, 0, false
	}
	bs := uint64(st.Bsize)
	return int64(uint64(st.Bavail) * bs), int64(uint64(st.Blocks) * bs), true
}
