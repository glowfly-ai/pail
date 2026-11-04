// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build linux

package deploysec

import "syscall"

func fsMagic(p string) (int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(p, &st); err != nil {
		return 0, false
	}
	return int64(st.Type), true
}
