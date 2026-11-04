// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build linux

package grpcauth

import "syscall"

// peerCred reads SO_PEERCRED, the kernel's own answer about who is on the other
// end of the socket. It cannot be spoofed by the peer, which is why it is worth
// journaling at all.
func peerCred(raw syscall.RawConn) (uid, gid uint32, ok bool) {
	var uc *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		uc, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || serr != nil || uc == nil {
		return 0, 0, false
	}
	return uint32(uc.Uid), uint32(uc.Gid), true
}
