// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build !linux

package grpcauth

import "syscall"

// peerCred has no portable form. On non-Linux hosts (macOS development) the
// caller is journaled as kind=uds with an empty id — "we know the transport,
// we do not know the peer" — rather than a fabricated uid. The deployment
// target is Linux; this build exists so the dev host compiles, not so it lies.
func peerCred(_ syscall.RawConn) (uid, gid uint32, ok bool) { return 0, 0, false }
