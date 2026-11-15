// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build !unix

package ledgerq

// statfsUsage is unknown here; the index then follows its retention window and a
// fixed budget only, and the guidance says nothing about the disk.
func statfsUsage(string) (free, total int64, ok bool) { return 0, 0, false }
