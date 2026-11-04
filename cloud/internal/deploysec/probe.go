// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

// The gate has to look at the machine it is running on — environment, files,
// filesystem types. Every such lookup goes through Probe, so the verdict itself
// stays a pure function of what was observed and can be tested without a host
// that has the fault.

import "os"

type Probe struct {
	Get      func(string) string
	ReadFile func(string) ([]byte, error)
	Exists   func(string) bool
	// FSMagic reports the filesystem type of an existing path. ok=false means
	// unknown — non-Linux, or the call failed — and the caller must not read
	// that as "persistent".
	FSMagic func(string) (int64, bool)
	// StatMode reports the permission bits of a path. The error is returned
	// rather than folded into a mode, because "absent" and "there but could not
	// be read" are different answers and only the caller knows which of them is
	// its business (S18 owns the first, S19 the second).
	StatMode func(string) (os.FileMode, error)
}

func SystemProbe() Probe {
	return Probe{
		Get:      os.Getenv,
		ReadFile: os.ReadFile,
		Exists: func(p string) bool {
			_, err := os.Stat(p)
			return err == nil
		},
		FSMagic: fsMagic,
		// Stat, not Lstat: the question is who can read the key, and a symlink
		// carries 0777 that the kernel ignores. Judging the link would report a
		// violation that does not exist and hide the one that does.
		StatMode: func(p string) (os.FileMode, error) {
			fi, err := os.Stat(p)
			if err != nil {
				return 0, err
			}
			return fi.Mode().Perm(), nil
		},
	}
}
