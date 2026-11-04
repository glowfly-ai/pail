// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//go:build linux || darwin

package robotops

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Pin each directory fd and reject symlinks/FIFOs/devices; do not resolve then
// reopen a caller-controlled symlink. The root itself was selected by the caller.
func readContained(root, rel string) ([]byte, error) {
	b, _, e := readContainedInfo(root, rel)
	return b, e
}

func readContainedInfo(root, rel string) ([]byte, fileMetadata, error) {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fileMetadata{}, err
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "." {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if e != nil {
			return nil, fileMetadata{}, e
		}
		fd = next
	}
	last, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	unix.Close(fd)
	if err != nil {
		return nil, fileMetadata{}, err
	}
	f := os.NewFile(uintptr(last), "public-resource")
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > MaxDocument {
		return nil, fileMetadata{}, fmt.Errorf("not a bounded regular public file")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxDocument+1))
	if len(b) > MaxDocument {
		return nil, fileMetadata{}, fmt.Errorf("resource too large")
	}
	stat := st.Sys().(*syscall.Stat_t)
	return b, fileMetadata{UID: stat.Uid, Mode: uint32(st.Mode().Perm())}, err
}

func listContained(root, rel string) ([]string, error) {
	fd, e := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == "." {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	dir := os.NewFile(uintptr(fd), "public-directory")
	defer dir.Close()
	names, e := dir.Readdirnames(10001)
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(names) > 10000 {
		return nil, fmt.Errorf("directory entry limit")
	}
	return names, nil
}
