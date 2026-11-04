// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//go:build linux

package robotops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type NodePeer struct {
	PID                                  int32
	UID                                  uint32
	StartTicks, BootID, ExecutableSHA256 string
}

// InspectNodePeer binds a connection to its kernel peer process and pins that
// process's executable in one step. Callers whose server bounds the request
// window (the node status transport: 250 ms from accept) use the two halves
// separately, because hashing a node binary on an embedded CPU can take longer
// than the window (TB3 RPi5, 2026-09-23: ~0.3 s for the gate executable).
func InspectNodePeer(c net.Conn, uid uint32, expectedSHA string) (NodePeer, error) {
	p, e := InspectNodePeerIdentity(c, uid)
	if e != nil {
		return NodePeer{}, e
	}
	got, e := NodeExecutableSHA256(p)
	if e != nil || got != expectedSHA {
		return NodePeer{}, fmt.Errorf("RO_NODE_PEER: kernel/process/executable binding unavailable")
	}
	p.ExecutableSHA256 = got
	return p, nil
}

// InspectNodePeerIdentity reads the kernel peer credentials of c and the peer
// process's start ticks, boot id and clock relation. It touches no executable
// bytes; ExecutableSHA256 is left empty.
func InspectNodePeerIdentity(c net.Conn, uid uint32) (NodePeer, error) {
	fail := func() (NodePeer, error) {
		return NodePeer{}, fmt.Errorf("RO_NODE_PEER: kernel/process/executable binding unavailable")
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return fail()
	}
	raw, e := sc.SyscallConn()
	if e != nil {
		return fail()
	}
	var cred *unix.Ucred
	var lookup error
	if e = raw.Control(func(fd uintptr) { cred, lookup = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); e != nil || lookup != nil || cred.Pid <= 0 || cred.Uid != uid {
		return fail()
	}
	prefix := "/proc/" + strconv.Itoa(int(cred.Pid))
	read := func(path string) (string, error) {
		b, e := os.ReadFile(path)
		if e != nil || len(b) > 16384 {
			return "", fmt.Errorf("unavailable")
		}
		return strings.TrimSpace(string(b)), nil
	}
	process, e := read(prefix + "/stat")
	if e != nil {
		return fail()
	}
	pos := strings.LastIndex(process, ")")
	if pos < 0 {
		return fail()
	}
	fields := strings.Fields(process[pos+1:])
	if len(fields) < 20 {
		return fail()
	}
	start := fields[19]
	// Never subtract unrelated clocks. The peer may live in another time namespace
	// (container runtimes create one per container: Docker 29 / runc 1.4 on the TB3
	// rig, measured 2026-09-23) and still share this process's CLOCK_MONOTONIC: the
	// kernel exposes each namespace's offsets from the initial one, so equal offset
	// tables mean the same clock. Anything else, including an unreadable table, is
	// refused.
	localNS, e := os.Readlink("/proc/self/ns/time")
	peerNS, e2 := os.Readlink(prefix + "/ns/time")
	if e != nil || e2 != nil {
		return fail()
	}
	if localNS != peerNS {
		mine, e := read("/proc/self/timens_offsets")
		theirs, e2 := read(prefix + "/timens_offsets")
		if e != nil || e2 != nil || !sameClock(mine, theirs) {
			return fail()
		}
	}
	boot, e := read("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return fail()
	}
	return NodePeer{cred.Pid, cred.Uid, start, boot, ""}, nil
}

// NodeExecutableSHA256 hashes the executable of the process identified by p
// through /proc/<pid>/exe (a kernel link, not a user-selected path) and then
// re-reads the process start ticks: the hash is only reported for the same
// process instance that p described.
func NodeExecutableSHA256(p NodePeer) (string, error) {
	fail := func() (string, error) {
		return "", fmt.Errorf("RO_NODE_PEER: kernel/process/executable binding unavailable")
	}
	if p.PID <= 0 || p.StartTicks == "" {
		return fail()
	}
	prefix := "/proc/" + strconv.Itoa(int(p.PID))
	f, e := os.Open(prefix + "/exe")
	if e != nil {
		return fail()
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 128<<20 {
		return fail()
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if e != nil || n > 128<<20 {
		return fail()
	}
	again, e := os.ReadFile(prefix + "/stat")
	if e != nil || len(again) > 16384 || processStart(strings.TrimSpace(string(again))) != p.StartTicks {
		return fail()
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sameClock reports whether two /proc/<pid>/timens_offsets tables describe the
// same monotonic and boottime clocks: both must list exactly those two clocks with
// identical offsets. Field-wise comparison, so whitespace differences do not matter
// and a truncated or unknown table never passes.
func sameClock(mine, theirs string) bool {
	parse := func(raw string) (map[string][2]string, bool) {
		out := map[string][2]string{}
		for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
			f := strings.Fields(line)
			if len(f) != 3 || (f[0] != "monotonic" && f[0] != "boottime") {
				return nil, false
			}
			if _, dup := out[f[0]]; dup {
				return nil, false
			}
			for _, n := range f[1:] {
				if _, e := strconv.ParseInt(n, 10, 64); e != nil {
					return nil, false
				}
			}
			out[f[0]] = [2]string{f[1], f[2]}
		}
		return out, len(out) == 2
	}
	a, ok := parse(mine)
	b, ok2 := parse(theirs)
	return ok && ok2 && a["monotonic"] == b["monotonic"] && a["boottime"] == b["boottime"]
}

func processStart(raw string) string {
	p := strings.LastIndex(raw, ")")
	if p < 0 {
		return ""
	}
	f := strings.Fields(raw[p+1:])
	if len(f) < 20 {
		return ""
	}
	return f[19]
}
func LocalMonotonicNS() (int64, error) {
	var ts unix.Timespec
	e := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return ts.Nano(), e
}
