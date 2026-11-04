// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

// S9 (PAIL-SD2-LLD-v1 §3): refuse to keep the evidence chain on a filesystem
// that does not survive a restart.
//
// The blackbox is the reason the rest of PAIL is worth anything: a decision
// nobody can check afterwards is not an authorization, it is a hope. Writing it
// to tmpfs — or to a container's own write layer, which is the shipped default
// when no volume is mounted — means the evidence is gone exactly when it is
// needed, and nothing in the system complains.

import (
	"fmt"
	"os"
	"path"
	"strings"
)

// Filesystem magics (linux/include/uapi/linux/magic.h). overlayfs is here for
// the container write layer, which looks perfectly ordinary from inside.
const (
	magicTmpfs   int64 = 0x01021994
	magicRamfs   int64 = 0x858458f6
	magicOverlay int64 = 0x794c7630
)

// Conventionally volatile prefixes, applied when statfs is unavailable or
// inconclusive. The two rules are OR: either is enough to refuse.
var volatilePrefixes = []string{"/tmp", "/var/tmp", "/dev/shm", "/run"}

const DefaultBlackboxDir = "/var/log/pail_blackbox"

// BlackboxDir is where the evidence chain is written. The check and the writer
// must resolve it the same way, or S9 would pass judgement on a path nothing
// uses — which is worse than no check, because it reads as one.
func BlackboxDir() string {
	if d := os.Getenv("PAIL_BLACKBOX_DIR"); d != "" {
		return d
	}
	return DefaultBlackboxDir
}

func fsName(magic int64) string {
	switch magic {
	case magicTmpfs:
		return "tmpfs"
	case magicRamfs:
		return "ramfs"
	case magicOverlay:
		return "overlayfs (container write layer — a new container starts empty)"
	}
	return fmt.Sprintf("0x%x", magic)
}

func isVolatileMagic(magic int64) bool {
	return magic == magicTmpfs || magic == magicRamfs || magic == magicOverlay
}

// underVolatilePrefix matches whole path components, so /tmpdata is not /tmp.
func underVolatilePrefix(p string) string {
	c := path.Clean(p)
	if !path.IsAbs(c) {
		return ""
	}
	for _, pre := range volatilePrefixes {
		if c == pre || strings.HasPrefix(c, pre+"/") {
			return pre
		}
	}
	return ""
}

// nearestExisting walks up to the closest ancestor that exists. A directory the
// process creates at startup is normal, so "not there yet" is not a violation —
// but the filesystem it will be created on is already decided.
func nearestExisting(p string, exists func(string) bool) string {
	c := path.Clean(p)
	for {
		if exists(c) {
			return c
		}
		parent := path.Dir(c)
		if parent == c {
			return ""
		}
		c = parent
	}
}

// evaluatePath judges one directory. label names it in the message.
func evaluatePath(label, p string, pr Probe) *Finding {
	if pre := underVolatilePrefix(p); pre != "" {
		return &Finding{"S9", fmt.Sprintf(
			"%s=%s is under %s — conventionally cleared on reboot; the evidence chain would not survive one",
			label, p, pre)}
	}
	probed := nearestExisting(p, pr.Exists)
	if probed == "" {
		return nil
	}
	magic, ok := pr.FSMagic(probed)
	if !ok || !isVolatileMagic(magic) {
		return nil
	}
	where := probed
	if probed != path.Clean(p) {
		where = fmt.Sprintf("%s (nearest existing: %s)", p, probed)
	}
	return &Finding{"S9", fmt.Sprintf(
		"%s=%s is on %s — the evidence chain is lost on restart. Mount a persistent volume there",
		label, where, fsName(magic))}
}

// evaluatePaths is the S9 rule set for one component.
func evaluatePaths(pr Probe) (fail []Finding, warn []Finding) {
	bb := pr.Get("PAIL_BLACKBOX_DIR")
	if bb == "" {
		bb = DefaultBlackboxDir
	}
	if f := evaluatePath("PAIL_BLACKBOX_DIR", bb, pr); f != nil {
		fail = append(fail, *f)
	}

	anchorDir := pr.Get("PAIL_ANCHOR_DIR")
	if anchorDir != "" {
		if f := evaluatePath("PAIL_ANCHOR_DIR", anchorDir, pr); f != nil {
			fail = append(fail, *f)
		}
	}
	// §1 responsibility boundary: whether to anchor at all is the operator's
	// call — an air-gapped site may have nowhere to anchor to. Unanchored
	// evidence is still signed and chained; it just has no external reference
	// point. That is a warning, not a refusal.
	if anchorDir == "" && pr.Get("PAIL_ANCHOR_URL") == "" {
		warn = append(warn, Finding{"S9", "no PAIL_ANCHOR_URL or PAIL_ANCHOR_DIR — the chain has no external reference point, so a wholesale rewrite of the local evidence is not externally detectable"})
	}
	return fail, warn
}
