// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

import (
	"os"
	"strings"
	"testing"
)

// fakeProbe replaces the host. fs maps an existing path to its filesystem
// magic; magic 0 means the path exists but statfs told us nothing, which is what
// a non-Linux build sees everywhere.
func fakeProbe(env map[string]string, fs map[string]int64) Probe {
	return Probe{
		Get:      func(k string) string { return env[k] },
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		Exists:   func(p string) bool { _, ok := fs[p]; return ok },
		FSMagic: func(p string) (int64, bool) {
			m, ok := fs[p]
			if !ok || m == 0 {
				return 0, false
			}
			return m, true
		},
	}
}

func failIDs(f []Finding) string {
	ids := make([]string, 0, len(f))
	for _, x := range f {
		ids = append(ids, x.ID)
	}
	return strings.Join(ids, ",")
}

// TestShippedDefaultIsRefused is the SD2-0 measurement turned into a rule: the
// blackbox default /var/log/pail_blackbox lands on the container write layer
// when no volume is mounted, and a recreated container starts with no records.
func TestShippedDefaultIsRefused(t *testing.T) {
	p := fakeProbe(
		map[string]string{"PAIL_ANCHOR_URL": "http://anchor:46100"},
		map[string]int64{"/var/log": magicOverlay, "/var": magicOverlay, "/": magicOverlay})
	fail, _ := evaluatePaths(p)
	if len(fail) != 1 || fail[0].ID != "S9" {
		t.Fatalf("want one S9, got %+v", fail)
	}
	if !strings.Contains(fail[0].Msg, "overlayfs") {
		t.Errorf("the message must name the filesystem: %s", fail[0].Msg)
	}
	if !strings.Contains(fail[0].Msg, "/var/log/pail_blackbox") {
		t.Errorf("the message must name the path that was judged: %s", fail[0].Msg)
	}
}

// TestMountedVolumePasses: the same default, on a mounted volume, is fine.
// Without this, "refuses everything" would look like a working rule.
func TestMountedVolumePasses(t *testing.T) {
	p := fakeProbe(
		map[string]string{"PAIL_ANCHOR_URL": "http://anchor:46100"},
		map[string]int64{"/var/log/pail_blackbox": 0x9123683e, "/var/log": magicOverlay})
	fail, warn := evaluatePaths(p)
	if len(fail) != 0 {
		t.Fatalf("a persistent volume must pass: %+v", fail)
	}
	if len(warn) != 0 {
		t.Fatalf("unexpected warning: %+v", warn)
	}
}

// TestVolatilePrefixesRefused covers hosts where statfs says nothing (non-Linux
// builds, or a directory that does not exist yet on a path we cannot resolve).
func TestVolatilePrefixesRefused(t *testing.T) {
	for _, dir := range []string{
		"/tmp/pail_blackbox", "/var/tmp/bb", "/dev/shm/bb", "/run/pail/bb", "/tmp",
	} {
		p := fakeProbe(map[string]string{
			"PAIL_BLACKBOX_DIR": dir,
			"PAIL_ANCHOR_URL":   "http://anchor:46100",
		}, nil)
		fail, _ := evaluatePaths(p)
		if len(fail) != 1 || fail[0].ID != "S9" {
			t.Errorf("%s: want one S9, got %+v", dir, fail)
		}
	}
}

// TestOrdinaryPathsPass: the prefix rule matches path components, so a name that
// merely starts with the same letters is not a violation. AS-13 requires that a
// range of normal values pass, not just that violations are refused.
func TestOrdinaryPathsPass(t *testing.T) {
	for _, dir := range []string{
		"/tmpdata/pail", "/var/lib/pail/blackbox", "/data/pail_blackbox",
		"/mnt/evidence", "/opt/pail/runs/", "/srv/run-archive",
	} {
		p := fakeProbe(map[string]string{
			"PAIL_BLACKBOX_DIR": dir,
			"PAIL_ANCHOR_URL":   "http://anchor:46100",
		}, nil)
		if fail, _ := evaluatePaths(p); len(fail) != 0 {
			t.Errorf("%s: must pass, got %+v", dir, fail)
		}
	}
}

func TestAnchorDirJudgedToo(t *testing.T) {
	p := fakeProbe(map[string]string{
		"PAIL_BLACKBOX_DIR": "/data/bb",
		"PAIL_ANCHOR_DIR":   "/dev/shm/anchors",
	}, nil)
	fail, warn := evaluatePaths(p)
	if len(fail) != 1 || !strings.Contains(fail[0].Msg, "PAIL_ANCHOR_DIR") {
		t.Fatalf("want one S9 naming PAIL_ANCHOR_DIR, got %+v", fail)
	}
	// Anchoring is configured, so the "no reference point" warning must not fire.
	if len(warn) != 0 {
		t.Fatalf("unexpected warning: %+v", warn)
	}
}

// TestNoAnchorIsAWarning: §1 responsibility boundary. Whether to anchor at all
// is the operator's call — an air-gapped site may have nowhere to anchor to.
func TestNoAnchorIsAWarning(t *testing.T) {
	p := fakeProbe(map[string]string{"PAIL_BLACKBOX_DIR": "/data/bb"}, nil)
	fail, warn := evaluatePaths(p)
	if len(fail) != 0 {
		t.Fatalf("an unanchored chain must not be refused: %+v", fail)
	}
	if len(warn) != 1 || warn[0].ID != "S9" {
		t.Fatalf("want one S9 warning, got %+v", warn)
	}
}

// TestTmpfsUnderAnOrdinaryPath: the prefix rule would let this through; only
// statfs sees it. Both halves of S9 are needed.
func TestTmpfsUnderAnOrdinaryPath(t *testing.T) {
	p := fakeProbe(map[string]string{
		"PAIL_BLACKBOX_DIR": "/data/pail/blackbox",
		"PAIL_ANCHOR_URL":   "http://anchor:46100",
	}, map[string]int64{"/data/pail/blackbox": magicTmpfs})
	fail, _ := evaluatePaths(p)
	if len(fail) != 1 || !strings.Contains(fail[0].Msg, "tmpfs") {
		t.Fatalf("want one S9 naming tmpfs, got %+v", fail)
	}
	if strings.Contains(fail[0].Msg, "nearest existing") {
		t.Errorf("the directory itself was probed; no need to mention an ancestor: %s", fail[0].Msg)
	}
}

// TestRobotAgentIsNotJudgedOnPaths: it writes no evidence chain, so refusing it
// for a filesystem it never touches would be noise the operator learns to skip.
func TestRobotAgentIsNotJudgedOnPaths(t *testing.T) {
	env := map[string]string{
		"PAIL_BLACKBOX_DIR":  "/tmp/bb",
		"PAIL_GRPC_TLS":      "off",
		"PAIL_GRPC_UDS_PATH": "/run/pail/x.sock",
		"PAIL_POLICY_AUTH":   "/etc/pail/policy-auth.json", // S40 is its own test; keep this one about paths
	}
	if r := EvaluateDeployment("pail_robot_agent", fakeProbe(env, nil)); failIDs(r.Fail) != "" {
		t.Fatalf("want no failure, got %+v", r.Fail)
	}
	if r := EvaluateDeployment("pail_cloud", fakeProbe(env, nil)); failIDs(r.Fail) != "S9" {
		t.Fatalf("want S9 for the component that holds the chain, got %+v", r.Fail)
	}
}
