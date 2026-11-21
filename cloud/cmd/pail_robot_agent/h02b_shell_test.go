// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// SEC-H02B — a fallback that cannot be executed is not a fallback (test LLD §3).
//
// The restart command became optional in SEC-H02: the gate applies a placed bundle by itself. What is left of the
// 0.2.3 defect is the shape, not the frequency — an operator who configures the fallback, on a host whose image has
// no shell, has configured something that cannot run, and the start-up check that used to guard this path only asked
// whether the variable was non-empty.
//
// The two functions under DOOR are the only code here that differs before and after the fix.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// ------------------------------------ DOOR ----------------------------------------------

// h02bShellPath is the shell the agent would use to run PAIL_GATE_RESTART_CMD. (Before the fix this door held the
// test's own copy of the literal in the exec call: setting it changed nothing in the product, which is why T02, T04
// and T05 were red.)
func h02bShellPath() string { return restartShell }

// h02bSetShellPath points that shell elsewhere for the duration of one test.
func h02bSetShellPath(t *testing.T, path string) {
	t.Helper()
	prev := restartShell
	restartShell = path
	t.Cleanup(func() { restartShell = prev })
}

// ---------------------------------- END DOOR --------------------------------------------

// T01 — positive control: with the three settings and a shell that exists, the puller stands.
func TestH02BPullerStandsWithAShellThatExists(t *testing.T) {
	reachEnv(t)
	if _, err := os.Stat(h02bShellPath()); err != nil {
		t.Skipf("this machine has no %s", h02bShellPath())
	}
	k, err := newKeyringPullerFromEnv(nil, "robot-1")
	if err != nil || k == nil {
		t.Fatalf("refused with a shell present: err=%v nil=%v", err, k == nil)
	}
}

// T02 — the restart command is configured and its shell is not there: refused by name.
func TestH02BRefusesAConfiguredCommandWithNoShell(t *testing.T) {
	reachEnv(t)
	h02bSetShellPath(t, filepath.Join(t.TempDir(), "no-such-shell"))
	k, err := newKeyringPullerFromEnv(nil, "robot-1")
	if err == nil {
		t.Fatalf("accepted a restart command that cannot be executed (puller=%v)", k != nil)
	}
	if k != nil {
		t.Error("a refused configuration must not return a puller")
	}
	if got := deploysec.RuleID(err); got != "S20g" {
		t.Errorf("rule = %q, want S20g (err=%v)", got, err)
	}
}

// T03 — no fallback was asked for: the shell is nobody's business.
func TestH02BNoRestartCommandNeedsNoShell(t *testing.T) {
	reachEnv(t)
	t.Setenv(EnvGateRestartCmd, "")
	h02bSetShellPath(t, filepath.Join(t.TempDir(), "no-such-shell"))
	k, err := newKeyringPullerFromEnv(nil, "robot-1")
	if err != nil || k == nil {
		t.Fatalf("refused although no restart command is configured: err=%v nil=%v", err, k == nil)
	}
}

// T04 — the refusal says which of the two to fix.
func TestH02BRefusalNamesTheSettingAndTheShell(t *testing.T) {
	reachEnv(t)
	missing := filepath.Join(t.TempDir(), "no-such-shell")
	h02bSetShellPath(t, missing)
	_, err := newKeyringPullerFromEnv(nil, "robot-1")
	if err == nil {
		t.Fatal("precondition: the configuration must be refused")
	}
	for _, want := range []string{EnvGateRestartCmd, missing} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// T05 — one source for the shell path: the check and the exec cannot drift apart.
func TestH02BShellPathHasOneSource(t *testing.T) {
	src, err := os.ReadFile("keyring_pull.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(src), `"/bin/sh"`); n != 1 {
		t.Errorf(`"/bin/sh" appears %d times in keyring_pull.go; want exactly 1 (the one source)`, n)
	}
	for _, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, "exec.Command(") && strings.Contains(line, `"/bin/sh"`) {
			t.Errorf("the exec names the shell literally instead of reading the checked value: %s", strings.TrimSpace(line))
		}
	}
}
