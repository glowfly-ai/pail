// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

// SEC-H05: plaintext gRPC is refused in the production profile, whatever
// PAIL_GRPC_UDS_PATH says.
//
// Rule S4 used to pass when a Unix-socket path was set. But the socket is an
// additional listener, not a replacement: pail_cloud, pail_services and
// pail_robot_agent all open their TCP port regardless, and with TLS off that
// port is plaintext (pail_cloud has no such socket at all). So "TLS off + any
// socket path" started in production with an open plaintext port.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func h05Env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func h05S4(r Result) (Finding, bool) {
	for _, f := range r.Fail {
		if f.ID == "S4" {
			return f, true
		}
	}
	return Finding{}, false
}

const h05Sock = "/var/run/pail/x.sock"

func TestH05T01PlaintextWithoutASocketPathIsS4(t *testing.T) {
	if _, ok := h05S4(Evaluate(h05Env(map[string]string{"PAIL_GRPC_TLS": "off"}))); !ok {
		t.Fatal("production + PAIL_GRPC_TLS=off: no S4")
	}
}

func TestH05T02PlaintextWithASocketPathIsStillS4(t *testing.T) {
	r := Evaluate(h05Env(map[string]string{"PAIL_GRPC_TLS": "off", "PAIL_GRPC_UDS_PATH": h05Sock}))
	if r.Profile != "production" {
		t.Fatalf("profile=%q", r.Profile)
	}
	if _, ok := h05S4(r); !ok {
		t.Fatal("production + PAIL_GRPC_TLS=off + PAIL_GRPC_UDS_PATH: no S4 — the TCP listener is still opened in plaintext")
	}
}

func TestH05T03TLSWithAnAdditionalSocketIsAccepted(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"tls on":      {"PAIL_GRPC_TLS": "on", "PAIL_GRPC_UDS_PATH": h05Sock},
		"tls default": {"PAIL_GRPC_UDS_PATH": h05Sock},
	} {
		if f, ok := h05S4(Evaluate(h05Env(env))); ok {
			t.Errorf("%s: S4 raised although TLS is on: %s", name, f.Msg)
		}
	}
}

func TestH05T04DevProfileStillNamesS4(t *testing.T) {
	r := Evaluate(h05Env(map[string]string{"PAIL_PROFILE": "dev", "PAIL_GRPC_TLS": "off", "PAIL_GRPC_UDS_PATH": h05Sock}))
	if r.Profile != "dev" {
		t.Fatalf("profile=%q", r.Profile)
	}
	if _, ok := h05S4(r); !ok {
		t.Fatal("dev banner would not list S4: the finding must not depend on the profile")
	}
}

func TestH05T05S4DoesNotOfferTheSocketAsAnAlternative(t *testing.T) {
	f, ok := h05S4(Evaluate(h05Env(map[string]string{"PAIL_GRPC_TLS": "off", "PAIL_GRPC_UDS_PATH": h05Sock})))
	if !ok {
		t.Fatal("no S4 to read")
	}
	if strings.Contains(f.Msg, "no PAIL_GRPC_UDS_PATH") {
		t.Errorf("S4 still reads as if setting a socket path would satisfy it: %q", f.Msg)
	}
	for _, want := range []string{"PAIL_GRPC_TLS=off", "TCP"} {
		if !strings.Contains(f.Msg, want) {
			t.Errorf("S4 message lacks %q: %q", want, f.Msg)
		}
	}
}

// ---- the executables --------------------------------------------------------

var h05Mains = map[string]string{
	"pail_cloud":       "./issuer/cmd/pail_cloud",
	"pail_services":    "./issuer/cmd/pail_services",
	"pail_robot_agent": "./cmd/pail_robot_agent",
}

// h05Build builds one of the executables. The Core source tree is also built
// and tested on its own, without the Issuer's sources; there the two Issuer
// executables do not exist and their cases are skipped — pail_robot_agent is
// part of Core and is always exercised (a missing agent fails the test instead of skipping).
func h05Build(t *testing.T, name string) string {
	t.Helper()
	if _, err := os.Stat(filepath.Join("..", "..", filepath.FromSlash(h05Mains[name]))); os.IsNotExist(err) {
		if name == "pail_robot_agent" {
			t.Fatalf("%s is missing from this tree: the executable-level check would test nothing", h05Mains[name])
		}
		t.Skipf("%s is not part of this source tree", h05Mains[name])
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-tags", "pail_generated", "-o", bin, h05Mains[name])
	cmd.Dir = filepath.Join("..", "..") // services/pail_services_go
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, out)
	}
	return bin
}

// h05Start runs the executable in the production profile (no PAIL_PROFILE) with
// only the given settings, and returns its exit code and combined output. A
// start-up refusal ends at once; ten seconds without an exit is a failure.
func h05Start(t *testing.T, bin string, env map[string]string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Dir = t.TempDir()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("%s did not exit within 10 s — it was not refused at start-up\n%s", filepath.Base(bin), out.String())
	}
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("run %s: %v", bin, err)
	}
	return cmd.ProcessState.ExitCode(), out.String()
}

func h05WantRefusedForS4(t *testing.T, name string, env map[string]string, sock string) {
	t.Helper()
	rc, out := h05Start(t, h05Build(t, name), env)
	if rc != ExitConfig {
		t.Errorf("%s: exit code %d, want %d\n%s", name, rc, ExitConfig, out)
	}
	if !strings.Contains(out, "PAIL PREFLIGHT FAIL: S4 ") {
		t.Errorf("%s: no S4 refusal line\n%s", name, out)
	}
	if strings.Contains(strings.ToLower(out), "listening") {
		t.Errorf("%s: a listener was opened before the refusal\n%s", name, out)
	}
	if sock != "" {
		if _, err := os.Stat(sock); err == nil {
			t.Errorf("%s: the socket %s was created", name, sock)
		}
	}
}

func TestH05T06ExecutablesRefusePlaintextWithASocketPath(t *testing.T) {
	for name := range h05Mains {
		name := name
		t.Run(name, func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), "x.sock")
			h05WantRefusedForS4(t, name, map[string]string{"PAIL_GRPC_TLS": "off", "PAIL_GRPC_UDS_PATH": sock}, sock)
		})
	}
}

func TestH05T07ExecutablesRefusePlaintextWithoutASocketPath(t *testing.T) {
	for name := range h05Mains {
		name := name
		t.Run(name, func(t *testing.T) {
			h05WantRefusedForS4(t, name, map[string]string{"PAIL_GRPC_TLS": "off"}, "")
		})
	}
}
