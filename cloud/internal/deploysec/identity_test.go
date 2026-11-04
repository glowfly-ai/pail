// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStderr runs fn with os.Stderr replaced by a pipe and returns what was
// written. Preflight writes to os.Stderr directly rather than through a logger,
// so there is no seam to inject — swapping the file is the seam.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stderr = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// TestL10IdentityLineCarriesRealIds is the value arm: the line must carry the
// ids this process actually has. Asserting only that the line exists would pass
// on a hardcoded `uid=10001`, and a hardcoded value is worse than no line —
// it reads as a measurement.
func TestL10IdentityLineCarriesRealIds(t *testing.T) {
	out := captureStderr(t, func() { EmitProcessIdentity("unit") })
	want := fmt.Sprintf("%s uid=%d euid=%d gid=%d egid=%d component=unit",
		IdentityPrefix, os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid())
	if !strings.Contains(out, want) {
		t.Fatalf("identity line missing or wrong\n want: %s\n got:  %q", want, out)
	}
	for _, field := range []string{"uid=", "euid=", "gid=", "egid=", "component="} {
		if !strings.Contains(out, field) {
			t.Errorf("field %q absent — 접힌 칸은 조용하다", field)
		}
	}
}

// TestL10RealAndEffectiveAreSeparateFields guards the fold. On an ordinary run
// uid == euid, so a change that printed one value twice would still look right
// in the arm above. This one reads the two fields back out and requires them to
// be *named* separately, which is what a fold destroys.
func TestL10RealAndEffectiveAreSeparateFields(t *testing.T) {
	out := captureStderr(t, func() { EmitProcessIdentity("unit") })
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, IdentityPrefix) {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("identity line absent")
	}
	seen := map[string]bool{}
	for _, tok := range strings.Fields(line) {
		if k, _, ok := strings.Cut(tok, "="); ok {
			if seen[k] {
				t.Errorf("field %q appears twice — 같은 이름의 두 칸은 대조되지 않는다", k)
			}
			seen[k] = true
		}
	}
	for _, k := range []string{"uid", "euid", "gid", "egid"} {
		if !seen[k] {
			t.Errorf("field %q absent", k)
		}
	}
}

// TestL10IdentityPrecedesVerdict is the ordering arm. Preflight has three exits
// — OK, dev banner, and os.Exit — and the last one is the launch we most want
// described. The refusal path cannot be exercised in-process, so what is
// measured here is the weaker, checkable half: the identity line comes out
// before the verdict does. The source-position claim (first statement of the
// function) is measured by the runner's structure arm.
func TestL10IdentityPrecedesVerdict(t *testing.T) {
	t.Setenv("PAIL_PROFILE", "dev")
	out := captureStderr(t, func() { Preflight("unit") })
	i := strings.Index(out, IdentityPrefix)
	if i < 0 {
		t.Fatalf("Preflight emitted no identity line:\n%s", out)
	}
	j := strings.Index(out, "PAIL PREFLIGHT: profile=")
	if j < 0 {
		t.Fatalf("Preflight emitted no verdict line — 이 팔의 전제가 없다:\n%s", out)
	}
	if i > j {
		t.Errorf("identity line comes after the verdict (identity@%d verdict@%d)", i, j)
	}
}
