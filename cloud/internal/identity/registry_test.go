// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package identity

// RED-C3 units . One rule per test, and every refusal
// test carries a passing baseline in the same battery — a loader that refuses
// everything must not read as "all rules enforced" (an always-red gate is a
// wall, not a gate).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/grpcauth"
)

var (
	fpRobot1  = strings.Repeat("1a", 32) // 64-char lowercase hex
	fpRobot1b = strings.Repeat("2b", 32) // rotation twin for robot-1
	fpRobot2  = strings.Repeat("3c", 32)
	fpOrch    = strings.Repeat("4d", 32)
)

func validYAML() string {
	return `version: 1
robots:
  - robot_id: robot-1
    role: robot
    fingerprints: ["` + fpRobot1 + `", "` + fpRobot1b + `"]
  - robot_id: robot-2
    role: robot
    fingerprints: ["` + fpRobot2 + `"]
  - robot_id: "*"
    role: orchestrator
    fingerprints: ["` + fpOrch + `"]
`
}

func mustParse(t *testing.T, body string) *Registry {
	t.Helper()
	r, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("baseline registry must load: %v", err)
	}
	return r
}

func wantRefusal(t *testing.T, body, rule, hint string) {
	t.Helper()
	_, err := Parse([]byte(body))
	if err == nil {
		t.Fatalf("%s: load must refuse (%s)", rule, hint)
	}
	if !strings.Contains(err.Error(), rule) {
		t.Fatalf("%s: refusal must name its rule (%s), got: %v", rule, hint, err)
	}
}

func TestRegistryRG1(t *testing.T) {
	mustParse(t, validYAML()) // the same shape with valid fingerprints loads
	for _, bad := range []struct{ fp, hint string }{
		{strings.Repeat("1a", 31) + "1", "63 chars"},
		{strings.ToUpper(fpRobot1), "uppercase hex"},
		{strings.Repeat("g", 64), "non-hex"},
		{fpRobot1 + "00", "66 chars"},
	} {
		wantRefusal(t, `version: 1
robots:
  - robot_id: robot-1
    role: robot
    fingerprints: ["`+bad.fp+`"]
`, "RG-1", bad.hint)
	}
}

func TestRegistryRG2(t *testing.T) {
	// 1:N stays legal — one robot, two fingerprints, is the rotation window.
	r := mustParse(t, validYAML())
	for _, fp := range []string{fpRobot1, fpRobot1b} {
		if b := r.Bind(grpcauth.CallerMTLS, fp, "robot-1"); b.Verdict != Bound {
			t.Fatalf("rotation twin %s… must bind, got %s (%s)", fp[:8], b.Verdict, b.Reason)
		}
	}
	// N:1 breaks functionality — the same fingerprint under two robot_ids.
	wantRefusal(t, `version: 1
robots:
  - robot_id: robot-1
    role: robot
    fingerprints: ["`+fpRobot1+`"]
  - robot_id: robot-2
    role: robot
    fingerprints: ["`+fpRobot1+`"]
`, "RG-2", "shared fingerprint")
}

func TestRegistryRG3(t *testing.T) {
	mustParse(t, validYAML()) // orchestrator as "*" loads
	wantRefusal(t, `version: 1
robots:
  - robot_id: orch-1
    role: orchestrator
    fingerprints: ["`+fpOrch+`"]
`, "RG-3", "orchestrator with a concrete robot_id")
	wantRefusal(t, `version: 1
robots:
  - robot_id: "*"
    role: robot
    fingerprints: ["`+fpRobot1+`"]
`, "RG-3", `"*" with role robot`)
	wantRefusal(t, `version: 1
robots:
  - robot_id: robot-1
    role: admin
    fingerprints: ["`+fpRobot1+`"]
`, "RG-3", "unknown role must not quietly become a robot")
}

func TestRegistryRG4(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil ||
		!strings.Contains(err.Error(), "RG-4") {
		t.Fatalf("missing file must refuse with RG-4, got: %v", err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "robot_registry.yaml")
	if err := os.WriteFile(p, []byte(validYAML()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("valid file must load: %v", err)
	}
	wantRefusal(t, "robots: [", "RG-4", "yaml parse failure")
	wantRefusal(t, "version: 2\nrobots: []\n", "RG-4", "unsupported version")
	wantRefusal(t, "version: 1\nrobots: []\n", "RG-4", "empty registry")
	wantRefusal(t, `version: 1
robots:
  - robot_id: robot-1
    role: robot
    fingerprint: ["`+fpRobot1+`"]
`, "RG-4", "unknown field (strict decode) — a typo must not become an empty list")
}

func TestBindBound(t *testing.T) {
	r := mustParse(t, validYAML())
	b := r.Bind(grpcauth.CallerMTLS, fpRobot1, "robot-1")
	if b.Verdict != Bound || b.Reason != "" {
		t.Fatalf("registered fingerprint + matching robot_id must be bound, got %s (%s)", b.Verdict, b.Reason)
	}
	if got := b.Verdict.String(); got != "bound" {
		t.Fatalf("journal vocabulary: want \"bound\", got %q", got)
	}
	// The zero value is a judgment nobody made — it must not equal any verdict
	// a judge can return (H-B2).
	if (Binding{}).Verdict == Bound || Verdict(0).String() != "invalid" {
		t.Fatalf("zero-value Binding must read as invalid, not as a pass")
	}
}

func TestBindDelegated(t *testing.T) {
	r := mustParse(t, validYAML())
	for _, robot := range []string{"robot-1", "robot-2", "robot-99"} {
		b := r.Bind(grpcauth.CallerMTLS, fpOrch, robot)
		if b.Verdict != Delegated {
			t.Fatalf("orchestrator fingerprint for %s must be delegated, got %s (%s)", robot, b.Verdict, b.Reason)
		}
		// DF-C4 surface: delegated merged into bound erases "who actually
		// called" from the post-incident trace.
		if b.Verdict == Bound {
			t.Fatalf("delegated and bound must stay distinct values")
		}
	}
	if got := Delegated.String(); got != "delegated" {
		t.Fatalf("journal vocabulary: want \"delegated\", got %q", got)
	}
}

func TestBindUnbound(t *testing.T) {
	r := mustParse(t, validYAML())
	unregistered := strings.Repeat("9e", 32)
	if b := r.Bind(grpcauth.CallerMTLS, unregistered, "robot-1"); b.Verdict != Unbound ||
		b.Reason != "fingerprint_unregistered" {
		t.Fatalf("unregistered fingerprint must be unbound, got %s (%s)", b.Verdict, b.Reason)
	}
	if b := r.Bind(grpcauth.CallerMTLS, fpRobot2, "robot-1"); b.Verdict != Unbound ||
		b.Reason != "robot_id_mismatch" {
		t.Fatalf("robot-2's fingerprint claiming robot-1 must be unbound, got %s (%s)", b.Verdict, b.Reason)
	}
	// A caller kind outside the frozen vocabulary is refused, not waved
	// through as unchecked — no else-arm that passes.
	if b := r.Bind("tcp", fpRobot1, "robot-1"); b.Verdict != Unbound ||
		b.Reason != "caller_kind_unrecognized" {
		t.Fatalf("unrecognized caller kind must be unbound, got %s (%s)", b.Verdict, b.Reason)
	}
	if got := Unbound.String(); got != "unbound" {
		t.Fatalf("journal vocabulary: want \"unbound\", got %q", got)
	}
}

func TestBindUnchecked(t *testing.T) {
	r := mustParse(t, validYAML())
	for _, kind := range []string{grpcauth.CallerUDS, grpcauth.CallerUnknown} {
		b := r.Bind(kind, "", "robot-1")
		if b.Verdict != Unchecked {
			t.Fatalf("kind=%s must be unchecked, got %s (%s)", kind, b.Verdict, b.Reason)
		}
		// DF-C4 surface, both directions: unchecked merged into bound makes
		// "we could not check" read as "we checked and it matched"; merged
		// into unbound it severs every local (UDS) pipe.
		if b.Verdict == Bound || b.Verdict == Unbound {
			t.Fatalf("unchecked must stay distinct from bound and unbound")
		}
		if !strings.Contains(b.Reason, kind) {
			t.Fatalf("unchecked must record which kind went unjudged, got %q", b.Reason)
		}
	}
	if got := Unchecked.String(); got != "unchecked" {
		t.Fatalf("journal vocabulary: want \"unchecked\", got %q", got)
	}
}
