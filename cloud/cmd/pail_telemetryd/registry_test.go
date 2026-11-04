// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// AL-0 (implementation contract D7) — robot hash → name resolution material.
//
// Owner of G-LED-01 (server half). The dashboard half lives in
// tests/contract/test_dashboard_registry.py. Both halves are needed: a server
// that emits the right hash and a page that ignores it are the same green.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/glowfly/pail/services/internal/burst"
	"github.com/glowfly/pail/services/internal/ledgerq"
)

const testRegistryYAML = `version: 1
robots:
  - robot_id: robot-1
    role: robot
    fingerprints:
      - "0000000000000000000000000000000000000000000000000000000000000001"
  - robot_id: robot-2
    role: robot
    fingerprints:
      - "0000000000000000000000000000000000000000000000000000000000000002"
      - "0000000000000000000000000000000000000000000000000000000000000003"
  - robot_id: "*"
    role: orchestrator
    fingerprints:
      - "0000000000000000000000000000000000000000000000000000000000000004"
`

func testSignKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func writeRegistry(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "robot_registry.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The hash the view publishes must be the hash the gate puts on the wire —
// derived through the burst package, not re-typed here (a re-typed constant
// would keep passing after packet_v2 changed its truncation).
func TestAL0_RegistryHashMatchesBurstV2(t *testing.T) {
	pkt := burst.BuildPacketV2(testSignKey(t), 0x02, 0, 0, "robot-1", burst.TokenHash16("tok"), 1)
	wire := pkt[16:32]
	got := ledgerq.RobotHash16("robot-1")
	if len(got) != 32 {
		t.Fatalf("RobotHash16 length %d, want 32 hex chars", len(got))
	}
	want := make([]byte, 0, 32)
	for _, b := range wire {
		want = append(want, "0123456789abcdef"[b>>4], "0123456789abcdef"[b&15])
	}
	if got != string(want) {
		t.Fatalf("ledgerq.RobotHash16(robot-1)=%s, burst v2 wire=%s", got, want)
	}
}

func TestAL0_RegistryView_Loaded(t *testing.T) {
	v := registryView(writeRegistry(t, testRegistryYAML))
	if v.Source != "registry" || v.Error != "" {
		t.Fatalf("source=%q error=%q, want registry/none", v.Source, v.Error)
	}
	// "*" (orchestrator) is not a robot and must not be hashed into the list;
	// robot-2's two fingerprints collapse to one row.
	if len(v.Robots) != 2 || v.Robots[0].RobotID != "robot-1" || v.Robots[1].RobotID != "robot-2" {
		t.Fatalf("robots=%+v, want [robot-1 robot-2]", v.Robots)
	}
	for _, r := range v.Robots {
		if r.RobotHash != ledgerq.RobotHash16(r.RobotID) {
			t.Fatalf("%s hash %s != %s", r.RobotID, r.RobotHash, ledgerq.RobotHash16(r.RobotID))
		}
	}
}

// Three outcomes, three values. Absent and invalid must not arrive as an
// empty registry — an empty list reads as "no robots" on the page.
func TestAL0_RegistryView_AbsentAndInvalidAreNamed(t *testing.T) {
	absent := registryView(filepath.Join(t.TempDir(), "nope.yaml"))
	if absent.Source != "absent" || absent.Error == "" || len(absent.Robots) != 0 {
		t.Fatalf("absent: %+v", absent)
	}
	invalid := registryView(writeRegistry(t, "version: 1\nrobots: []\n"))
	if invalid.Source != "invalid" || invalid.Error == "" || len(invalid.Robots) != 0 {
		t.Fatalf("invalid: %+v", invalid)
	}
	if absent.Source == invalid.Source {
		t.Fatalf("absent and invalid share source %q", absent.Source)
	}
}

func TestAL0_RegistryEndpoint(t *testing.T) {
	h := registryHandler(writeRegistry(t, testRegistryYAML))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/telemetry/registry", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status %d", rec.Code)
	}
	var body registryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	// Count/ordering/membership are TestAL0_RegistryView_Loaded's judgement;
	// here only "the wire carries the view" (one observation point per test,
	// H-B9) — so look robot-1 up instead of assuming its position.
	var hash string
	for _, r := range body.Robots {
		if r.RobotID == "robot-1" {
			hash = r.RobotHash
		}
	}
	if body.Source != "registry" || hash != ledgerq.RobotHash16("robot-1") {
		t.Fatalf("body=%s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/telemetry/registry", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d, want 405", rec.Code)
	}
}

func TestAL0_ResolveRegistryPath(t *testing.T) {
	if got := resolveRegistryPath("/a", "/b"); got != "/a" {
		t.Fatalf("flag should win: %s", got)
	}
	if got := resolveRegistryPath("", "/b"); got != "/b" {
		t.Fatalf("env should be second: %s", got)
	}
	if got := resolveRegistryPath("", ""); got == "" {
		t.Fatal("default must not be empty")
	}
}
