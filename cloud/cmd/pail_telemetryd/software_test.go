// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// G-EUC-02 (EC-2) — collector side. Each word of the three vocabularies gets a
// fixture of its own so that folding two words together is seen by one name.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
)

func swFixture(t *testing.T, records []map[string]any) (bbDir, sbomDir string) {
	t.Helper()
	bbDir = filepath.Join(t.TempDir(), "bb")
	sbomDir = filepath.Join(t.TempDir(), "sbom")
	if err := os.MkdirAll(sbomDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := blackbox.OpenDir(bbDir, blackbox.Config{
		Signer: signer.NewLocal(&devcrypto.Keypair{Public: pub, Private: priv, KeyID: "k"}), IdleFlushAfter: -1})
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range records {
		b, _ := json.Marshal(p)
		typ := blackbox.RecordAttestation
		if p["kind"] == "CONFIG_SEALED" {
			typ = blackbox.RecordConfigSealed
		}
		if err := w.Append(typ, uint64(1000+i), b); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return bbDir, sbomDir
}

func writeSBOM(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func rowOf(t *testing.T, v softwareResponse, component string) softwareComponent {
	t.Helper()
	for _, c := range v.Components {
		if c.Component == component {
			return c
		}
	}
	t.Fatalf("no row for %s in %+v", component, v.Components)
	return softwareComponent{}
}

func TestSW01_SealedValidAndSBOMPresent(t *testing.T) {
	bb, sb := swFixture(t, nil)
	sha := writeSBOM(t, sb, "pep_gate.cdx.json", `{"bomFormat":"CycloneDX"}`)
	bb, _ = swFixture(t, []map[string]any{{
		"kind": "ATTESTATION", "component": "pep_gate",
		"build_info": "pail-build:v1:pep_gate:0.1:4a3a441:-:" + sha,
	}})
	v, code := softwareView(bb, sb)
	if code != http.StatusOK || v.Source != "chain" {
		t.Fatalf("code=%d source=%s errors=%v", code, v.Source, v.Errors)
	}
	r := rowOf(t, v, "pep_gate")
	if r.Source != "sealed" || r.BuildInfoState != "valid" || r.Kind != "ATTESTATION" || r.SBOM.State != "present" {
		t.Fatalf("%+v", r)
	}
	if len(v.Components) != 5 {
		t.Fatalf("every component is a row: %d", len(v.Components))
	}
}

func TestSW02_HashMismatchIsNotPresent(t *testing.T) {
	bb, sb := swFixture(t, []map[string]any{{
		"kind": "CONFIG_SEALED", "component": "pep_gate",
		"build_info": "pail-build:v1:pep_gate:0.1:4a3a441:-:" + hex.EncodeToString(make([]byte, 32)),
	}})
	writeSBOM(t, sb, "pep_gate.cdx.json", `{"bomFormat":"CycloneDX","edited":true}`)
	r := rowOf(t, mustView(t, bb, sb), "pep_gate")
	if r.SBOM.State != "hash_mismatch" {
		t.Fatalf("an SBOM that is not the claimed one read as %q", r.SBOM.State)
	}
	if r.Kind != "CONFIG_SEALED" {
		t.Fatalf("kind=%s", r.Kind)
	}
}

func TestSW03_AbsentAndUnclaimedAreDifferentWords(t *testing.T) {
	bb, sb := swFixture(t, []map[string]any{
		{"kind": "ATTESTATION", "component": "issuer", "build_info": "pail-build:v1:issuer:-:-:-:-"},
	})
	v := mustView(t, bb, sb)
	if r := rowOf(t, v, "issuer"); r.SBOM.State != "absent" || r.BuildInfoState != "valid" {
		t.Fatalf("no file must be absent: %+v", r)
	}
	writeSBOM(t, sb, "pail_services_go.cdx.json", `{}`)
	if r := rowOf(t, mustView(t, bb, sb), "issuer"); r.SBOM.State != "unclaimed" {
		t.Fatalf("a file with no hash claim must be unclaimed, not present: %+v", r)
	}
}

func TestSW04_UnsealedAndInvalidAreTheirOwnWords(t *testing.T) {
	bb, sb := swFixture(t, []map[string]any{
		{"kind": "ATTESTATION", "component": "telemetryd", "build_info": "pail-build:v1:telemetryd:0.1"},
	})
	v := mustView(t, bb, sb)
	if r := rowOf(t, v, "robot_agent"); r.Source != "unsealed" || r.BuildInfoState != "absent" {
		t.Fatalf("never-attested component: %+v", r)
	}
	if r := rowOf(t, v, "telemetryd"); r.Source != "sealed" || r.BuildInfoState != "invalid" || r.Error == "" {
		t.Fatalf("malformed build_info must be invalid with a reason: %+v", r)
	}
}

func TestSW05_NewestRecordWinsAndUnreadableChainIs503(t *testing.T) {
	bb, sb := swFixture(t, []map[string]any{
		{"kind": "ATTESTATION", "component": "pep_gate", "build_info": "pail-build:v1:pep_gate:old:-:-:-"},
		{"kind": "ATTESTATION", "component": "pep_gate", "build_info": "pail-build:v1:pep_gate:new:-:-:-"},
	})
	if r := rowOf(t, mustView(t, bb, sb), "pep_gate"); r.BuildInfo != "pail-build:v1:pep_gate:new:-:-:-" {
		t.Fatalf("newest must win: %s", r.BuildInfo)
	}
	rec := httptest.NewRecorder()
	softwareHandler(filepath.Join(t.TempDir(), "missing"), sb)(rec, httptest.NewRequest("GET", "/v1/telemetry/software", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable chain must be 503, got %d: %s", rec.Code, rec.Body.String())
	}
	var v softwareResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.Source != "unreadable" || len(v.Errors) == 0 {
		t.Fatalf("503 body must say unreadable with a reason: %s", rec.Body.String())
	}
}

func mustView(t *testing.T, bb, sb string) softwareResponse {
	t.Helper()
	v, code := softwareView(bb, sb)
	if code != http.StatusOK {
		t.Fatalf("code=%d errors=%v", code, v.Errors)
	}
	return v
}
