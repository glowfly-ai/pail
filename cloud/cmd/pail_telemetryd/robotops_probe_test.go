// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/glowfly/pail/services/internal/telemetry"
	ops "github.com/glowfly/pail/services/pkg/robotops"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectorProbeUsesActualQueryBytesAndNoStaleCache(t *testing.T) {
	path := writeRegistry(t, testRegistryYAML)
	h := collectorProbeHandler(path)
	nonce := strings.Repeat("a", 64)
	query := func() ops.CollectorProbe {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest("GET", "/v1/telemetry/robotops/probe?nonce="+nonce, nil))
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		var v ops.CollectorProbe
		if json.Unmarshal(w.Body.Bytes(), &v) != nil {
			t.Fatal("invalid report")
		}
		if strings.Contains(w.Body.String(), path) {
			t.Fatal("private host path disclosed")
		}
		return v
	}
	first := query()
	sum := sha256.Sum256([]byte(testRegistryYAML))
	if first.RegistryDigest != hex.EncodeToString(sum[:]) || first.ResolutionStrategy != "per_request" || first.Nonce != nonce {
		t.Fatal(first)
	}
	raw, _ := os.ReadFile(path)
	raw = append(raw, []byte("\n# source changed\n")...)
	os.WriteFile(path, raw, 0600)
	second := query()
	if first.RegistryDigest == second.RegistryDigest || first.InstanceID != second.InstanceID {
		t.Fatal("stale cache or unstable instance")
	}
	os.WriteFile(path, []byte("version: 1\nrobots: []\n"), 0600)
	broken := query()
	if broken.RegistryState != "invalid" || broken.RegistryDigest != "" || len(broken.Robots) != 0 {
		t.Fatal("old success reused", broken)
	}
}
func TestCollectorProbeWiringAuthMethodsAndNonce(t *testing.T) {
	old := registryPath
	defer func() { registryPath = old }()
	registryPath = writeRegistry(t, testRegistryYAML)
	mux := newMux("test-only-token", t.TempDir(), 30*time.Second)
	for _, row := range []struct {
		method, query, token string
		want                 int
	}{{"GET", "?nonce=" + strings.Repeat("b", 64), "", 401}, {"GET", "?nonce=" + strings.Repeat("b", 64), "test-only-token", 200}, {"HEAD", "?nonce=" + strings.Repeat("b", 64), "test-only-token", 200}, {"POST", "?nonce=" + strings.Repeat("b", 64), "test-only-token", 405}, {"GET", "?nonce=00", "test-only-token", 400}, {"GET", "?nonce=" + strings.Repeat("b", 64) + "&extra=1", "test-only-token", 400}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(row.method, "/v1/telemetry/robotops/probe"+row.query, nil)
		if row.token != "" {
			r.Header.Set("Authorization", "Bearer "+row.token)
		}
		mux.ServeHTTP(w, r)
		if w.Code != row.want {
			t.Fatalf("%s: %d want %d", row.method, w.Code, row.want)
		}
	}
}
func TestExistingRegistryWireShapeIsUnchanged(t *testing.T) {
	view := registryView(writeRegistry(t, testRegistryYAML))
	raw, e := json.Marshal(view)
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]interface{}
	json.Unmarshal(raw, &fields)
	for k := range fields {
		switch k {
		case "version", "source", "path", "error", "robots":
		default:
			t.Fatal("unversioned field added to existing registry API", k)
		}
	}
	if view.Digest == "" {
		t.Fatal("internal parsed digest missing")
	}
}
func TestCollectorProbeRejectsDuplicateNonce(t *testing.T) {
	h := collectorProbeHandler(writeRegistry(t, testRegistryYAML))
	w := httptest.NewRecorder()
	nonce := strings.Repeat("d", 64)
	h(w, httptest.NewRequest("GET", "/v1/telemetry/robotops/probe?nonce="+nonce+"&nonce="+nonce, nil))
	if w.Code != 400 {
		t.Fatal("ambiguous nonce accepted")
	}
}
func TestSignalsEndpointRequiresLiveSourceAndPreservesAuth(t *testing.T) {
	old := registryPath
	defer func() { registryPath = old }()
	registryPath = writeRegistry(t, testRegistryYAML)
	dir := t.TempDir()
	// A plausible historical file must not become a live receipt source.
	os.WriteFile(filepath.Join(dir, "decisions-20260922.jsonl"), []byte("{\"v\":1,\"kind\":\"tick\",\"ms\":1700000000000}\n"), 0600)
	path := "/v1/telemetry/robotops/signals?nonce=" + strings.Repeat("e", 64)
	mux := newMux("test-only-token", dir, time.Second)
	w := httptest.NewRecorder()
	q := httptest.NewRequest("GET", path, nil)
	q.Header.Set("Authorization", "Bearer test-only-token")
	mux.ServeHTTP(w, q)
	if w.Code != 503 {
		t.Fatal("disk evidence impersonated live source", w.Code)
	}
	live := telemetry.NewLiveSignals("burst", "mirror")
	live.Observe(telemetry.Record{Kind: telemetry.KindBurst, Robot: "hash", Sig: telemetry.SigOK, Seq: 1, Event: "CHECKPOINT", Raw: "PRIVATE_CANARY", Token: "TOKEN_CANARY"}, time.Now())
	mux = newMux("test-only-token", dir, time.Second, live)
	w = httptest.NewRecorder()
	q = httptest.NewRequest("GET", path, nil)
	mux.ServeHTTP(w, q)
	if w.Code != 401 {
		t.Fatal("signal auth bypass")
	}
	w = httptest.NewRecorder()
	q.Header.Set("Authorization", "Bearer test-only-token")
	mux.ServeHTTP(w, q)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if strings.Contains(w.Body.String(), "CANARY") {
		t.Fatal("raw/token material disclosed")
	}
	var v ops.SignalProbe
	if json.Unmarshal(w.Body.Bytes(), &v) != nil || len(v.Signals) != 1 || v.Signals[0].Mirror.State != "NEVER" || v.RegistryDigest == "" {
		t.Fatal(w.Body.String())
	}
}
