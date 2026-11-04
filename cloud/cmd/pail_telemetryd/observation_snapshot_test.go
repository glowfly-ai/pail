// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"encoding/json"
	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/observability"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMOBSProjectionConditionalTTL(t *testing.T) {
	p := projFixture(1)
	path := writeProj(t, t.TempDir(), p)
	src := newProjectionSource(path, 300*time.Second)
	now := time.Now()
	src.now = func() time.Time { return now }
	h := projectionHandler(src)
	w := get(h, "GET", "/v1/telemetry/robotops", nil)
	tag := w.Header().Get("ETag")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	now = now.Add(301 * time.Second)
	w = get(h, "GET", "/v1/telemetry/robotops", map[string]string{"If-None-Match": tag})
	if w.Code != 200 || w.Header().Get("ETag") == tag || !strings.Contains(w.Body.String(), `"stale":true`) {
		t.Fatal("stale bypass via 304", w.Code, w.Body.String())
	}
	now = time.UnixMilli(p.GeneratedAtMS - 1000)
	w = get(h, "GET", "/v1/telemetry/robotops", nil)
	if !strings.Contains(w.Body.String(), "CLOCK_UNCERTAIN") {
		t.Fatal("future projection fresh")
	}
}
func TestMOBSConfigComposition(t *testing.T) {
	b := []byte(`{"schema_version":1}`)
	storage, c, e := parseObservationConfig(b)
	if e != nil || c != nil || storage.RetentionMode != "retain_no_delete" {
		t.Fatal(e)
	}
	b = []byte(`{"schema_version":1,"source_map":{"schema_version":1,"source_id":"c68d3bdd-62b0-4721-9aec-9ea0d4ab0301","deployment_id":"","providers":[]}}`)
	_, c, e = parseObservationConfig(b)
	if e != nil || c == nil || c.Snapshot().DeploymentKnown {
		t.Fatal(e)
	}
	for _, bad := range []string{`{"schema_version":1,"source_map":null}`, `{"schema_version":1,"surprise":1}`, `{"schema_version":1,"schema_version":1}`, `{"schema_version":1,"source_map":{"schema_version":1,"source_id":"bad"}}`} {
		if _, _, e = parseObservationConfig([]byte(bad)); e == nil {
			t.Fatal(bad)
		}
	}
}
func TestMOBSLegacyDispatcherBinding(t *testing.T) {
	p := observability.Provider{ProviderID: "burst", Kind: "legacy_burst", DeploymentID: projDep, RobotID: "robot-1", Identity: "device-1", Allowed: []string{"gate"}, Trust: "verified_signature", Role: "primary"}
	c, e := observability.New(observability.SourceMap{SchemaVersion: 1, SourceID: "c68d3bdd-62b0-4721-9aec-9ea0d4ab0301", Providers: []observability.Provider{p}})
	if e != nil {
		t.Fatal(e)
	}
	c.ObserveLegacy("legacy_burst", ledgerq.RobotHash16("robot-1"), 5, true, false)
	s := c.Snapshot()
	f := s.Robots[0].Sources[0].Facets["gate"]
	if len(s.Unresolved) != 0 || f.Trust != "verified_signature" || f.Quality != "UNKNOWN" || f.Producer != nil || f.Seq != nil {
		t.Fatal(f)
	}
	before := *f.Received
	c.ObserveLegacy("legacy_burst", ledgerq.RobotHash16("robot-1"), 5, true, false)
	if *c.Snapshot().Robots[0].Sources[0].Facets["gate"].Received != before {
		t.Fatal("legacy duplicate advanced")
	}
}
func TestMOBSAPIAuthAndMethods(t *testing.T) {
	old := observationCollector
	defer func() { observationCollector = old }()
	observationCollector, _ = observability.New(observability.SourceMap{SchemaVersion: 1, SourceID: "c68d3bdd-62b0-4721-9aec-9ea0d4ab0301"})
	h := newMux("secret", t.TempDir(), time.Second, nil)
	for _, path := range []string{"/v2/observation/capabilities", "/v2/observation/robots"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("auth bypass", w.Code)
		}
		r.Header.Set("Authorization", "Bearer secret")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var v map[string]any
		if json.Unmarshal(w.Body.Bytes(), &v) != nil {
			t.Fatal("not JSON")
		}
		r.Method = "POST"
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 405 {
			t.Fatal("write allowed")
		}
	}
}
