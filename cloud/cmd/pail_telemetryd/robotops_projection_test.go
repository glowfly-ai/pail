// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ops "github.com/glowfly/pail/services/pkg/robotops"
)

const projDep = "5e8b24a0-2319-4a53-b5cf-a03afc977301"

func projFixture(rows int) ops.ProjectionSnapshot {
	p := ops.ProjectionSnapshot{SchemaVersion: 1, DocumentKind: "RobotOpsProjection", DeploymentID: projDep, SnapshotRevision: 3, Source: "executor-store", Producer: "test", GeneratedAtMS: time.Now().UnixMilli(), Capabilities: []string{"inventory.v1", "diagnostics.v1"}, Findings: []string{}, Rows: []ops.ProjectionRow{}}
	for i := 0; i < rows; i++ {
		p.Rows = append(p.Rows, ops.ProjectionRow{RobotID: "robot-" + string(rune('a'+i)), DisplayName: "r", Lifecycle: "planned", DesiredGeneration: strings.Repeat("ab", 32), ExecutionID: "9a1f2e3d-4c5b-4a69-8877-665544332211", JobState: "VERIFYING", Registration: map[string]string{}, LoadedConfig: []ops.ProjectionLoaded{{ComponentRef: "cmp:issuer", Kind: "issuer-loaded-status", Status: "PASS", Reason: "ok"}}, IdentityBinding: map[string]string{}, ApplyReadiness: "VERIFICATION_INCOMPLETE", Findings: []string{}, Diagnostics: map[string]string{"k": "v"}})
	}
	return p
}

func writeProj(t *testing.T, dir string, p ops.ProjectionSnapshot) string {
	t.Helper()
	path := filepath.Join(dir, "projection.json")
	b, _ := json.Marshal(p)
	if e := os.WriteFile(path, b, 0644); e != nil {
		t.Fatal(e)
	}
	return path
}

func get(h http.HandlerFunc, method, url string, headers map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, url, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	h(w, r)
	return w
}

func TestProjectionEndpointContract(t *testing.T) {
	dir := t.TempDir()
	path := writeProj(t, dir, projFixture(5))
	src := newProjectionSource(path, 300*time.Second)
	h := projectionHandler(src)

	if w := get(projectionHandler(nil), "GET", "/v1/telemetry/robotops", nil); w.Code != 404 {
		t.Fatal("unset projection must be 404", w.Code)
	}
	if w := get(h, "POST", "/v1/telemetry/robotops", nil); w.Code != 405 || w.Header().Get("Allow") == "" {
		t.Fatal("POST accepted", w.Code)
	}
	for _, bad := range []string{"?view=all", "?limit=0", "?limit=1001", "?cursor=abc", "?foo=1", "?robot_id=", "?view=inventory&view=diagnostics"} {
		if w := get(h, "GET", "/v1/telemetry/robotops"+bad, nil); w.Code != 400 {
			t.Fatalf("%s accepted: %d", bad, w.Code)
		}
	}
	w := get(h, "GET", "/v1/telemetry/robotops?view=diagnostics&limit=2", nil)
	if w.Code != 200 || w.Header().Get("ETag") == "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Header())
	}
	var page projectionResponse
	json.Unmarshal(w.Body.Bytes(), &page)
	if page.Total != 5 || len(page.Rows) != 2 || page.NextCursor != "3:2" || page.Stale || page.Resolution != "resolved" || page.Rows[0].LoadedConfig == nil {
		t.Fatal(page)
	}
	etag := w.Header().Get("ETag")
	// inventory view strips diagnostics.
	w = get(h, "GET", "/v1/telemetry/robotops?view=inventory", nil)
	json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Rows) != 5 || page.Rows[0].LoadedConfig != nil || page.Rows[0].Diagnostics != nil {
		t.Fatal("inventory view leaked diagnostics")
	}
	// If-None-Match → 304 only for the first page.
	if w = get(h, "GET", "/v1/telemetry/robotops", map[string]string{"If-None-Match": etag}); w.Code != 304 {
		t.Fatal("304 expected", w.Code)
	}
	if w = get(h, "GET", "/v1/telemetry/robotops?cursor=3:2", map[string]string{"If-None-Match": etag}); w.Code != 200 {
		t.Fatal("cursor page must not 304", w.Code)
	}
	// HEAD carries the ETag without a body.
	if w = get(h, "HEAD", "/v1/telemetry/robotops", nil); w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("ETag") != etag {
		t.Fatal("HEAD", w.Code, w.Body.Len())
	}
	// Unknown robot: 200 empty with resolution=unresolved, never the whole list.
	w = get(h, "GET", "/v1/telemetry/robotops?robot_id=robot-zz", nil)
	json.Unmarshal(w.Body.Bytes(), &page)
	if w.Code != 200 || page.Total != 0 || page.Resolution != "unresolved" {
		t.Fatal(page)
	}
	// Snapshot revision changes between pages → 409, and the ETag changes only with membership.
	next := projFixture(5)
	next.SnapshotRevision = 4
	next.Rows[0].JobState = "APPLIED_HELD"
	writeProj(t, dir, next)
	if w = get(h, "GET", "/v1/telemetry/robotops?cursor=3:2", nil); w.Code != 409 || !strings.Contains(w.Body.String(), "SNAPSHOT_CHANGED") {
		t.Fatal("stale cursor accepted", w.Code)
	}
	if w = get(h, "GET", "/v1/telemetry/robotops", map[string]string{"If-None-Match": etag}); w.Code != 304 {
		t.Fatal("diagnostic-only change must keep the membership ETag", w.Code)
	}
	renamed := next
	renamed.Rows[1].DisplayName = "renamed"
	writeProj(t, dir, renamed)
	if w = get(h, "GET", "/v1/telemetry/robotops", map[string]string{"If-None-Match": etag}); w.Code != 200 {
		t.Fatal("membership change must invalidate the ETag", w.Code)
	}
	// Schema problems → 503 SCHEMA_UNSUPPORTED; secrets never served.
	bad := projFixture(1)
	bad.SchemaVersion = 9
	writeProj(t, dir, bad)
	if w = get(h, "GET", "/v1/telemetry/robotops", nil); w.Code != 503 || !strings.Contains(w.Body.String(), "SCHEMA_UNSUPPORTED") {
		t.Fatal(w.Code, w.Body.String())
	}
	os.WriteFile(path, []byte(`{"schema_version":1,"document_kind":"RobotOpsProjection","deployment_id":"`+projDep+`","snapshot_revision":1,"source":"x","producer":"y","generated_at_ms":1,"capabilities":[],"findings":[],"rows":[],"private_key":"leak"}`), 0644)
	if w = get(h, "GET", "/v1/telemetry/robotops", nil); w.Code != 503 || strings.Contains(w.Body.String(), "leak") {
		t.Fatal("secret-bearing projection served", w.Code)
	}
	os.Remove(path)
	if w = get(h, "GET", "/v1/telemetry/robotops", nil); w.Code != 503 {
		t.Fatal("missing file must be 503, not an empty list", w.Code)
	}
}

func TestProjectionStaleness(t *testing.T) {
	dir := t.TempDir()
	old := projFixture(1)
	old.GeneratedAtMS = time.Now().Add(-time.Hour).UnixMilli()
	path := writeProj(t, dir, old)
	h := projectionHandler(newProjectionSource(path, 300*time.Second))
	w := get(h, "GET", "/v1/telemetry/robotops", nil)
	var page projectionResponse
	json.Unmarshal(w.Body.Bytes(), &page)
	if w.Code != 200 || !page.Stale || page.StaleReason == "" {
		t.Fatal("old generated_at_ms not marked stale", page)
	}
	fresh := projFixture(1)
	writeProj(t, dir, fresh)
	src := newProjectionSource(path, 300*time.Second)
	src.now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	w = get(projectionHandler(src), "GET", "/v1/telemetry/robotops", nil)
	json.Unmarshal(w.Body.Bytes(), &page)
	if !page.Stale {
		t.Fatal("old file mtime not marked stale")
	}
}
