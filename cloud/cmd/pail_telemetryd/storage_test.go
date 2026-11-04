// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/telemetry"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMOBSStorageHTTPFailureDiagnostics(t *testing.T) {
	old, oldStore := ledgerIndex, observationStore
	defer func() { ledgerIndex = old; observationStore = oldStore }()
	dir := t.TempDir()
	d, e := ledgerq.Open(filepath.Join(dir, "ledger.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	ledgerIndex = d
	os.WriteFile(filepath.Join(dir, "decisions-legacy.jsonl"), []byte(`{"v":1,"kind":"tick","ms":1000}`+"\n"), 0600)
	if _, e = d.IngestTelemetry(dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	mux := newMux("", dir, time.Second)
	for _, failure := range []string{"healthy", "db", "writer"} {
		if failure == "db" {
			c := telemetry.DefaultStorageConfig()
			c.DBMaxBytes = 1
			d.ConfigureStorage(c)
			if e = d.CheckStorage(); e == nil {
				t.Fatal("pressure control did not fail")
			}
		}
		if failure == "writer" {
			d.ConfigureStorage(telemetry.DefaultStorageConfig())
			d.IngestTelemetry(dir, time.Now())
			c := telemetry.DefaultStorageConfig()
			c.RawMaxBytes = 1
			s, e := telemetry.OpenStoreWithConfig(dir, c)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			observationStore = s
			if e = s.AppendLine([]byte(`{"v":1,"kind":"tick","ms":1000}`), time.Now()); e == nil {
				t.Fatal("writer quota accepted")
			}
		}
		for _, api := range []string{"storage", "decisions", "liveness", "permits"} {
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/telemetry/"+api+"?from_ms=900&to_ms=1100", nil))
			want := 503
			if failure == "healthy" {
				want = 200
			}
			if rr.Code != want {
				t.Fatalf("%s %s %d %s", failure, api, rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), dir) {
				t.Fatal("host path exposed")
			}
			if failure == "db" && api == "storage" && !strings.Contains(rr.Body.String(), "DB_DISK_PRESSURE") {
				t.Fatal(rr.Body.String())
			}
			if failure == "writer" && !strings.Contains(rr.Body.String(), "OBSERVATION_LOSS") {
				t.Fatal(rr.Body.String())
			}
		}
	}
}

func TestMOBSStorageHTTPRetainedRawBoundary(t *testing.T) {
	old, oldStore := ledgerIndex, observationStore
	defer func() { ledgerIndex = old; observationStore = oldStore }()
	dir := t.TempDir()
	d, e := ledgerq.Open(filepath.Join(dir, "ledger.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	ledgerIndex = d
	c := telemetry.DefaultStorageConfig()
	c.RetentionMode = "managed"
	c.RetainDays = 7
	c.RawMaxBytes = 2 << 30
	c.TrashGraceSeconds = 1
	s, e := telemetry.OpenStoreWithConfig(dir, c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	observationStore = s
	at := time.UnixMilli(1000)
	for _, offset := range []time.Duration{0, 24 * time.Hour} {
		b, _ := telemetry.MarshalTick(uint64(at.Add(offset).UnixMilli()))
		if e = s.AppendLine(b, at.Add(offset)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = d.IngestTelemetry(dir, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e = s.Maintain(at.Add(10*24*time.Hour), d.IndexedRaw); e != nil {
		t.Fatal(e)
	}
	mux := newMux("", dir, time.Second)
	for _, api := range []string{"decisions", "liveness", "permits"} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/telemetry/"+api+"?from_ms=900&to_ms=1100", nil))
		if rr.Code != 200 || rr.Header().Get("X-PAIL-Raw-Complete") != "false" {
			t.Fatal(api, rr.Code, rr.Header(), rr.Body.String())
		}
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/telemetry/storage", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"raw_incomplete":true`) {
		t.Fatal(rr.Code, rr.Body.String())
	}
}
