// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"github.com/glowfly/pail/services/internal/ledgerq"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMOBS_HTTPIndexFailureNoFallback(t *testing.T) {
	old := ledgerIndex
	defer func() { ledgerIndex = old }()
	dir := t.TempDir()
	raw := filepath.Join(dir, "decisions-01.jsonl")
	os.WriteFile(raw, []byte("{\"v\":1,\"kind\":\"tick\",\"ms\":1000}\n"), 0600)
	d, e := ledgerq.Open(filepath.Join(dir, "ledger.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	mux := newMux("", dir, time.Second)
	for _, state := range []string{"nil", "building", "ready", "closed"} {
		switch state {
		case "nil":
			ledgerIndex = nil
		case "building":
			ledgerIndex = d
		case "ready":
			if _, e = d.IngestTelemetry(dir, time.Now()); e != nil {
				t.Fatal(e)
			}
			os.Remove(raw)
			os.Mkdir(raw, 0700)
		case "closed":
			d.Close()
		}
		for _, api := range []string{"decisions", "liveness", "permits"} {
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest("GET", "/v1/telemetry/"+api+"?from_ms=900&to_ms=1100", nil))
			want := 503
			if state == "ready" {
				want = 200
			}
			if rr.Code != want {
				t.Fatalf("%s/%s %d: %s", state, api, rr.Code, rr.Body.String())
			}
			if want == 503 && !strings.Contains(rr.Body.String(), "INDEX_UNAVAILABLE") {
				t.Fatal(rr.Body.String())
			}
		}
	}
}
