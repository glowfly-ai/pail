// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// AL-1 (implementation contract D6) — the query surface's honesty at the HTTP edge: names
// resolve through the registry, an unknown name is answered as unknown (not
// as "all robots"), telemetry rows get their name at response time.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/signer"
	"github.com/glowfly/pail/services/internal/telemetry"
)

func ledgerFixture(t *testing.T) {
	t.Helper()
	bb := filepath.Join(t.TempDir(), "bb")
	tel := filepath.Join(t.TempDir(), "tel")
	for _, d := range []string{bb, tel} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := blackbox.OpenDir(bb, blackbox.Config{
		Signer: signer.NewLocal(&devcrypto.Keypair{Public: pub, Private: priv, KeyID: "k"}), IdleFlushAfter: -1})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := json.Marshal(map[string]any{"kind": "token_issued", "robot_id": "robot-1", "plan_id": "p", "token_id": "tok-1", "step_id": "s1"})
	if err := w.Append(blackbox.RecordTokenIssued, 1_700_000_001_000, tok); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	d := false
	burst, _ := json.Marshal(telemetry.Record{V: 1, Kind: telemetry.KindBurst, Ms: 1_700_000_002_000, Event: "BLOCK",
		ReasonValue: 0x13, Robot: ledgerq.RobotHash16("robot-1"), Token: ledgerq.TokenHash16("tok-1"), Sig: telemetry.SigOK, Dup: &d, Raw: "00"})
	if err := os.WriteFile(filepath.Join(tel, "decisions-20260904.jsonl"), append(burst, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	idx, err := ledgerq.Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := idx.Ingest(bb, tel, time.Now()); err != nil {
		t.Fatal(err)
	}
	prevIdx, prevReg := ledgerIndex, registryPath
	ledgerIndex = idx
	registryPath = writeRegistry(t, testRegistryYAML)
	t.Cleanup(func() { idx.Close(); ledgerIndex, registryPath = prevIdx, prevReg })
}

func getEvents(t *testing.T, query string) (int, ledgerq.Result) {
	t.Helper()
	rec := httptest.NewRecorder()
	ledgerEventsHandler(30*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/ledger/events?"+query, nil))
	var res ledgerq.Result
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("body: %v: %s", err, rec.Body.String())
		}
	}
	return rec.Code, res
}

func TestAL1_EventsByNameResolveThroughRegistry(t *testing.T) {
	ledgerFixture(t)
	code, res := getEvents(t, "from_ms=1&robot=robot-1")
	if code != 200 || len(res.Rows) != 2 || res.Resolution.Robot != "registry" {
		t.Fatalf("code=%d rows=%d resolution=%+v", code, len(res.Rows), res.Resolution)
	}
	// the telemetry row carries no plaintext; its name is attached at response
	// time from the registry — and says so
	for _, r := range res.Rows {
		if r.RobotID != "robot-1" || !r.Resolved {
			t.Fatalf("row %s/%s unresolved: %+v", r.Src, r.Outcome, r)
		}
	}
	code, res = getEvents(t, "from_ms=1&robot="+ledgerq.RobotHash16("robot-1"))
	if code != 200 || len(res.Rows) != 2 || res.Resolution.Robot != "hash_only" {
		t.Fatalf("hash query: code=%d rows=%d resolution=%+v", code, len(res.Rows), res.Resolution)
	}
}

// An unknown robot name must not be answered with every robot's events. The
// filter the operator typed is answered as "unknown", rows empty, and the
// response says why.
func TestAL1_UnknownRobotNameIsAnsweredNotReplaced(t *testing.T) {
	ledgerFixture(t)
	code, res := getEvents(t, "from_ms=1&robot=robot-9")
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	if len(res.Rows) != 0 || res.Resolution.Robot != "unresolved" {
		t.Fatalf("unknown name must yield 0 rows + unresolved, got rows=%d resolution=%+v", len(res.Rows), res.Resolution)
	}
	if res.Verify.State != "unverified" {
		t.Fatalf("an unanswered query cannot claim a chain verdict: %+v", res.Verify)
	}
}

func TestAL1_EventsRejectsBadWindowAndCarriesFreshness(t *testing.T) {
	ledgerFixture(t)
	if code, _ := getEvents(t, "from_ms=abc"); code != http.StatusBadRequest {
		t.Fatalf("bad from_ms: code=%d", code)
	}
	code, res := getEvents(t, "around_ms=1700000001500&span_ms=1000")
	if code != 200 || len(res.Rows) != 2 {
		t.Fatalf("around window: code=%d rows=%d", code, len(res.Rows))
	}
	if res.Index.ChainRows != 1 || res.Index.TelemetryRows != 1 || res.Index.LastIngestMs == 0 {
		t.Fatalf("index freshness missing: %+v", res.Index)
	}
	// AL-4: the handler passes the index's zone verdict through untouched.
	// The fixture's token names no target → "none"; a constant here would
	// have read as "unresolved" and hidden the index's answer.
	if res.Resolution.Zone != "none" {
		t.Fatalf("zone resolution must come from the index (fixture has no target → none): %+v", res.Resolution)
	}
}

func TestAL1_EventsWithoutIndexIs503(t *testing.T) {
	prev := ledgerIndex
	ledgerIndex = nil
	defer func() { ledgerIndex = prev }()
	if code, _ := getEvents(t, "from_ms=1"); code != http.StatusServiceUnavailable {
		t.Fatalf("no index must be 503, got %d", code)
	}
}
