// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

// AL-4 (implementation contract D6) — zone resolution answers from the model of that day:
// recorded at issuance, else that model's kept snapshot, else "unresolved".
// Never "current_model".

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

const siteHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// fixtureZones writes three TOKEN_ISSUED records: one with a recorded zone
// (journal_v 7), one legacy row naming a model but no zone, one with no target.
func fixtureZones(t *testing.T) (bbDir, telDir string) {
	t.Helper()
	bbDir = filepath.Join(t.TempDir(), "bb")
	telDir = filepath.Join(t.TempDir(), "tel")
	for _, d := range []string{bbDir, telDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	w, err := blackbox.OpenDir(bbDir, blackbox.Config{Signer: testSigner(t), IdleFlushAfter: -1})
	if err != nil {
		t.Fatal(err)
	}
	for i, rec := range []map[string]any{
		{"kind": "TOKEN_ISSUED", "journal_v": 7, "robot_id": "robot-1", "plan_id": "p", "token_id": "t1", "step_id": "s1",
			"target_object_id": "crate-1", "zone_id": "z1", "site_model_hash_hex": siteHashA},
		{"kind": "TOKEN_ISSUED", "journal_v": 5, "robot_id": "robot-1", "plan_id": "p", "token_id": "t2", "step_id": "s2",
			"target_object_id": "crate-2", "site_model_hash_hex": siteHashA},
		{"kind": "TOKEN_ISSUED", "journal_v": 7, "robot_id": "robot-1", "plan_id": "p", "token_id": "t3", "step_id": "s3",
			"target_object_id": "", "zone_id": "", "site_model_hash_hex": siteHashA},
	} {
		b, _ := json.Marshal(rec)
		if err := w.Append(blackbox.RecordTokenIssued, uint64(tToken+int64(i)), b); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	return bbDir, telDir
}

func TestAL4_ZoneRecordedThenSnapshotThenUnresolved(t *testing.T) {
	bb, tel := fixtureZones(t)
	now := time.UnixMilli(tToken + 10_000)
	d, err := Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, _, err := d.Ingest(bb, tel, now); err != nil {
		t.Fatal(err)
	}
	// no resolver: the legacy row cannot be answered → unresolved, and the
	// summary says so; the recorded row keeps its zone
	res, err := d.Query(Filter{FromMs: 1}, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	byTok := map[string]OutRow{}
	for _, r := range res.Rows {
		byTok[r.TokenID] = r
	}
	if byTok["t1"].Zone != "z1" || byTok["t1"].ZoneResolution != "recorded" {
		t.Fatalf("recorded: %+v", byTok["t1"])
	}
	if byTok["t2"].ZoneResolution != "unresolved" || byTok["t3"].ZoneResolution != "none" || res.Resolution.Zone != "unresolved" {
		t.Fatalf("legacy without snapshot: t2=%+v t3=%+v summary=%s", byTok["t2"], byTok["t3"], res.Resolution.Zone)
	}
	// a snapshot of THAT model answers the legacy row; a snapshot of another
	// model does not (the hash is the key, not "the latest")
	d.ZoneResolver = func(hash, target string) (string, bool) {
		if hash == siteHashA && target == "crate-2" {
			return "z2", true
		}
		return "", false
	}
	res, err = d.Query(Filter{FromMs: 1}, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	byTok = map[string]OutRow{}
	for _, r := range res.Rows {
		byTok[r.TokenID] = r
	}
	if byTok["t2"].Zone != "z2" || byTok["t2"].ZoneResolution != "snapshot" || res.Resolution.Zone != "snapshot" {
		t.Fatalf("snapshot resolution: t2=%+v summary=%s", byTok["t2"], res.Resolution.Zone)
	}
	if byTok["t1"].SiteModelHash != siteHashA {
		t.Fatalf("site_model_hash must ride the row: %+v", byTok["t1"])
	}
	// a resolver that has the snapshot but not the object (or no snapshot at
	// all) must answer "unresolved" — never "snapshot"
	d.ZoneResolver = func(hash, target string) (string, bool) { return "", false }
	res, err = d.Query(Filter{FromMs: 1}, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Rows {
		if r.TokenID == "t2" && (r.ZoneResolution != "unresolved" || r.Zone != "") {
			t.Fatalf("resolver miss must be unresolved: %+v", r)
		}
	}
	if res.Resolution.Zone != "unresolved" {
		t.Fatalf("summary after a miss: %s", res.Resolution.Zone)
	}
	d.ZoneResolver = func(hash, target string) (string, bool) {
		if hash == siteHashA && target == "crate-2" {
			return "z2", true
		}
		return "", false
	}
	// zone filter matches the recorded zone only
	res, err = d.Query(Filter{FromMs: 1, Zone: "z1"}, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0].TokenID != "t1" {
		t.Fatalf("zone filter: %+v", res.Rows)
	}
}
