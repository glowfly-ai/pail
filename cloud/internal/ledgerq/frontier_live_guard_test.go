// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

// Review items 15/21, negative side (PAIL-P43-LEDGER-LIVE-TEST-LLD-001 §2): the live-append change must keep
// refusing everything that is not a pure append. R1 (closed segment changed), R5 (checkpoint signature), R6
// (segment set incomplete) and R8 (budget) are already pinned by TestMOBSFrontierCorruptionAndIdentity,
// TestMOBSFrontierMissingMiddleAndForeignSegment, TestMOBSFrontierBudgetAndInputImmutability and
// TestMOBSFrontierEachGuardAlone; this file adds R2, R3, R4 and the two shapes of R7.

import (
	"os"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

func appendPlans(t *testing.T, bb string, n int64) {
	t.Helper()
	w, err := blackbox.OpenDir(bb, liveConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= n; i++ {
		if err := w.Append(blackbox.RecordPlanAccepted, uint64(tPlan+5000+i), planPayload(100+i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func notPublished(t *testing.T, d *DB, now time.Time, what string) {
	t.Helper()
	r, err := d.Query(Filter{}, time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify.State == "chain_ok" { // a verified prefix may remain visible after a failure; the verdict may not be chain_ok
		t.Fatalf("%s must not read as chain_ok: %+v", what, r.Verify)
	}
}

// R2 — the observed prefix of the active segment changed while the segment also grew.
func TestLedgerLiveGuardPrefixChanged(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	seg := bb + "/" + segmentName(1)
	info, _ := os.Stat(seg)
	verified := info.Size() // the bytes pass 1 verified
	appendPlans(t, bb, 3)   // it grows (the writer opens a healthy ledger) …
	b, _ := os.ReadFile(seg)
	b[verified-40] ^= 1 // … and a byte inside the already-verified prefix changes
	if err := os.WriteFile(seg, b, 0600); err != nil {
		t.Fatal(err)
	}
	cs, err := d.IngestChain(bb, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != "chain_error" {
		t.Fatalf("R2: a changed prefix that also grew must be an error, got %+v", cs)
	}
	notPublished(t, d, now.Add(time.Second), "R2 prefix change")
}

// R3 — the active segment shrank (a record boundary cut).
func TestLedgerLiveGuardShrunk(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	appendPlans(t, bb, 5)
	if cs, err := d.IngestChain(bb, now.Add(time.Second)); err != nil || cs.State != "ok" || cs.CheckedToSeq != 8 {
		t.Fatalf("pass with the 5 plans: %+v %v", cs, err) // the trusted frontier now includes the 5 plans
	}
	path, off := lastRecordOffset(t, bb)
	if err := os.Truncate(path, off); err != nil { // drop the last complete record entirely
		t.Fatal(err)
	}
	cs, err := d.IngestChain(bb, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != "chain_error" || (cs.Error != "JOURNAL_REGRESSION" && cs.Error != "JOURNAL_PREFIX_CHANGED") {
		t.Fatalf("R3: a shorter ledger is a regression: %+v", cs)
	}
	notPublished(t, d, now.Add(time.Second), "R3 shrink")
}

// R4 — same size, different bytes inside the last record (replacement).
func TestLedgerLiveGuardReplacedSameSize(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	appendPlans(t, bb, 5)
	if cs, err := d.IngestChain(bb, now.Add(time.Second)); err != nil || cs.State != "ok" || cs.CheckedToSeq != 8 {
		t.Fatalf("pass with the 5 plans: %+v %v", cs, err)
	}
	path, off := lastRecordOffset(t, bb)
	b, _ := os.ReadFile(path)
	b[off+30] ^= 1 // inside the payload of the last record
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	cs, err := d.IngestChain(bb, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != "chain_error" {
		t.Fatalf("R4: replaced bytes at the same size must be an error: %+v", cs)
	}
	notPublished(t, d, now.Add(time.Second), "R4 replacement")
}

// R7-a — the ledger is TAMPERED (not appended) while the pass runs: already-copied bytes change, size kept.
func TestLedgerLiveGuardTamperDuringPass(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	seg := bb + "/" + segmentName(1)
	original, _ := os.ReadFile(seg)
	d.snapshotCopied = func() {
		b := append([]byte{}, original...)
		b[len(b)-100] ^= 1
		if err := os.WriteFile(seg, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { d.snapshotCopied = nil }()
	cs, err := d.IngestChain(bb, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cs.State == "ok" {
		t.Fatalf("R7-a: a ledger whose read bytes changed during the pass was published: %+v", cs)
	}
	notPublished(t, d, now.Add(time.Second), "R7-a tamper during pass")
}

// R7-b — the ledger GROWS and its copied prefix changes during the pass: growth must not hide the change.
func TestLedgerLiveGuardGrowThenTamperDuringPass(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	seg := bb + "/" + segmentName(1)
	d.snapshotCopied = func() {
		appendPlans(t, bb, 2)
		b, _ := os.ReadFile(seg)
		b[100] ^= 1 // inside the copied prefix (the fixture records)
		if err := os.WriteFile(seg, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { d.snapshotCopied = nil }()
	cs, err := d.IngestChain(bb, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cs.State == "ok" {
		t.Fatalf("R7-b: growth plus a changed prefix was published as a stable append: %+v", cs)
	}
	notPublished(t, d, now.Add(time.Second), "R7-b grow then tamper")
}
