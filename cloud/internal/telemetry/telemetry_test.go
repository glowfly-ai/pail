// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/burst"
)

// --- DB-0 RED ① / G-DB-1 결측≠부재 --------------------------------------

// PAIL-OWNS: G-DB-1
// A query over a span the collector did not listen to must not answer with
// the same bytes as "0 events happened". The answer carries its own absence:
// gaps + listened_ratio (implementation contract D2, H-B2).
func TestDB0_QueryCarriesItsOwnAbsence(t *testing.T) {
	var recs []Record
	for ms := uint64(0); ms <= 60_000; ms += 10_000 {
		recs = append(recs, Record{V: 1, Kind: KindTick, Ms: ms})
	}
	// collector dead 60s..180s: no ticks, no bursts
	for ms := uint64(180_000); ms <= 240_000; ms += 10_000 {
		recs = append(recs, Record{V: 1, Kind: KindTick, Ms: ms})
	}
	res := Query(recs, Filter{FromMs: 0, ToMs: 240_000}, 30*time.Second)
	if len(res.Rows) != 0 {
		t.Fatalf("expected 0 burst rows, got %d", len(res.Rows))
	}
	if len(res.Coverage.Gaps) == 0 {
		t.Fatalf("dead span 60s..180s answered as fully covered: 0 rows + 0 gaps reads as \"nothing happened\" (H-B2)")
	}
	covered := false
	for _, g := range res.Coverage.Gaps {
		if g.FromMs <= 60_000 && g.ToMs >= 180_000 {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("gaps %+v do not cover the dead span [60000,180000]", res.Coverage.Gaps)
	}
	if res.Coverage.ListenedRatio >= 1.0 {
		t.Fatalf("listened_ratio %v claims full coverage over a window that was half dead", res.Coverage.ListenedRatio)
	}
	if res.Coverage.ListenedRatio <= 0.0 {
		t.Fatalf("listened_ratio %v claims zero coverage although 2 minutes of ticks exist (mirror bound)", res.Coverage.ListenedRatio)
	}
}

// Mirror of the gap case: a window fully walked by ticks must report no gaps
// and ratio 1.0 — a coverage that always cries absence would pass the test
// above and be just as blind (거울상 짝).
func TestDB0_FullyTickedWindowIsCovered(t *testing.T) {
	var recs []Record
	for ms := uint64(0); ms <= 120_000; ms += 10_000 {
		recs = append(recs, Record{V: 1, Kind: KindTick, Ms: ms})
	}
	res := Query(recs, Filter{FromMs: 0, ToMs: 120_000}, 30*time.Second)
	if len(res.Coverage.Gaps) != 0 {
		t.Fatalf("fully ticked window reported gaps %+v", res.Coverage.Gaps)
	}
	if res.Coverage.ListenedRatio != 1.0 {
		t.Fatalf("fully ticked window listened_ratio = %v, want 1.0", res.Coverage.ListenedRatio)
	}
}

// --- DB-0 RED ② / G-DB-3 중복 관측 ---------------------------------------

// PAIL-OWNS: G-DB-3
// A replayed (sig-class, robot, seq) inside the window is recorded and marked
// dup:true — not dropped (dropping erases the fact that a replay happened)
// and not counted as a second independent event (implementation contract D1).
func TestDB0_ReplayIsMarkedNotRecounted(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	in := NewIngester([]ed25519.PublicKey{pub})
	pkt := burst.BuildPacketV2(priv, burst.EventBlock, 0x10, 1_000, "robot-1", burst.TokenHash16("tok-1"), 7)
	now := time.UnixMilli(1_000_000)

	r1, err := in.Observe(pkt, now)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Dup == nil || *r1.Dup {
		t.Fatalf("first arrival marked dup=%v, want explicit false", r1.Dup)
	}
	r2, err := in.Observe(pkt, now.Add(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if r2.Dup == nil || !*r2.Dup {
		t.Fatalf("re-arrival of the same (sig,robot,seq) recorded with dup=%v — two rows now count as two events", r2.Dup)
	}
}

// Mirror: a different seq from the same robot inside the window is NOT a dup —
// a marker that fires on everything would pass the test above.
func TestDB0_DistinctSeqIsNotDup(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	in := NewIngester([]ed25519.PublicKey{pub})
	now := time.UnixMilli(1_000_000)
	p1 := burst.BuildPacketV2(priv, burst.EventBlock, 0x10, 1_000, "robot-1", burst.TokenHash16("tok-1"), 7)
	p2 := burst.BuildPacketV2(priv, burst.EventBlock, 0x10, 1_200, "robot-1", burst.TokenHash16("tok-1"), 8)
	if _, err := in.Observe(p1, now); err != nil {
		t.Fatal(err)
	}
	r2, err := in.Observe(p2, now.Add(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if r2.Dup == nil || *r2.Dup {
		t.Fatalf("distinct seq marked dup=%v", r2.Dup)
	}
}

// --- DB-0 RED ③ / G-DB-2 sig 3값 ------------------------------------------

// PAIL-OWNS: G-DB-2
// With no trust anchors loaded the verdict is "unverifiable", never "ok":
// vacuous truth over an empty key set is exactly the H-B2 shape — "could not
// check" wearing "checked and fine" (implementation contract D1).
func TestDB0_NoKeyIsUnverifiableNotOK(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkt := burst.BuildPacketV2(priv, burst.EventBlock, 0x10, 1_000, "robot-1", burst.TokenHash16("tok-1"), 7)
	in := NewIngester(nil)
	rec, err := in.Observe(pkt, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Sig != SigUnverifiable {
		t.Fatalf("no-key verdict = %q, want %q", rec.Sig, SigUnverifiable)
	}
}

// Mirror: with keys present the verdict must still split ok/bad — a constant
// "unverifiable" would pass the test above (거울상 짝).
func TestDB0_SigSplitsOKBadWithKeysPresent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	strangerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkt := burst.BuildPacketV2(priv, burst.EventBlock, 0x10, 1_000, "robot-1", burst.TokenHash16("tok-1"), 7)

	rec, err := NewIngester([]ed25519.PublicKey{pub}).Observe(pkt, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Sig != SigOK {
		t.Fatalf("issuer-signed packet verdict = %q, want %q", rec.Sig, SigOK)
	}
	rec2, err := NewIngester([]ed25519.PublicKey{strangerPub}).Observe(pkt, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if rec2.Sig != SigBad {
		t.Fatalf("packet signed by an untrusted key verdict = %q, want %q", rec2.Sig, SigBad)
	}
}

// --- store / parser (owned correctness, not milestone RED targets) ---------

func TestDB0_StoreRollsOnUTCDay(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	d1 := time.Date(2026, 9, 2, 23, 59, 0, 0, time.UTC)
	d2 := d1.Add(2 * time.Minute) // crosses the UTC day boundary
	for _, at := range []time.Time{d1, d2} {
		line, err := MarshalTick(uint64(at.UnixMilli()))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AppendLine(line, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{d1, d2} {
		names, err := filepath.Glob(filepath.Join(dir, "decisions-"+dayOf(at)+"-*.jsonl"))
		if err != nil || len(names) != 1 {
			t.Fatalf("day %v files=%v err=%v", at, names, err)
		}
		f, err := os.Open(names[0])
		if err != nil {
			t.Fatalf("roll file for %v missing: %v", at, err)
		}
		recs, bad, err := ReadAll(f)
		f.Close()
		if err != nil || len(bad) != 0 || len(recs) != 1 {
			t.Fatalf("roll file for %v: recs=%d bad=%v err=%v, want exactly 1 clean record", at, len(recs), bad, err)
		}
	}
}

func TestDB0_ParserVersionCheckPrecedesFieldStrictness(t *testing.T) {
	// unknown field on a v1 line: strict reject
	if _, err := ParseLine([]byte(`{"v":1,"kind":"tick","ms":5,"surprise":true}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	// future version with an unknown field: must fail as a VERSION error, or
	// the migration hint is never printed (OB2 convention)
	_, err := ParseLine([]byte(`{"v":9,"kind":"tick","ms":5,"new_field":1}`))
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("future-version line failed as %v, want a version error", err)
	}
	// missing v is not v==0 semantics
	if _, err := ParseLine([]byte(`{"kind":"tick","ms":5}`)); err == nil {
		t.Fatal("line without v accepted")
	}
}

// ReadAll lists bad lines by number and keeps going — a dropped line is
// indistinguishable from a line that never existed.
func TestDB0_ReadAllReportsBadLines(t *testing.T) {
	in := strings.NewReader(`{"v":1,"kind":"tick","ms":1}
not json at all
{"v":1,"kind":"tick","ms":3}`)
	recs, bad, err := ReadAll(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || len(bad) != 1 || bad[0] != 2 {
		t.Fatalf("recs=%d bad=%v, want 2 records and bad line [2]", len(recs), bad)
	}
}

// --- G-DSH-07 행 상한은 최신을 남기고 잘림을 말한다 ----------------------
//
// 2026-09-04 observed regression: 현황판 「6시간」이 최근 것을 안 보여 줬다. 창의 실제
// 행 525건 중 limit=200 이 **오래된 쪽** 200건(전부 CHECKPOINT)을 돌려주고
// 14:33 이후의 BLOCK 165건을 조용히 버렸다 — 타일은 그 창을 「평온」으로 그렸다.

func dshBursts(n int) []Record {
	recs := make([]Record, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, Record{V: 1, Kind: KindBurst, Ms: uint64(1000 * (i + 1)), Seq: uint32(i + 1),
			Event: "BLOCK", Robot: "r1", Sig: SigOK})
	}
	return recs
}

// PAIL-OWNS: G-DSH-07
// A page bound keeps the NEWEST rows. The status board asks "what is happening
// now"; the oldest-N answer is exactly the one that hides the present.
func TestDSH07_LimitKeepsNewest(t *testing.T) {
	res := Query(dshBursts(5), Filter{FromMs: 0, ToMs: 10_000, Limit: 2}, 30*time.Second)
	if len(res.Rows) != 2 {
		t.Fatalf("rows=%d, want 2", len(res.Rows))
	}
	if res.Rows[0].Seq != 4 || res.Rows[1].Seq != 5 {
		t.Fatalf("limit kept seq %d,%d — want the newest (4,5) in reception order", res.Rows[0].Seq, res.Rows[1].Seq)
	}
}

// PAIL-OWNS: G-DSH-07
// A cut page says so: truncated=true and matched=<rows before the cut>. Mirror:
// a page that was not cut says truncated=false and matched==len(rows) — an
// answer that always cried "cut" would pass the case above and be as blind.
func TestDSH07_LimitTruncationIsDeclared(t *testing.T) {
	cut := Query(dshBursts(5), Filter{FromMs: 0, ToMs: 10_000, Limit: 2}, 30*time.Second)
	if !cut.Truncated || cut.Matched != 5 {
		t.Fatalf("cut page: truncated=%v matched=%d, want true/5 — a silent cut reads as the whole window (H-B2)", cut.Truncated, cut.Matched)
	}
	whole := Query(dshBursts(5), Filter{FromMs: 0, ToMs: 10_000, Limit: 0}, 30*time.Second)
	if whole.Truncated || whole.Matched != 5 || len(whole.Rows) != 5 {
		t.Fatalf("uncut page: truncated=%v matched=%d rows=%d, want false/5/5", whole.Truncated, whole.Matched, len(whole.Rows))
	}
	exact := Query(dshBursts(5), Filter{FromMs: 0, ToMs: 10_000, Limit: 5}, 30*time.Second)
	if exact.Truncated || len(exact.Rows) != 5 {
		t.Fatalf("limit == matched is not a cut: truncated=%v rows=%d", exact.Truncated, len(exact.Rows))
	}
}
