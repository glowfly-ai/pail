// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

// AL-1 (implementation contract D6) — the index is derived, reproducible, and honest about
// what it has not verified. Owners: G-LED-02 (TestAL1_RebuildReproducesSameRowSet,
// TestAL1_CheckOriginsCatchesTamperedRow), G-LED-03 (TestAL1_VerifyStateIsNotAGuess).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
	"github.com/glowfly/pail/services/internal/telemetry"
)

const (
	tPlan  = 1_700_000_000_000
	tToken = 1_700_000_001_000
	tBurst = 1_700_000_002_000
)

func testSigner(t *testing.T) signer.Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer.NewLocal(&devcrypto.Keypair{Public: pub, Private: priv, KeyID: "test-key-1"})
}

// fixture writes a two-record chain (PLAN_ACCEPTED, TOKEN_ISSUED for robot-1)
// through the production writer and a JSONL with two ticks and one burst.
func fixture(t *testing.T) (bbDir, telDir string) {
	t.Helper()
	bbDir = filepath.Join(t.TempDir(), "bb")
	telDir = filepath.Join(t.TempDir(), "tel")
	if err := os.MkdirAll(bbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(telDir, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := blackbox.OpenDir(bbDir, blackbox.Config{Signer: testSigner(t), IdleFlushAfter: -1})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := json.Marshal(map[string]any{"kind": "plan_accepted", "unix_ms": tPlan, "robot_id": "robot-1",
		"plan_id": "plan-A", "chain_id": "chain-1", "policy_hash_hex": "ab", "key_id": "dev-key-1"})
	if err := w.Append(blackbox.RecordPlanAccepted, tPlan, plan); err != nil {
		t.Fatal(err)
	}
	tok, _ := json.Marshal(map[string]any{"kind": "token_issued", "unix_ms": tToken, "robot_id": "robot-1",
		"plan_id": "plan-A", "chain_id": "chain-1", "token_id": "tok-1", "step_id": "s1", "sequence_index": 0,
		"target_object_id": "shelf-3", "token_hash_hex": "cd", "key_id": "dev-key-1"})
	if err := w.Append(blackbox.RecordTokenIssued, tToken, tok); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(999, tToken+1, []byte{0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	d := false
	lines := [][]byte{}
	for _, r := range []telemetry.Record{
		{V: 1, Kind: telemetry.KindTick, Ms: tPlan - 5000},
		{V: 1, Kind: telemetry.KindBurst, Ms: tBurst, Event: "BLOCK", ReasonValue: 0x13,
			Robot: RobotHash16("robot-1"), Token: TokenHash16("tok-1"), Sig: telemetry.SigOK, Dup: &d, Raw: "00"},
		{V: 1, Kind: telemetry.KindTick, Ms: tBurst + 5000},
	} {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, b)
	}
	if err := os.WriteFile(filepath.Join(telDir, "decisions-20260904.jsonl"),
		[]byte(string(lines[0])+"\n"+string(lines[1])+"\n"+string(lines[2])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return bbDir, telDir
}

func openIngested(t *testing.T, bbDir, telDir string, now time.Time) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	cs, ts, err := d.Ingest(bbDir, telDir, now)
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != "ok" || cs.Records != 3 || ts.Bursts != 1 || ts.Ticks != 2 {
		t.Fatalf("ingest: chain=%+v telemetry=%+v", cs, ts)
	}
	return d
}

func TestAL1_QueryByRobotTokenAndOrigin(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10_000)
	d := openIngested(t, bb, tel, now)
	res, err := d.Query(Filter{FromMs: tPlan - 1, RobotHash: RobotHash16("robot-1")}, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	// newest first: burst, token, plan — the unknown-type record has no robot
	if len(res.Rows) != 3 || res.Rows[0].Outcome != "BLOCK" || res.Rows[1].Outcome != "TOKEN_ISSUED" || res.Rows[2].Outcome != "PLAN_ACCEPTED" {
		t.Fatalf("rows=%+v", res.Rows)
	}
	if res.Rows[1].Origin == nil || res.Rows[1].Origin.Seg != "pail_blackbox.00000001.seg" || res.Rows[1].Origin.Off == 0 {
		t.Fatalf("token row origin=%+v", res.Rows[1].Origin)
	}
	if res.Rows[0].Origin == nil || res.Rows[0].Origin.Seg != "decisions-20260904.jsonl" || res.Rows[0].Origin.Off != 2 {
		t.Fatalf("burst row origin=%+v", res.Rows[0].Origin)
	}
	if res.Rows[1].RobotID != "robot-1" || !res.Rows[1].Resolved || res.Rows[0].RobotID != "" || res.Rows[0].Resolved {
		t.Fatalf("robot resolution: chain=%q/%v telemetry=%q/%v", res.Rows[1].RobotID, res.Rows[1].Resolved, res.Rows[0].RobotID, res.Rows[0].Resolved)
	}
	// coverage comes from the ticks table: the window [plan-1, now] has ticks
	// inside it and no span longer than max-gap without one
	if len(res.Coverage.Gaps) != 0 || res.Coverage.ListenedRatio != 1.0 {
		t.Fatalf("coverage from ticks: %+v", res.Coverage)
	}
	// one token_id follows the token across both sources
	res, err = d.Query(Filter{FromMs: 1, TokenID: "tok-1"}, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 || res.Rows[0].Src != "telemetry" || res.Rows[1].Src != "chain" {
		t.Fatalf("token follow: %+v", res.Rows)
	}
	// a window that starts long before the first tick reports that unheard
	// span as a gap — "no events" there is not "nothing happened"
	if len(res.Coverage.Gaps) == 0 || res.Coverage.Gaps[0].FromMs != 1 {
		t.Fatalf("unheard span must be a gap: %+v", res.Coverage)
	}
}

func TestAL1_UnknownRecordTypeIsVisible(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10_000)
	d := openIngested(t, bb, tel, now)
	res, err := d.Query(Filter{FromMs: 1, Outcome: "TYPE_999"}, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0].Src != "chain" {
		t.Fatalf("unknown type must arrive as TYPE_999: %+v", res.Rows)
	}
}

func TestAL1_CursorPagesWithoutOverlap(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10_000)
	d := openIngested(t, bb, tel, now)
	seen := map[int64]bool{}
	cursor := ""
	pages := 0
	for {
		res, err := d.Query(Filter{FromMs: 1, Limit: 2, Cursor: cursor}, 30*time.Second, now)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, r := range res.Rows {
			if seen[r.Seq] {
				t.Fatalf("row %d served twice", r.Seq)
			}
			seen[r.Seq] = true
		}
		if res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	if len(seen) != 4 || pages != 2 {
		t.Fatalf("seen=%d pages=%d", len(seen), pages)
	}
}

// G-LED-02: the index file is not the ledger. Delete it, rebuild, same rows.
func TestAL1_RebuildReproducesSameRowSet(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10_000)
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Ingest(bb, tel, now); err != nil {
		t.Fatal(err)
	}
	before, err := d.Query(Filter{FromMs: 1}, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2, cs, ts, err := Rebuild(path, bb, tel, now)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if cs.Inserted != 3 || ts.Bursts != 1 {
		t.Fatalf("rebuild inserted chain=%d bursts=%d", cs.Inserted, ts.Bursts)
	}
	after, err := d2.Query(Filter{FromMs: 1}, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(before.Rows)
	a, _ := json.Marshal(after.Rows)
	if string(a) != string(b) {
		t.Fatalf("row set changed across rebuild:\n before=%s\n after=%s", b, a)
	}
	if len(after.Rows) != 4 {
		t.Fatalf("rows=%d", len(after.Rows))
	}
}

// G-LED-02: a row the origin does not reproduce is named, by field.
func TestAL1_CheckOriginsCatchesTamperedRow(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10_000)
	d := openIngested(t, bb, tel, now)
	rep, err := d.CheckOrigins(bb)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() || rep.Checked != 3 || rep.Extra != 0 {
		t.Fatalf("clean index must check clean: %+v", rep)
	}
	if _, err := d.sql.Exec(`UPDATE events SET plan_id = 'plan-FORGED' WHERE token_id = 'tok-1'`); err != nil {
		t.Fatal(err)
	}
	rep, err = d.CheckOrigins(bb)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() || len(rep.Mismatches) != 1 || !strings.Contains(rep.Mismatches[0], "plan_id index=plan-FORGED origin=plan-A") {
		t.Fatalf("tampered row must be named with its field: %+v", rep)
	}
}

// G-LED-03: verify.state says what was done — chain_ok only behind a fresh,
// clean walk; chain_error keeps the reader's error; stale or absent is unverified.
func TestAL1_VerifyStateIsNotAGuess(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10_000)
	d := openIngested(t, bb, tel, now)
	res, err := d.Query(Filter{FromMs: 1}, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.State != "chain_ok" || res.Verify.CheckedToSeq != 3 {
		t.Fatalf("fresh clean walk: %+v", res.Verify)
	}
	// stale walk: the same index asked two minutes later without a new walk
	res, err = d.Query(Filter{FromMs: 1}, 30*time.Second, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.State != "unverified" {
		t.Fatalf("stale walk must not claim chain_ok: %+v", res.Verify)
	}
	// broken chain: flip one payload byte in the segment, walk again
	seg := filepath.Join(bb, "pail_blackbox.00000001.seg")
	data, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-100] ^= 0xff
	if err := os.WriteFile(seg, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cs, err := d.IngestChain(bb, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != "chain_error" || cs.Error == "" {
		t.Fatalf("broken chain must be reported: %+v", cs)
	}
	res, err = d.Query(Filter{FromMs: 1}, 30*time.Second, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.State != "chain_error" || res.Verify.Error == "" {
		t.Fatalf("chain_error must reach the response with its text: %+v", res.Verify)
	}
	// absent directory: unverified, and the index says why
	cs, err = d.IngestChain(filepath.Join(t.TempDir(), "nope"), now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != "absent" {
		t.Fatalf("absent dir: %+v", cs)
	}
	res, err = d.Query(Filter{FromMs: 1}, 30*time.Second, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if res.Verify.State != "unverified" || res.Index.ChainState != "absent" {
		t.Fatalf("absent: verify=%+v index=%+v", res.Verify, res.Index)
	}
}

func TestAL1_IncrementalIngestIsIdempotent(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10_000)
	d := openIngested(t, bb, tel, now)
	cs, ts, err := d.Ingest(bb, tel, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cs.Inserted != 0 || ts.Bursts != 0 || ts.Ticks != 0 {
		t.Fatalf("second pass must add nothing: chain=%+v tel=%+v", cs, ts)
	}
	st, _ := d.Stats()
	if st.ChainRows != 3 || st.TelemetryRows != 1 || st.Ticks != 2 {
		t.Fatalf("stats=%+v", st)
	}
}

// The package must never write into the blackbox directory. The only file
// removal targets are its own index and explicitly pinned private verification
// copies. Writes into journal input are forbidden — a structural pin, because a test that
// merely observes "the segment did not change" would pass on a package that
// writes on a path the test did not exercise.
func TestAL1_PackageNeverWritesOutsideIndex(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := regexp.MustCompile(`os\.(Create|OpenFile|WriteFile|Rename|Link|Truncate|MkdirAll|Mkdir)\(`)
	remove := regexp.MustCompile(`os\.Remove(All)?\(`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if f == "frontier.go" {
			if strings.Count(string(src), "os.OpenFile(") != 1 || !strings.Contains(string(src), "os.OpenFile(filepath.Join(dst, name)") || strings.Count(string(src), "os.RemoveAll(snap)") != 1 || !strings.Contains(string(src), `os.MkdirTemp(filepath.Dir(d.path), ".ledger-verify-")`) {
				t.Fatal("snapshot writes must stay in the owned index-side temporary directory")
			}
		}
		if m := forbidden.Find(src); m != nil && f != "index_publish.go" && f != "frontier.go" {
			t.Fatalf("%s: write primitive %s is forbidden in ledgerq", f, m)
		}
		if n := len(remove.FindAll(src, -1)); n > 0 && f != "ledgerq.go" && f != "frontier.go" {
			t.Fatalf("%s: os.Remove outside removeIndexFiles", f)
		}
	}
}
