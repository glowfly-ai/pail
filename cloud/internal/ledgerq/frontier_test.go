// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/glowfly/pail/services/internal/blackbox"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMOBSFrontierCorruptionAndIdentity(t *testing.T) {
	for _, mode := range []string{"byte", "missing", "mixed", "regression", "torn", "empty"} {
		t.Run(mode, func(t *testing.T) {
			bb, tel := fixture(t)
			now := time.UnixMilli(tBurst + 10000)
			d := openIngested(t, bb, tel, now)
			seg := filepath.Join(bb, "pail_blackbox.00000001.seg")
			original, err := os.ReadFile(seg)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "byte":
				b := append([]byte{}, original...)
				b[len(b)-100] ^= 0xff
				if err = os.WriteFile(seg, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err = os.Rename(seg, seg+".missing"); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err = os.WriteFile(seg, []byte{}, 0600); err != nil {
					t.Fatal(err)
				}
			case "mixed":
				other, _ := fixture(t)
				b, e := os.ReadFile(filepath.Join(other, "pail_blackbox.00000001.seg"))
				if e != nil {
					t.Fatal(e)
				}
				if err = os.WriteFile(seg, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "regression":
				var off int64
				_, err = blackbox.WalkDir(bb, func(r blackbox.Record) error { off = r.Offset; return nil })
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(seg, original[:off], 0600); err != nil {
					t.Fatal(err)
				}
			case "torn":
				if err = os.WriteFile(seg, append(original, 1, 2, 3), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for pass := 0; pass < 2; pass++ {
				cs, e := d.IngestChain(bb, now)
				if e != nil {
					t.Fatal(e)
				}
				r, e := d.Query(Filter{}, time.Second, now)
				if e != nil {
					t.Fatal(e)
				}
				if mode == "torn" {
					// Review 15/21: a torn tail of the ACTIVE segment is the writer mid-record, not a fault — the
					// pass confirms through the last complete record and reports the pending bytes.
					if cs.State != "ok" || !cs.TornTail || cs.CheckedToSeq != 3 || r.Verify.State != "chain_ok" || r.Verify.Diagnostic.PendingTailBytes != 3 {
						t.Fatalf("torn pass %d must be pending, not refused: %+v %+v", pass, cs, r.Verify)
					}
					continue
				}
				if cs.State == "ok" || r.Verify.State == "chain_ok" {
					t.Fatalf("%s pass %d accepted: %+v", mode, pass, r.Verify)
				}
				raw, _ := json.Marshal(r)
				if strings.Contains(string(raw), bb) || strings.Contains(string(raw), d.path) {
					t.Fatal("host path leaked")
				}
				if mode == "byte" && r.Verify.Diagnostic.VerifiedThrough == nil {
					t.Fatal("valid prefix lost")
				}
				if mode == "mixed" && len(r.Rows) > 1 {
					t.Fatal("foreign journal exposed as verified prefix")
				}
			}
			// Diagnosis is read-only: only our explicit fault injection changed bytes.
			if mode != "missing" {
				after, _ := os.ReadFile(seg)
				if len(after) == 0 && mode != "empty" {
					t.Fatal("source removed")
				}
			}
		})
	}
}

func TestMOBSFrontierStale(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	for _, delta := range []time.Duration{StaleWalk + time.Millisecond, -time.Millisecond} {
		r, err := d.Query(Filter{}, time.Second, now.Add(delta))
		if err != nil {
			t.Fatal(err)
		}
		if r.Verify.State == "chain_ok" || r.Verify.Diagnostic.ChainState != "UNVERIFIED" {
			t.Fatalf("stale/future: %+v", r.Verify)
		}
	}
	r, err := d.Query(Filter{}, time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	f := r.Verify.Diagnostic.VerifiedThrough
	if r.Verify.State != "chain_ok" || f == nil || f.Sequence != 3 || len(f.Hash) != 64 || f.Offset == 0 || f.VerifiedAtMs != now.UnixMilli() {
		t.Fatalf("fresh frontier: %+v", r.Verify)
	}
}

func TestMOBSFrontierUnstable(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	seg := filepath.Join(bb, "pail_blackbox.00000001.seg")
	original, _ := os.ReadFile(seg)
	d.snapshotCopied = func() {
		b := append([]byte{}, original...)
		b[len(b)-100] ^= 1
		if err := os.WriteFile(seg, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cs, err := d.IngestChain(bb, now)
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != "unverified" || cs.Error != "SOURCE_UNSTABLE" {
		t.Fatalf("unstable source was published: %+v", cs)
	}
	r, err := d.Query(Filter{}, time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify.State == "chain_ok" || r.Verify.Diagnostic.VerifiedThrough != nil {
		t.Fatalf("unstable frontier: %+v", r.Verify)
	}
	d.snapshotCopied = nil
	if err = os.WriteFile(seg, original, 0600); err != nil {
		t.Fatal(err)
	}
	cs, err = d.IngestChain(bb, now)
	if err != nil || cs.State != "ok" || cs.Inserted != 0 {
		t.Fatalf("stable retry duplicated insert count: %+v %v", cs, err)
	}
}

func TestMOBSFrontier2000CheckpointsAndPlans(t *testing.T) {
	bb := t.TempDir()
	w, err := blackbox.OpenDir(bb, blackbox.Config{Signer: testSigner(t), IdleFlushAfter: -1})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"old-plan", "second-plan"} {
		b, _ := json.Marshal(map[string]any{"plan_id": p, "robot_id": "r1"})
		if err = w.Append(blackbox.RecordPlanAccepted, tPlan, b); err != nil {
			t.Fatal(err)
		}
		if err = w.Append(blackbox.RecordTokenIssued, tPlan+1, b); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2000; i++ {
		if err = w.Append(blackbox.RecordCheckpoint, tPlan+100+uint64(i), []byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Abandon(); err != nil {
		t.Fatal(err)
	}
	d, err := Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	now := time.UnixMilli(tPlan + 10000)
	if _, err = d.IngestChain(bb, now); err != nil {
		t.Fatal(err)
	}
	r, err := d.Query(Filter{Limit: 2000}, time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rows) != 2000 || r.NextCursor == "" || r.Rows[1999].Kind != "CHECKPOINT" {
		t.Fatalf("first page: %d %s", len(r.Rows), r.NextCursor)
	}
	r2, err := d.Query(Filter{Limit: 2000, Cursor: r.NextCursor}, time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Rows) != 4 || r2.NextCursor != "" || r2.Rows[0].PlanID == "" {
		t.Fatalf("second page: %+v", r2)
	}
	ps, err := d.QueryPlans(Filter{Limit: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps.Plans) != 1 || ps.NextCursor == "" || ps.Plans[0].Accepted != 1 || ps.Plans[0].Tokens != 1 || ps.Plans[0].LastKind != "TOKEN_ISSUED" {
		t.Fatalf("plan summary: %+v", ps)
	}
	ps2, err := d.QueryPlans(Filter{Limit: 1, Cursor: ps.NextCursor}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps2.Plans) != 1 || ps2.NextCursor != "" || ps2.Plans[0].PlanID == ps.Plans[0].PlanID {
		t.Fatalf("plan second page: %+v", ps2)
	}
	empty, err := d.QueryPlans(Filter{RobotHash: RobotHash16("another")}, now)
	if err != nil || len(empty.Plans) != 0 {
		t.Fatalf("robot isolation: %+v %v", empty, err)
	}
	if _, err = d.QueryPlans(Filter{Cursor: "bad!"}, now); err == nil {
		t.Fatal("invalid cursor accepted")
	}
	drill, err := d.Query(Filter{PlanID: ps.Plans[0].PlanID}, time.Second, now)
	if err != nil || len(drill.Rows) != 2 {
		t.Fatalf("drill: %+v %v", drill, err)
	}
	t.Logf("T12 measured: checkpoint page=%d next events=%d summary pages=1+1", len(r.Rows), len(r2.Rows))
}

func TestMOBSFrontierConcurrentSnapshot(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	entered := make(chan struct{})
	release := make(chan struct{})
	d.snapshotCopied = func() { close(entered); <-release }
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := d.IngestChain(bb, now); err != nil {
			t.Error(err)
		}
	}()
	<-entered
	r, err := d.Query(Filter{}, time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify.State == "chain_ok" || r.Index.ChainState != "verifying" {
		t.Fatalf("in-progress verdict: %+v", r.Verify)
	}
	close(release)
	wg.Wait()
	d.snapshotCopied = nil
	r, err = d.Query(Filter{}, time.Second, now)
	if err != nil || r.Verify.State != "chain_ok" || r.Verify.CheckedToSeq != 3 {
		t.Fatalf("published snapshot: %+v %v", r.Verify, err)
	}
}

func TestMOBSFrontierMissingMiddleAndForeignSegment(t *testing.T) {
	for _, mode := range []string{"middle", "tail", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			bb := t.TempDir()
			w, err := blackbox.OpenDir(bb, blackbox.Config{Signer: testSigner(t), IdleFlushAfter: -1, MaxSegmentBytes: 250})
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 12; i++ {
				if err = w.Append(blackbox.RecordPlanAccepted, tPlan+uint64(i), []byte(`{"plan_id":"p"}`)); err != nil {
					t.Fatal(err)
				}
			}
			if err = w.Abandon(); err != nil {
				t.Fatal(err)
			}
			files, err := filepath.Glob(filepath.Join(bb, "*.seg"))
			if err != nil || len(files) < 3 {
				t.Fatalf("rotating fixture: %v %v", files, err)
			}
			d, err := Open(filepath.Join(t.TempDir(), "index.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			now := time.UnixMilli(tPlan + 10000)
			if cs, e := d.IngestChain(bb, now); e != nil || cs.State != "ok" {
				t.Fatalf("baseline: %+v %v", cs, e)
			}
			path := files[1]
			if mode == "tail" {
				path = files[len(files)-1]
			}
			if mode == "foreign" {
				other, _ := fixture(t)
				b, e := os.ReadFile(filepath.Join(other, "pail_blackbox.00000001.seg"))
				if e != nil {
					t.Fatal(e)
				}
				if err = os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = os.Rename(path, path+".missing"); err != nil {
					t.Fatal(err)
				}
			}
			for pass := 0; pass < 2; pass++ {
				cs, e := d.IngestChain(bb, now)
				if e != nil {
					t.Fatal(e)
				}
				if cs.State == "ok" {
					t.Fatalf("missing/mixed %s accepted: %+v", mode, cs)
				}
				r, e := d.Query(Filter{}, time.Second, now)
				if e != nil || r.Verify.State == "chain_ok" {
					t.Fatalf("false success: %+v %v", r, e)
				}
			}
		})
	}
}

func TestMOBSFrontierRestartIdentityAndHash(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	r, err := d.Query(Filter{}, time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(filepath.Join(bb, "pail_blackbox.00000001.seg"))
	if r.Verify.Diagnostic.VerifiedThrough.Hash != fmt.Sprintf("%x", original[len(original)-32:]) {
		t.Fatal("frontier hash is not the verified record's wire hash")
	}
	// A separate reader cannot inherit a fresh verdict merely by reopening DB.
	reopened, err := Open(d.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	r, err = reopened.Query(Filter{}, time.Second, now)
	if err != nil || r.Verify.State == "chain_ok" {
		t.Fatalf("restart inherited verdict: %+v %v", r.Verify, err)
	}
	other, _ := fixture(t)
	cs, err := reopened.IngestChain(other, now)
	if err != nil || cs.State == "ok" {
		t.Fatalf("persisted identity lost: %+v %v", cs, err)
	}
}

func TestMOBSFrontierBudgetAndInputImmutability(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	before, err := copyChainSnapshot(context.Background(), bb, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.IngestChain(bb, now); err != nil {
		t.Fatal(err)
	}
	after, err := copyChainSnapshot(context.Background(), bb, "")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("verifier changed original bytes")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(d.path), ".ledger-verify-*"))
	if len(leftovers) != 0 {
		t.Fatalf("snapshot leak: %v", leftovers)
	}
	p := filepath.Join(bb, "pail_blackbox.00000002.seg")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(129 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	cs, err := d.IngestChain(bb, now)
	if err != nil {
		t.Fatal(err)
	}
	if cs.State == "ok" || cs.Error != "VERIFY_BUDGET_EXCEEDED" {
		t.Fatalf("budget: %+v", cs)
	}
	r, err := d.Query(Filter{}, time.Second, now)
	if err != nil || r.Verify.State == "chain_ok" {
		t.Fatalf("budget verdict: %+v %v", r.Verify, err)
	}
}

// The canonical reader treats empty segments as transparent. The observation
// inventory must still detect deletion of an already observed empty suffix.
func TestMOBSFrontierMissingEmptySegment(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	b, err := os.ReadFile(filepath.Join(bb, "pail_blackbox.00000001.seg"))
	if err != nil {
		t.Fatal(err)
	}
	header := append([]byte{}, b[:56]...)
	binary.LittleEndian.PutUint64(header[8:16], 2)
	copy(header[16:48], b[len(b)-32:])
	empty := filepath.Join(bb, "pail_blackbox.00000002.seg")
	if err = os.WriteFile(empty, header, 0600); err != nil {
		t.Fatal(err)
	}
	d := openIngested(t, bb, tel, now)
	if err = os.Rename(empty, empty+".missing"); err != nil {
		t.Fatal(err)
	}
	cs, err := d.IngestChain(bb, now)
	if err != nil || cs.State == "ok" {
		t.Fatalf("empty suffix deletion hidden: %+v %v", cs, err)
	}
	cs, err = d.IngestChain(bb, now)
	if err != nil || cs.State == "ok" {
		t.Fatalf("second pass lost inventory: %+v %v", cs, err)
	}
}

func TestMOBSFrontierPlanSummaryByteBound(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	tx, err := d.sql.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		r := Row{Src: "chain", Seg: "fixture", Off: int64(i), ChainSeq: int64(i + 1), Ms: tPlan, Kind: "PLAN_ACCEPTED", Outcome: "PLAN_ACCEPTED", PlanID: fmt.Sprintf("%03d-", i) + strings.Repeat("x", 60<<10)}
		if err = insertRow(tx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(tPlan + 10000)
	p, err := d.QueryPlans(Filter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(p)
	if len(encoded) > 1<<20 || p.NextCursor == "" || len(p.Plans) == 0 || len(p.Plans) >= 25 {
		t.Fatalf("byte bound: bytes=%d plans=%d cursor=%s", len(encoded), len(p.Plans), p.NextCursor)
	}
	p2, err := d.QueryPlans(Filter{Cursor: p.NextCursor}, now)
	if err != nil || len(p.Plans)+len(p2.Plans) != 25 {
		t.Fatalf("byte pagination omitted rows: %d+%d %v", len(p.Plans), len(p2.Plans), err)
	}
	t.Logf("summary actual bytes=%d pages=%d+%d", len(encoded), len(p.Plans), len(p2.Plans))
}

func TestMOBSFrontierEmptyHeaderReplacementAndAppend(t *testing.T) {
	for _, mode := range []string{"rewrite", "append"} {
		t.Run(mode, func(t *testing.T) {
			bb, tel := fixture(t)
			now := time.UnixMilli(tBurst + 10000)
			b, err := os.ReadFile(filepath.Join(bb, "pail_blackbox.00000001.seg"))
			if err != nil {
				t.Fatal(err)
			}
			header := append([]byte{}, b[:56]...)
			binary.LittleEndian.PutUint64(header[8:16], 2)
			copy(header[16:48], b[len(b)-32:])
			path := filepath.Join(bb, "pail_blackbox.00000002.seg")
			if err = os.WriteFile(path, header, 0600); err != nil {
				t.Fatal(err)
			}
			d := openIngested(t, bb, tel, now)
			if mode == "rewrite" {
				header[48] ^= 1
				if err = os.WriteFile(path, header, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				w, e := blackbox.OpenDir(bb, blackbox.Config{Signer: testSigner(t), IdleFlushAfter: -1})
				if e != nil {
					t.Fatal(e)
				}
				if e = w.Append(blackbox.RecordPlanAccepted, tBurst+1, []byte(`{"plan_id":"later"}`)); e != nil {
					t.Fatal(e)
				}
				if e = w.Abandon(); e != nil {
					t.Fatal(e)
				}
			}
			cs, err := d.IngestChain(bb, now)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "rewrite" && cs.State == "ok" {
				t.Fatal("empty header rewritten but chain_ok")
			}
			if mode == "append" && cs.State != "ok" {
				t.Fatalf("legitimate growth rejected: %+v", cs)
			}
		})
	}
}

func TestMOBSFrontierInvalidMetadata(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	if err := d.setMeta("chain_trusted_frontier", "broken JSON"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.IngestChain(bb, now); err == nil {
		t.Fatal("invalid persisted identity was ignored")
	}
	r, err := d.Query(Filter{}, time.Second, now)
	if err != nil || r.Verify.State == "chain_ok" {
		t.Fatalf("metadata failure promoted: %+v %v", r.Verify, err)
	}
}
