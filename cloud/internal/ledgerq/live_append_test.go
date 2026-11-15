// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

// Review items 15/21 (PAIL-P43-LEDGER-LIVE-TEST-LLD-001 §1): a ledger that is being appended to while the
// collector verifies it is normal operation, not instability. These tests drive a real blackbox writer in a
// goroutine and call IngestChain repeatedly; the verified position must keep advancing without the writer
// ever stopping. Fail-first on the preview.42 tree: every pass ends SOURCE_UNSTABLE and no decision is
// published (the evaluator's 0/38 measurement).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

// liveWriter appends plan_accepted records at a steady pace until stopped.
type liveWriter struct {
	w         *blackbox.Writer
	appended  chan int64
	stop      chan struct{}
	done      chan struct{}
	burst     chan int // appendSync: the goroutine appends n records, then acknowledges on burstDone
	burstDone chan struct{}
	count     atomic.Int64
	failed    atomic.Value // error
}

func liveConfig(t *testing.T) blackbox.Config {
	return blackbox.Config{Signer: testSigner(t), IdleFlushAfter: -1, CheckpointEveryRecords: 50}
}

func planPayload(i int64) []byte {
	b, _ := json.Marshal(map[string]any{"kind": "plan_accepted", "unix_ms": tPlan + 1000 + i, "robot_id": "robot-1",
		"plan_id": fmt.Sprintf("plan-live-%06d", i), "chain_id": "chain-live", "policy_hash_hex": "ab", "key_id": "dev-key-1"})
	return b
}

func startLiveWriter(t *testing.T, dir string, cfg blackbox.Config, every time.Duration) *liveWriter {
	t.Helper()
	w, err := blackbox.OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	lw := &liveWriter{w: w, appended: make(chan int64, 1024), stop: make(chan struct{}), done: make(chan struct{}),
		burst: make(chan int), burstDone: make(chan struct{})}
	appendOne := func() bool {
		n := lw.count.Load() + 1
		if err := w.Append(blackbox.RecordPlanAccepted, uint64(tPlan+1000+n), planPayload(n)); err != nil {
			lw.failed.Store(err)
			return false
		}
		lw.count.Store(n)
		select {
		case lw.appended <- n:
		default:
		}
		return true
	}
	go func() {
		defer close(lw.done)
		for {
			select {
			case <-lw.stop:
				return
			case n := <-lw.burst:
				for i := 0; i < n; i++ {
					if !appendOne() {
						break
					}
				}
				lw.burstDone <- struct{}{}
				continue
			default:
			}
			if every > 0 {
				if !appendOne() {
					return
				}
				time.Sleep(every)
			} else {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	return lw
}

// appendSync makes the writer goroutine append n records now and returns when they are on disk — used from the
// snapshotCopied hook so that growth DURING a verification pass is guaranteed, not left to timing (LLD §6 risk 1).
func (lw *liveWriter) appendSync(n int) {
	lw.burst <- n
	<-lw.burstDone
}

// waitForMore blocks until the writer has appended past `than` (the pass that follows is guaranteed to see
// growth), failing the test instead of waiting forever.
func (lw *liveWriter) waitForMore(t *testing.T, than int64, within time.Duration) int64 {
	t.Helper()
	deadline := time.After(within)
	for {
		if n := lw.count.Load(); n > than {
			return n
		}
		select {
		case <-lw.appended:
		case <-deadline:
			if e := lw.failed.Load(); e != nil {
				t.Fatalf("writer failed: %v", e)
			}
			t.Fatalf("writer did not append past %d within %v", than, within)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (lw *liveWriter) stopAndClose(t *testing.T) {
	t.Helper()
	close(lw.stop)
	<-lw.done
	if e := lw.failed.Load(); e != nil {
		t.Fatalf("writer failed: %v", e)
	}
	if err := lw.w.Abandon(); err != nil {
		t.Fatal(err)
	}
}

// recordsOnDisk counts every chain record (plans, checkpoints, fixture records) the live directory holds now; a
// torn tail of the segment being written is tolerated by the reader and not counted.
func recordsOnDisk(t *testing.T, dir string) int64 {
	t.Helper()
	var n int64
	if _, err := blackbox.WalkDir(dir, func(blackbox.Record) error { n++; return nil }); err != nil {
		t.Fatalf("walking the live ledger: %v", err)
	}
	return n
}

func planRows(r Result) int {
	n := 0
	for _, row := range r.Rows {
		if row.Outcome == "PLAN_ACCEPTED" {
			n++
		}
	}
	return n
}

// L1 · L2 · L3 — appends never stop; the verified position advances monotonically and decisions are published.
func TestLedgerLiveAppendKeepsVerifying(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	lw := startLiveWriter(t, bb, liveConfig(t), 5*time.Millisecond)
	var atSnapshot atomic.Int64
	// the snapshot has been copied: record how many records the ledger holds right now (an upper bound of what the
	// snapshot can hold — counted by walking the live directory, because the writer also appends checkpoint records
	// the plan counter does not see), then make the ledger grow before the verifier compares the directory again —
	// exactly the situation of a robot writing while the collector reads
	d.snapshotCopied = func() { atSnapshot.Store(recordsOnDisk(t, bb)); lw.appendSync(7) }
	defer func() { d.snapshotCopied = nil }()
	prev, unstable, grew := int64(3), 0, 0
	for pass := 0; pass < 12; pass++ {
		lw.waitForMore(t, lw.count.Load(), 2*time.Second)
		cs, err := d.IngestChain(bb, now.Add(time.Duration(pass+1)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if cs.State == "unverified" && cs.Error == "SOURCE_UNSTABLE" {
			unstable++
			continue
		}
		if cs.State != "ok" {
			t.Fatalf("pass %d: a growing ledger is not an error: %+v", pass, cs)
		}
		if cs.CheckedToSeq < prev {
			t.Fatalf("pass %d: verified position went back %d -> %d", pass, prev, cs.CheckedToSeq)
		}
		// L2: never confirm records the snapshot could not have held (every record on disk when the copy ended)
		if limit := atSnapshot.Load(); cs.CheckedToSeq > limit {
			t.Fatalf("pass %d: confirmed %d records but only %d existed at the snapshot", pass, cs.CheckedToSeq, limit)
		}
		if cs.CheckedToSeq > prev {
			grew++
		}
		prev = cs.CheckedToSeq
		r, err := d.Query(Filter{}, time.Second, now.Add(time.Duration(pass+1)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if r.Verify.State != "chain_ok" || r.Verify.Diagnostic.VerifiedThrough == nil || planRows(r) < 1 {
			t.Fatalf("pass %d: nothing published while appending: verify=%+v plan rows=%d", pass, r.Verify, planRows(r))
		}
	}
	lw.stopAndClose(t)
	if unstable != 0 {
		t.Fatalf("L1: %d of 12 passes ended SOURCE_UNSTABLE while the ledger was only being appended to (review 15/21)", unstable)
	}
	if grew < 3 {
		t.Fatalf("L1: the verified position advanced in only %d passes while thousands of records were appended", grew)
	}
}

// L5 — the same, across segment rotation (small MaxSegmentBytes).
func TestLedgerLiveAppendAcrossRotation(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	cfg := liveConfig(t)
	cfg.MaxSegmentBytes = 16 << 10
	lw := startLiveWriter(t, bb, cfg, 2*time.Millisecond)
	prev := int64(3)
	bad := map[string]int{}
	for pass := 0; pass < 20; pass++ {
		lw.waitForMore(t, lw.count.Load()+20, 2*time.Second)
		cs, err := d.IngestChain(bb, now.Add(time.Duration(pass+1)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if cs.State != "ok" {
			bad[cs.Error]++
			continue
		}
		if cs.CheckedToSeq < prev {
			t.Fatalf("pass %d: verified position went back %d -> %d", pass, prev, cs.CheckedToSeq)
		}
		prev = cs.CheckedToSeq
	}
	lw.stopAndClose(t)
	segs, _ := filepath.Glob(filepath.Join(bb, "pail_blackbox.*.seg"))
	if len(segs) < 3 {
		t.Fatalf("the writer did not rotate: %d segments", len(segs))
	}
	if len(bad) != 0 {
		t.Fatalf("L5: passes that did not confirm while appending across rotation: %v", bad)
	}
}

// lastRecordOffset returns the start offset of the last complete record of the newest segment and that segment's path.
func lastRecordOffset(t *testing.T, dir string) (string, int64) {
	t.Helper()
	var seg uint64
	var off int64
	if _, err := blackbox.WalkDir(dir, func(rec blackbox.Record) error {
		seg, off = rec.SegmentSeq, rec.Offset
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, segmentName(seg)), off
}

// L4 (positive) — a snapshot taken in the middle of the newest record confirms through the last complete record.
func TestLedgerTornTailOfActiveSegmentIsPending(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	w, err := blackbox.OpenDir(bb, liveConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 10; i++ {
		if err := w.Append(blackbox.RecordPlanAccepted, uint64(tPlan+1000+i), planPayload(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	path, off := lastRecordOffset(t, bb)
	if err := os.Truncate(path, off+10); err != nil { // inside the last record's header: a torn tail, not corruption (DUR-L2)
		t.Fatal(err)
	}
	cs, err := d.IngestChain(bb, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != "ok" || !cs.TornTail || cs.CheckedToSeq != 3+9 {
		t.Fatalf("L4: a torn tail of the newest segment is pending, not a refusal: %+v (want ok, torn, checked_to_seq=12)", cs)
	}
	r, err := d.Query(Filter{}, time.Second, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify.State != "chain_ok" || r.Verify.Diagnostic.VerifiedThrough == nil || r.Verify.Diagnostic.VerifiedThrough.Sequence != 12 {
		t.Fatalf("L4: published frontier must be the last complete record: %+v", r.Verify)
	}
}

// L4 (negative) — a truncation inside a CLOSED segment is history-mid corruption and stays an error.
func TestLedgerTornTailInClosedSegmentIsAnError(t *testing.T) {
	bb, tel := fixture(t)
	now := time.UnixMilli(tBurst + 10000)
	d := openIngested(t, bb, tel, now)
	cfg := liveConfig(t)
	cfg.MaxSegmentBytes = 4 << 10
	w, err := blackbox.OpenDir(bb, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 200; i++ { // enough to rotate at least once
		if err := w.Append(blackbox.RecordPlanAccepted, uint64(tPlan+1000+i), planPayload(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	segs, _ := filepath.Glob(filepath.Join(bb, "pail_blackbox.*.seg"))
	if len(segs) < 2 {
		t.Fatalf("no rotation: %d segments", len(segs))
	}
	first := filepath.Join(bb, segmentName(1))
	info, err := os.Stat(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(first, info.Size()-7); err != nil {
		t.Fatal(err)
	}
	cs, err := d.IngestChain(bb, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cs.State != "chain_error" {
		t.Fatalf("a truncated closed segment is corruption: %+v", cs)
	}
	r, err := d.Query(Filter{}, time.Second, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify.State == "chain_ok" { // a verified PREFIX may stay visible after a failure (frontier.go), the verdict may not be chain_ok
		t.Fatalf("a corrupted ledger must not read as chain_ok: %+v", r.Verify)
	}
}
