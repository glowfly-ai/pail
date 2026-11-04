// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type segf struct {
	seq  uint64
	data []byte
}

// readSegs loads every segment file in dir, ordered by seq.
func readSegs(t *testing.T, dir string) []segf {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var out []segf
	for _, e := range entries {
		var seq uint64
		if _, err := fmt.Sscanf(e.Name(), "pail_blackbox.%d.seg", &seq); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		out = append(out, segf{seq: seq, data: data})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

// twoSegJournal writes a 2-segment journal (writer restart) with 3 records.
func twoSegJournal(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	w := testWriter(t, dir)
	if err := w.Append(RecordTokenIssued, 111, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Append(RecordGateDecision, 222, []byte(`{"b":2}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	w.Close()
	w2 := testWriter(t, dir)
	if err := w2.Append(RecordChainRevoked, 333, []byte(`{"c":3}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	w2.Close()
	return dir
}

// Feeding real segment bytes in tiny (7-byte) chunks yields exactly the
// records WalkDir yields, with nothing pending — frame boundaries are
// irrelevant to verification.
func TestStreamVerifierRoundTripChunked(t *testing.T) {
	dir := twoSegJournal(t)
	var want []Record
	if _, err := WalkDir(dir, func(r Record) error { want = append(want, r); return nil }); err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	var got []Record
	v := NewStreamVerifier(func(r Record) error { got = append(got, r); return nil })
	for _, s := range readSegs(t, dir) {
		if err := v.BeginSegment(s.seq); err != nil {
			t.Fatalf("BeginSegment(%d): %v", s.seq, err)
		}
		for off := 0; off < len(s.data); off += 7 {
			end := off + 7
			if end > len(s.data) {
				end = len(s.data)
			}
			if err := v.Feed(s.data[off:end]); err != nil {
				t.Fatalf("Feed seg=%d off=%d: %v", s.seq, off, err)
			}
		}
	}
	if v.Pending() != 0 {
		t.Fatalf("pending=%d after clean journal", v.Pending())
	}
	if len(got) != len(want) || len(got) != 3 {
		t.Fatalf("records=%d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].UnixMs != want[i].UnixMs || string(got[i].Payload) != string(want[i].Payload) {
			t.Fatalf("record %d mismatch: %+v vs %+v", i, got[i], want[i])
		}
	}
}

// A standby may receive history starting mid-journal: the first shipped
// segment's prev tail is adopted as the trust anchor.
func TestStreamVerifierAnchorsAtFirstShippedSegment(t *testing.T) {
	dir := twoSegJournal(t)
	segs := readSegs(t, dir)
	if len(segs) != 2 {
		t.Fatalf("segments=%d, want 2", len(segs))
	}
	n := 0
	v := NewStreamVerifier(func(Record) error { n++; return nil })
	if err := v.BeginSegment(segs[1].seq); err != nil {
		t.Fatalf("BeginSegment: %v", err)
	}
	if err := v.Feed(segs[1].data); err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if n != 1 || v.Pending() != 0 {
		t.Fatalf("records=%d pending=%d, want 1/0", n, v.Pending())
	}
}

// One flipped payload byte must fail verification (no ack).
func TestStreamVerifierTamperDetected(t *testing.T) {
	dir := twoSegJournal(t)
	segs := readSegs(t, dir)
	bad := append([]byte(nil), segs[0].data...)
	bad[segHeaderSize+20] ^= 0x01 // first payload byte of record 1

	v := NewStreamVerifier(nil)
	if err := v.BeginSegment(segs[0].seq); err != nil {
		t.Fatalf("BeginSegment: %v", err)
	}
	err := v.Feed(bad)
	if err == nil || !strings.Contains(err.Error(), "this_hash mismatch") {
		t.Fatalf("tampered feed err=%v, want this_hash mismatch", err)
	}
}

// A partial record at the end of the open stream is not an error — it stays
// pending until more bytes arrive (or the stream ends: torn tail).
func TestStreamVerifierTornTailPending(t *testing.T) {
	dir := twoSegJournal(t)
	segs := readSegs(t, dir)
	data := segs[0].data
	v := NewStreamVerifier(nil)
	if err := v.BeginSegment(segs[0].seq); err != nil {
		t.Fatalf("BeginSegment: %v", err)
	}
	if err := v.Feed(data[:len(data)-10]); err != nil {
		t.Fatalf("Feed torn: %v", err)
	}
	if v.Pending() == 0 {
		t.Fatal("pending=0 for a torn tail")
	}
	// ...but a successor segment on top of a torn tail IS an error.
	if err := v.BeginSegment(segs[0].seq + 1); err == nil || !strings.Contains(err.Error(), "torn record") {
		t.Fatalf("BeginSegment over torn tail err=%v, want torn record", err)
	}
}

// Segment sequence gaps break the chain.
func TestStreamVerifierSeqGap(t *testing.T) {
	dir := twoSegJournal(t)
	segs := readSegs(t, dir)
	v := NewStreamVerifier(nil)
	if err := v.BeginSegment(segs[0].seq); err != nil {
		t.Fatalf("BeginSegment: %v", err)
	}
	if err := v.Feed(segs[0].data); err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if err := v.BeginSegment(segs[0].seq + 2); err == nil || !strings.Contains(err.Error(), "gap") {
		t.Fatalf("seq-gap BeginSegment err=%v, want gap", err)
	}
}

// Cross-segment tail inheritance: corrupting the successor's
// prev_segment_tail_hash must be caught.
func TestStreamVerifierCrossSegmentTailMismatch(t *testing.T) {
	dir := twoSegJournal(t)
	segs := readSegs(t, dir)
	bad := append([]byte(nil), segs[1].data...)
	bad[16] ^= 0x01 // prev_segment_tail_hash first byte

	v := NewStreamVerifier(nil)
	if err := v.BeginSegment(segs[0].seq); err != nil {
		t.Fatalf("BeginSegment: %v", err)
	}
	if err := v.Feed(segs[0].data); err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if err := v.BeginSegment(segs[1].seq); err != nil {
		t.Fatalf("BeginSegment 2: %v", err)
	}
	err := v.Feed(bad)
	if err == nil || !strings.Contains(err.Error(), "prev_segment_tail_hash mismatch") {
		t.Fatalf("cross-segment tamper err=%v, want prev_segment_tail_hash mismatch", err)
	}
}
