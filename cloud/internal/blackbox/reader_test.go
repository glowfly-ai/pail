// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

import (
	"os"
	"testing"

	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
)

func testWriter(t *testing.T, dir string) *Writer {
	t.Helper()
	kp, err := devcrypto.NewDevKeypair("test-key-1")
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	w, err := OpenDir(dir, Config{Signer: signer.NewLocal(kp)})
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	return w
}

func lastSegmentPath(t *testing.T, dir string) string {
	t.Helper()
	_, p, err := latestSegment(dir)
	if err != nil || p == "" {
		t.Fatalf("latestSegment: %q %v", p, err)
	}
	return p
}

// Round trip across a writer restart (two segments): every record comes back
// in order, chain-verified, torn=false.
func TestWalkDirRoundTripAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	w := testWriter(t, dir)
	if err := w.Append(RecordTokenIssued, 111, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Append(RecordGateDecision, 222, []byte(`{"b":2}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	w.Abandon()
	w2 := testWriter(t, dir) // restart: new segment inheriting the tail
	if err := w2.Append(RecordChainRevoked, 333, []byte(`{"c":3}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	w2.Abandon()

	var got []Record
	torn, err := WalkDir(dir, func(r Record) error { got = append(got, r); return nil })
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if torn {
		t.Fatal("torn=true on a clean journal")
	}
	if len(got) != 3 {
		t.Fatalf("records=%d, want 3", len(got))
	}
	if got[0].Type != RecordTokenIssued || got[0].UnixMs != 111 || string(got[0].Payload) != `{"a":1}` {
		t.Fatalf("record[0] wrong: %+v", got[0])
	}
	if got[2].Type != RecordChainRevoked || got[2].SegmentSeq != 2 {
		t.Fatalf("record[2] wrong: %+v", got[2])
	}
}

// Flipping one payload byte breaks the chain: WalkDir must error.
func TestWalkDirTamperFails(t *testing.T) {
	dir := t.TempDir()
	w := testWriter(t, dir)
	if err := w.Append(RecordTokenIssued, 1, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	w.Close()

	p := lastSegmentPath(t, dir)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	data[segHeaderSize+20] ^= 0x01 // first payload byte
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := WalkDir(dir, func(Record) error { return nil }); err == nil {
		t.Fatal("WalkDir accepted a tampered payload")
	}
}

// A half-written final record in the newest segment is a pre-commit crash:
// tolerated, prior records still delivered.
func TestWalkDirTornTailTolerated(t *testing.T) {
	dir := t.TempDir()
	w := testWriter(t, dir)
	if err := w.Append(RecordTokenIssued, 1, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Append(RecordGateDecision, 2, []byte(`{"b":2}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	w.Abandon()

	p := lastSegmentPath(t, dir)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.Truncate(p, fi.Size()-10); err != nil { // torn this_hash
		t.Fatalf("truncate: %v", err)
	}
	var got []Record
	torn, err := WalkDir(dir, func(r Record) error { got = append(got, r); return nil })
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if !torn {
		t.Fatal("torn=false, want true")
	}
	if len(got) != 1 || got[0].UnixMs != 1 {
		t.Fatalf("records=%d, want exactly the 1 complete record", len(got))
	}
}

// Truncation in a NON-final segment is corruption, not a torn tail: error.
func TestWalkDirMidHistoryTruncationFails(t *testing.T) {
	dir := t.TempDir()
	w := testWriter(t, dir)
	if err := w.Append(RecordTokenIssued, 1, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	w.Close()
	firstSeg := lastSegmentPath(t, dir)
	w2 := testWriter(t, dir)
	if err := w2.Append(RecordGateDecision, 2, []byte(`{"b":2}`)); err != nil {
		t.Fatalf("append: %v", err)
	}
	w2.Close()

	fi, err := os.Stat(firstSeg)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.Truncate(firstSeg, fi.Size()-10); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := WalkDir(dir, func(Record) error { return nil }); err == nil {
		t.Fatal("WalkDir accepted mid-history truncation")
	}
}
