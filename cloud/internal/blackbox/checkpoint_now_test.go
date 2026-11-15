// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

// SEC-H08 (R4): the Issuer attests what it adopted at start-up. After replay
// has accepted a journal that ended without a checkpoint, the first thing the
// newly opened writer does is sign a checkpoint — before any new record, so
// the adopted records are under a signature at once instead of whenever the
// next periodic checkpoint happens to fall.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"
)

// h08Checkpoint calls Writer.Checkpoint through an interface so that this file
// compiles — and fails by assertion — on a tree that does not have it yet.
func h08Checkpoint(t *testing.T, w *Writer) {
	t.Helper()
	c, ok := any(w).(interface{ Checkpoint() error })
	if !ok {
		t.Fatalf("Writer has no Checkpoint() method")
	}
	if err := c.Checkpoint(); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
}

func h08VerifyCkpt(t *testing.T, r Record, pub ed25519.PublicKey, wantCount uint64) {
	t.Helper()
	if r.Type != RecordCheckpointV2 {
		t.Fatalf("record type=%d, want CHECKPOINT v2", r.Type)
	}
	count := binary.BigEndian.Uint64(r.Payload[32:40])
	seq := binary.BigEndian.Uint64(r.Payload[40:48])
	if count != wantCount {
		t.Errorf("record_count=%d, want %d", count, wantCount)
	}
	if !ed25519.Verify(pub, CheckpointV2SignedInput(r.Payload[0:32], count, seq), r.Payload[48:112]) {
		t.Errorf("checkpoint signature does not verify")
	}
}

func TestH08T13aCheckpointOnAnEmptySegment(t *testing.T) {
	dir := t.TempDir()
	w, s := h07Open(t, dir, 1000, -1)
	h08Checkpoint(t, w)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	recs := h07Walk(t, dir)
	if len(recs) != 1 {
		t.Fatalf("records=%d, want the one checkpoint", len(recs))
	}
	h08VerifyCkpt(t, recs[0], s.Public(), 0)
	// T13c: with nothing before it, the head it signs is the segment header's
	// hash — which carries the previous segment's tail, so everything before
	// this writer session is under the signature.
	b, err := os.ReadFile(lastSegmentPath(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(b[:segHeaderSize])
	if string(recs[0].Payload[0:32]) != string(want[:]) {
		t.Errorf("head of a checkpoint on an empty segment is not the header hash")
	}
}

func TestH08T13bCheckpointIsUnconditional(t *testing.T) {
	dir := t.TempDir()
	w, s := h07Open(t, dir, 1000, -1)
	h07Bodies(t, w, 0, 2)
	h08Checkpoint(t, w)
	h08Checkpoint(t, w)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	recs := h07Walk(t, dir)
	if len(recs) != 4 {
		t.Fatalf("records=%d, want body body CHECKPOINT CHECKPOINT", len(recs))
	}
	h08VerifyCkpt(t, recs[2], s.Public(), 2)
	h08VerifyCkpt(t, recs[3], s.Public(), 3)
}
