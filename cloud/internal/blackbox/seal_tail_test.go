// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

// SEC-H07 (R5): a journal at rest is covered by a signed checkpoint.
//
// The checkpoint trigger lived only inside Append, so a short run, or the last
// records before a stop, ended up outside every signature. A verifier that
// insists on signed coverage is only usable if the writer closes that gap when
// it stops (Close) and when writes pause (idle).

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
)

// h07Signer signs with a real key until told to fail.
type h07Signer struct {
	inner *signer.Local
	fail  atomic.Bool
}

func (s *h07Signer) Sign(msg []byte) ([]byte, error) {
	if s.fail.Load() {
		return nil, errors.New("h07: signer unavailable")
	}
	return s.inner.Sign(msg)
}
func (s *h07Signer) KeyID() string             { return s.inner.KeyID() }
func (s *h07Signer) Public() ed25519.PublicKey { return s.inner.Public() }

func h07Open(t *testing.T, dir string, every int, idle time.Duration) (*Writer, *h07Signer) {
	t.Helper()
	kp, err := devcrypto.NewDevKeypair("h07-key-1")
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	s := &h07Signer{inner: signer.NewLocal(kp)}
	w, err := OpenDir(dir, Config{
		Signer:                 s,
		CheckpointEveryRecords: every,
		CheckpointEvery:        24 * time.Hour,
		IdleFlushAfter:         idle,
	})
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	return w, s
}

func h07Bodies(t *testing.T, w *Writer, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		if err := w.Append(RecordGateDecision, uint64(1700000000000+i), []byte(fmt.Sprintf("h07-body-%03d", i))); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
}

func h07Walk(t *testing.T, dir string) []Record {
	t.Helper()
	var out []Record
	if _, err := WalkDir(dir, func(r Record) error { out = append(out, r); return nil }); err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	return out
}

func h07Checkpoints(recs []Record) (n int, lastCount uint64) {
	for _, r := range recs {
		if r.Type == RecordCheckpointV2 {
			n++
			lastCount = binary.BigEndian.Uint64(r.Payload[32:40])
		}
	}
	return
}

// h07Await polls instead of sleeping a fixed time: the idle path is a timer.
func h07Await(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestH07T11aCloseCoversTheTail(t *testing.T) {
	dir := t.TempDir()
	w, s := h07Open(t, dir, 1000, -1)
	h07Bodies(t, w, 0, 5)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	recs := h07Walk(t, dir)
	if len(recs) != 6 {
		t.Fatalf("records=%d, want 5 bodies + 1 closing checkpoint", len(recs))
	}
	last := recs[len(recs)-1]
	if last.Type != RecordCheckpointV2 {
		t.Fatalf("last record type=%d, want CHECKPOINT v2 (%d)", last.Type, RecordCheckpointV2)
	}
	count := binary.BigEndian.Uint64(last.Payload[32:40])
	seq := binary.BigEndian.Uint64(last.Payload[40:48])
	if count != 5 {
		t.Errorf("closing checkpoint record_count=%d, want 5", count)
	}
	if !ed25519.Verify(s.Public(), CheckpointV2SignedInput(last.Payload[0:32], count, seq), last.Payload[48:112]) {
		t.Errorf("closing checkpoint signature does not verify")
	}
}

func TestH07T11bCloseWritesNothingWhenAlreadyCovered(t *testing.T) {
	dir := t.TempDir()
	w, _ := h07Open(t, dir, 1, -1)
	h07Bodies(t, w, 0, 3)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	recs := h07Walk(t, dir)
	if n, _ := h07Checkpoints(recs); n != 3 || len(recs) != 6 {
		t.Errorf("records=%d checkpoints=%d, want 6 and 3 (no extra checkpoint at Close)", len(recs), n)
	}
}

func TestH07T11cCloseOnAnEmptyJournalWritesNothing(t *testing.T) {
	dir := t.TempDir()
	w, _ := h07Open(t, dir, 1000, -1)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if recs := h07Walk(t, dir); len(recs) != 0 {
		t.Errorf("records=%d, want 0", len(recs))
	}
}

// A stop that could not sign its last checkpoint must say so. The file is
// closed either way; what must not happen is a silent success.
func TestH07T11dCloseReportsASigningFailure(t *testing.T) {
	dir := t.TempDir()
	w, s := h07Open(t, dir, 1000, -1)
	h07Bodies(t, w, 0, 2)
	s.fail.Store(true)
	if err := w.Close(); err == nil {
		t.Fatalf("Close returned nil although the closing checkpoint could not be signed")
	}
	if recs := h07Walk(t, dir); len(recs) != 2 {
		t.Errorf("records=%d, want the 2 bodies and no checkpoint", len(recs))
	}
}

func TestH07T12IdleCoversTheTailOncePerPause(t *testing.T) {
	dir := t.TempDir()
	w, _ := h07Open(t, dir, 1000, 50*time.Millisecond)
	defer w.Close()

	h07Bodies(t, w, 0, 3)
	h07Await(t, "T12a: one checkpoint after the first pause", func() bool {
		n, _ := h07Checkpoints(h07Walk(t, dir))
		return n == 1
	})
	if _, c := h07Checkpoints(h07Walk(t, dir)); c != 3 {
		t.Errorf("T12a: record_count=%d, want 3", c)
	}

	// T12b: staying idle writes no second checkpoint.
	time.Sleep(300 * time.Millisecond)
	if n, _ := h07Checkpoints(h07Walk(t, dir)); n != 1 {
		t.Errorf("T12b: checkpoints=%d after staying idle, want 1", n)
	}

	// T12c: a new burst and a new pause -> exactly one more.
	h07Bodies(t, w, 3, 2)
	h07Await(t, "T12c: second checkpoint after the second pause", func() bool {
		n, _ := h07Checkpoints(h07Walk(t, dir))
		return n == 2
	})
	if _, c := h07Checkpoints(h07Walk(t, dir)); c != 6 {
		t.Errorf("T12c: record_count=%d, want 6 (5 bodies + the first checkpoint)", c)
	}
}

// The idle path has no caller to hand an error to, so the failure is repaid by
// the next Append: it retries the owed checkpoint first and refuses the record
// while that still fails (issuer-first). Once the signer is back the owed
// checkpoint lands ahead of the new record and nothing is lost.
func TestH07T12dIdleSigningFailureIsRepaidByTheNextAppend(t *testing.T) {
	dir := t.TempDir()
	w, s := h07Open(t, dir, 1000, 50*time.Millisecond)
	defer w.Close()

	h07Bodies(t, w, 0, 2)
	s.fail.Store(true)
	h07Await(t, "the idle callback to have run", func() bool {
		fires, _, _ := w.IdleFlushStats()
		return fires >= 1
	})
	// The records already in the file still reach the disk: durability at idle
	// (F-PRF-1) does not depend on the signer being reachable.
	h07Await(t, "the idle fsync despite the signing failure", func() bool {
		_, flushes, _ := w.IdleFlushStats()
		return flushes >= 1
	})
	if _, owed := w.IdleSealStats(); owed == nil {
		t.Fatalf("idle checkpoint failed but nothing is recorded as owed")
	}
	if err := w.Append(RecordGateDecision, 1700000000998, []byte("while-signer-down")); err == nil {
		t.Fatalf("Append succeeded although the owed idle checkpoint still cannot be signed")
	}
	s.fail.Store(false)
	if err := w.Append(RecordGateDecision, 1700000000999, []byte("after-recovery")); err != nil {
		t.Fatalf("Append after the signer recovered: %v", err)
	}
	recs := h07Walk(t, dir)
	if len(recs) < 4 {
		t.Fatalf("records=%d, want at least body body CHECKPOINT body", len(recs))
	}
	if recs[2].Type != RecordCheckpointV2 || binary.BigEndian.Uint64(recs[2].Payload[32:40]) != 2 {
		t.Errorf("record[2] type=%d, want the owed CHECKPOINT covering 2 records", recs[2].Type)
	}
	if recs[3].Type != RecordGateDecision || string(recs[3].Payload) != "after-recovery" {
		t.Errorf("record[3] = type %d %q, want the record appended after recovery", recs[3].Type, recs[3].Payload)
	}
}

// Abandon skips the closing checkpoint on purpose, for fixtures that need the
// shape a crash leaves. A service that called it would quietly bring back the
// journal this change exists to remove, so nothing outside tests may.
func TestH07AbandonHasNoProductionCaller(t *testing.T) {
	root := filepath.Join("..", "..") // services/pail_services_go
	var hits []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, ".Abandon(") {
				hits = append(hits, fmt.Sprintf("%s:%d", p, i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("Abandon() is called from non-test code: %v", hits)
	}
}
