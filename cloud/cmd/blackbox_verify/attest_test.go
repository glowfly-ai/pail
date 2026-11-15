// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// SEC-H07: what a passing --check-chain is allowed to mean.
//
// A hash chain can be recomputed by anyone who can write the files, so the chain
// alone attests nothing; only the signed CHECKPOINT records do. These tests run
// the built tool the way a recipient runs it and pin: a journal with no signed
// checkpoint does not pass with a key (R1), records after the last checkpoint
// are reported and do not pass silently (R2), a keyless run never says
// "verified" (R3), and an externally held head detects truncation at a
// checkpoint boundary (R4). T01-T03 are the controls that must stay as they are.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
)

var h07Bin string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "h07-verify-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkdtemp:", err)
		os.Exit(1)
	}
	h07Bin = filepath.Join(tmp, "blackbox_verify")
	build := exec.Command("go", "build", "-tags", "pail_generated", "-o", h07Bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build blackbox_verify: %v\n%s\n", err, out)
		os.Exit(1)
	}
	rc := m.Run()
	os.RemoveAll(tmp)
	os.Exit(rc)
}

// ---- journal construction -------------------------------------------------

type h07Journal struct {
	dir string
	pub string // base64 issuer public key
}

func h07Key(t *testing.T) *devcrypto.Keypair {
	t.Helper()
	kp, err := devcrypto.NewDevKeypair("h07-key-1")
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return kp
}

// h07Write appends `bodies` body records with the real writer. A negative
// `every` keeps the package defaults (interval and idle both).
func h07Write(t *testing.T, kp *devcrypto.Keypair, dir string, every, bodies int) *blackbox.Writer {
	t.Helper()
	cfg := blackbox.Config{Signer: signer.NewLocal(kp)}
	if every > 0 {
		cfg.CheckpointEveryRecords = every
		cfg.CheckpointEvery = 24 * time.Hour
		cfg.IdleFlushAfter = -1
	}
	w, err := blackbox.OpenDir(dir, cfg)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	h07Append(t, w, 0, bodies)
	return w
}

func h07Append(t *testing.T, w *blackbox.Writer, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		if err := w.Append(blackbox.RecordGateDecision, uint64(1700000000000+i), []byte(fmt.Sprintf("h07-body-%03d", i))); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
}

func h07Pub(kp *devcrypto.Keypair) string { return base64.StdEncoding.EncodeToString(kp.Public) }

// h07Snapshot copies the segment files as they are on disk right now — the
// shape a journal has after a power cut, before any Close could tidy it.
func h07Snapshot(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	names, err := listSegments(src)
	if err != nil {
		t.Fatalf("listSegments: %v", err)
	}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(src, n))
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		if err := os.WriteFile(filepath.Join(dst, n), b, 0o600); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
	return dst
}

// h07Base is journal J: a checkpoint after every body record, six bodies,
// cleanly closed -> b0 c1 b2 c3 b4 c5 b6 c7 b8 c9 b10 c11.
func h07Base(t *testing.T) (h07Journal, []record) {
	t.Helper()
	kp := h07Key(t)
	dir := t.TempDir()
	w := h07Write(t, kp, dir, 1, 6)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	recs := h07Records(t, dir)
	if len(recs) != 12 {
		t.Fatalf("base journal has %d records, want 12", len(recs))
	}
	return h07Journal{dir: dir, pub: h07Pub(kp)}, recs
}

func h07Segment(t *testing.T, dir string) string {
	t.Helper()
	names, err := listSegments(dir)
	if err != nil || len(names) != 1 {
		t.Fatalf("want exactly one segment in %s, got %v (%v)", dir, names, err)
	}
	return filepath.Join(dir, names[0])
}

func h07Records(t *testing.T, dir string) []record {
	t.Helper()
	_, _, recs, err := readSegment(h07Segment(t, dir))
	if err != nil {
		t.Fatalf("readSegment: %v", err)
	}
	return recs
}

func h07IsCkpt(r record) bool {
	return r.recType == blackbox.RecordCheckpoint || r.recType == blackbox.RecordCheckpointV2
}

// ---- journal editing (what a party with file access but no key can do) ----

// h07Rewrite writes `keep` back as one segment with the hash chain recomputed
// from the header. Checkpoint payloads get their head and count moved to the
// new position; the signature bytes are left alone, because the editor has no
// signing key.
func h07Rewrite(t *testing.T, srcDir string, keep []record) string {
	t.Helper()
	src := h07Segment(t, srcDir)
	_, header, _, err := readSegment(src)
	if err != nil {
		t.Fatalf("readSegment: %v", err)
	}
	var out bytes.Buffer
	out.Write(header)
	prev := sha256.Sum256(header)
	for i, r := range keep {
		payload := append([]byte(nil), r.payload...)
		switch r.recType {
		case blackbox.RecordCheckpointV2:
			copy(payload[0:32], prev[:])
			binary.BigEndian.PutUint64(payload[32:40], uint64(i))
		case blackbox.RecordCheckpoint:
			copy(payload[0:32], prev[:])
			binary.LittleEndian.PutUint64(payload[32:40], uint64(i))
		}
		h := sha256.New()
		h.Write(r.hdr)
		h.Write(payload)
		h.Write(prev[:])
		var this [32]byte
		copy(this[:], h.Sum(nil))
		var ln [4]byte
		binary.LittleEndian.PutUint32(ln[:], uint32(len(payload)))
		out.Write(r.hdr)
		out.Write(ln[:])
		out.Write(payload)
		out.Write(prev[:])
		out.Write(this[:])
		prev = this
	}
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(dst, filepath.Base(src)), out.Bytes(), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dst
}

func h07Drop(recs []record, pred func(i int, r record) bool) []record {
	var out []record
	for i, r := range recs {
		if !pred(i, r) {
			out = append(out, r)
		}
	}
	return out
}

// ---- running the tool ------------------------------------------------------

type h07Run struct {
	rc       int
	out, err string
}

func (r h07Run) all() string { return r.out + r.err }

func h07Verify(t *testing.T, dir string, args ...string) h07Run {
	t.Helper()
	full := append([]string{"-check-chain", "-dir", dir}, args...)
	cmd := exec.Command(h07Bin, full...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	rc := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run blackbox_verify: %v", err)
		}
		rc = ee.ExitCode()
	}
	return h07Run{rc: rc, out: so.String(), err: se.String()}
}

func h07Want(t *testing.T, r h07Run, rc int, must []string, mustNot []string) {
	t.Helper()
	if r.rc != rc {
		t.Errorf("rc=%d, want %d\nstdout:\n%s\nstderr:\n%s", r.rc, rc, r.out, r.err)
	}
	for _, s := range must {
		if !strings.Contains(r.all(), s) {
			t.Errorf("output lacks %q\nstdout:\n%s\nstderr:\n%s", s, r.out, r.err)
		}
	}
	for _, s := range mustNot {
		if strings.Contains(r.all(), s) {
			t.Errorf("output must not contain %q\nstdout:\n%s\nstderr:\n%s", s, r.out, r.err)
		}
	}
}

var h07AttestedRe = regexp.MustCompile(`ATTESTED: through (\S+) record\[(\d+)\] \((\d+) records?\); unattested tail: (\d+) record`)

// h07Attested parses the coverage line: index of the last covering checkpoint,
// records covered (that checkpoint included) and records after it.
func h07Attested(t *testing.T, r h07Run) (idx, covered, tail int) {
	t.Helper()
	m := h07AttestedRe.FindStringSubmatch(r.all())
	if m == nil {
		t.Fatalf("no ATTESTED line\nstdout:\n%s\nstderr:\n%s", r.out, r.err)
	}
	idx, _ = strconv.Atoi(m[2])
	covered, _ = strconv.Atoi(m[3])
	tail, _ = strconv.Atoi(m[4])
	return
}

// ---- helper self-check -----------------------------------------------------

// An edit that changes nothing must give back the same bytes; otherwise every
// "the tool accepted an edited journal" below could be an artefact of the editor.
func TestH07EditorIdentityIsByteIdentical(t *testing.T) {
	j, recs := h07Base(t)
	same := h07Rewrite(t, j.dir, recs)
	a, _ := os.ReadFile(h07Segment(t, j.dir))
	b, _ := os.ReadFile(h07Segment(t, same))
	if !bytes.Equal(a, b) {
		t.Fatalf("identity rewrite differs: %x vs %x", sha256.Sum256(a), sha256.Sum256(b))
	}
}

// ---- controls (R6) ---------------------------------------------------------

func TestH07T01IntactFullyAttestedJournalPasses(t *testing.T) {
	j, _ := h07Base(t)
	h07Want(t, h07Verify(t, j.dir, "-pubkey", j.pub), 0, []string{"OK: chain verified ("}, []string{"UNATTESTED_TAIL"})
}

func TestH07T02ByteFlipFails(t *testing.T) {
	j, _ := h07Base(t)
	dir := h07Snapshot(t, j.dir)
	p := h07Segment(t, dir)
	b, _ := os.ReadFile(p)
	b[segHeaderSize+16+4+2] ^= 0x01 // inside the first record's payload
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	h07Want(t, h07Verify(t, dir, "-pubkey", j.pub), 1, []string{"this_hash mismatch"}, []string{"OK: chain verified"})
}

func TestH07T03RecordDeletedWithCheckpointsKeptFails(t *testing.T) {
	j, recs := h07Base(t)
	dir := h07Rewrite(t, j.dir, h07Drop(recs, func(i int, _ record) bool { return i == 4 }))
	h07Want(t, h07Verify(t, dir, "-pubkey", j.pub), 1, []string{"signature invalid"}, []string{"OK: chain verified"})
}

// An empty journal is a valid empty prefix: like a cut at a checkpoint boundary
// it cannot be told from "everything was removed" without an outside reference.
func TestH07T15EmptyJournalIsAValidEmptyPrefix(t *testing.T) {
	kp := h07Key(t)
	dir := t.TempDir()
	w := h07Write(t, kp, dir, 1, 0)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	h07Want(t, h07Verify(t, dir, "-pubkey", h07Pub(kp)), 0, []string{"OK: chain verified (1 segments, 0 records, 0 checkpoints)"}, nil)
}

// ---- R1: no signed checkpoint, nothing attested ----------------------------

func TestH07T04AllCheckpointsStrippedFails(t *testing.T) {
	j, recs := h07Base(t)
	dir := h07Rewrite(t, j.dir, h07Drop(recs, func(_ int, r record) bool { return h07IsCkpt(r) }))
	h07Want(t, h07Verify(t, dir, "-pubkey", j.pub), 1, []string{"FAIL: no signed CHECKPOINT"}, []string{"OK: chain verified"})
}

func TestH07T05RecordDeletedAndCheckpointsStrippedFails(t *testing.T) {
	j, recs := h07Base(t)
	dir := h07Rewrite(t, j.dir, h07Drop(recs, func(i int, r record) bool { return i == 4 || h07IsCkpt(r) }))
	h07Want(t, h07Verify(t, dir, "-pubkey", j.pub), 1, []string{"FAIL: no signed CHECKPOINT"}, []string{"OK: chain verified"})
}

func TestH07T06JournalThatNeverReachedACheckpointFails(t *testing.T) {
	kp := h07Key(t)
	live := t.TempDir()
	w := h07Write(t, kp, live, 1000, 5)
	dir := h07Snapshot(t, live) // before Close: the power-cut shape
	_ = w.Close()
	if n := len(h07Records(t, dir)); n != 5 {
		t.Fatalf("precondition: snapshot has %d records, want 5 bodies and no checkpoint", n)
	}
	h07Want(t, h07Verify(t, dir, "-pubkey", h07Pub(kp)), 1, []string{"FAIL: no signed CHECKPOINT"}, []string{"OK: chain verified"})
}

// ---- R2: records after the last signed checkpoint ---------------------------

// every=4: b b b b C b b b b C, then three more bodies -> 13 records, the last
// covering checkpoint is record[9], three records are outside any signature.
func h07TailJournal(t *testing.T) (dir, pub string) {
	t.Helper()
	kp := h07Key(t)
	live := t.TempDir()
	w := h07Write(t, kp, live, 4, 8)
	h07Append(t, w, 8, 3)
	dir = h07Snapshot(t, live)
	_ = w.Close()
	recs := h07Records(t, dir)
	if len(recs) != 13 || !h07IsCkpt(recs[9]) || h07IsCkpt(recs[12]) {
		t.Fatalf("precondition: want 13 records with the last checkpoint at [9], got %d", len(recs))
	}
	return dir, h07Pub(kp)
}

func TestH07T07aUnattestedTailIsNotAPass(t *testing.T) {
	dir, pub := h07TailJournal(t)
	r := h07Verify(t, dir, "-pubkey", pub)
	h07Want(t, r, 7, []string{"UNATTESTED_TAIL: 3 record(s)"}, []string{"OK: chain verified"})
	if t.Failed() {
		return
	}
	idx, covered, tail := h07Attested(t, r)
	if idx != 9 || covered != 10 || tail != 3 {
		t.Errorf("ATTESTED idx=%d covered=%d tail=%d, want 9/10/3", idx, covered, tail)
	}
}

func TestH07T07bUnattestedTailAllowedExplicitly(t *testing.T) {
	dir, pub := h07TailJournal(t)
	r := h07Verify(t, dir, "-pubkey", pub, "-allow-unattested-tail")
	h07Want(t, r, 0, []string{"OK: chain verified (", "NOTE: 3 record(s) after the last signed CHECKPOINT"}, nil)
}

func TestH07T08LaterCheckpointsStrippedShowsAsTail(t *testing.T) {
	j, recs := h07Base(t)
	// delete body [4] and every checkpoint after it: b0 c1 b2 c3 | b6 b8 b10
	dir := h07Rewrite(t, j.dir, h07Drop(recs, func(i int, r record) bool { return i == 4 || (i > 4 && h07IsCkpt(r)) }))
	r := h07Verify(t, dir, "-pubkey", j.pub)
	h07Want(t, r, 7, []string{"UNATTESTED_TAIL: 3 record(s)"}, []string{"OK: chain verified"})
	if t.Failed() {
		return
	}
	idx, covered, tail := h07Attested(t, r)
	if idx != 3 || covered != 4 || tail != 3 {
		t.Errorf("ATTESTED idx=%d covered=%d tail=%d, want 3/4/3", idx, covered, tail)
	}
}

// ---- R3: no key, no "verified" ----------------------------------------------

func h07Stripped(t *testing.T) (dir string, j h07Journal) {
	t.Helper()
	j, recs := h07Base(t)
	return h07Rewrite(t, j.dir, h07Drop(recs, func(_ int, r record) bool { return h07IsCkpt(r) })), j
}

func TestH07T09aNoKeyIsAUsageError(t *testing.T) {
	dir, _ := h07Stripped(t)
	h07Want(t, h07Verify(t, dir), 2, []string{"-structure-only"}, []string{"chain verified"})
}

func TestH07T09bStructureOnlySaysUnauthenticated(t *testing.T) {
	dir, _ := h07Stripped(t)
	h07Want(t, h07Verify(t, dir, "-structure-only"), 0,
		[]string{"OK: chain structure consistent", "UNAUTHENTICATED"}, []string{"chain verified"})
}

func TestH07T09cStructureOnlyOnACheckpointedJournal(t *testing.T) {
	j, _ := h07Base(t)
	h07Want(t, h07Verify(t, j.dir, "-structure-only"), 0,
		[]string{"OK: chain structure consistent", "UNAUTHENTICATED"}, []string{"chain verified"})
}

func TestH07T09dStructureOnlyWithAKeyIsAUsageError(t *testing.T) {
	j, _ := h07Base(t)
	h07Want(t, h07Verify(t, j.dir, "-pubkey", j.pub, "-structure-only"), 2,
		[]string{"-structure-only cannot be combined with a key"}, []string{"chain verified"})
}

// ---- R4: an externally held head ---------------------------------------------

func h07Head(r record) string { return hex.EncodeToString(r.thisHash[:]) }

// A journal cut at a checkpoint boundary is a valid signed prefix. Nothing in
// the files says it is short; this pins that limit so the docs cannot drift
// into claiming otherwise.
func TestH07T10aTruncationAtACheckpointPassesWithoutAReference(t *testing.T) {
	j, recs := h07Base(t)
	dir := h07Rewrite(t, j.dir, recs[:8])
	h07Want(t, h07Verify(t, dir, "-pubkey", j.pub), 0, []string{"OK: chain verified ("}, nil)
}

func TestH07T10bTruncationFailsAgainstTheHeldHead(t *testing.T) {
	j, recs := h07Base(t)
	dir := h07Rewrite(t, j.dir, recs[:8])
	h07Want(t, h07Verify(t, dir, "-pubkey", j.pub, "-expect-head", h07Head(recs[10])), 1,
		[]string{"FAIL: expected head"}, []string{"OK: chain verified"})
}

func TestH07T10cIntactJournalContainsTheHeldHead(t *testing.T) {
	j, recs := h07Base(t)
	h07Want(t, h07Verify(t, j.dir, "-pubkey", j.pub, "-expect-head", h07Head(recs[10])), 0,
		[]string{"OK: chain verified (", "OK: expected head found"}, nil)
}

func TestH07T10dJournalThatGrewPastTheHeldHeadPasses(t *testing.T) {
	j, recs := h07Base(t)
	h07Want(t, h07Verify(t, j.dir, "-pubkey", j.pub, "-expect-head", h07Head(recs[4])), 0,
		[]string{"OK: expected head found"}, nil)
}

func TestH07T10eMalformedHeldHeadIsAUsageError(t *testing.T) {
	j, _ := h07Base(t)
	h07Want(t, h07Verify(t, j.dir, "-pubkey", j.pub, "-expect-head", "zz"), 2,
		[]string{"-expect-head must be 64 hex"}, []string{"chain verified"})
}

// ---- R1 + R5 together: an ordinary short run --------------------------------

var h07OKRe = regexp.MustCompile(`OK: chain verified \((\d+) segments, (\d+) records, (\d+) checkpoints\)`)

// Package defaults (checkpoint every 1000 records / 60 s): five records and a
// clean stop used to leave a journal with no checkpoint at all, which then
// "verified" without a key. After a clean stop it must verify WITH the key.
func TestH07T13ShortDefaultRunVerifiesAfterCleanStop(t *testing.T) {
	kp := h07Key(t)
	dir := t.TempDir()
	w := h07Write(t, kp, dir, -1, 5)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r := h07Verify(t, dir, "-pubkey", h07Pub(kp))
	h07Want(t, r, 0, []string{"OK: chain verified ("}, []string{"UNATTESTED_TAIL"})
	m := h07OKRe.FindStringSubmatch(r.out)
	if m == nil {
		t.Fatalf("no summary line\n%s%s", r.out, r.err)
	}
	if n, _ := strconv.Atoi(m[3]); n < 1 {
		t.Errorf("clean stop left %d checkpoints, want at least 1 (records=%s)", n, m[2])
	}
}
