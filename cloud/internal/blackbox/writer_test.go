// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func testSigner(key ed25519.PrivateKey) signer.Signer {
	return signer.NewLocal(&devcrypto.Keypair{
		Public:  key.Public().(ed25519.PublicKey),
		Private: key,
		KeyID:   "test-key-1",
	})
}

type segInfo struct {
	seq      uint64
	prevTail [32]byte
	records  []testRecord
	tail     [32]byte // last record this_hash, or prevTail if empty
}

type testRecord struct {
	recType  uint32
	payload  []byte
	prevHash [32]byte
	thisHash [32]byte
}

// verifySegments re-implements blackbox_verify --check-chain over a directory.
func verifySegments(t *testing.T, dir string, pub ed25519.PublicKey) []segInfo {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var segs []segInfo
	for _, name := range names {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		hdr := make([]byte, segHeaderSize)
		if _, err := io.ReadFull(f, hdr); err != nil {
			t.Fatalf("%s: header: %v", name, err)
		}
		if string(hdr[0:4]) != segMagic {
			t.Fatalf("%s: bad magic", name)
		}
		if v := binary.LittleEndian.Uint32(hdr[4:8]); v != segVersion {
			t.Fatalf("%s: version=%d", name, v)
		}
		si := segInfo{seq: binary.LittleEndian.Uint64(hdr[8:16])}
		copy(si.prevTail[:], hdr[16:48])
		si.tail = si.prevTail

		prevExpected := sha256.Sum256(hdr)
		for i := 0; ; i++ {
			rhdr := make([]byte, 16)
			n, err := io.ReadFull(f, rhdr)
			if (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) && n == 0 {
				break
			}
			if err != nil {
				t.Fatalf("%s record[%d]: header: %v", name, i, err)
			}
			lenBuf := make([]byte, 4)
			if _, err := io.ReadFull(f, lenBuf); err != nil {
				t.Fatalf("%s record[%d]: len: %v", name, i, err)
			}
			payload := make([]byte, binary.LittleEndian.Uint32(lenBuf))
			if _, err := io.ReadFull(f, payload); err != nil {
				t.Fatalf("%s record[%d]: payload: %v", name, i, err)
			}
			var prevHash, thisHash [32]byte
			if _, err := io.ReadFull(f, prevHash[:]); err != nil {
				t.Fatalf("%s record[%d]: prev_hash: %v", name, i, err)
			}
			if _, err := io.ReadFull(f, thisHash[:]); err != nil {
				t.Fatalf("%s record[%d]: this_hash: %v", name, i, err)
			}
			if prevHash != prevExpected {
				t.Fatalf("%s record[%d]: prev_hash mismatch", name, i)
			}
			h := sha256.New()
			h.Write(rhdr)
			h.Write(payload)
			h.Write(prevHash[:])
			var expected [32]byte
			copy(expected[:], h.Sum(nil))
			if thisHash != expected {
				t.Fatalf("%s record[%d]: this_hash mismatch", name, i)
			}
			recType := binary.LittleEndian.Uint32(rhdr[4:8])
			// E-C3: the writer emits v2 only. Type 30 here is not "an older
			// record we tolerate" — nothing in this tree writes one — so it is
			// a regression of the writer and fails rather than being skipped.
			if recType == RecordCheckpoint {
				t.Fatalf("%s record[%d]: writer emitted CHECKPOINT v1 (type 30); v2 (31) expected", name, i)
			}
			if recType == RecordCheckpointV2 {
				if len(payload) != 32+8+8+64 {
					t.Fatalf("%s record[%d]: checkpoint payload len=%d, want 112", name, i, len(payload))
				}
				var head [32]byte
				copy(head[:], payload[0:32])
				if head != prevHash {
					t.Fatalf("%s record[%d]: checkpoint head_hash != prev record hash", name, i)
				}
				count := binary.BigEndian.Uint64(payload[32:40])
				if count != uint64(i) {
					t.Fatalf("%s record[%d]: checkpoint record_count=%d want %d", name, i, count, i)
				}
				segSeq := binary.BigEndian.Uint64(payload[40:48])
				if segSeq != si.seq {
					t.Fatalf("%s record[%d]: checkpoint segment_seq=%d want %d", name, i, segSeq, si.seq)
				}
				if !ed25519.Verify(pub, CheckpointV2SignedInput(head[:], count, segSeq), payload[48:112]) {
					t.Fatalf("%s record[%d]: checkpoint signature invalid", name, i)
				}
				// The count is inside the signed input now — flipping it must
				// break the signature, or X13a is still open in the writer.
				if ed25519.Verify(pub, CheckpointV2SignedInput(head[:], count+1, segSeq), payload[48:112]) {
					t.Fatalf("%s record[%d]: signature accepts a different record_count (X13a)", name, i)
				}
			}
			si.records = append(si.records, testRecord{recType: recType, payload: payload, prevHash: prevHash, thisHash: thisHash})
			si.tail = thisHash
			prevExpected = thisHash
		}
		f.Close()
		segs = append(segs, si)
	}

	// segment-boundary inheritance
	for i := 1; i < len(segs); i++ {
		if segs[i].seq != segs[i-1].seq+1 {
			t.Fatalf("segment seq not contiguous: %d -> %d", segs[i-1].seq, segs[i].seq)
		}
		if segs[i].prevTail != segs[i-1].tail {
			t.Fatalf("segment %d prev_segment_tail_hash mismatch", segs[i].seq)
		}
	}
	return segs
}

func totalRecords(segs []segInfo) int {
	n := 0
	for _, s := range segs {
		n += len(s.records)
	}
	return n
}

func TestChainContinuesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	cfg := Config{Signer: testSigner(key)}

	w, err := OpenDir(dir, cfg)
	if err != nil {
		t.Fatalf("open #1: %v", err)
	}
	if err := w.Append(RecordPlanAccepted, 1, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordTokenIssued, 2, []byte(`{"b":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}

	// simulate process restart: must open a NEW segment inheriting the tail
	w, err = OpenDir(dir, cfg)
	if err != nil {
		t.Fatalf("open #2 (restart): %v", err)
	}
	if err := w.Append(RecordGateDecision, 3, []byte(`{"c":3}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}

	segs := verifySegments(t, dir, key.Public().(ed25519.PublicKey))
	if len(segs) != 2 {
		t.Fatalf("segments=%d, want 2 (restart must start a new segment)", len(segs))
	}
	if segs[0].prevTail != ([32]byte{}) {
		t.Fatal("first segment must inherit zero tail")
	}
	if n := totalRecords(segs); n != 3 {
		t.Fatalf("records=%d, want 3", n)
	}
}

func TestRotationAtMaxBytes(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	// tiny segment cap: header(56) + one record (~16+4+7+64=91B) exceeds it
	cfg := Config{Signer: testSigner(key), MaxSegmentBytes: 120}

	w, err := OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := w.Append(RecordGateDecision, uint64(i), []byte(`{"i":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	w.Abandon()

	segs := verifySegments(t, dir, key.Public().(ed25519.PublicKey))
	if len(segs) < 2 {
		t.Fatalf("segments=%d, want rotation to have produced >=2", len(segs))
	}
	if n := totalRecords(segs); n != 4 {
		t.Fatalf("records=%d, want 4", n)
	}
}

func TestCheckpointEveryNRecords(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	cfg := Config{Signer: testSigner(key), CheckpointEveryRecords: 3}

	w, err := OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if err := w.Append(RecordGateDecision, uint64(i), []byte(`{"i":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	w.Abandon()

	segs := verifySegments(t, dir, key.Public().(ed25519.PublicKey))
	ckpts := 0
	for _, s := range segs {
		for _, r := range s.records {
			if r.recType == RecordCheckpointV2 {
				ckpts++
			}
		}
	}
	// 7 records with checkpoint every 3 => after records 3 and 6 => 2 checkpoints
	if ckpts != 2 {
		t.Fatalf("checkpoints=%d, want 2", ckpts)
	}
	if n := totalRecords(segs); n != 9 { // 7 + 2 checkpoint records
		t.Fatalf("records=%d, want 9", n)
	}
}

func TestCheckpointByTime(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	cfg := Config{Signer: testSigner(key), CheckpointEvery: 50 * time.Millisecond}

	w, err := OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordGateDecision, 1, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if err := w.Append(RecordGateDecision, 2, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	w.Close()

	segs := verifySegments(t, dir, key.Public().(ed25519.PublicKey))
	ckpts := 0
	for _, s := range segs {
		for _, r := range s.records {
			if r.recType == RecordCheckpointV2 {
				ckpts++
			}
		}
	}
	if ckpts != 1 {
		t.Fatalf("checkpoints=%d, want 1 (time-triggered)", ckpts)
	}
}

func TestOpenRequiresSignKey(t *testing.T) {
	if _, err := OpenDir(t.TempDir(), Config{}); err == nil {
		t.Fatal("expected OpenDir to fail without sign key (fail-closed)")
	}
}

// TestOpenRecoversTruncatedTail — [DUR-L2/L3] 이 테스트는 2026-08-23 이전에
// `TestOpenRefusesTruncatedTail` 이었고, **결함을 정답으로 갖고 있었다**: 거부를
// fail-closed 로 읽었지만 실제로는 벽이었다(전원 상실 뒤 영구 미기동, `F-DUR-1`).
// 진짜로 지키려던 절(손상은 거부한다)은 아래 TestOpenRefusesCorruptTail 로
// 떼어 냈다 — 한 테스트가 두 절을 함께 재면 어느 쪽이 죽었는지 알 수 없다(H-B9).
func TestOpenRecoversTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	cfg := Config{Signer: testSigner(key)}

	w, err := OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordPlanAccepted, 1, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	w.Abandon()

	path := filepath.Join(dir, segmentName(1))
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	const cut = 10
	if err := os.Truncate(path, st.Size()-cut); err != nil {
		t.Fatal(err)
	}

	w2, err := OpenDir(dir, cfg)
	if err != nil {
		t.Fatalf("OpenDir must recover a torn tail, not refuse it: %v", err)
	}
	defer w2.Close()

	// 잘린 세그먼트는 파일에서 실제로 잘려 나갔다 — 찢김은 과도 상태다.
	if st2, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if want := int64(segHeaderSize); st2.Size() != want {
		t.Errorf("torn segment size=%d, want %d (partial record must be cut away)", st2.Size(), want)
	}

	// 버린 바이트는 서명된 레코드로 선언된다. 조용한 파괴는 기록이 아니다.
	var recs []Record
	torn, err := WalkDir(dir, func(r Record) error { recs = append(recs, r); return nil })
	if err != nil || torn {
		t.Fatalf("replay after recovery: torn=%v err=%v", torn, err)
	}
	var found *Record
	for i := range recs {
		if recs[i].Type == RecordRecoveryTruncate {
			found = &recs[i]
		}
	}
	if found == nil {
		t.Fatalf("no RecordRecoveryTruncate in %d records — a silent destruction reads exactly like 'nothing happened' (H-B2)", len(recs))
	}
	if len(found.Payload) != RecoveryTruncatePayloadLen {
		t.Fatalf("recovery payload len=%d, want %d", len(found.Payload), RecoveryTruncatePayloadLen)
	}
	discarded := binary.BigEndian.Uint64(found.Payload[0:8])
	// 원래 레코드는 payload_len 이후로 잘렸으므로, 버려진 것은 잘라낸 양이 아니라
	// 헤더 뒤에 남아 있던 미완성 레코드 전체다.
	if discarded != uint64(st.Size())-uint64(cut)-uint64(segHeaderSize) {
		t.Errorf("discarded_bytes=%d, want %d", discarded, uint64(st.Size())-cut-segHeaderSize)
	}
	sigOff := RecoveryTruncatePayloadLen - ed25519.SignatureSize
	signed := RecoveryTruncateSignedInput(
		discarded,
		found.Payload[8:40],
		binary.BigEndian.Uint64(found.Payload[40:48]),
		binary.BigEndian.Uint64(found.Payload[48:56]),
	)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), signed, found.Payload[sigOff:]) {
		t.Error("recovery record signature does not verify — an unsigned recovery declaration is one an attacker can also write")
	}

	// 복구 후에도 진행하고, 이후 replay 가 무오류다.
	if err := w2.Append(RecordPlanAccepted, 2, []byte(`{"a":2}`)); err != nil {
		t.Fatalf("append after recovery: %v", err)
	}
	if _, err := WalkDir(dir, func(Record) error { return nil }); err != nil {
		t.Fatalf("replay after post-recovery append: %v", err)
	}
}

// TestOpenRefusesCorruptTail — 위 테스트에서 떼어 낸 절. 복구는 **찢김에만**
// 적용된다. 내용이 바뀐 레코드는 전원 상실이 남길 수 있는 형상이 아니므로
// 기동을 거부한다. 이 절이 없으면 `DUR-L2` 는 "무엇이든 잘라내고 진행한다"가 된다.
func TestOpenRefusesCorruptTail(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	cfg := Config{Signer: testSigner(key)}

	w, err := OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordPlanAccepted, 1, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	w.Close()

	path := filepath.Join(dir, segmentName(1))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[segHeaderSize+22] ^= 0xff // payload 한 바이트를 뒤집는다 (this_hash 불일치)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, oerr := OpenDir(dir, cfg)
	if oerr == nil {
		t.Fatal("expected OpenDir to refuse a TAMPERED tail (fail-closed)")
	}
	// 거부는 여러 사유로 일어날 수 있다 — 재려던 그 사유인지 확인한다(H-B9).
	if !strings.Contains(oerr.Error(), "this_hash mismatch") {
		t.Errorf("refused for the wrong reason: %v", oerr)
	}
}

// TestOpenRefusesOverlongTornTail — [§3.3] 찢김의 상한. write(2) 하나가 남길 수
// 있는 미완성 레코드는 하나뿐이므로, 그보다 큰 잔여는 전원 상실이 아니라 손상이거나
// 누군가 덧붙인 바이트다. 상한이 없으면 복구는 공격자가 지울 수 있는 창이 된다.
func TestOpenRefusesOverlongTornTail(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	cfg := Config{Signer: testSigner(key)}

	w, err := OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordPlanAccepted, 1, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	w.Close()

	// 완전한 레코드 뒤에 "payload_len 이 거대한 레코드 머리"를 붙인다.
	junk := make([]byte, 20)
	binary.LittleEndian.PutUint32(junk[0:4], recVersion)
	binary.LittleEndian.PutUint32(junk[4:8], RecordGateDecision)
	binary.LittleEndian.PutUint32(junk[16:20], uint32(maxTornBytes)*4)
	f, err := os.OpenFile(filepath.Join(dir, segmentName(1)), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(junk, make([]byte, maxTornBytes+1)...)); err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, oerr := OpenDir(dir, cfg)
	if oerr == nil {
		t.Fatal("expected OpenDir to refuse trailing bytes beyond the one-record torn-tail bound")
	}
	if !strings.Contains(oerr.Error(), "torn-tail bound") {
		t.Errorf("refused for the wrong reason: %v", oerr)
	}
}

func TestRotationTailAcrossEmptySegment(t *testing.T) {
	// B-F3 (found by G-EVI-03's falsified_by, implementation contract 커밋 ① 실측): rotating away
	// from an EMPTY segment must inherit the tail transparently. Reader
	// (walkSegment), segmentTailHash and OpenDir all treat an empty segment as
	// transparent; rotateIfNeeded was the one path that stamped
	// sha256(empty segment header) into the next header instead — after which
	// the reader rejects the journal ("prev_segment_tail_hash mismatch") and
	// Rebuild refuses to start. Realistic trigger: writer opened, idle past
	// MaxSegmentAge (default 24h) with zero appends, then the first append.
	dir := t.TempDir()
	key := testKey(t)
	// every append rotates: the first one rotates away from the EMPTY seg 1
	cfg := Config{Signer: testSigner(key), MaxSegmentBytes: 1}

	w, err := OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordPlanAccepted, 1, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	// second rotation leaves a NON-empty segment: the normal path stays intact
	if err := w.Append(RecordTokenIssued, 2, []byte(`{"b":2}`)); err != nil {
		t.Fatal(err)
	}
	w.Abandon()

	// verifySegments enforces prev_segment_tail_hash inheritance including
	// empty-segment transparency; the reader must agree.
	segs := verifySegments(t, dir, key.Public().(ed25519.PublicKey))
	if n := totalRecords(segs); n != 2 {
		t.Fatalf("records=%d, want 2", n)
	}
	n := 0
	torn, err := WalkDir(dir, func(Record) error { n++; return nil })
	if err != nil {
		t.Fatalf("reader must accept a rotation-produced journal: %v", err)
	}
	if torn || n != 2 {
		t.Fatalf("torn=%t records=%d, want false/2", torn, n)
	}
}

func TestEmptySegmentTransparentInheritance(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	cfg := Config{Signer: testSigner(key)}

	// seg 1: two records
	w, err := OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordPlanAccepted, 1, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordTokenIssued, 2, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	tail1 := w.prevHash
	w.Abandon()

	// seg 2: opened but crashed before any record (header only)
	w, err = OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	w.Abandon()

	// seg 3: must still inherit seg 1's record tail through the empty seg 2
	w, err = OpenDir(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordGateDecision, 3, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	w.Abandon()

	segs := verifySegments(t, dir, key.Public().(ed25519.PublicKey))
	if len(segs) != 3 {
		t.Fatalf("segments=%d, want 3", len(segs))
	}
	if segs[1].prevTail != tail1 {
		t.Fatal("empty segment must inherit prior record tail")
	}
	if segs[2].prevTail != tail1 {
		t.Fatal("segment after empty one must still chain to the last record tail")
	}
}
