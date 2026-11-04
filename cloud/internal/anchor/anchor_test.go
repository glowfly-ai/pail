// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package anchor

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
)

type fakeSource struct {
	head  [32]byte
	seq   uint64
	count uint64
}

func (f *fakeSource) Snapshot() ([32]byte, uint64, uint64) { return f.head, f.seq, f.count }

type fakeStore struct {
	mu       sync.Mutex
	fail     bool
	failName string
	puts     map[string][]byte
	order    []string
	attempts int // every Put call, failed or not (BA-3 backoff observes this)
}

func (s *fakeStore) Put(name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.fail || (s.failName != "" && name == s.failName) {
		return errors.New("store down")
	}
	if s.puts == nil {
		s.puts = map[string][]byte{}
	}
	s.puts[name] = append([]byte{}, data...)
	s.order = append(s.order, name)
	return nil
}

func (s *fakeStore) setFail(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = v
}

func (s *fakeStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.puts)
}

func newAgent(t *testing.T, st Store) (*Agent, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	src := &fakeSource{seq: 3, count: 42}
	src.head[0] = 0xAB
	return &Agent{
		Source:   src,
		Signer:   signer.NewLocal(&devcrypto.Keypair{Public: pub, Private: priv, KeyID: "dev-key-1"}),
		RobotID:  "robot-1",
		Store:    st,
		QueueDir: filepath.Join(t.TempDir(), "anchor_queue"),
		Logf:     t.Logf,
	}, pub
}

// §9 M9: 저장소 다운 → 로컬 큐 적재, 복구 후 재시도로 전량 업로드.
func TestOfflineQueueAndRetry(t *testing.T) {
	st := &fakeStore{fail: true}
	a, _ := newAgent(t, st)

	a.Tick()
	a.Tick()
	a.Tick()

	entries, err := os.ReadDir(a.QueueDir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("queue: want 3 files, got %d (err=%v)", len(entries), err)
	}
	if st.count() != 0 {
		t.Fatalf("no uploads expected while store down, got %d", st.count())
	}

	st.setFail(false)
	a.Tick() // drains 3 queued, then uploads current

	if st.count() != 4 {
		t.Fatalf("want 4 uploads after recovery, got %d", st.count())
	}
	entries, _ = os.ReadDir(a.QueueDir)
	if len(entries) != 0 {
		t.Fatalf("queue must be drained, %d files remain", len(entries))
	}

	// BO-2 ordering invariant: monotonic anchor repositories reject count
	// rewinds, so the backlog (oldest first) MUST seal before the current
	// record. Names are zero-padded => lexicographic == chronological.
	st.mu.Lock()
	order := append([]string{}, st.order...)
	st.mu.Unlock()
	if !sort.StringsAreSorted(order) {
		t.Fatalf("uploads out of chronological order (backlog must drain before current): %v", order)
	}
}

// While the backlog cannot fully drain, the current record must be queued —
// never uploaded ahead of older records (a monotonic store would then reject
// the backlog forever with a count-rewind conflict).
func TestBacklogBlocksCurrentUpload(t *testing.T) {
	st := &fakeStore{fail: true}
	a, _ := newAgent(t, st)

	a.Tick()
	a.Tick() // 2 records queued, store down

	st.setFail(false)
	st.mu.Lock()
	entries, _ := os.ReadDir(a.QueueDir)
	st.failName = entries[0].Name() // oldest queued record keeps failing
	st.mu.Unlock()

	a.Tick()

	if st.count() != 0 {
		t.Fatalf("no upload may succeed while oldest backlog record fails, got %d", st.count())
	}
	entries, _ = os.ReadDir(a.QueueDir)
	if len(entries) != 3 {
		t.Fatalf("current record must join the queue: want 3 files, got %d", len(entries))
	}
}

// 업로드 레코드의 서명이 issuer pubkey로 검증되고 스냅샷 값을 담는다.
func TestRecordSignatureAndContent(t *testing.T) {
	st := &fakeStore{}
	a, pub := newAgent(t, st)

	a.Tick()
	if st.count() != 1 {
		t.Fatalf("want 1 upload, got %d", st.count())
	}
	for _, data := range st.puts {
		var r Record
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !VerifyRecord(pub, r) {
			t.Fatal("anchor record signature invalid")
		}
		if r.SegmentSeq != 3 || r.RecordCount != 42 || r.RobotID != "robot-1" {
			t.Fatalf("record content mismatch: %+v", r)
		}
		// tamper → verify fails
		r.RecordCount = 43
		if VerifyRecord(pub, r) {
			t.Fatal("tampered record must not verify")
		}
	}
}

// Keepalive > 0: 스냅샷이 변하지 않으면 keepalive 창 안에서는 재발신하지 않는다.
func TestKeepaliveSkipsUnchangedSnapshot(t *testing.T) {
	st := &fakeStore{}
	a, _ := newAgent(t, st)
	a.Keepalive = time.Hour

	a.Tick()
	a.Tick()
	a.Tick()

	if st.count() != 1 {
		t.Fatalf("unchanged snapshot inside keepalive: want 1 upload, got %d", st.count())
	}
}

// Keepalive 경과 후에는 스냅샷이 그대로여도 생존신호로 1건 재발신한다.
func TestKeepaliveReemitsAfterWindow(t *testing.T) {
	st := &fakeStore{}
	a, _ := newAgent(t, st)
	a.Keepalive = time.Hour

	a.Tick()
	a.lastEmit = time.Now().Add(-2 * time.Hour) // keepalive 창 경과 시뮬레이션
	a.Tick()

	if st.count() != 2 {
		t.Fatalf("keepalive elapsed: want 2 uploads, got %d", st.count())
	}
}

// 스냅샷(head/seq/count)이 바뀌면 keepalive와 무관하게 다음 틱에 즉시 발신한다.
func TestKeepaliveEmitsImmediatelyOnChange(t *testing.T) {
	st := &fakeStore{}
	a, _ := newAgent(t, st)
	a.Keepalive = time.Hour
	src := a.Source.(*fakeSource)

	a.Tick() // 1: 최초
	src.head[1] = 0xCD
	a.Tick() // 2: head 변화
	src.count++
	a.Tick() // 3: count 변화
	a.Tick() // 스킵 (불변)

	if st.count() != 3 {
		t.Fatalf("changed snapshots must anchor immediately: want 3 uploads, got %d", st.count())
	}
}

// Keepalive == 0 (레거시): 불변 스냅샷도 매 틱 발신한다.
func TestKeepaliveZeroEmitsEveryTick(t *testing.T) {
	st := &fakeStore{}
	a, _ := newAgent(t, st)

	a.Tick()
	a.Tick()
	a.Tick()

	if st.count() != 3 {
		t.Fatalf("legacy mode: want 3 uploads, got %d", st.count())
	}
}

// FSStore 참조 구현이 파일을 남긴다.
func TestFSStore(t *testing.T) {
	dir := t.TempDir()
	s := &FSStore{Dir: filepath.Join(dir, "anchors")}
	if err := s.Put("a.json", []byte("{}")); err != nil {
		t.Fatalf("fs put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "anchors", "a.json")); err != nil {
		t.Fatalf("fs file missing: %v", err)
	}
}
