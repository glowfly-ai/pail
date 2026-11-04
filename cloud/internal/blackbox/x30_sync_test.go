// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build red_lldb

// implementation contract X30 — 동기화 시임 실측. red_x30_test.go 의 구조 검사가
// "시임이 있다"까지만 말하는 반면, 여기서는 그 시임이 **언제 몇 번** 불리는지를
// 센다. 시임을 넣고도 부르지 않는 코드는 구조 검사를 통과하기 때문이다.
//
// 이 파일이 증명하는 것과 증명하지 않는 것을 구별한다:
//
//	증명한다   — 체크포인트마다 정확히 1회 fsync 가 호출되고, 그 실패가
//	             append 실패로 전파된다.
//	증명 못 한다 — 전원 손실 시 실제 유실 한도. 페이지 캐시는 프로세스와 함께
//	             죽지 않으므로 이 프로세스 안에서는 관측 불가다(native Linux).
//
// 실행: go test -tags red_lldb -run TestX30 ./internal/blackbox -v
package blackbox

import (
	"errors"
	"os"
	"testing"
	"time"
)

// newCountingWriter 는 동기화 시임을 카운터로 바꿔 끼운 Writer 를 연다.
// 시간 기준 체크포인트는 꺼 둔다(테스트가 벽시계에 의존하면 계수가 흔들린다).
func newCountingWriter(t *testing.T, everyRecords int, syncErr error) (*Writer, *int) {
	t.Helper()
	w, err := OpenDir(t.TempDir(), Config{
		Signer:                 testSigner(testKey(t)),
		CheckpointEveryRecords: everyRecords,
		CheckpointEvery:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	n := 0
	w.syncFn = func(f *os.File) error {
		if f == nil {
			t.Errorf("syncFn called with a nil file")
		}
		n++
		return syncErr
	}
	return w, &n
}

// TestX30_FsyncOncePerCheckpoint: 체크포인트 1회 = fsync 1회. 그 사이 레코드에는
// 부르지 않는다 — 매 레코드 fsync 는 §2.9 가 과하다고 판정한 형상이다.
func TestX30_FsyncOncePerCheckpoint(t *testing.T) {
	const every = 4
	w, calls := newCountingWriter(t, every, nil)
	defer w.Close()

	for i := 0; i < every-1; i++ {
		if err := w.Append(RecordGateDecision, uint64(time.Now().UnixMilli()), []byte("x")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if *calls != 0 {
		t.Fatalf("fsync before the first checkpoint: got %d calls, want 0", *calls)
	}

	for round := 1; round <= 3; round++ {
		for i := 0; i < every; i++ {
			if err := w.Append(RecordGateDecision, uint64(time.Now().UnixMilli()), []byte("x")); err != nil {
				t.Fatalf("round %d append %d: %v", round, i, err)
			}
		}
		if *calls != round {
			t.Fatalf("after %d checkpoint(s): got %d fsync calls, want %d", round, *calls, round)
		}
	}
	t.Logf("GREEN(syscall): fsync fired exactly once per checkpoint (%d checkpoints, %d calls)", 3, *calls)
	t.Logf("N/A(native-linux-required): power-loss retention is not observable from inside this process")
}

// TestX30_FsyncFailureFailsAppend: 디스크가 죽었는데 "기록했다"고 반환하는 것이
// X30 의 본질이다. fsync 오류는 append 오류가 되어야 하고, issuer-first 아래에서
// 그것은 곧 발급 거부다.
func TestX30_FsyncFailureFailsAppend(t *testing.T) {
	diskGone := errors.New("input/output error")
	w, calls := newCountingWriter(t, 2, diskGone)
	defer w.Close()

	if err := w.Append(RecordGateDecision, uint64(time.Now().UnixMilli()), []byte("x")); err != nil {
		t.Fatalf("pre-checkpoint append: %v", err)
	}
	err := w.Append(RecordGateDecision, uint64(time.Now().UnixMilli()), []byte("x"))
	if err == nil {
		t.Fatalf("append returned success while fsync failed — the caller would grant on a lost record")
	}
	if !errors.Is(err, diskGone) {
		t.Fatalf("append error does not carry the fsync cause: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("got %d fsync calls, want 1", *calls)
	}
	t.Logf("GREEN: fsync failure propagates as an append failure (%v)", err)
}
