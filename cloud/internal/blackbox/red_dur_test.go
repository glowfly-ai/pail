// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build red_dur

// implementation contract — 전원 상실 내구성. 착수 실측을 그대로 옮긴 FAIL-first 행.
//
// 이 파일이 재는 것과 재지 못하는 것을 먼저 구분한다:
//
//	잰다     — 전원 상실이 **남기는 바이트 형상**(꼬리 절단, ENOSPC)에 대해
//	           기동 경로·리더·방출 순서·내구화 지점이 어떻게 행동하는가.
//	못 잰다  — 전원 상실 그 자체. 페이지 캐시는 프로세스와 함께 죽지 않는다.
//	           정본 실측은 native Linux(dm-flakey) 또는 실기 전원 차단이며
//	           `DUR-N1` 으로 등재돼 있다. 이 파일의 GREEN 에 합산하지 않는다.
//
// `kill -9` 는 여기 없다 — write(2) 는 프로세스 사망에 원자적이라 레코드를
// 찢지 못한다. 그것이 `G-EVI-11` 의 두 절이 곱해진 적 없는 이유다(F-DUR-6).
//
// 실행: go test -tags red_dur -run TestRED_DUR ./internal/blackbox -v
package blackbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func durWriter(t *testing.T, dir string, everyRecords int) *Writer {
	t.Helper()
	w, err := OpenDir(dir, Config{
		Signer:                 testSigner(testKey(t)),
		CheckpointEveryRecords: everyRecords,
		CheckpointEvery:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenDir(%s): %v", dir, err)
	}
	return w
}

// TestRED_DUR1_TornTailBricksStartup: 리더가 명시적으로 관용하는 바이트를
// 기동 경로가 거부한다 — 전원 상실 뒤 영구 미기동.
func TestRED_DUR1_TornTailBricksStartup(t *testing.T) {
	dir := t.TempDir()
	w := durWriter(t, dir, 4)
	for i := 0; i < 10; i++ {
		if err := w.Append(RecordGateDecision, uint64(i), []byte("payload")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	w.Close()

	// 전원 상실 형상: 최종 레코드가 중간에서 끊긴다.
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) == 0 {
		t.Fatalf("read dir: %v (entries=%d)", err, len(ents))
	}
	seg := filepath.Join(dir, ents[len(ents)-1].Name())
	fi, err := os.Stat(seg)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.Truncate(seg, fi.Size()-7); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	n := 0
	torn, rerr := WalkDir(dir, func(Record) error { n++; return nil })
	if rerr != nil || !torn {
		t.Fatalf("전제 실패: 리더가 절단을 관용하지 않았다 (torn=%v err=%v)", torn, rerr)
	}
	t.Logf("리더: 레코드=%d tornTail=true — reader.go 가 문서로 약속한 그대로", n)

	w2, oerr := OpenDir(dir, Config{Signer: testSigner(testKey(t))})
	if oerr != nil {
		t.Logf("RED CONFIRMED: 같은 바이트를 기동 경로가 거부한다: %v", oerr)
		t.Logf("  전원 상실은 정상 사건이다. 그 뒤 로봇이 다시 뜨지 못한다 —")
		t.Logf("  이것은 fail-closed 가 아니라 벽이고, 「공격자가 잘랐다」와")
		t.Logf("  「전원이 나갔다」가 같은 붉은 줄로 도착한다(H-B2).")
		t.Fatalf("RED-DUR-1: OpenDir refuses a torn tail that WalkDir tolerates")
	}
	defer w2.Close()

	// 수정 후에도 지켜야 하는 것: 복구가 이력을 조용히 버리지 않는다.
	if err := w2.Append(RecordGateDecision, 99, []byte("after-recovery")); err != nil {
		t.Fatalf("복구 후 append: %v", err)
	}
	if _, err := WalkDir(dir, func(Record) error { return nil }); err != nil {
		t.Fatalf("복구 후 재replay 가 깨졌다: %v", err)
	}
	t.Logf("GREEN: 절단 뒤 기동이 복구하고 진행하며, 이후 replay 가 무오류다")
}

// TestRED_DUR1b_SecondRestart: §3.1 의 2차 결함. 단순 관용이면 찢긴 세그먼트가
// 비최종이 되는 순간 같은 바이트가 이력 중간 손상으로 재분류된다.
func TestRED_DUR1b_SecondRestart(t *testing.T) {
	dir := t.TempDir()
	w := durWriter(t, dir, 4)
	for i := 0; i < 10; i++ {
		if err := w.Append(RecordGateDecision, uint64(i), []byte("payload")); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	w.Close()

	ents, _ := os.ReadDir(dir)
	seg := filepath.Join(dir, ents[len(ents)-1].Name())
	fi, _ := os.Stat(seg)
	if err := os.Truncate(seg, fi.Size()-7); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	w2, err := OpenDir(dir, Config{Signer: testSigner(testKey(t))})
	if err != nil {
		t.Skipf("RED-DUR-1 이 아직 열려 있다 — 이 행은 그 뒤에 의미를 갖는다: %v", err)
	}
	if err := w2.Append(RecordGateDecision, 100, []byte("run2")); err != nil {
		t.Fatalf("run2 append: %v", err)
	}
	w2.Close()

	// 두 번째 재기동: 찢겼던 세그먼트는 이제 최종이 아니다.
	w3, err := OpenDir(dir, Config{Signer: testSigner(testKey(t))})
	if err != nil {
		t.Fatalf("RED-DUR-1b: 두 번째 재기동이 거부됐다 — 관용은 결함을 다음 부팅으로 미룬다: %v", err)
	}
	w3.Close()
	if _, err := WalkDir(dir, func(Record) error { return nil }); err != nil {
		t.Fatalf("RED-DUR-1b: 비최종이 된 찢긴 세그먼트를 리더가 거부한다: %v", err)
	}
	t.Logf("GREEN: 찢김은 과도 상태이지 이력이 아니다")
}

// TestRED_DUR2_AnnounceBeforeFsync: 내구화 전에 체크포인트 head 를 방출한다.
// C-B18 의 거울상 — 방출은 사실의 보고이지 의도의 보고가 아니다.
func TestRED_DUR2_AnnounceBeforeFsync(t *testing.T) {
	var order []string
	w, err := OpenDir(t.TempDir(), Config{
		Signer:                 testSigner(testKey(t)),
		CheckpointEveryRecords: 2,
		CheckpointEvery:        24 * time.Hour,
		OnCheckpoint:           func([32]byte, uint64) { order = append(order, "announce") },
	})
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	defer w.Close()

	diskGone := errors.New("disk gone")
	w.syncFn = func(*os.File) error { order = append(order, "fsync"); return diskGone }

	if err := w.Append(RecordGateDecision, 1, []byte("a")); err != nil {
		t.Fatalf("pre-checkpoint append: %v", err)
	}
	aerr := w.Append(RecordGateDecision, 2, []byte("b"))
	if aerr == nil {
		t.Fatalf("전제 실패: fsync 가 실패했는데 append 가 성공을 반환했다")
	}

	for i, ev := range order {
		if ev == "announce" {
			for _, before := range order[:i] {
				if before == "fsync" {
					t.Logf("GREEN: 방출(%d번째)은 fsync 뒤에만 일어난다, 순서=%v", i, order)
					return
				}
			}
			t.Logf("RED CONFIRMED: 순서=%v — fsync 앞에서 방출했다", order)
			t.Logf("  fsync 는 정직하게 실패해 append 를 거부했지만, 방출은 이미 나갔다.")
			t.Logf("  전원 상실 시 앵커는 블랙박스에 없는 head 를 붙든다.")
			t.Fatalf("RED-DUR-2: checkpoint head announced before it is durable")
		}
	}
	if len(order) == 0 {
		t.Fatalf("전제 실패: 체크포인트가 한 번도 일어나지 않았다")
	}
	t.Logf("GREEN: fsync 실패 시 방출이 아예 일어나지 않았다, 순서=%v", order)
}

// TestRED_DUR3_CloseNoFsync: 예정된 종료에서 잃는 것은 스펙이 아니라 결함이다.
func TestRED_DUR3_CloseNoFsync(t *testing.T) {
	w := durWriter(t, t.TempDir(), 1000) // 체크포인트가 끼어들지 않게
	calls := 0
	w.syncFn = func(*os.File) error { calls++; return nil }

	if err := w.Append(RecordGateDecision, 1, []byte("x")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if calls == 0 {
		t.Fatalf("RED-DUR-3: Close() 가 내구화하지 않는다 — 정상 종료도 체크포인트 창을 통째로 잃는다")
	}
	t.Logf("GREEN: Close() 가 fsync 한다 (%d회)", calls)
}

// TestRED_DUR4_RotateNoFsync: 새 세그먼트 헤더는 디스크에 없을 수도 있는
// 레코드의 tail 을 상속한다고 주장한다. 헤더는 체인에 참여한다.
func TestRED_DUR4_RotateNoFsync(t *testing.T) {
	w, err := OpenDir(t.TempDir(), Config{
		Signer:                 testSigner(testKey(t)),
		CheckpointEveryRecords: 1000,
		CheckpointEvery:        24 * time.Hour,
		MaxSegmentBytes:        200, // 즉시 회전
	})
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	defer w.Close()

	calls := 0
	w.syncFn = func(*os.File) error { calls++; return nil }

	for i := 0; i < 6; i++ {
		if err := w.Append(RecordGateDecision, uint64(i), []byte("payloadpayload")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if w.segSeq < 2 {
		t.Fatalf("전제 실패: 회전이 일어나지 않았다 (segSeq=%d)", w.segSeq)
	}
	if calls == 0 {
		t.Fatalf("RED-DUR-4: 회전이 이전 세그먼트를 내구화하지 않는다 (회전 %d회, fsync 0회)", w.segSeq-1)
	}
	t.Logf("GREEN: 회전이 이전 세그먼트를 내구화한다 (회전 %d회, fsync %d회)", w.segSeq-1, calls)
}

// TestRED_DUR5_NoDirSync: 내용이 살아남아도 디렉터리 엔트리가 없으면 파일은
// 사라진다. 같은 리포의 crypto/keyfile.go 는 이 패턴을 이미 안다.
func TestRED_DUR5_NoDirSync(t *testing.T) {
	b, err := os.ReadFile("writer.go")
	if err != nil {
		t.Fatalf("read writer.go: %v", err)
	}
	src := string(b)
	hasSeam := strings.Contains(src, "syncDirFn")
	if !hasSeam {
		t.Logf("RED CONFIRMED: writer.go 에 디렉터리 동기화 시임이 없다.")
		t.Logf("  대조: internal/crypto/keyfile.go 는 새 파일 뒤 d.Sync() 를 한다.")
		t.Fatalf("RED-DUR-5: the blackbox never fsyncs its directory")
	}
	t.Logf("GREEN(structural): 디렉터리 동기화 시임이 존재한다")
}
