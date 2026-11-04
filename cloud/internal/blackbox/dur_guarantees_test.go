// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

// implementation contract (`DUR-L7`) — `G-DUR-01`~`G-DUR-05` 의 소유자.
//
// **소유가 왜 하네스가 아니라 여기인가.** 설계서 §7 은 다섯 보증을
// `integration/dur/run_dur1.sh` 에 함께 걸 생각이었다. 두 가지가 그것을 막는다:
//
//	CG-C  한 테스트가 둘 이상의 보증을 소유할 수 없다 — 한 파일이 다섯을 지면
//	      다섯이 함께 붉고 함께 초록이 되어 `H-B9` 가 무너진다.
//	실행  하네스는 도커·tmpfs·빌드를 요구해 자동 경로에서 돌지 않는다.
//	      **관측점이 있는 것과 그것이 도는 것은 다른 값이다.**
//
// 그래서 소유는 상시 `go test` 로 도는 이 파일의 다섯 함수에 있고, 하네스는
// 같은 성질을 **실물 매체**(진짜 ENOSPC) 위에서 한 번 더 재는 diagnostic 이다.
// 하네스가 없어도 보증은 관측되고, 하네스는 in-package 가 만들 수 없는 형상
// (매체가 실제로 가득 참)을 더한다.
//
// 각 함수는 **자기 혼자 지키는 형상**을 갖는다:
//
//	01  절단 뒤 기동이 진행한다        — 복구 레코드는 세지 않는다(02 의 몫)
//	02  버린 바이트가 서명되어 남는다   — 기동 성공 자체는 01 이 이미 쟀다
//	03  이력 중간 손상은 fail-closed   — 01·02 의 초록이 "다 삼킨다"와 갈린다
//	04  방출은 fsync 성공 뒤에만       — 파일 동기화 시임
//	05  종료·회전·디렉터리가 각각 내구화 — 셋을 따로 센다

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// gdWriter — 체크포인트가 끼어들지 않는 설정. 체크포인트가 섞이면 레코드 수의
// 차이에 이유가 여러 개가 되고, 그러면 거짓 성공과 정상 삽입이 같은 숫자로
// 도착한다(`H-B2`).
func gdWriter(t *testing.T, dir string, key ed25519.PrivateKey) *Writer {
	t.Helper()
	w, err := OpenDir(dir, Config{
		Signer:                 testSigner(key),
		CheckpointEveryRecords: 1000,
		CheckpointEvery:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenDir(%s): %v", dir, err)
	}
	return w
}

// gdTornTail 은 최신 세그먼트의 꼬리에서 n 바이트를 걷어내 전원 상실이 남기는
// 형상을 만든다. 잘라낸 바이트 수를 돌려준다.
func gdTornTail(t *testing.T, dir string, n int64) (path string, cut int64) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) == 0 {
		t.Fatalf("read dir: %v (entries=%d)", err, len(ents))
	}
	path = filepath.Join(dir, ents[len(ents)-1].Name())
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if fi.Size() <= int64(segHeaderSize)+n {
		t.Fatalf("전제 실패: 세그먼트가 %d바이트뿐이라 꼬리를 만들 수 없다", fi.Size())
	}
	if err := os.Truncate(path, fi.Size()-n); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return path, n
}

func gdSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}

// TestG_DUR_01_TornTailStartupRecoversAndProceeds — `G-DUR-01`.
//
// 재는 것은 **기동이 진행한다**는 것 하나다. 복구 레코드는 세지 않는다 —
// 그것은 `G-DUR-02` 가 홀로 지키는 형상이고, 여기서 함께 재면 선언을 지우는
// 변형이 두 보증을 함께 붉혀 둘이 사실 하나가 된다(`H-B9`).
func TestG_DUR_01_TornTailStartupRecoversAndProceeds(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	w := gdWriter(t, dir, key)
	for i := 0; i < 6; i++ {
		if err := w.Append(RecordGateDecision, uint64(i), []byte("payload")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	seg, _ := gdTornTail(t, dir, 7)

	w2, err := OpenDir(dir, Config{Signer: testSigner(key)})
	if err != nil {
		t.Fatalf("G-DUR-01 거짓: 찢긴 꼬리에 기동이 거부됐다 — 전원 상실이 영구 미기동이다: %v", err)
	}
	if err := w2.Append(RecordGateDecision, 99, []byte("after-recovery")); err != nil {
		t.Fatalf("G-DUR-01 거짓: 기동은 했으나 진행하지 못한다: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("close after recovery: %v", err)
	}

	// 절단이 **내구화**됐는지 본다. 관용만 하고 파일을 그대로 두면 같은 바이트가
	// 다음 부팅에서 이력 중간 손상이 된다(§3.1) — 그때는 원인이 멀어져 있다.
	res, err := scanSegment(seg, nil, nil)
	if err != nil {
		t.Fatalf("복구된 세그먼트를 다시 읽을 수 없다: %v", err)
	}
	if res.tornBytes != 0 {
		t.Errorf("G-DUR-01 거짓: 복구 뒤에도 찢긴 꼬리 %d바이트가 파일에 남아 있다 — 관용은 상태를 남긴다", res.tornBytes)
	}

	// 그리고 재생이 깨끗해야 한다. 두 번째 재기동까지 가서 위치 관용에 기대지
	// 않는다는 것을 확인한다.
	torn, err := WalkDir(dir, func(Record) error { return nil })
	if err != nil {
		t.Fatalf("G-DUR-01 거짓: 복구 뒤 재생이 실패한다: %v", err)
	}
	if torn {
		t.Errorf("G-DUR-01 거짓: 복구 뒤에도 TORN_TAIL — 절단이 내구화되지 않았다")
	}
}

// TestG_DUR_02_DiscardIsSignedAndDeclared — `G-DUR-02`.
//
// 서명까지 검증한다. 세기만 하면 "복구 레코드가 있다"와 "복구 레코드처럼 생긴
// 바이트가 있다"가 같은 값이 된다 — 이 레코드를 서명한 이유가 정확히 그것이다.
func TestG_DUR_02_DiscardIsSignedAndDeclared(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	w := gdWriter(t, dir, key)
	for i := 0; i < 6; i++ {
		if err := w.Append(RecordGateDecision, uint64(i), []byte("payload")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	seg, _ := gdTornTail(t, dir, 9)

	// 선언을 무엇과 대조할 것인가. **결함이 없앤 바이트 수(9)는 잣대가 아니다** —
	// 마지막 레코드가 9바이트를 잃으면 디스크에 남는 것은 그 레코드의 잔해
	// 전부이고, 복구가 잘라내는 것도 그 잔해다(여기서는 82). 9 와 대조하면
	// 프로덕션이 정직하게 82 를 선언해도 붉는다 — 검사가 아니라 잣대가 틀린
	// 것이다. 잣대는 **복구가 실제로 파일에서 없앤 바이트**이며, 그것은 복구
	// 전후의 파일 크기 차로 잰다(선언과 독립적인 출처).
	before := gdSize(t, seg)

	w2, err := OpenDir(dir, Config{Signer: testSigner(key)})
	if err != nil {
		t.Fatalf("전제 실패(G-DUR-01 이 이미 붉다): %v", err)
	}
	cut := before - gdSize(t, seg)
	if cut <= 0 {
		t.Fatalf("전제 실패: 복구가 파일에서 아무것도 없애지 않았다 (%d바이트 그대로)", before)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	pub := key.Public().(ed25519.PublicKey)
	declared, sigOK := 0, 0
	var discarded uint64
	if _, err := WalkDir(dir, func(r Record) error {
		if r.Type != RecordRecoveryTruncate {
			return nil
		}
		declared++
		if len(r.Payload) != RecoveryTruncatePayloadLen {
			t.Errorf("복구 레코드 길이 %d, %d 여야 한다", len(r.Payload), RecoveryTruncatePayloadLen)
			return nil
		}
		d := binary.BigEndian.Uint64(r.Payload[0:8])
		tail := r.Payload[8:40]
		seg := binary.BigEndian.Uint64(r.Payload[40:48])
		ms := binary.BigEndian.Uint64(r.Payload[48:56])
		sig := r.Payload[56:RecoveryTruncatePayloadLen]
		discarded += d
		if ed25519.Verify(pub, RecoveryTruncateSignedInput(d, tail, seg, ms), sig) {
			sigOK++
		}
		if seg == 0 {
			t.Errorf("G-DUR-02 거짓: segment_seq=0 이 서명됐다 — 스캔이 seq 필드까지 가지 못한 0 을 그대로 적었다")
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	if declared != 1 {
		t.Fatalf("G-DUR-02 거짓: 복구 선언 %d건 — 침묵은 기록이 아니다", declared)
	}
	if sigOK != 1 {
		t.Errorf("G-DUR-02 거짓: 복구 선언이 검증되는 서명을 갖지 않는다 — 서명 없는 선언은 공격자도 쓴다")
	}
	if discarded != uint64(cut) {
		t.Errorf("G-DUR-02 거짓: 선언된 버린 바이트 %d, 복구가 실제로 없앤 것은 %d", discarded, cut)
	}
}

// TestG_DUR_03_MidHistoryCorruptionFailsClosed — `G-DUR-03`.
//
// `G-DUR-01`·`02` 의 **양성 대조**다. 이것이 없으면 저 둘의 초록은 "복구가 뭐든
// 다 삼킨다"와 구별되지 않는다.
func TestG_DUR_03_MidHistoryCorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	// 두 번 부팅해 세그먼트 둘을 만든다 — 1번이 이력 중간이 된다.
	for boot := 0; boot < 2; boot++ {
		w := gdWriter(t, dir, key)
		for i := 0; i < 3; i++ {
			if err := w.Append(RecordGateDecision, uint64(boot*10+i), []byte("payload")); err != nil {
				t.Fatalf("boot %d append %d: %v", boot, i, err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("boot %d close: %v", boot, err)
		}
	}

	// 이력 **중간** 세그먼트의 페이로드 1바이트를 뒤집는다. 절단이 아니라 변조다 —
	// 절단은 §3.3 의 관용 대상이고 변조는 어느 위치에서도 관용 대상이 아니다.
	mid := filepath.Join(dir, segmentName(1))
	b, err := os.ReadFile(mid)
	if err != nil {
		t.Fatalf("read mid segment: %v", err)
	}
	if len(b) <= segHeaderSize+24 {
		t.Fatalf("전제 실패: 중간 세그먼트가 %d바이트뿐이다", len(b))
	}
	b[segHeaderSize+22] ^= 0xff
	if err := os.WriteFile(mid, b, 0o600); err != nil {
		t.Fatalf("write mid segment: %v", err)
	}

	if _, err := WalkDir(dir, func(Record) error { return nil }); err == nil {
		t.Fatalf("G-DUR-03 거짓: 리더가 이력 중간 변조를 관용했다 — 복구가 손상을 삼킨다")
	} else {
		t.Logf("GREEN: 리더 fail-closed — %v", err)
	}

	// 기동 경로도 같은 답을 내야 한다. 최신 세그먼트가 아니므로 기동 스캔의 시야
	// 밖이고(F-DUR-9), 여기서는 기동이 성공하는 것이 정상이다 — 그 사실을 적어
	// 두어 다음 사람이 "기동이 됐으니 괜찮다"로 읽지 않게 한다.
	if w, err := OpenDir(dir, Config{Signer: testSigner(key)}); err == nil {
		w.Close()
		t.Logf("기록(F-DUR-9): 기동 스캔은 최신 세그먼트만 본다 — 이 손상의 관측점은 리더 하나뿐이다")
	}
}

// TestG_DUR_04_AnnounceOnlyAfterDurable — `G-DUR-04`.
//
// 방출은 사실의 보고이지 의도의 보고가 아니다. fsync 가 실패했는데 방출이 나가면
// 앵커는 블랙박스에 존재하지 않는 head 를 붙든다.
func TestG_DUR_04_AnnounceOnlyAfterDurable(t *testing.T) {
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

	w.syncFn = func(*os.File) error { order = append(order, "fsync"); return errors.New("disk gone") }

	if err := w.Append(RecordGateDecision, 1, []byte("a")); err != nil {
		t.Fatalf("pre-checkpoint append: %v", err)
	}
	if err := w.Append(RecordGateDecision, 2, []byte("b")); err == nil {
		t.Fatalf("전제 실패: fsync 가 실패했는데 append 가 성공을 반환했다 — 이 테스트가 재려던 상태에 닿지 못했다")
	}
	if len(order) == 0 {
		t.Fatalf("전제 실패: 체크포인트가 한 번도 일어나지 않았다 — 방출 순서를 재지도 못했다")
	}
	for _, ev := range order {
		if ev == "announce" {
			t.Fatalf("G-DUR-04 거짓: fsync 가 실패했는데 방출이 나갔다, 순서=%v", order)
		}
	}
	t.Logf("GREEN: fsync 실패 시 방출 0회, 순서=%v", order)
}

// TestG_DUR_05_ThreeDurabilityPoints — `G-DUR-05`.
//
// 셋을 **따로** 센다. 합계 하나로 재면 하나가 죽어도 다른 둘이 초록을 유지한다 —
// 그것이 `F-DUR-6` 이 살아남은 방식이다.
func TestG_DUR_05_ThreeDurabilityPoints(t *testing.T) {
	t.Run("close", func(t *testing.T) {
		w := gdWriter(t, t.TempDir(), testKey(t))
		calls := 0
		w.syncFn = func(*os.File) error { calls++; return nil }
		if err := w.Append(RecordGateDecision, 1, []byte("x")); err != nil {
			t.Fatalf("append: %v", err)
		}
		before := calls
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if calls == before {
			t.Fatalf("G-DUR-05 거짓(종료): Close() 가 내구화하지 않는다 — 예정된 종료에서 잃는 것은 스펙이 아니라 결함이다")
		}
	})

	t.Run("rotate", func(t *testing.T) {
		w, err := OpenDir(t.TempDir(), Config{
			Signer:                 testSigner(testKey(t)),
			CheckpointEveryRecords: 1000,
			CheckpointEvery:        24 * time.Hour,
			MaxSegmentBytes:        200,
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
			t.Fatalf("전제 실패: 회전이 일어나지 않았다 (segSeq=%d) — 회전 내구화를 재지도 못했다", w.segSeq)
		}
		if calls == 0 {
			t.Fatalf("G-DUR-05 거짓(회전): 회전 %d회에 fsync 0회 — 새 헤더가 디스크에 없을 수도 있는 tail 을 상속한다고 주장한다", w.segSeq-1)
		}
	})

	t.Run("dir", func(t *testing.T) {
		dir := t.TempDir()
		w, err := OpenDir(dir, Config{
			Signer:                 testSigner(testKey(t)),
			CheckpointEveryRecords: 1000,
			CheckpointEvery:        24 * time.Hour,
			MaxSegmentBytes:        200,
		})
		if err != nil {
			t.Fatalf("OpenDir: %v", err)
		}
		defer w.Close()
		// 디렉터리 동기화는 파일 동기화와 **다른 시임**이다. 한 카운터로 합치면
		// 파일 fsync 가 디렉터리 fsync 의 부재를 가린다.
		dirCalls := 0
		w.syncDirFn = func(*os.File) error { dirCalls++; return nil }
		for i := 0; i < 6; i++ {
			if err := w.Append(RecordGateDecision, uint64(i), []byte("payloadpayload")); err != nil {
				t.Fatalf("append %d: %v", i, err)
			}
		}
		if w.segSeq < 2 {
			t.Fatalf("전제 실패: 새 세그먼트가 만들어지지 않았다 (segSeq=%d)", w.segSeq)
		}
		if dirCalls == 0 {
			t.Fatalf("G-DUR-05 거짓(디렉터리): 새 세그먼트 %d개에 디렉터리 fsync 0회 — 내용이 살아남아도 엔트리가 없으면 파일은 사라진다", w.segSeq-1)
		}
	})
}
