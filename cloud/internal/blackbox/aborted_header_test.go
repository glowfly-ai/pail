// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

// implementation contract (`DUR-06`, `DUR-01`) — 헤더가 끝까지 착지하지 못한 세그먼트.
//
// 하네스(integration/dur/run_dur1.sh)가 이 형상을 실제로 만들어 프로덕션 경로에
// 물어보지만, 하네스는 도커·tmpfs·빌드를 요구하므로 자동 경로에서 자주 돌지
// 않는다. **관측점이 있는 것과 그것이 도는 것은 다른 값이다** — 그래서 같은
// 성질을 상시 ctest 대상인 in-package 테스트로도 세운다.
//
// 여기서 재는 것은 세 갈래이고, 각 갈래는 **자기 혼자 지키는 형상**을 갖는다:
//
//	최신이 미완 헤더  → 폐기하고 기동, 선언 1건 (DUR-06)
//	이력 중간 미완 헤더 → 리더 거부 (관용이 위치에 기댄다는 사실의 양성 대조)
//	선언의 seq       → 파일 이름에서 온다 (0바이트 헤더는 seq 필드까지 못 갔다)

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// abWriter — `durWriter` 와 같은 설정이되 `red_dur` 태그 뒤에 있지 않다. 상시로
// 도는 것이 이 파일의 요점이므로 태그가 걸린 헬퍼를 빌려 쓰지 않는다.
func abWriter(t *testing.T, dir string) *Writer {
	t.Helper()
	w, err := OpenDir(dir, Config{
		Signer:                 testSigner(testKey(t)),
		CheckpointEveryRecords: 1000,
		CheckpointEvery:        24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenDir(%s): %v", dir, err)
	}
	return w
}

// abortedSegment 는 `seq` 번 세그먼트를 `n` 바이트짜리 미완 헤더로 만든다.
// 바이트는 합성하지 않고 실재하는 헤더에서 잘라 온다 — 주입기가 형식을 알면
// 형식이 바뀔 때 주입기가 조용히 딴 것을 잰다.
func abortedSegment(t *testing.T, dir string, srcSeq, seq uint64, n int) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(dir, segmentName(srcSeq)))
	if err != nil {
		t.Fatalf("read src segment: %v", err)
	}
	if len(src) < n {
		t.Fatalf("src segment %d bytes < %d", len(src), n)
	}
	path := filepath.Join(dir, segmentName(seq))
	if err := os.WriteFile(path, src[:n], 0o600); err != nil {
		t.Fatalf("write aborted segment: %v", err)
	}
	return path
}

func TestDUR6_AbortedHeaderIsDiscardedAndDeclared(t *testing.T) {
	dir := t.TempDir()
	w := abWriter(t, dir)
	for i := 0; i < 3; i++ {
		if err := w.Append(RecordGateDecision, uint64(i), []byte("x")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// 생성 직후 전원 상실: seq 2 가 20바이트만 착지했다.
	corpse := abortedSegment(t, dir, 1, 2, 20)

	w2, err := OpenDir(dir, Config{Signer: testSigner(testKey(t))})
	if err != nil {
		t.Fatalf("RED: 미완 헤더에 기동 거부 — 세그먼트 생성 직후의 전원 상실이 영구 미기동이다: %v", err)
	}
	defer w2.Close()

	// 경로의 존재 여부로는 판정할 수 없다: 폐기 뒤 `latestSegment` 가 seq 를 되돌리므로
	// `startSegment` 가 **같은 이름**을 새 세그먼트로 다시 연다. `os.Stat` 이 성공하는
	// 것은 "시체가 살아남았다"와 "이름이 재사용됐다"를 구별하지 못한다 — 재는 것은
	// 이름이 아니라 **바이트**여야 한다.
	if b, err := os.ReadFile(corpse); err == nil {
		if len(b) < segHeaderSize {
			t.Errorf("미완 헤더가 그대로 남아 있다(%d바이트) — 다음 부팅의 리더에게는 이력 중간 손상이 된다", len(b))
		} else if string(b[0:4]) != segMagic {
			t.Errorf("같은 이름에 세그먼트가 아닌 바이트가 있다(magic=%q)", b[0:4])
		}
	} else if !os.IsNotExist(err) {
		t.Errorf("폐기 대상 경로를 읽을 수 없다: %v", err)
	}

	var declared int
	var gotSeq, gotDiscarded uint64
	torn, err := WalkDir(dir, func(r Record) error {
		if r.Type != RecordRecoveryTruncate {
			return nil
		}
		declared++
		gotDiscarded = binary.BigEndian.Uint64(r.Payload[0:8])
		gotSeq = binary.BigEndian.Uint64(r.Payload[40:48])
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if torn {
		t.Errorf("복구 뒤에도 TORN_TAIL — 절단이 내구화되지 않았다")
	}
	if declared != 1 {
		t.Fatalf("복구 선언 %d건, 1건이어야 한다 — 선언이 없으면 '폐기가 있었다'와 '없었다'가 같은 침묵이다", declared)
	}
	// 이 두 줄이 F-DUR-7 의 거짓 서명을 막는다: 스캔은 seq 필드까지 가지 못했고
	// (0 을 반환한다) 참값은 파일 이름에만 있다.
	if gotSeq != 2 {
		t.Errorf("선언된 segment_seq=%d, 2 여야 한다 — 스캔의 0 을 그대로 서명했다", gotSeq)
	}
	if gotDiscarded != 20 {
		t.Errorf("선언된 discarded=%d, 20 이어야 한다", gotDiscarded)
	}
}

// TestDUR6_AbortedHeaderMidHistoryIsRefused — 관용은 **최신 세그먼트**에만
// 적용된다. 이 대조가 없으면 위 테스트의 초록은 "미완 헤더를 늘 삼킨다"와
// 구별되지 않는다.
func TestDUR6_AbortedHeaderMidHistoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	// OpenDir 이 부팅마다 새 세그먼트를 연다 — 세 번 열어 1·2·3 을 만든다.
	for boot := 0; boot < 3; boot++ {
		w := abWriter(t, dir)
		if err := w.Append(RecordGateDecision, uint64(boot), []byte("x")); err != nil {
			t.Fatalf("boot %d append: %v", boot, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("boot %d close: %v", boot, err)
		}
	}
	mid := filepath.Join(dir, segmentName(2))
	if err := os.Truncate(mid, 20); err != nil {
		t.Fatalf("truncate mid segment: %v", err)
	}

	if _, err := WalkDir(dir, func(Record) error { return nil }); err == nil {
		t.Fatalf("이력 중간의 미완 헤더를 리더가 관용했다 — 뒤 세그먼트들이 존재하지 않는 tail 을 상속했다고 주장하는 상태다")
	} else {
		t.Logf("GREEN: 중간 미완 헤더 거부 — %v", err)
	}

	// 기동 경로도 같은 답을 내야 한다. 최신(3번)은 온전하므로 폐기 대상이 아니고,
	// 2번의 손상은 기동 스캔의 시야 밖이라 여기서는 기동이 성공한다 — 그것이
	// 리더의 거부를 유일한 관측점으로 만든다. 그 사실을 적어 둔다(F-DUR-9).
	w, err := OpenDir(dir, Config{Signer: testSigner(testKey(t))})
	if err == nil {
		w.Close()
		t.Logf("기록: 기동 경로는 최신 세그먼트만 스캔하므로 이 손상을 보지 못한다 — 관측점은 리더 하나뿐이다")
	}
}
