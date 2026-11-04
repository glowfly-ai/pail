// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package anchor

// `C-B18` (승격된 `L8`) — 쓰기 실패한 레코드가 방출됨으로 표시된다.
//
// `Tick` 은 `emitted=true` 와 `last*` 를 **큐 쓰기보다 먼저** 세우고, 업로드도
// 큐잉도 실패하면 로그 한 줄만 남긴다. 그 레코드는 어디에도 없는데 에이전트는
// 그것을 방출한 것으로 기억하므로, 스냅샷이 그대로인 다음 틱은 keepalive 창
// 안에서 **건너뛰어진다** — 유실이 재시도로 이어지지 않는다.
//
// 이것이 「모든 액션이 기록된다」의 직접 반증인 이유는 침묵의 모양 때문이다.
// 앵커 저장소 쪽에서 보면 레코드가 안 오는 것은 "로봇이 조용하다"(idle)와
// 구별되지 않는데, 그 구별을 지으라고 있는 것이 바로 keepalive 재발신이다.
// **실패한 쓰기를 방출로 표시하는 것은 그 관측점을 끄는 것과 같다.**
//
// 저널 append 실패는 발급 거부다(issuer-first). 앵커만 그렇지 않은 비대칭
// 자체는 설계다 — 앵커링은 발급을 막지 않는다. 여기서 고치는 것은 그 비대칭이
// 아니라 **실패를 성공으로 적는 것**이다.

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 큐를 쓸 수 없는 상태를 만든다. 디스크 가득 참을 테스트에서 재현할 수는
// 없으므로 같은 결과(`MkdirAll`/`WriteFile` 실패)를 내는 ENOTDIR 을 쓴다 —
// 큐 경로에 일반 파일을 둔다. 권한(`chmod`)이 아니라 경로 종류를 쓰는 이유는
// **root 로 도는 컨테이너에서 권한 픽스처가 조용히 무력해지기** 때문이다
// (그 경우 이 시험은 실패를 재현하지 못한 채 통과한다).
func unwritableQueue(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "queue-is-a-file")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatalf("픽스처: %v", err)
	}
	return f
}

func TestCB18_DroppedRecordMustBeRetried(t *testing.T) {
	st := &fakeStore{fail: true}
	a, _ := newAgent(t, st)
	a.Keepalive = time.Hour // 프로덕션 모양 (pail_cloud 기본 300s)
	a.QueueDir = unwritableQueue(t)

	a.Tick()

	// 프로브가 자기 전제를 먼저 검사한다. 여기서 레코드가 어딘가에 남아
	// 있었다면 아래 판정은 "유실이 재시도됐다"가 아니라 "유실이 없었다"를
	// 재는 것이고, 둘은 같은 초록으로 도착한다.
	if st.count() != 0 {
		t.Fatalf("전제 불성립: 저장소가 죽어 있는데 업로드가 %d 건 성공했다", st.count())
	}
	if entries, err := os.ReadDir(a.QueueDir); err == nil {
		t.Fatalf("전제 불성립: 큐를 읽을 수 있다 (%d 항목) — 쓰기 실패를 재현하지 못했다", len(entries))
	}

	// 저장소가 살아나고 큐도 정상이 된다. 스냅샷은 변하지 않았다.
	st.setFail(false)
	a.QueueDir = filepath.Join(t.TempDir(), "anchor_queue")

	a.Tick()

	if st.count() == 0 {
		t.Fatalf("유실된 레코드가 재시도되지 않았다 — 쓰기 실패가 방출됨으로 표시되어 " +
			"불변 스냅샷의 다음 틱이 keepalive 창에서 건너뛰어졌다 (C-B18)")
	}
}

// 위 시험과 **다른 자리**를 잰다. 재시도가 살아나는 것과 유실이 세어지는 것은
// 따로 죽을 수 있다 — 하나로 합치면 계수를 통째로 지워도 초록이다(`H-B9`).
func TestCB18_DropIsCounted(t *testing.T) {
	st := &fakeStore{fail: true}
	a, _ := newAgent(t, st)
	a.Keepalive = time.Hour
	a.QueueDir = unwritableQueue(t)

	if n, why := a.Dropped(); n != 0 || why != "" {
		t.Fatalf("전제 불성립: 틱 전에 이미 유실이 %d 건 (%s)", n, why)
	}

	a.Tick()

	n, why := a.Dropped()
	if n != 1 {
		t.Fatalf("사라진 레코드가 세어지지 않았다: got %d, want 1", n)
	}
	if why == "" {
		t.Fatalf("유실은 세어졌으나 사유가 비었다 — 수만 있는 계수는 무엇이 " +
			"막혔는지 말하지 못한다")
	}
}

// 만족될 수 있는 가드레일인가. 항상 세는 계수는 게이트가 아니라 벽이다 —
// 정상 큐잉(저장소만 죽음)은 유실이 **아니다**: 레코드가 로컬에 있고 드레인된다.
func TestCB18_QueuedIsNotDropped(t *testing.T) {
	st := &fakeStore{fail: true}
	a, _ := newAgent(t, st)
	a.Keepalive = time.Hour

	a.Tick()

	entries, err := os.ReadDir(a.QueueDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("전제 불성립: 큐에 1건이어야 한다 (got %d, err=%v)", len(entries), err)
	}
	if n, why := a.Dropped(); n != 0 {
		t.Fatalf("큐잉 성공을 유실로 셌다: %d (%s)", n, why)
	}
}
