// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package anchor

// D §7.5 (C-B14) — 못 읽은 큐는 빈 큐가 아니다 (H-B2).
//
// drainQueue 가 ReadDir 오류를 전부 '백로그 없음'(true)으로 접으면 권한·I/O
// 오류가 앵커링 완료로 보고된다. ErrNotExist(큐 디렉터리가 아직 없다 = 진짜
// 큐잉된 것 없음)만 true 고, 그 밖의 오류는 '모름' = 드레인 미완(false)이다.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDrainQueueReadDirError(t *testing.T) {
	// 1) 디렉터리 부재 = 아직 아무것도 큐잉된 적 없음 → 백로그 없음 (true).
	a := &Agent{QueueDir: filepath.Join(t.TempDir(), "never-created"), Logf: t.Logf}
	if !a.drainQueue() {
		t.Fatalf("큐 디렉터리 부재는 진짜 빈 큐다 — false 는 앵커링을 영구히 막는다")
	}

	// 2) ReadDir 이 ENOTDIR 로 죽는다 (경로가 일반 파일) — '빈 큐'가 아니라
	//    '읽지 못함'이다 → 드레인 미완 (false).
	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	a = &Agent{QueueDir: f, Logf: t.Logf}
	if a.drainQueue() {
		t.Fatalf("ReadDir 오류가 '백로그 없음'으로 접혔다 — 못 읽음 != 비어 있음 (H-B2)")
	}
}
