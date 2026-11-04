// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/reason"
)

// TestGCTR04_ReasonDictDumpFresh — G-CTR-04 의 RD-01 .
//
// reason_dict.vec 는 Go 사전(internal/reason.table)의 커밋된 덤프다.
// 파이썬 소비자 검사(RD-02~05)는 이 덤프를 기준으로 삼으므로, 덤프가
// 낡으면 파이썬 검사 전체가 헛것을 본다 — 신선도는 Go 가 보증한다:
// 덤프 ≡ reason.All() 전건 (코드·값·평면, 값 오름차순).
//
// 배치 편차 노트: 설계 §4.3 은 "internal/reason 테스트가" 대조한다고
// 적었으나, .vec 리더(readFlatVec/goldenPath)가 이 패키지 소유라 여기에
// 둔다. 검사 주체가 Go 인 사실은 동일하고, internal/reason 에는 이미
// 사전 자체 불변식(reason_test.go)이 있다 — 파일 위치만의 편차다.
//
// U-D1 해소의 결과로 덤프는 처분·등급·하한을 싣지 않는다. 그 필드들의
// 동결은 reason_test.go::TestFrozenValuesPinned(G-CTR-04 승격분) 소관.
func TestGCTR04_ReasonDictDumpFresh(t *testing.T) {
	var want []string
	for _, e := range reason.All() {
		want = append(want, fmt.Sprintf("reason\t%s\t0x%02x\t%s", e.Code, e.Value, e.Plane))
	}
	// 2026-09-04 AL-2: 0x83~0x86 등재로 67 → 71. AL-3: 0x87~0x89 로 74.
	// 2026-09-14 SKL v2.1: 0x8A ERR_ENVELOPE_EXCEEDED 로 75.
	// 2026-10-01 OI-01: 0x5A ERR_REPORT_GAP (LOCAL) → 76.
	// 2026-10-18 P19-M1: 0x8B~0x8D ERR_BUNDLE_CLOCK/LIFETIME/POLICY (LOCAL) → 79.
	if len(want) != 79 {
		t.Fatalf("reason.All() %d항목 — 79여야 한다 (사전이 변했으면 덤프·리터럴 동시 갱신)", len(want))
	}

	var got []string
	for _, cols := range readFlatVec(t, goldenPath(t, "tests/golden/contract/reason_dict.vec")) {
		got = append(got, strings.Join(cols, "\t"))
	}

	n := len(want)
	if len(got) < n {
		n = len(got)
	}
	for i := 0; i < n; i++ {
		if want[i] != got[i] {
			t.Errorf("RD-01: 행 %d 불일치\n dict=%s\n vec =%s", i, want[i], got[i])
		}
	}
	if len(want) != len(got) {
		t.Errorf("RD-01: 사전 %d행 / 덤프 %d행", len(want), len(got))
	}
	t.Logf("GOLDEN-REASONS go n=%d ok=%v", len(got), !t.Failed())
}
