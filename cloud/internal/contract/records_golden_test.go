// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/blackbox"
)

// TestGCTR05_RecordTypesFrozen — G-CTR-05 의 Go 축 .
//
//	RT-01 Go 레코드 타입 번호 유일
//	RT-02 record_types.vec ≡ records.go 전건 (이름·번호 쌍)
//
// 구현 시 정정: 설계서는 16종이라 적었으나 records.go 실측은 15종이었다 —
// 리터럴은 실측을 따른다 (골든 파일 머리말에 동일 기록).
// 2026-08-06 OR2: 51 RecordContextProvenance 가 더해져 16종.
// 2026-08-12 OB3(implementation contract C2-C6): 90 RecordIdentityRefused 가 더해져 17종.
// 2026-08-23 implementation contract(§4 DUR-L3): 32 RecordRecoveryTruncate 가 더해져 19종
// (18종은 OB6 의 31 을 센 값이다).
//
// 이중 확보: ① 소스 스캔(records.go 원문 정규식)이 신규 상수 추가를 잡고,
// ② 컴파일된 상수 대조가 스캔 정규식 자체의 오독을 잡는다. 한쪽만 있으면
// 스캔 누락(새 이름 꼴)이나 사본 표류(테스트 안 사본)를 놓친다.
// 파이썬 미러(segment_chain.py 8종 부분집합, RT-03~05)는 pvs 쪽 소관.
func TestGCTR05_RecordTypesFrozen(t *testing.T) {
	// ① 소스 스캔.
	src, err := os.ReadFile(goldenPath(t,
		"services/pail_services_go/internal/blackbox/records.go"))
	if err != nil {
		t.Fatalf("records.go 읽기: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*(Record\w+)\s+uint32\s*=\s*(\d+)\s*$`)
	scanned := map[string]uint32{}
	byNum := map[uint32]string{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		name := m[1]
		num, _ := strconv.ParseUint(m[2], 10, 32)
		if _, dup := scanned[name]; dup {
			t.Fatalf("records.go: 상수 %s 중복 선언", name)
		}
		scanned[name] = uint32(num)
		// RT-01: 번호 유일.
		if prev, dup := byNum[uint32(num)]; dup {
			t.Errorf("RT-01: 번호 %d 재사용 — %s ↔ %s", num, prev, name)
		}
		byNum[uint32(num)] = name
	}
	// 2026-09-04 AL-2(implementation contract D5): 12 RecordContextSealed · 13 RecordPlanRejected. 19 → 21.
	if len(scanned) != 23 {
		t.Fatalf("records.go 스캔 %d종 — 23종이어야 한다 (기존 21종 + core operation 100 + core report 101)", len(scanned))
	}

	// ② 컴파일된 상수 대조 — 스캔 정규식의 오독 방지.
	compiled := map[string]uint32{
		"RecordCoreOperation":     blackbox.RecordCoreOperation,
		"RecordCoreReport":        blackbox.RecordCoreReport,
		"RecordTokenIssued":       blackbox.RecordTokenIssued,
		"RecordPlanAccepted":      blackbox.RecordPlanAccepted,
		"RecordContextSealed":     blackbox.RecordContextSealed, // AL-2
		"RecordPlanRejected":      blackbox.RecordPlanRejected,  // AL-2
		"RecordGateDecision":      blackbox.RecordGateDecision,
		"RecordChainRevoked":      blackbox.RecordChainRevoked,
		"RecordCheckpoint":        blackbox.RecordCheckpoint,
		"RecordCheckpointV2":      blackbox.RecordCheckpointV2,
		"RecordRecoveryTruncate":  blackbox.RecordRecoveryTruncate,
		"RecordSafeStop":          blackbox.RecordSafeStop,
		"RecordOperatorEvent":     blackbox.RecordOperatorEvent,
		"RecordGraphMutation":     blackbox.RecordGraphMutation,
		"RecordContextProvenance": blackbox.RecordContextProvenance,
		"RecordAttestation":       blackbox.RecordAttestation,
		"RecordConfigSealed":      blackbox.RecordConfigSealed,
		"RecordLeaseGranted":      blackbox.RecordLeaseGranted,
		"RecordLeaseReconciled":   blackbox.RecordLeaseReconciled,
		"RecordFleetCensus":       blackbox.RecordFleetCensus,
		"RecordLeaseRetracted":    blackbox.RecordLeaseRetracted,
		"RecordHaMembership":      blackbox.RecordHaMembership,
		"RecordIdentityRefused":   blackbox.RecordIdentityRefused,
	}
	for name, num := range compiled {
		if got, ok := scanned[name]; !ok {
			t.Errorf("스캔이 %s 를 놓침 — 정규식 오독", name)
		} else if got != num {
			t.Errorf("스캔 %s=%d vs 컴파일 %d — 정규식 오독", name, got, num)
		}
	}
	for name := range scanned {
		if _, ok := compiled[name]; !ok {
			t.Errorf("records.go 신규 상수 %s — 이 표와 record_types.vec 에 의도 선언 필요", name)
		}
	}

	// RT-02: 골든 ≡ Go 전건.
	rows := readFlatVec(t, goldenPath(t, "tests/golden/contract/record_types.vec"))
	golden := map[string]uint32{}
	var prevNum int64 = -1
	for _, cols := range rows {
		if cols[0] != "record" || len(cols) != 3 {
			t.Fatalf("record 행 문법 위반: %v", cols)
		}
		num, err := strconv.ParseUint(cols[2], 10, 32)
		if err != nil {
			t.Fatalf("record %s 번호 파싱: %v", cols[1], err)
		}
		if _, dup := golden[cols[1]]; dup {
			t.Fatalf("골든 이름 중복: %s", cols[1])
		}
		golden[cols[1]] = uint32(num)
		if int64(num) <= prevNum {
			t.Errorf("골든 정렬 위반(번호 오름차순): %s=%d", cols[1], num)
		}
		prevNum = int64(num)
	}
	for name, num := range golden {
		if got, ok := scanned[name]; !ok {
			t.Errorf("RT-02: 골든에 있으나 Go 에 없음: %s (삭제/개명)", name)
		} else if got != num {
			t.Errorf("RT-02: %s 골든 %d / Go %d", name, num, got)
		}
	}
	var extra []string
	for name := range scanned {
		if _, ok := golden[name]; !ok {
			extra = append(extra, name)
		}
	}
	if len(extra) > 0 {
		t.Errorf("RT-02: Go 에 있으나 골든에 없음(무단 추가): %s", strings.Join(extra, ", "))
	}
	t.Log(fmt.Sprintf("GOLDEN-RECORDS go n=%d ok=%v", len(golden), !t.Failed()))
}
