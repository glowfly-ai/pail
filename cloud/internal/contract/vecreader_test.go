// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package contract — TB-2/TB-3 골든 벡터 소비자 . 테스트 전용 패키지:
// 프로덕션 코드가 없고 내보내는 심볼도 없다 (P6/IR-2).
//
// .vec 형식 (§2.1):
//   - key<TAB>value 행 지향. '#' 시작 줄과 빈 줄 무시.
//   - 'id' 줄이 새 레코드를 연다. 레코드 안에서 key 유일 — 중복 = 파싱 오류
//     (마지막 승 금지: 조용한 덮어쓰기는 골든을 죽인다).
//   - 탭 없는 key 단독 줄 = 빈 값 (트레일링 탭 금지 규약, canon.vec CV-02).
package contract

import (
	"bufio"
	"fmt"
	"github.com/glowfly/pail/services/internal/testlayout"
	"os"
	"strings"
	"testing"
)

type vecRecord struct {
	ID     string
	Fields map[string]string
	Line   int // 'id' 줄 번호 (진단용)
}

func (r vecRecord) get(t *testing.T, key string) string {
	t.Helper()
	v, ok := r.Fields[key]
	if !ok {
		t.Fatalf("%s: 필수 key %q 없음 (줄 %d 레코드)", r.ID, key, r.Line)
	}
	return v
}

// goldenPath 는 리포 루트 기준 상대 경로를 절대화한다.
// 기본: 이 패키지 위치(services/pail_services_go/internal/contract)에서 4단계 상위.
// PAIL_REPO_ROOT 가 있으면 그것이 이긴다 (컨테이너/CI 유연성).
func goldenPath(t *testing.T, rel string) string {
	return testlayout.Path(t, rel)
}

func readVec(t *testing.T, path string) []vecRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var recs []vecRecord
	var cur *vecRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val := line, ""
		if i := strings.IndexByte(line, '\t'); i >= 0 {
			key, val = line[:i], line[i+1:]
		}
		if key == "id" {
			recs = append(recs, vecRecord{ID: val, Fields: map[string]string{"id": val}, Line: lineNo})
			cur = &recs[len(recs)-1]
			continue
		}
		if cur == nil {
			t.Fatalf("%s:%d: 첫 'id' 이전에 key %q", path, lineNo, key)
		}
		if _, dup := cur.Fields[key]; dup {
			t.Fatalf("%s:%d: 레코드 %s 안에서 key %q 중복 — 마지막 승 금지", path, lineNo, cur.ID, key)
		}
		cur.Fields[key] = val
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	if len(recs) == 0 {
		t.Fatalf("%s: 레코드 0건", path)
	}
	seen := map[string]bool{}
	for _, r := range recs {
		if r.ID == "" {
			t.Fatalf("%s: 빈 id (줄 %d)", path, r.Line)
		}
		if seen[r.ID] {
			t.Fatalf("%s: id %s 중복", path, r.ID)
		}
		seen[r.ID] = true
	}
	return recs
}

// readFlatVec 는 평면 TSV 골든(proto_schema/reason_dict/record_types/ros_msgs)을
// 읽는다 — §2.1 id-레코드형이 아니라 설계 §4.1 예시 형식: 각 줄이 독립 레코드,
// 첫 칼럼이 행 종류(file/field/enum/reason/record). '#'/빈 줄 무시.
// 반환은 탭 분해된 칼럼 배열의 원문 순서 목록이다.
func readFlatVec(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var rows [][]string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s: 행 0건", path)
	}
	return rows
}

// verdict 는 교차 언어 대조용 정형 로그를 남긴다 (§7.3-3).
// 형식: GOLDEN-VERDICT <lang> <id> valid=<0|1> reason=<r>
func verdict(t *testing.T, lang, id string, valid bool, reason string) {
	t.Helper()
	v := 0
	if valid {
		v = 1
	}
	t.Logf("GOLDEN-VERDICT %s %s valid=%d reason=%s", lang, id, v, reason)
	fmt.Printf("GOLDEN-VERDICT %s %s valid=%d reason=%s\n", lang, id, v, reason)
}
