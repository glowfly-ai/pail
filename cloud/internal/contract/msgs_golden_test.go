// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestGCTR03_MsgFieldsFrozen — G-CTR-03 .
//
// ROS .msg 는 디스크립터가 없는 텍스트다 — ros_msgs.vec(손 전사)와
// pail_ws/src/pail_msgs/msg/*.msg 원문을 직접 대조한다.
//
//	MG-01 파일이 정확히 6개 (§1.6 실측, HLD "6종"과 일치)
//	MG-02 각 파일의 (타입, 이름, 순서) 전건 일치
//	MG-03 주석('#' 이후)·빈 줄 제거 후 비교 — 주석 변경은 FAIL 이 아니다
func TestGCTR03_MsgFieldsFrozen(t *testing.T) {
	dir := goldenPath(t, "pail_ws/src/pail_msgs/msg")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("msg 디렉토리 읽기: %v", err)
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".msg") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) != 6 {
		t.Fatalf("MG-01: .msg 파일 %d개 — 6개여야 한다: %v", len(names), names)
	}

	// 실물 → 골든과 같은 행 문법.
	var actual []string
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var fields []string
		for _, line := range strings.Split(string(raw), "\n") {
			// MG-03: 주석·빈 줄 제거.
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			toks := strings.Fields(line)
			if len(toks) != 2 {
				// 상수(=)나 기본값이 생기면 골든 문법 확장이 먼저다 — 조용히
				// 지나가지 않는다.
				t.Fatalf("%s: 필드 행이 아님(토큰 %d): %q", name, len(toks), line)
			}
			fields = append(fields, fmt.Sprintf("field\t%s\t%d\t%s\t%s",
				name, len(fields), toks[0], toks[1]))
		}
		actual = append(actual, fmt.Sprintf("file\t%s\t%d", name, len(fields)))
		actual = append(actual, fields...)
	}

	var golden []string
	for _, cols := range readFlatVec(t, goldenPath(t, "tests/golden/contract/ros_msgs.vec")) {
		golden = append(golden, strings.Join(cols, "\t"))
	}

	// MG-02: 순서 포함 전건 일치.
	n := len(golden)
	if len(actual) < n {
		n = len(actual)
	}
	for i := 0; i < n; i++ {
		if golden[i] != actual[i] {
			t.Errorf("MG-02: 행 %d 불일치\n golden=%s\n actual=%s", i, golden[i], actual[i])
		}
	}
	if len(golden) != len(actual) {
		t.Errorf("MG-02: 행 수 골든 %d / 실물 %d", len(golden), len(actual))
	}
	t.Logf("GOLDEN-MSGS go files=%d rows=%d ok=%v", len(names), len(actual), !t.Failed())
}
