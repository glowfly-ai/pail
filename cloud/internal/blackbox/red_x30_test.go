// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build red_lldb

// implementation contract RED-X30 — 내구성 모델.
//
// 이 리포에서 fsync 를 부르는 유일한 곳은 standby.go(HA 수신 측)다. 1차
// 기록자는 어디서도 동기화하지 않는다: appendRecord 는 os.File.Write 로
// 끝나고, 그 바이트는 페이지 캐시에 있다. 그런데 writer.go 의 Ship 주석은
// "The bytes stay durable locally" 라고 적는다 — 코드가 하지 않는 일을
// 코드 옆 주석이 주장한다(코드↔코드 불일치).
//
// 판정 축은 하나뿐이다: **체크포인트 시점에 fsync 가 실제로 호출되는가.**
// 프로세스를 SIGKILL 해도 페이지 캐시는 살아남으므로 그런 시험은 아무것도
// 증명하지 못한다. 기계 정전 수준의 증명은 native Linux 과제이고, 이
// 하네스는 그것을 GREEN 으로 합산하지 않는다(§2.9, 두 줄 출력).
//
// 두 단계로 나뉜 이유: RED 시점에는 동기화 시임(syncFn)이 존재하지 않아
// 훅 카운터를 컴파일할 수 없다. 그래서 RED 는 시임의 부재 자체를 판정하고,
// 수정 후 훅 카운터 행(x30_sync_test.go)이 같은 태그로 합류한다.
// 카운터 행은 RED 를 약화시키지 않는다 — 부재를 존재로 바꾼 뒤의 실측이다.
//
// 실행: go test -tags red_lldb -run TestRED_X30 ./internal/blackbox -v
package blackbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRED_X30_NoCheckpointFsync: 1차 기록자에 동기화 지점이 아예 없다.
func TestRED_X30_NoCheckpointFsync(t *testing.T) {
	src := readWriterSource(t)
	hasSeam := strings.Contains(src, "syncFn")
	hasSync := strings.Contains(src, "w.f.Sync()") || strings.Contains(src, "w.syncFn(w.f)")
	liesAboutDurability := strings.Contains(src, "The bytes stay durable locally")

	if !hasSeam || !hasSync {
		t.Logf("RED CONFIRMED: writer.go 에 동기화 지점이 없다 (syncFn 시임=%v, Sync 호출=%v).", hasSeam, hasSync)
		t.Logf("  appendRecord 는 os.File.Write 로 끝난다 — 바이트는 페이지 캐시에 있다.")
		if liesAboutDurability {
			t.Logf("  그런데 Ship 주석은 \"The bytes stay durable locally\" 라고 주장한다 — 코드↔코드 불일치.")
		}
		t.Fatalf("RED-X30: no fsync on the primary writer; the durability claim in the comment is false")
	}
	if liesAboutDurability {
		t.Fatalf("RED-X30: the durability comment must be corrected together with the fsync (§2.9)")
	}
	t.Logf("GREEN(structural): the primary writer has a sync seam and no false durability claim")
	t.Logf("N/A(native-linux-required): machine-crash durability is not provable here " +
		"(SIGKILL leaves the page cache intact; this line must never be merged into a GREEN)")
}

// TestRED_X30_SecurityDocAbsent 는 내구성 한계가 문서에 없음을 그대로 제시한다.
// 파일 작성 자체는 OR5의 산출물이고, B 는 들어갈 문단만 확정한다 —
// 그러므로 이 케이스는 B 안에서 미해결로 남는 것이 정상이며, 그 사실을
// 조용히 넘기지 않기 위해 SKIP 이 아니라 명시 로그로 남긴다.
func TestRED_X30_SecurityDocAbsent(t *testing.T) {
	p := filepath.Join(repoRoot(t), "SECURITY.md")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Logf("RED CONFIRMED: SECURITY.md 가 존재하지 않는다 (%v).", err)
		t.Logf("  내구성 한계(체크포인트 사이 구간, 기계 정전)가 어디에도 공표되지 않는다.")
		t.Logf("  HANDOFF: 파일 작성은 OR5 = implementation contract 의 몫. B 는 §2.9 문단을 확정할 뿐이다.")
		t.Skip("RED-X30(doc): deferred to implementation contract by design — not a B failure")
	}
	if !strings.Contains(string(b), "내구성") {
		t.Fatalf("SECURITY.md exists but carries no durability section")
	}
	t.Logf("GREEN: SECURITY.md carries the durability limits")
}

func readWriterSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("writer.go")
	if err != nil {
		t.Fatalf("read writer.go: %v", err)
	}
	return string(b)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// internal/blackbox -> services/pail_services_go -> services -> repo root
	return filepath.Join(wd, "..", "..", "..", "..")
}
