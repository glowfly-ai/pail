// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package reason

import (
	"github.com/glowfly/pail/services/internal/testlayout"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 드리프트 탐지 — 이 작업의 진짜 산출물이다 (LLD §1.5).
//
// 게이트에 새 ERR_* 를 추가한 사람은 처분·등급을 정하지 않고서는 빌드를 통과시킬 수 없다.
// 반대로 생산자가 사라진 사유가 사전에 남아 있으면 그것도 잡는다.

// 닫는 따옴표만 받으면 상세를 이어 붙인 사유는 검사에 보이지 않는다 —
// `"ERR_X:count=" + n` 은 사전에 없어도 전방 드리프트가 침묵한다(2026-08-10 실측:
// `ERR_KEYRING_ENTRY` 가 그 자리에 있었다). 접미어 구분자까지 종단으로 받는다.
var errLiteral = regexp.MustCompile(`"(ERR_[A-Z0-9_]+)[":]`)

// repoRoot — Go 모듈 루트가 services/pail_services_go 이므로 패키지 디렉터리 기준 ../../../.. 이다.
func repoRoot(t *testing.T) string { return testlayout.Root(t) }

type site struct {
	code string
	at   string
}

// scanProducers — 게이트·Go 소스에서 ERR_* 리터럴을 수집한다.
//
// 제외 규칙:
//   - `/test/` 경로와 `_test.go`: 테스트는 의도적으로 가짜 코드를 쓴다
//   - `internal/reason/`: 사전 자신이다. 이것을 세면 역방향 검사가 공허해진다
func scanProducers(t *testing.T) []site {
	t.Helper()
	root := repoRoot(t)

	targets := []struct {
		dir  string
		exts map[string]bool
	}{
		{testlayout.Path(t, "pail_ws/src/"), map[string]bool{".cpp": true, ".hpp": true, ".h": true}},
		// AD-5 (2026-09-06) moved the decision library to libpail_gate/ — the
		// producers of ERR_CONSTRAINT, ERR_ACTION_MISMATCH, … live there now.
		// Without this line the reverse check reported 33 orphans (SK-1, 2026-09-09).
		{testlayout.Path(t, "libpail_gate"), map[string]bool{".cpp": true, ".hpp": true, ".h": true}},
		{testlayout.Path(t, "services/pail_services_go/"), map[string]bool{".go": true}},
	}

	var out []site
	scanned := 0
	for _, tg := range targets {
		if _, err := os.Stat(tg.dir); err != nil {
			t.Fatalf("스캔 대상이 없다: %s (%v) — PAIL_REPO_ROOT 를 확인하라", tg.dir, err)
		}
		err := filepath.Walk(tg.dir, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !tg.exts[filepath.Ext(p)] {
				return nil
			}
			slash := filepath.ToSlash(p)
			if strings.Contains(slash, "/test/") || strings.HasSuffix(slash, "_test.go") {
				return nil
			}
			if strings.Contains(slash, "/internal/reason/") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			scanned++
			rel, _ := filepath.Rel(root, p)
			for i, line := range strings.Split(string(b), "\n") {
				for _, m := range errLiteral.FindAllStringSubmatch(line, -1) {
					out = append(out, site{code: m[1], at: filepath.ToSlash(rel) + ":" + itoa(i+1)})
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("스캔 실패 %s: %v", tg.dir, err)
		}
	}
	if scanned == 0 {
		t.Fatalf("스캔한 파일이 0개다 — 검사가 공허하게 통과하는 것을 막는다")
	}
	t.Logf("스캔 파일 %d개, ERR_* 리터럴 출현 %d회", scanned, len(out))
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestDriftForward — 소스에 있는데 사전에 없으면 FAIL.
func TestDriftForward(t *testing.T) {
	sites := scanProducers(t)

	missing := map[string][]string{}
	for _, s := range sites {
		if _, ok := Lookup(s.code); !ok {
			missing[s.code] = append(missing[s.code], s.at)
		}
	}
	if len(missing) == 0 {
		return
	}

	codes := make([]string, 0, len(missing))
	for c := range missing {
		codes = append(codes, c)
	}
	sort.Strings(codes)

	var b strings.Builder
	b.WriteString("사전에 없는 사유가 소스에서 발행된다 — 버스트에서 0xFF 로 뭉개지고 " +
		"북바운드는 처분을 실을 수 없다:\n")
	for _, c := range codes {
		b.WriteString("  " + c + "\n")
		for _, at := range missing[c] {
			b.WriteString("      " + at + "\n")
		}
	}
	b.WriteString("→ internal/reason/reason.go 에 값·평면·처분·등급·하한을 정해 등재하라.")
	t.Fatal(b.String())
}

// issuerPresent — PAIL-Issuer 묶음(cloud/issuer/, 내부는 services/pail_services_go/issuer/)이
// 이 트리에 있는가. 라이선스가 다른 묶음이라 PAIL-Core 만 받은 트리에는 없다.
func issuerPresent(t *testing.T) bool {
	t.Helper()
	_, err := os.Stat(testlayout.Resolve(t, "services/pail_services_go/issuer"))
	return err == nil
}

// TestDriftReverse — 사전에 있는데 생산자가 없으면 FAIL (ProducerNone 선언 시 제외).
//
// Issuer 선언은 양방향으로 잰다: 묶음이 있으면 그 코드의 생산자는 issuer/ 아래에
// **있어야** 하고, issuer/ 밖에서만 발행되는 코드에 Issuer 선언이 붙어 있으면 그것도
// 틀린 것이다. 묶음이 없는 트리에서는 Issuer 코드의 생산자 부재가 사실이므로 세어서
// 적고 넘어간다 — 조용히 넘기지 않는다.
func TestDriftReverse(t *testing.T) {
	sites := scanProducers(t)
	produced := map[string]bool{}
	inIssuer := map[string]bool{}
	outsideIssuer := map[string]bool{}
	for _, s := range sites {
		produced[s.code] = true
		if strings.Contains("/"+s.at, "/issuer/") {
			inIssuer[s.code] = true
		} else {
			outsideIssuer[s.code] = true
		}
	}
	present := issuerPresent(t)

	var orphans, staleDecl, issuerAbsent, issuerWrong []string
	for _, e := range table {
		if e.Code == "OK" {
			continue
		}
		has := produced[e.Code]
		switch {
		case !has && e.Issuer && !present:
			issuerAbsent = append(issuerAbsent, e.Code)
		case !has && !e.ProducerNone:
			orphans = append(orphans, e.Code)
		case has && e.ProducerNone:
			staleDecl = append(staleDecl, e.Code)
		case has && e.Issuer && !inIssuer[e.Code]:
			issuerWrong = append(issuerWrong, e.Code+" (생산자가 issuer/ 밖에만 있다)")
		case has && !e.Issuer && !outsideIssuer[e.Code]:
			issuerWrong = append(issuerWrong, e.Code+" (생산자가 issuer/ 안에만 있는데 Issuer 선언이 없다)")
		}
	}
	if len(issuerAbsent) > 0 {
		sort.Strings(issuerAbsent)
		t.Logf("PAIL-Issuer 묶음이 이 트리에 없다 — 생산자가 그 묶음에 사는 사유 %d건은 요구하지 않았다: %v",
			len(issuerAbsent), issuerAbsent)
	}
	if len(issuerWrong) > 0 {
		sort.Strings(issuerWrong)
		t.Errorf("Issuer 선언이 사실과 다르다: %v\n→ 선언은 생산자의 위치를 말한다. 위치가 바뀌었으면 선언을 바꿔라.", issuerWrong)
	}

	if len(orphans) > 0 {
		sort.Strings(orphans)
		t.Errorf("사전에 있으나 발행하는 곳이 없다: %v\n"+
			"→ 생산자가 실제로 사라졌다면 항목을 삭제하고, 동결 값이라 지울 수 없다면 "+
			"ProducerNone: true 를 명시 선언하라(신규 코드에는 붙일 수 없다).", orphans)
	}
	if len(staleDecl) > 0 {
		sort.Strings(staleDecl)
		t.Errorf("ProducerNone 선언이 사실과 다르다(생산자가 존재한다): %v\n"+
			"→ 선언을 제거하라. 사실이 아닌 예외는 역방향 검사를 무디게 만든다.", staleDecl)
	}
}
