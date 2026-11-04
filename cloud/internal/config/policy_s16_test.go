// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package config

import (
	"github.com/glowfly/pail/services/internal/testlayout"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// `B6-7` 행위 유닛 .
//
// 다섯 사망을 **각각** 잰다. 한 유닛으로 접으면 규칙 하나를 통째로 지워도 나머지
// 넷이 같은 붉은 줄을 내어 그 죽음이 초록 아래로 지나간다(`H-B9`). 판정은 사유
// 문구가 아니라 **규칙 id** 로 한다 — 문구는 바뀌어도 규칙의 생사는 계속 보여야
// 한다.

// 유효한 정책의 모양은 **하나뿐**이므로 사본을 두지 않는다(policy_polclass_test.go).
// 두 벌이면 `D-L3` 가 절을 더한 날 이쪽 사본만 낡고, 낡은 사본은 "합성 정본이
// 거부됐다"가 아니라 위 다섯 유닛이 전부 **엉뚱한 사유**(S16e)로 초록을 잃는
// 형태로 도착한다 — 그때 붉은 줄의 뜻은 결함이 아니라 픽스처의 낡음이다.
const validPolicy = validPolclassPolicy

func loadContent(t *testing.T, content string) (*Policy, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	p, _, err := LoadPolicy(path)
	return p, err
}

// wantRule 는 "거부했다"가 아니라 "**이 규칙이** 거부했다"를 잰다. 거부만 재면
// 규칙 하나를 지워도 다른 규칙이 대신 잡아 통과하고, 그때 지워진 규칙의 부재는
// 관측되지 않는다.
func wantRule(t *testing.T, id, content string) {
	t.Helper()
	p, err := loadContent(t, content)
	if err == nil {
		t.Fatalf("%s: 적재가 성공했다 (%+v). 형식이 깨진 정책이 기동을 통과한다", id, p)
	}
	if got := deploysec.RuleID(err); got != id {
		t.Fatalf("%s: 규칙 id %q (사유: %v)", id, got, err)
	}
}

func TestS16RefusesEmptyPolicy(t *testing.T) {
	// YAML 은 빈 문서를 오류로 보지 않는다. 그것이 §3.8.1 결함의 뿌리이고,
	// 주석뿐인 파일이 같은 바이트로 도착하므로 둘 다 잰다.
	wantRule(t, "S16", "")
	wantRule(t, "S16", "# 정책을 아직 안 적었다\n")
}

func TestS16RefusesUnknownField(t *testing.T) {
	// 오타난 키가 조용히 무시되면 운영자가 켠 보호가 꺼진 채 기동한다.
	wantRule(t, "S16b", strings.Replace(validPolicy, "human_safety:", "human_safty:", 1))
	wantRule(t, "S16b", validPolicy+"unexpected_section:\n  x: 1\n")
}

func TestS16RefusesMissingRequired(t *testing.T) {
	// 결측을 0 으로 접으면 "적지 않았다"가 **무제한**(속도)·**해제**(사람 안전)가
	// 된다. 절 단위 결측과 필드 단위 결측을 각각 잰다.
	wantRule(t, "S16e", strings.Replace(validPolicy,
		"motion:\n  max_linear_speed_mps: 1.0\n  max_angular_speed_rps: 1.0\n", "", 1))
	wantRule(t, "S16e", strings.Replace(validPolicy, "  max_linear_speed_mps: 1.0\n", "", 1))
	wantRule(t, "S16e", strings.Replace(validPolicy, "  enabled: true\n", "", 1))
}

func TestS16RefusesMissingAuthz(t *testing.T) {
	// 인가표가 없는 채로 뜬 프로세스는 "인가가 선 것처럼" 보인다. 집행이 아직
	// 없더라도 그 상태를 만들지 않는 것이 `O-2` 다.
	wantRule(t, "S16c", strings.Split(validPolicy, "authz:")[0])
	wantRule(t, "S16c", strings.Split(validPolicy, "authz:")[0]+"authz:\n  callers: []\n")
}

func TestS16RefusesBadAuthzEntry(t *testing.T) {
	base := strings.Split(validPolicy, "authz:")[0]
	entry := func(kind, id, allow string) string {
		return base + "authz:\n  callers:\n    - caller_kind: " + kind +
			"\n      caller_id: \"" + id + "\"\n      allow: " + allow + "\n"
	}
	good := "[GetActiveToken]"
	for _, tc := range []struct {
		name, content string
	}{
		// `unknown` 은 "호출자를 식별하지 못했다"이다. 인가 대상으로 적을 수 있으면
		// 미식별 호출자에게 자격을 주는 문장이 형식상 합법이 된다.
		{"kind unknown", entry("unknown", "uid=1,gid=1", good)},
		{"kind 오타", entry("mTLS", strings.Repeat("a", 64), good)},
		// id 형식은 kind 마다 다르다 — 저널이 기록하는 값과 같아야 한다.
		{"mtls 에 uds 형식", entry("mtls", "uid=1,gid=1", good)},
		{"uds 에 hex", entry("uds", strings.Repeat("a", 64), good)},
		{"hex 대문자", entry("mtls", strings.Repeat("A", 64), good)},
		{"hex 63자", entry("mtls", strings.Repeat("a", 63), good)},
		// 빈 id = "소켓이었지만 피어를 알 수 없었다". 인가 대상이 아니다.
		{"빈 id", entry("uds", "", good)},
		// 빈 allow 는 "아무것도"로도 "전부"로도 읽힌다. 읽는 쪽이 정하게 두지 않는다.
		{"빈 allow", entry("uds", "uid=1,gid=1", "[]")},
		{"공백 메서드", entry("uds", "uid=1,gid=1", "[\"\"]")},
	} {
		t.Run(tc.name, func(t *testing.T) { wantRule(t, "S16d", tc.content) })
	}
	// 같은 호출자를 두 번 적으면 하나만 지우는 폐기가 통과한다.
	t.Run("중복 항목", func(t *testing.T) {
		dup := entry("uds", "uid=1,gid=1", good) +
			"    - caller_kind: uds\n      caller_id: \"uid=1,gid=1\"\n      allow: [Attest]\n"
		wantRule(t, "S16d", dup)
	})
}

// 양성 대조. 만족 시 통과를 재지 않으면 이것은 게이트가 아니라 벽이고, 그때는
// **배포된 정책까지 거부하면서도** 위 다섯 유닛이 전부 초록이다.
func TestS16AcceptsShippedPolicies(t *testing.T) {
	if p, err := loadContent(t, validPolicy); err != nil {
		t.Fatalf("합성 정본이 거부됐다: %v (%+v)", err, p)
	}
	// `config/policy.yaml` 이 유일한 원본이고 `deploy/config-*` 는 split_config.sh
	// 가 만드는 사본이다(추적되지 않는다). 있으면 잰다 — 사본이 낡으면 배포된
	// 프로세스가 78 로 죽으므로, 없는 것과 낡은 것을 같게 취급하지 않는다.
	checked := 0
	for _, rel := range []string{
		testlayout.Path(t, "config/policy.yaml"),
		testlayout.Resolve(t, "deploy/config-robot/policy.yaml"),
		testlayout.Resolve(t, "deploy/config-cloud/policy.yaml"),
	} {
		if _, err := os.Stat(rel); os.IsNotExist(err) {
			t.Logf("%s 없음 (split_config.sh 미실행) — 건너뜀", rel)
			continue
		}
		p, raw, err := LoadPolicy(rel)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if len(raw) == 0 {
			t.Fatalf("%s: raw 가 비었다", rel)
		}
		if p.Motion.MaxLinearSpeedMPS != 1.0 || p.Motion.MaxAngularSpeedRPS != 1.0 {
			t.Fatalf("%s: 한계 (%v/%v), want 1.0/1.0", rel,
				p.Motion.MaxLinearSpeedMPS, p.Motion.MaxAngularSpeedRPS)
		}
		if len(p.Authz.Callers) == 0 {
			t.Fatalf("%s: 인가 항목 0건", rel)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("배포 정책을 하나도 읽지 못했다 — 아무것도 재지 않고 낸 초록이다")
	}
	t.Logf("배포 정책 %d개 통과", checked)
}

// 명시적으로 적힌 `false`·`0` 은 통과한다. `S16e` 가 재는 것은 값이 아니라
// **운영자가 그 값을 선언했는가**이고, 둘을 섞으면 "사람 안전을 끄겠다"는 선언을
// 형식이 표현할 수 없게 된다. `max_linear_speed_mps: 0` 이 여전히 무제한인 것은
// 이 규칙의 밖이다 — §11 `U-B6`.
func TestS16AcceptsExplicitZeroAndFalse(t *testing.T) {
	c := strings.Replace(validPolicy, "  enabled: true\n", "  enabled: false\n", 1)
	c = strings.Replace(c, "max_linear_speed_mps: 1.0", "max_linear_speed_mps: 0", 1)
	p, err := loadContent(t, c)
	if err != nil {
		t.Fatalf("명시된 false/0 이 거부됐다: %v", err)
	}
	if p.HumanSafety.Enabled || p.Motion.MaxLinearSpeedMPS != 0 {
		t.Fatalf("값이 실리지 않았다: %+v", p)
	}
}
