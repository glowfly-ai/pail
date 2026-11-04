// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// G-EUC-01 (EC-1, EUC D1): `retention:` 은 production 에서 필수(S24)이고, 선언은
// 자기모순이면 거부된다(S25). 규칙마다 테스트가 하나다 — 한 규칙을 지우면 정확히
// 한 이름이 붉어야 그 규칙의 생사가 보인다(H-B9). 값 셋을 고를 때 **다른 규칙은
// 전부 만족**시킨다: RET05 는 바닥만, RET06 은 blackbox<lower 만, RET07 은
// anchor<blackbox 만 어긴다. 두 규칙을 함께 어기는 픽스처는 어느 쪽이 잡았는지
// 말하지 못한다.
package config

import (
	"bytes"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/deploysec"
)

func withRetention(bb, an, lb string) string {
	var sb strings.Builder
	sb.WriteString(validPolicy)
	sb.WriteString("retention:\n")
	if bb != "" {
		sb.WriteString("  blackbox_years: " + bb + "\n")
	}
	if an != "" {
		sb.WriteString("  anchor_years: " + an + "\n")
	}
	if lb != "" {
		sb.WriteString("  lower_bound_years: " + lb + "\n")
	}
	return sb.String()
}

func TestRET01_ValidRetentionLoadsAndIsDeclared(t *testing.T) {
	p, err := loadFrom(t, withRetention("5", "7", "5"))
	if err != nil {
		t.Fatalf("유효한 retention 이 거부됨: %v", err)
	}
	r := p.Retention
	if !r.Declared || r.BlackboxYears != 5 || r.AnchorYears != 7 || r.LowerBoundYears != 5 {
		t.Fatalf("retention 값이 실리지 않음: %+v", r)
	}
}

func TestRET02_MissingSectionRefusedInProduction(t *testing.T) {
	t.Setenv("PAIL_PROFILE", "production")
	wantRule(t, "S24", validPolicy)
}

func TestRET03_MissingSectionIsBannerOutsideProduction(t *testing.T) {
	// 배너는 관측점이다 — 찍히지 않는 배너는 없는 배너다. 직접 호출로 바이트를 잰다.
	var banner bytes.Buffer
	r, err := retentionAbsent("dev", &banner)
	if err != nil {
		t.Fatalf("dev 에서 결측이 거부됨: %v", err)
	}
	if r.Declared {
		t.Fatalf("결측이 Declared=true 로 실림: %+v", r)
	}
	if !strings.Contains(banner.String(), "S24") || !strings.Contains(banner.String(), "retention") {
		t.Fatalf("배너에 규칙 id 와 절 이름이 없다: %q", banner.String())
	}
	// 로더 경로에서도 같은 값이어야 한다.
	t.Setenv("PAIL_PROFILE", "dev")
	p, err := loadFrom(t, validPolicy)
	if err != nil {
		t.Fatalf("dev 로더 경로에서 결측이 거부됨: %v", err)
	}
	if p.Retention.Declared {
		t.Fatalf("로더 경로: 결측이 Declared=true 로 실림: %+v", p.Retention)
	}
}

func TestRET04_MissingLeafRefusedAndNamed(t *testing.T) {
	cases := map[string]string{
		"blackbox_years":    withRetention("", "7", "5"),
		"anchor_years":      withRetention("5", "", "5"),
		"lower_bound_years": withRetention("5", "7", ""),
	}
	for leaf, content := range cases {
		t.Run(leaf, func(t *testing.T) {
			wantRule(t, "S25", content)
			_, err := loadContent(t, content)
			if err == nil || !strings.Contains(err.Error(), leaf) {
				t.Fatalf("%s: 사유에 잎 이름이 없다: %v", leaf, err)
			}
		})
	}
}

func TestRET05_LowerBoundBelowFloorRefused(t *testing.T) {
	// lower=4 만 어긴다. blackbox(5)≥lower(4) · anchor(7)≥blackbox(5) 는 만족.
	wantRule(t, "S25", withRetention("5", "7", "4"))
	_, err := loadContent(t, withRetention("5", "7", "4"))
	if err == nil || !strings.Contains(err.Error(), "lower_bound_years") || !strings.Contains(err.Error(), "floor") {
		t.Fatalf("사유가 바닥 위반을 이름으로 말하지 않는다: %v", err)
	}
}

func TestRET06_BlackboxBelowLowerBoundRefused(t *testing.T) {
	// blackbox=4 < lower=5 만 어긴다. lower(5)≥바닥 · anchor(7)≥blackbox(4) 는 만족.
	wantRule(t, "S25", withRetention("4", "7", "5"))
	_, err := loadContent(t, withRetention("4", "7", "5"))
	if err == nil || !strings.Contains(err.Error(), "blackbox_years=4") {
		t.Fatalf("사유가 blackbox 하한 위반을 값으로 말하지 않는다: %v", err)
	}
}

func TestRET07_AnchorBelowBlackboxRefused(t *testing.T) {
	// anchor=4 < blackbox=5 만 어긴다. lower(5)≥바닥 · blackbox(5)≥lower(5) 는 만족.
	wantRule(t, "S25", withRetention("5", "4", "5"))
	_, err := loadContent(t, withRetention("5", "4", "5"))
	if err == nil || !strings.Contains(err.Error(), "anchor_years=4") {
		t.Fatalf("사유가 anchor 하한 위반을 값으로 말하지 않는다: %v", err)
	}
}

// pins_current_behavior: 비정수는 S25 가 아니라 엄격 파서(S16b)에 먼저 걸린다.
// 설계서 D1 은 「비정수 → S25」라 적었지만 실측은 여기다 — 두 규칙이 같은 결함을
// 두 번 재지 않도록 문서 쪽을 실측에 맞춘다. 이 줄이 붉는 날은 파서 순서가 바뀐
// 날이다.
func TestRET08_NonIntegerArrivesAsStrictParseError(t *testing.T) {
	_, err := loadContent(t, withRetention("five", "7", "5"))
	if err == nil {
		t.Fatal("비정수 blackbox_years 가 수용됨")
	}
	if got := deploysec.RuleID(err); got != "S16b" {
		t.Fatalf("비정수의 규칙 id %q (사유: %v) — S16b 에서 옮겨 갔다면 이 핀과 D1 문면을 함께 갱신할 것", got, err)
	}
}

func TestRET09_VerifierParseAgreesWithLoader(t *testing.T) {
	// 검증기는 느슨한 파서로 같은 규칙을 부른다. 둘이 갈라지면 발급자가 거부한
	// 파일을 검증기가 「matched」로 읽는다.
	r, err := RetentionFromPolicyBytes([]byte(withRetention("6", "8", "5")))
	if err != nil || !r.Declared || r.BlackboxYears != 6 || r.AnchorYears != 8 || r.LowerBoundYears != 5 {
		t.Fatalf("느슨한 파서가 유효한 선언을 다르게 읽음: %+v err=%v", r, err)
	}
	if _, err := RetentionFromPolicyBytes([]byte(withRetention("5", "7", "4"))); deploysec.RuleID(err) != "S25" {
		t.Fatalf("느슨한 파서가 로더의 S25 를 내지 않음: %v", err)
	}
	r, err = RetentionFromPolicyBytes([]byte(validPolicy))
	if err != nil || r.Declared {
		t.Fatalf("결측이 undeclared 로 읽히지 않음: %+v err=%v", r, err)
	}
}
