// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// G-ISS-14: 정책 로더는 오타·결측·빈 파일을 거부한다.
//
// **B-F1 은 2026-08-11 `B6-7` 로 해소됐다**. 아래 셋은 게이트를
// 벗고 상시 실행된다 — 기대를 올리는 것은 잠재우는 게 아니라 **회귀 감지로
// 바꾸는 것**이다. 규칙 id 까지 재는 행위 유닛은 `policy_s16_test.go` 에 있다.
//
// 넷째(명시적 0 한계)는 결함이 아니라 **결정된 경계**다 — `U-B6`(deployment policy,
// 2026-08-12, implementation contract): `0 = no per-token limit` 어휘 유지, 발급·게이트
// 계약 무변경. `S16` 이 닫은 것은 0 이 *실수로* 들어오는 경로(오타·결측·빈
// 파일)이고, 명시적 0 은 열린 채가 정본이다. 그 경계를 아래 핀 테스트가
// 고정한다 — 어휘를 바꾸는 날 이 테스트가 붉어 등재부 갱신을 강제한다.
package config

import (
	"github.com/glowfly/pail/services/internal/testlayout"
	"strings"
	"testing"
)

func loadFrom(t *testing.T, content string) (*Policy, error) {
	t.Helper()
	return loadContent(t, content)
}

func TestPolicyRED_UnknownKeyRejected(t *testing.T) {
	// 오타 키(max_linear_speed ← _mps 누락)가 조용히 버려지면 한계가 0 이 된다.
	p, err := loadFrom(t, strings.Replace(validPolicy,
		"max_linear_speed_mps: 1.0", "max_linear_speed: 1.0", 1))
	if err == nil {
		t.Fatalf("G-ISS-14: 미지의 키가 오류 없이 수용됨 (MaxLinearSpeedMPS=%v — 오타가 0 한계로 둔갑)",
			p.Motion.MaxLinearSpeedMPS)
	}
}

func TestPolicyRED_MissingRequiredRejected(t *testing.T) {
	p, err := loadFrom(t, "human_safety:\n  enabled: true\n")
	if err == nil {
		t.Fatalf("G-ISS-14: motion 블록 결측이 수용됨 (Motion=%+v — 게이트는 0 을 무제한으로 읽는다)",
			p.Motion)
	}
}

func TestPolicyRED_EmptyFileRejected(t *testing.T) {
	p, err := loadFrom(t, "{}\n")
	if err == nil {
		t.Fatalf("G-ISS-14: 빈 정책이 수용됨 (%+v)", p)
	}
}

// TestPolicyZeroLimit_PinsUB6Vocabulary 는 pins_current_behavior 다 — 결함
// 검출이 아니라 `U-B6` 결정(명시적 0 = per-token 무제한, 어휘 유지)의 경계
// 고정. 나머지가 **전부 갖춰진** 정책에서 한계만 0 이어야 한다 — 그래야
// `S16e`(필수 절 결측) 같은 다른 규칙에 얹힌 거부/수용과 구분된다.
// 이 테스트가 붉는 날은 회귀가 아니라 계약 변경이다: 게이트의 0 어휘와
// G-ISS-14 등재부 문면을 함께 갱신해야 한다.
func TestPolicyZeroLimit_PinsUB6Vocabulary(t *testing.T) {
	c := strings.Replace(validPolicy, "max_linear_speed_mps: 1.0", "max_linear_speed_mps: 0", 1)
	c = strings.Replace(c, "max_angular_speed_rps: 1.0", "max_angular_speed_rps: 0", 1)
	p, err := loadFrom(t, c)
	if err != nil {
		t.Fatalf("U-B6 계약 변경 감지: 명시적 0 한계가 로딩에서 거부됨 (%v) — 어휘를 바꿨다면 게이트 0 처리와 G-ISS-14 문면을 함께 갱신할 것", err)
	}
	if p.Motion.MaxLinearSpeedMPS != 0 || p.Motion.MaxAngularSpeedRPS != 0 {
		t.Fatalf("명시적 0 이 0 으로 실리지 않음: %+v", p.Motion)
	}
}

// ValidPolicyLoads 는 항상 실행된다 — 리포 정본 정책이 로드되고 알려진 리터럴
// 한계가 실린다는 양성 대조군. RED 4건이 로더의 구멍을 명세할 때, 이 케이스는
// 구멍을 막는 수정이 정상 경로를 부수지 않았음을 지킨다.
func TestPolicyValidPolicyLoads(t *testing.T) {
	p, raw, err := LoadPolicy(testlayout.Path(t, "config/policy.yaml"))
	if err != nil {
		t.Fatalf("LoadPolicy(repo policy.yaml): %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("raw policy bytes empty")
	}
	if p.Motion.MaxLinearSpeedMPS != 1.0 || p.Motion.MaxAngularSpeedRPS != 1.0 {
		t.Fatalf("정본 정책 한계 (%v/%v), want 1.0/1.0",
			p.Motion.MaxLinearSpeedMPS, p.Motion.MaxAngularSpeedRPS)
	}
}
