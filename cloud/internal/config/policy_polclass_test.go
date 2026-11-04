// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package config

import (
	"strings"
	"testing"
)

// implementation contract — `D-L3` 네 절과 `S16f`~`S16j`.
//
// 판정은 사유 문구가 아니라 **규칙 id** 로 한다(`wantRule`, policy_s16_test.go).
// 그리고 각 픽스처는 **정확히 하나의 조건만** 위반한다(`H-B9`). 인접 가드가 대신
// 걸리면 그 관측점은 자기가 재려던 것을 재지 못한 채 초록이 된다 — 2026-08-22
// UIR 에서 귀속 불가 픽스처 둘이 서로를 가려 변형 하나가 아무것도 못 붉혔다.
//
// 규칙 배정에서 한 가지를 설계서(§4.2)와 다르게 착지시켰다:
// `preconditions[].id` 와 `revocation_classes[].id` 의 어휘는 **파일 안에서 닫히지
// 않는다** — 그 어휘가 곧 코드가 아는 집합이다. 그래서 둘은 `S16f`(어휘)가 아니라
// `S16h`(선언↔구현 정합, 양방향)가 잡는다. 둘 다 잡게 두면 한 규칙을 지워도
// 다른 규칙이 대신 붉어져 그 죽음이 관측되지 않는다.

// `evidence.window_ms` 는 2026-08-23(단계 6)에 사라졌다 — 게이트와 Go 가 같은
// 변경에서 함께 움직였다. `KnownFields(true)` 라 이 픽스처에 그 키를 되살리면
// `S16b`(unknown key) 로 붉는다. 창은 이제 한 자리에서만 온다:
// `preconditions[id=evidence_claim].freshness_ms`.
const validPolclassPolicy = `human_safety:
  enabled: true
  estop_on_human_detect: true
evidence:
  confidence_threshold: 0.90
  min_trust_class: identity_bearing
motion:
  max_linear_speed_mps: 1.0
  max_angular_speed_rps: 1.0
preconditions:
  - id: safety_feed
    class: must_check_live
    freshness_ms: 1000
    exempt_in_progress_step: true
  - id: evidence_claim
    class: must_check_live
    freshness_ms: 2000
    exempt_in_progress_step: false
revocation_classes:
  - id: world_state
    mechanism: recheck_at_decision
    max_effective_delay_ms: 0
  - id: operator_key
    mechanism: recheck_at_use
    max_effective_delay_ms: 0
  - id: issuer_key
    mechanism: reload_scoped
    max_effective_delay_ms: unbounded
trust_classes:
  - id: identity_bearing
    rank: 3
    sources: [RFID, NFC, BARCODE]
  - id: inferential
    rank: 2
    sources: [VISION]
  - id: asserted
    rank: 1
    sources: [MANUAL]
horizon:
  token_ttl_ms: 3600000
  max_steps: 5
authz:
  callers:
    - caller_kind: uds
      caller_id: "uid=10001,gid=10001"
      allow: [GetActiveToken, ReportDecision, Attest]
`

// mut 는 치환이 **실제로 일어났는지** 확인한다. 치환이 미끄러지면 픽스처는
// 원본 그대로이고, 그 통과는 "규칙이 안 잡았다"가 아니라 "아무것도 안 바꿨다"인데
// 둘은 같은 초록으로 도착한다(`H-B2`).
func mut(t *testing.T, old, new string) string {
	t.Helper()
	if !strings.Contains(validPolclassPolicy, old) {
		t.Fatalf("픽스처 전제 붕괴: 기준 정책에 %q 가 없다 — 이 케이스는 아무것도 재지 않는다", old)
	}
	return strings.Replace(validPolclassPolicy, old, new, 1)
}

// ── PC-01: 네 절 각각의 부재가 `S16e` 이고 어느 절인지 이름이 나온다 ──────────

func TestPC01FourSectionsAreRequired(t *testing.T) {
	// 절별로 따로 잰다. 넷을 한 번에 지우면 첫 번째만 보고되고 나머지 셋의
	// 필수성은 관측되지 않는다.
	for _, sec := range []string{"preconditions", "revocation_classes", "trust_classes", "horizon"} {
		t.Run(sec, func(t *testing.T) {
			content := dropSection(t, sec)
			wantRule(t, "S16e", content)
			// 거부만으로는 부족하다 — **어느 절인지** 이름이 나와야 한다.
			// 이름이 없으면 운영자는 넷 중 무엇을 빠뜨렸는지 파일을 다시 읽어
			// 찾아야 하고, 그 순간 거부는 진단이 아니라 벽이 된다.
			_, err := loadContent(t, content)
			if err == nil || !strings.Contains(err.Error(), sec) {
				t.Fatalf("%s: 사유에 절 이름이 없다: %v", sec, err)
			}
		})
	}
}

// dropSection 은 최상위 절 하나를 통째로 지운다. 들여쓰기된 줄까지 함께
// 지워야 하므로 단순 치환으로는 안 된다.
func dropSection(t *testing.T, name string) string {
	t.Helper()
	lines := strings.Split(validPolclassPolicy, "\n")
	out := make([]string, 0, len(lines))
	dropping := false
	found := false
	for _, ln := range lines {
		if strings.HasPrefix(ln, name+":") {
			dropping, found = true, true
			continue
		}
		if dropping {
			// 최상위 줄(들여쓰기 없음, 비어 있지 않음)을 만나면 절이 끝났다.
			if ln != "" && !strings.HasPrefix(ln, " ") && !strings.HasPrefix(ln, "-") {
				dropping = false
			} else {
				continue
			}
		}
		out = append(out, ln)
	}
	if !found {
		t.Fatalf("픽스처 전제 붕괴: 기준 정책에 %q 절이 없다", name)
	}
	return strings.Join(out, "\n")
}

// ── PC-02~04: 어휘 밖 값 = `S16f` ──────────────────────────────────────────
//
// 셋을 한 유닛으로 접지 않는다. 세 필드의 어휘 검사는 코드에서 세 블록이고,
// 하나를 지워도 나머지 둘이 같은 `S16f` 를 내면 그 죽음이 초록 아래로 지나간다.

func TestPC02PreconditionClassVocabulary(t *testing.T) {
	wantRule(t, "S16f", mut(t, "    class: must_check_live\n    freshness_ms: 1000",
		"    class: maybe_live\n    freshness_ms: 1000"))
}

func TestPC03RevocationMechanismVocabulary(t *testing.T) {
	wantRule(t, "S16f", mut(t, "    mechanism: recheck_at_decision", "    mechanism: gossip"))
}

func TestPC04TrustSourceVocabulary(t *testing.T) {
	// `Evidence.msg:5` 의 다섯 밖. LIDAR 는 그럴듯해서 위험하다 — 조용히 무시되면
	// 운영자는 라이다 증거에 등급을 매겼다고 믿는다.
	wantRule(t, "S16f", mut(t, "    sources: [VISION]", "    sources: [VISION, LIDAR]"))
}

// ── PC-05~07: 참조 무결성 = `S16g` ────────────────────────────────────────

func TestPC05MinTrustClassMustResolve(t *testing.T) {
	wantRule(t, "S16g", mut(t, "  min_trust_class: identity_bearing", "  min_trust_class: platinum"))
}

func TestPC06SourceMappedTwice(t *testing.T) {
	// MANUAL 이 inferential 과 asserted 양쪽에. 다섯 전부 여전히 사상돼 있으므로
	// 누락 방향은 걸리지 않는다 — 이 픽스처가 재는 것은 중복 하나뿐이다.
	wantRule(t, "S16g", mut(t, "    sources: [VISION]", "    sources: [VISION, MANUAL]"))
}

func TestPC07SourceMappedNowhere(t *testing.T) {
	// 빈 목록은 그 자체로는 위반이 아니다(정량 규칙에 없다). 위반은 MANUAL 이
	// 어느 클래스에도 없다는 것 하나다 — **양방향**의 반대 방향이다.
	// 이 방향이 없으면 표를 비워도 초록이다(`U-B1`).
	wantRule(t, "S16g", mut(t, "    sources: [MANUAL]", "    sources: []"))
}

// ── PC-08~09: 선언 ↔ 구현 정합 = `S16h`, 양방향 ────────────────────────────

func TestPC08PredicateInTableOnly(t *testing.T) {
	// 코드에 소비자가 없는 술어. 조용히 무시하면 운영자는 신선도를 걸었다고
	// 믿는 채로 아무 검사도 안 도는 전제를 갖게 된다.
	wantRule(t, "S16h", mut(t, "revocation_classes:",
		`  - id: sensor_feed
    class: must_check_live
    freshness_ms: 500
    exempt_in_progress_step: false
revocation_classes:`))
}

func TestPC09PredicateInCodeOnly(t *testing.T) {
	wantRule(t, "S16h", mut(t, `  - id: safety_feed
    class: must_check_live
    freshness_ms: 1000
    exempt_in_progress_step: true
`, ""))
}

func TestPC08bRevocationFactInTableOnly(t *testing.T) {
	// 철회성 사실도 같은 양방향이다(§7 항1). 술어 쪽만 재면 이 방향은
	// 관측점이 없다.
	wantRule(t, "S16h", mut(t, "trust_classes:",
		`  - id: gossip_channel
    mechanism: recheck_at_use
    max_effective_delay_ms: 0
trust_classes:`))
}

func TestPC09bRevocationFactInCodeOnly(t *testing.T) {
	wantRule(t, "S16h", mut(t, `  - id: operator_key
    mechanism: recheck_at_use
    max_effective_delay_ms: 0
`, ""))
}

// ── PC-10~12: 정량·정합 = `S16i` ──────────────────────────────────────────

func TestPC10ReloadScopedMustBeUnbounded(t *testing.T) {
	// 리로드 채널이 없는 사실에 유한 상한을 적는 것은 거짓이고, 그 거짓이
	// §1.1 의 min(…) 명제를 참으로 보이게 만든다(`C-P1`).
	wantRule(t, "S16i", mut(t, `    mechanism: reload_scoped
    max_effective_delay_ms: unbounded`,
		`    mechanism: reload_scoped
    max_effective_delay_ms: 5000`))
}

func TestPC11DuplicateRank(t *testing.T) {
	// 등급이 같으면 "min_trust_class 이상"이라는 문장이 순서를 못 정한다.
	wantRule(t, "S16i", mut(t, "    rank: 2", "    rank: 3"))
}

func TestPC12FreshnessMustBePositive(t *testing.T) {
	// 0 은 이 시스템에서 **무제한**을 뜻해 왔다(`requireFields` 주석). 신선도에서
	// 0 을 허용하면 must_check_live 가 아무것도 요구하지 않게 된다.
	wantRule(t, "S16i", mut(t, "    freshness_ms: 1000", "    freshness_ms: 0"))
}

func TestPC12bHorizonQuantities(t *testing.T) {
	wantRule(t, "S16i", mut(t, "  max_steps: 5", "  max_steps: 0"))
	wantRule(t, "S16i", mut(t, "  token_ttl_ms: 3600000", "  token_ttl_ms: 0"))
}

// ── PC-13: 지평 env 잔재 = `S16j` (§12 단계 6, `D-L9` 와 같은 단계) ──────────
//
// 이 규칙이 단계 4 가 아니라 여기 있는 이유는 순서다. 거부를 이전보다 먼저 세우면
// `cmd/*/main.go` 가 아직 `LeasePolicyFromEnv()` 를 부르는 동안 그 두 변수가
// **읽히기도 전에** 프로세스를 78 로 죽인다 — 이전을 강제하는 것이 아니라 이전이
// 일어나기 전에 배치를 못 쓰게 만드는 것이다. 2026-08-23 에 셋이 함께 착지했다:
// 출처 이전 · 이 거부 · 리그 셋의 env 이관.
//
// 조용히 무시하지 않는 이유가 이 트랙의 전부다. `PAIL_LEASE_TTL_MS=60000` 을 걸어
// 둔 운영자는 토큰 수명을 1분으로 조였다고 믿는데, 이전 뒤에 그 변수는 아무것도
// 하지 않는다 — 그리고 정책 파일은 여전히 1시간을 말한다. 그것이 `P-19` 와 정확히
// 같은 형태의 거짓이다(믿는 값과 도는 값이 다른데 아무 줄도 붉지 않는다).

func TestPC13LeaseEnvResidueRefused(t *testing.T) {
	// 두 변수를 **따로** 잰다. 함께 걸면 한쪽 검사를 통째로 지워도 다른 쪽이 같은
	// `S16j` 를 내어 그 죽음이 초록 아래로 지나간다(`H-B9`).
	for _, env := range []string{"PAIL_LEASE_TTL_MS", "PAIL_LEASE_MAX_STEPS"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "60000")
			wantRule(t, "S16j", validPolclassPolicy)
			// 거부만으로는 부족하다 — **어느 변수인지** 이름이 나와야 한다.
			// 이름이 없으면 운영자는 두 변수 중 무엇을 지워야 하는지 모른 채
			// 78 만 본다.
			_, err := loadContent(t, validPolclassPolicy)
			if err == nil || !strings.Contains(err.Error(), env) {
				t.Fatalf("사유에 변수 이름이 없다: %v", err)
			}
		})
	}
}

func TestPC13LeaseEnvAbsenceIsNotResidue(t *testing.T) {
	// 항상 붉은 게이트는 게이트가 아니라 벽이다. 빈 문자열도 잔재가 아니다 —
	// compose 가 `PAIL_LEASE_TTL_MS=` 로 빈 값을 주입하는 형태가 실제로 있었고
	// (`deploy/docker-compose.yml`), 그것까지 거부하면 이전이 배치를 깨뜨린다.
	t.Setenv("PAIL_LEASE_TTL_MS", "")
	t.Setenv("PAIL_LEASE_MAX_STEPS", "")
	if _, err := loadContent(t, validPolclassPolicy); err != nil {
		t.Fatalf("빈 값이 잔재로 읽혔다: %v", err)
	}
}

// ── PC-14: 유효 정책은 통과하고 읽은 값이 실제로 돌아온다 ────────────────────

func TestPC14ValidPolicyLoadsAndValuesSurvive(t *testing.T) {
	// 항상 붉은 게이트는 게이트가 아니라 벽이다. 그리고 "거부하지 않았다"만
	// 재면 로더가 네 절을 **파싱조차 안 해도** 초록이다 — 값을 되읽는다.
	p, err := loadContent(t, validPolclassPolicy)
	if err != nil {
		t.Fatalf("유효 정책이 거부됐다: %v", err)
	}
	if got := p.Precondition("safety_feed").FreshnessMS; got != 1000 {
		t.Fatalf("safety_feed.freshness_ms = %d, 기대 1000", got)
	}
	if got := p.Precondition("evidence_claim").FreshnessMS; got != 2000 {
		t.Fatalf("evidence_claim.freshness_ms = %d, 기대 2000", got)
	}
	if !p.Precondition("safety_feed").ExemptInProgressStep {
		t.Fatalf("safety_feed.exempt_in_progress_step 가 false — gate_core.cpp:55-58 의 예외가 사라졌다")
	}
	if p.Precondition("evidence_claim").ExemptInProgressStep {
		t.Fatalf("evidence_claim.exempt_in_progress_step 가 true — 두 술어가 같은 값을 갖는다")
	}
	if got := p.Horizon.TokenTTLMS; got != 3600000 {
		t.Fatalf("horizon.token_ttl_ms = %d, 기대 3600000", got)
	}
	if got := p.Horizon.MaxSteps; got != 5 {
		t.Fatalf("horizon.max_steps = %d, 기대 5", got)
	}
	// 신뢰 등급은 **source 로** 되물어야 의미가 있다. id 로만 되읽으면 사상이
	// 실제로 만들어졌는지는 재지 않는다.
	if got := p.TrustRank("RFID"); got != 3 {
		t.Fatalf("TrustRank(RFID) = %d, 기대 3", got)
	}
	if got := p.TrustRank("MANUAL"); got != 1 {
		t.Fatalf("TrustRank(MANUAL) = %d, 기대 1", got)
	}
	// 어휘 밖 문자열은 0 이다 — 런타임에 온 미지 source 가 최저 등급도 못 받는다.
	if got := p.TrustRank("LIDAR"); got != 0 {
		t.Fatalf("TrustRank(LIDAR) = %d, 기대 0 (어휘 밖은 등급이 없다)", got)
	}
	if got := p.MinTrustRank(); got != 3 {
		t.Fatalf("MinTrustRank() = %d, 기대 3 (identity_bearing)", got)
	}
	if got := p.Revocation("issuer_key").MaxEffectiveDelayUnbounded; !got {
		t.Fatalf("issuer_key 의 상한이 unbounded 로 읽히지 않았다 — C-P1 배너의 근거가 사라진다")
	}
	if p.Revocation("world_state").MaxEffectiveDelayUnbounded {
		t.Fatalf("world_state 가 unbounded 로 읽혔다 — 0 과 unbounded 가 같은 값이 됐다")
	}
}
