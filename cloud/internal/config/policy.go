// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// §3.8  `B6-7`. 이 로더가 거부하는 것은 "보호가 꺼져 있다"가 아니라
// **설정이 형식으로 깨졌다**이므로, `PAIL_PROFILE=dev` 가 면제하지 않는다.
//
// 고치는 결함(§3.8.1 실측): `yaml.Unmarshal` 은 빈 문서를 오류로 보지 않고 미지
// 필드를 조용히 버린다. 그래서 빈 정책 파일이 **적재 성공**으로 돌아오고 전
// 필드가 0값으로 채워지는데, 게이트는 `max_linear_speed_mps=0` 을
// `0 = no per-token limit`(strict_verify.hpp)으로 읽는다. 즉 파일 하나가 비면
// 속도 상한이 통째로 사라지고 사람 안전도 함께 꺼진다. 같은 파일을 읽는 C++
// 쪽(`pep_gate_node.cpp`)은 반대로 fail-closed 다 — 두 벌이고, 조용한 쪽이 Go 다.

type Policy struct {
	HumanSafety struct {
		Enabled            bool `yaml:"enabled"`
		EStopOnHumanDetect bool `yaml:"estop_on_human_detect"`
	} `yaml:"human_safety"`

	Evidence struct {
		// `window_ms` 는 2026-08-23(단계 6)에 `preconditions[id=evidence_claim].
		// freshness_ms` 로 이사했다(`D-L1`, §3.1). 여기에 되살리지 말 것 — 두 절이
		// 같은 수를 말하는 순간 P-19 가 그대로 돌아온다(그때도 두 값은 우연히
		// 2000 으로 같았고, 그 우연이 몇 달 동안 검사를 통과시켰다).
		ConfidenceThreshold float64 `yaml:"confidence_threshold"`
		// MinTrustClass 는 `trust_classes[].id` 중 하나다. 집행은 게이트가
		// 한다(`D-L5`, §12 단계 5) — 여기서는 참조가 풀리는지만 잰다.
		MinTrustClass string `yaml:"min_trust_class"`
	} `yaml:"evidence"`

	Motion struct {
		MaxLinearSpeedMPS  float64 `yaml:"max_linear_speed_mps"`
		MaxAngularSpeedRPS float64 `yaml:"max_angular_speed_rps"`
	} `yaml:"motion"`

	// TokenSchema (SK-4): the token edition this issuer mints — 4 or 5.
	// Never 0 after LoadPolicy (absent = TokenSchemaClassMask).
	TokenSchema int `yaml:"token_schema"`

	// Guardrails (SK-1) is the envelope the issuer bakes per skill call.
	Guardrails Guardrails `yaml:"guardrails"`

	// ── `D-L3` 네 절 ────────────────────────────────────────────────────────
	Preconditions     []Precondition    `yaml:"preconditions"`
	RevocationClasses []RevocationClass `yaml:"revocation_classes"`
	TrustClasses      []TrustClass      `yaml:"trust_classes"`
	Horizon           Horizon           `yaml:"horizon"`

	// Authz 는 발급자 인가표다(§3.8.2). **별도 파일로 두지 않는다** — 봉인이
	// `pail-config-seal:v2` 의 `policy_file_sha256` 한 키로 이 파일을 덮고 있고,
	// 다른 파일은 새 정규문 키를 요구해 `R1` 발동이 된다.
	//
	// 집행(gRPC 인터셉터)은 `implementation contract` 의 몫이다. 이 패키지가 내는 것은 형식과
	// 기동 거부뿐이므로, 이 표가 있다고 해서 인가가 서 있는 것은 아니다.
	Authz Authz `yaml:"authz"`

	// Retention 은 EC-1 의 보존 선언이다(`retention.go`). 집행 타이머가 아니라
	// 봉인되는 숫자 — `Declared=false` 는 production 밖에서만 가능하다(S24).
	Retention Retention `yaml:"retention"`

	// RevocationHysteresis (AS-5 / O-8) damps the issuer's UNATTENDED re-grant
	// after a revocation storm: a node that flapped >= FlapThreshold times
	// inside FlapWindowMS has its recompile deferred until it has been quiet
	// for SettleMS. Revocation itself is never delayed. Declared=false is the
	// pre-AS-5 behavior (no damping) and is logged at startup.
	RevocationHysteresis RevocationHysteresis `yaml:"revocation_hysteresis"`
}

// RevocationHysteresis holds the operator's thresholds; the mechanism lives
// in the issuer (grpcserver/hysteresis.go).
type RevocationHysteresis struct {
	Declared      bool
	FlapWindowMS  int
	FlapThreshold int
	SettleMS      int
}

// ── `D-L3` 네 절의 값 타입  ──────────────────────────────

// Precondition 은 결정 시점에 **살아 있어야 하는 전제**다. `Class` 는 v1 에서
// `must_check_live` 한 값뿐인데도 필드로 두는 근거는 §4.2 에 있다: 두 번째 값이
// 생기는 날 기존 선언 전부가 **이미 자기를 밝히고 있어야** 한다. 나중에 필드를
// 더하면 그 시점의 모든 배치가 "선언 안 함"이 되고, 그 상태의 뜻을 그때 정해야
// 한다 — 정확히 지금 `gate_mode` 가 처한 자리다.
type Precondition struct {
	ID          string
	Class       string
	FreshnessMS int
	// ExemptInProgressStep 은 `gate_core.cpp:55-58` 의 예외를 선언으로 끌어낸
	// 것이다. 코드에만 있던 동안 이 예외는 정책 어디에도 나타나지 않았고,
	// 운영자는 자기가 건 신선도가 언제 면제되는지 읽을 자리가 없었다.
	ExemptInProgressStep bool
}

// RevocationClass 는 "이 사실이 철회되면 실제로 언제 효력이 사라지는가"를 말한다.
type RevocationClass struct {
	ID        string
	Mechanism string
	// 상한을 int 하나로 접지 않는 이유: "0ms"와 "상한 없음"이 `-1` 같은 관례로
	// 같은 축에 얹히면, 그 관례를 모르는 소비자가 **최악을 최선으로** 읽는다
	// (`H-B2`). Unbounded 가 true 일 때 MaxEffectiveDelayMS 는 뜻이 없다.
	MaxEffectiveDelayMS        int
	MaxEffectiveDelayUnbounded bool
}

// TrustClass 는 주장의 출처(`Evidence.msg:5` 의 다섯)에 등급을 매긴다.
type TrustClass struct {
	ID      string
	Rank    int
	Sources []string
}

// Horizon 은 발급자가 내주는 권한의 지평이다. 출처가 env 였던 것을 정책으로
// 옮긴다(`D-L9`, §8) — 병행이 아니라 **이전**이다.
//
// ✅ 이전은 2026-08-23 에 일어났다(§12 단계 6). 셋이 한 변경에서 함께 갔다:
// `grpcserver.New()` 가 이 절에서 지평을 세우고(`LeasePolicyFromPolicy`),
// 옛 출처(`LeasePolicyFromEnv`·`DefaultLeasePolicy`)가 사라졌고, 남은 env 는
// `S16j` 가 거부한다. 셋을 나눠 착지시킬 수 없었던 이유는 순서다 — 거부만 먼저
// 세우면 살아 있는 AV/HA 리그를 78 로 죽이면서 정작 지평은 여전히 env 가 정한다.
//
// 이전이 일어났다는 증거는 값이 같다는 것이 **아니다**. 이전 전에도 두 수는
// 우연히 같았다(1시간/5) — 일치는 배선이 아니다(`E-W5`). 증거는
// `TestHorizonGovernsIssuedTokenLifetime` 이다: 서로 다른 두 지평이 서로 다른
// 두 토큰 수명을 낸다.
type Horizon struct {
	TokenTTLMS int
	MaxSteps   int
}

// Precondition 은 id 로 술어를 찾는다. `S16h` 가 적재 시점에 표와 코드의 집합이
// 정확히 같음을 보장하므로, 여기서 못 찾는 것은 설정의 잘못이 아니라 **코드가
// 선언한 적 없는 id 를 물은 것**이다. 0값을 돌려주면 `FreshnessMS=0` 이 되고 이
// 시스템에서 0 은 무제한이다 — 조용한 fail-open 을 만드느니 죽는다.
func (p *Policy) Precondition(id string) Precondition {
	for i := range p.Preconditions {
		if p.Preconditions[i].ID == id {
			return p.Preconditions[i]
		}
	}
	panic("config: precondition " + id + " is not in the policy (S16h should make this unreachable)")
}

func (p *Policy) Revocation(id string) RevocationClass {
	for i := range p.RevocationClasses {
		if p.RevocationClasses[i].ID == id {
			return p.RevocationClasses[i]
		}
	}
	panic("config: revocation class " + id + " is not in the policy (S16h should make this unreachable)")
}

// TrustRank 는 **source 로** 등급을 되묻는다. 어휘 밖 문자열은 0 이다 — 런타임에
// 도착한 미지 source 는 최저 등급조차 받지 못한다. 0 을 "등급 없음"으로 쓸 수
// 있는 것은 선언된 등급이 전부 1 이상이기 때문이고, 그 하한은 `S16i` 가 지킨다.
func (p *Policy) TrustRank(source string) int {
	for _, tc := range p.TrustClasses {
		for _, s := range tc.Sources {
			if s == source {
				return tc.Rank
			}
		}
	}
	return 0
}

// MinTrustRank 는 `evidence.min_trust_class` 가 가리키는 등급이다. 참조가 풀리는
// 것은 `S16g` 가 적재 시점에 보장한다.
func (p *Policy) MinTrustRank() int {
	for _, tc := range p.TrustClasses {
		if tc.ID == p.Evidence.MinTrustClass {
			return tc.Rank
		}
	}
	panic("config: min_trust_class " + p.Evidence.MinTrustClass +
		" does not resolve (S16g should make this unreachable)")
}

type Authz struct {
	Callers []AuthzCaller `yaml:"callers"`
}

type AuthzCaller struct {
	// CallerKind 는 `DB-1` 이 정한 축이며 CN 이 아니다(§3.1). `unknown` 은 어휘
	// 밖이다 — 그것은 "호출자를 식별하지 못했다"이고, 인가 대상으로 적을 수
	// 있으면 미식별 호출자에게 자격을 주는 문장이 형식상 합법이 된다.
	CallerKind string `yaml:"caller_kind"`
	// CallerID 의 형식은 **kind 마다 다르다.** 저널이 실제로 기록하는 값과 같아야
	// 하기 때문이다(`grpcauth.CallerFromContext`): mtls 는 리프 인증서 DER 의
	// SHA-256(64 소문자 hex), uds 는 `uid=<n>,gid=<n>` 이다. 하나로 고정하면 uds
	// 경로를 **표현할 수 없고**, 표현할 수 없는 축은 집행이 조용히 건너뛰는
	// 자리가 된다 — main.go 는 같은 서비스를 두 리스너에 등록한다.
	CallerID string   `yaml:"caller_id"`
	Allow    []string `yaml:"allow"`
}

// 빈 id 는 어느 kind 에서도 쓸 수 없다. `CallerFromContext` 가 빈 문자열을 내는
// 경우는 "소켓이었지만 플랫폼이 피어를 알려주지 않았다"이고, 그것을 인가 대상으로
// 적을 수 있으면 미식별 호출자에게 자격을 주는 문장이 형식상 합법이 된다.
var callerIDForm = map[string]*regexp.Regexp{
	"mtls": regexp.MustCompile(`^[0-9a-f]{64}$`),
	"uds":  regexp.MustCompile(`^uid=[0-9]+,gid=[0-9]+$`),
}

var unknownFieldRe = regexp.MustCompile(`field (\S+) not found`)

// policyFile 은 **기재 여부**를 담는 중간 표현이다. `Policy` 의 값 필드로 바로
// 받으면 "적지 않았다"와 "0 을 적었다"가 같은 바이트가 되고, 둘이 같아지는 순간
// §3.8.1 의 fail-open 이 돌아온다(`H-B2`). 포인터는 그 둘을 갈라 놓는다.
//
// ── `polclass:"…"` 태그 (implementation contract, D-L4) ────────────────────────
// 같은 파일을 파서 둘이 읽는다. 어느 키를 누가 읽는지는 **판단**이고, 판단은
// 어딘가에 적혀야 한다. 별도 목록 파일에 두면 그 목록이 썩는다 — 그래서 필드와
// 같은 줄에 태그로 붙인다. `tests/tools/check_policy_schema_parity.py` 가 이
// 태그와 `pep_gate_node.cpp` 의 `PolicyKey("…")` 호출을 대조한다.
//
//	shared      두 파서가 다 읽는다            → C++ 에 있어야 한다
//	issuer_only 발급자만 집행한다              → C++ 에 없어야 한다
//	gate_only   Go 는 **알기만 하고 안 읽는다** → C++ 에 있어야 한다
//	opaque      절의 존재만 안다(원소 미해석)   → 하위 경로는 이 키로 절단
//	unconsumed  아무도 안 읽는다               → 수가 고정(EXPECT_UNCONSUMED)
//
// `gate_only` 가 왜 필요한가: `dec.KnownFields(true)` 때문에 **Go 가 모르는 키는
// 발급자를 죽인다**. 게이트만 읽는 키라도 Go 가 선언해 두지 않으면 그 키를 담은
// 정책 파일 하나로 발급자가 기동하지 못한다 — 가설이 아니라 트리에 이미 있는
// `deploy/config-robot/policy-observe.yaml` 이 그렇다(2026-08-22 실측:
// `S16b: policy: unknown field "gate_mode"`). 선언은 집행이 아니다. Go 는 이
// 값들을 읽지 않으며, **모르는 것과 쓰지 않는 것을 가르는** 것이 선언의 전부다.
type policyFile struct {
	HumanSafety *struct {
		Enabled *bool `yaml:"enabled" polclass:"shared"`
		// Declared here without an active consumer; do not claim runtime enforcement.
		// ("선언만, 게이트 로직 미연결"). 발급자 전용으로 적으면 "발급자가
		// 집행한다"는 거짓이 되고, `shared` 로 적으면 검사기가 게이트에서
		// 찾다가 붉어진다. 셋째 범주가 필요한 이유가 이 한 필드다(`E-C3`).
		EStopOnHumanDetect *bool `yaml:"estop_on_human_detect" polclass:"unconsumed"`
	} `yaml:"human_safety" polclass:"container"`

	Evidence *struct {
		ConfidenceThreshold *float64 `yaml:"confidence_threshold" polclass:"shared"`
		// 2026-08-22 단계 5 착지로 `issuer_only` → `shared`. 게이트가 이 값을
		// `limits.min_trust_rank` 로 해소해 실제로 집행한다(PC-21·PC-23).
		// 선언이 사실보다 좁으면 "게이트는 이 키를 안 본다"가 문서에 남는다
		// (`E-W5`) — 검사기가 `PARITY_CPP_LEAK` 로 그것을 대신 말해 줬다.
		MinTrustClass *string `yaml:"min_trust_class" polclass:"shared"`
	} `yaml:"evidence" polclass:"container"`

	Motion *struct {
		MaxLinearSpeedMPS  *float64 `yaml:"max_linear_speed_mps" polclass:"issuer_only"`
		MaxAngularSpeedRPS *float64 `yaml:"max_angular_speed_rps" polclass:"issuer_only"`
	} `yaml:"motion" polclass:"container"`

	// SK-4 : 4 | 5, absent = 4. Only the issuer reads it — the
	// gate learns the edition from the token's own schema_version.
	TokenSchema *int `yaml:"token_schema" polclass:"issuer_only"`

	// SK-1 : the guardrail envelope by name. `common` is the
	// absolute ceiling per GUARDRAILS.tsv name; `zones.<zone>.<name>` may only
	// tighten it (S34). `motion.*` is an alias of the two `sls.*` entries and
	// must agree with them (S34b). Absent: `common` is derived from `motion`.
	Guardrails *struct {
		Common map[string]float64            `yaml:"common" polclass:"issuer_only"`
		Zones  map[string]map[string]float64 `yaml:"zones" polclass:"issuer_only"`
	} `yaml:"guardrails" polclass:"container"`

	// `container` 가 아니라 `issuer_only` 다: 하위 잎(`caller_kind`·`caller_id`·
	// `allow`)이 이 구조체 밖(`Authz`/`AuthzCaller`)에 살고, **절 전체가**
	// 발급자 축이다. `container` 로 적으면 검사기가 태그 없는 잎을 찾아 들어가
	// 붉어지는데 그 붉음의 뜻은 결함이 아니라 "여기까지 못 읽었다"이다.
	Authz *Authz `yaml:"authz" polclass:"issuer_only"`

	// ── 아래 둘은 게이트만 읽는다 (D-L4). Go 는 값을 보지 않는다. ──

	// `yaml.Node` 로 받는 이유: `KnownFields(true)` 가 이 아래로 내려가면 안
	// 된다. `rules[]` 원소의 해석자는 게이트 하나이고(`rules[].mode` 는 §5.7
	// 예약·미구현이라 게이트가 **거부**한다), 발급자가 원소 형식까지 판정하면
	// 같은 문장을 두 곳에서 재게 된다.
	Rules *[]yaml.Node `yaml:"rules" polclass:"opaque"`

	// implementation contract D-S3. 게이트의 운전 모드. 값의 어휘 검사는 게이트가 한다 —
	// 여기서 또 재면 두 벌이 되고, 조용한 쪽이 생긴다.
	GateMode *string `yaml:"gate_mode" polclass:"gate_only"`

	// ── `D-L3` 네 절 ────────────────────────────────────────────────────────
	//
	// 2026-08-22 단계 5 착지로 **둘이 내려갔다**: `preconditions` 와
	// `trust_classes` 를 게이트가 실제로 읽는다(PC-21·PC-23·PC-27).
	//
	// 2026-08-23 단계 6 (`D-L8`)에 **셋째가 내려갔다**: `revocation_classes` 를
	// 게이트가 읽는다. 다만 판정하지 않는다 — 스키마의 권위는 여전히 발급자
	// (`S16h`·`S16i`)이고 게이트는 무경계 선언을 seal 배너에 사실로 적을 뿐이다.
	// 태그가 재는 것은 "누가 판정하는가"가 아니라 **"누가 읽는가"** 이므로 그래도
	// `shared` 다. `issuer_only` 로 두면 검사기가 `PARITY_CPP_LEAK` 로 붉는다.
	//
	// `horizon` 은 `issuer_only` 로 남는다. `D-L9` 로 출처가 정책 파일이 됐지만
	// 읽는 쪽은 발급자 하나다 — 게이트는 리스 깊이를 해석하지 않는다.
	//
	// 넷을 한 덩이로 옮기지 않는 이유: 태그는 **의도가 아니라 사실**을 적는
	// 자리다. 아직 안 읽는 절까지 미리 `shared` 로 적으면 검사기가 게이트에서
	// 찾다가 붉고, 그 붉음의 뜻은 결함이 아니라 "선언이 앞서갔다"가 된다 —
	// 고칠 수 없는 RED 는 진짜 결함을 가린다.
	//
	// 절 하나를 통째로 포인터로 받는 이유는 위와 같다: 부재와 빈 목록이 같은
	// 바이트가 되면 `S16e` 가 절의 결측을 못 본다.
	Preconditions     *[]preconditionFile    `yaml:"preconditions" polclass:"shared"`
	RevocationClasses *[]revocationClassFile `yaml:"revocation_classes" polclass:"shared"`
	TrustClasses      *[]trustClassFile      `yaml:"trust_classes" polclass:"shared"`
	Horizon           *horizonFile           `yaml:"horizon" polclass:"issuer_only"`

	// ── EC-1 (EUC D1): evidence retention. ────────────────────────────────
	//
	// `issuer_only` because no process enforces a retention timer — the gate
	// does not read it and the writer has no deletion path. What the issuer
	// does is refuse to start in production without it (S24) and refuse a
	// declaration that contradicts itself (S25). The value's job is to be
	// sealed: `policy_file_sha256` covers this file, so the number an auditor
	// reads here is the number the chain says the robot ran under.
	Retention *struct {
		BlackboxYears   *int `yaml:"blackbox_years" polclass:"issuer_only"`
		AnchorYears     *int `yaml:"anchor_years" polclass:"issuer_only"`
		LowerBoundYears *int `yaml:"lower_bound_years" polclass:"issuer_only"`
	} `yaml:"retention" polclass:"container"`

	// AS-5: revocation-storm hysteresis. `issuer_only` — the gate never reads
	// it; it only ever sees the resulting REVOKED chain, which it already
	// handles. Optional as a section; when present, all three keys are
	// required (S16e) and must be sane (S16i).
	RevocationHysteresis *struct {
		FlapWindowMS  *int `yaml:"flap_window_ms" polclass:"issuer_only"`
		FlapThreshold *int `yaml:"flap_threshold" polclass:"issuer_only"`
		SettleMS      *int `yaml:"settle_ms" polclass:"issuer_only"`
	} `yaml:"revocation_hysteresis" polclass:"container"`
}

type preconditionFile struct {
	ID                   *string `yaml:"id"`
	Class                *string `yaml:"class"`
	FreshnessMS          *int    `yaml:"freshness_ms"`
	ExemptInProgressStep *bool   `yaml:"exempt_in_progress_step"`
}

type revocationClassFile struct {
	ID        *string `yaml:"id"`
	Mechanism *string `yaml:"mechanism"`
	// `yaml.Node` 로 받는다. 이 필드는 음 아닌 정수와 문자열 `unbounded` 를 둘 다
	// 받는데, `*int` 로 받으면 `unbounded` 가 `yaml.TypeError` 가 되어 **`S16b`
	// (미지 키)** 로 도착한다 — 값의 잘못이 키의 잘못으로 보고되고, 운영자는 있는
	// 키를 지우러 간다.
	//
	// 여기만 포인터가 아니다. `*yaml.Node` 는 yaml.v3 가 받지 못한다(실측:
	// `cannot unmarshal !!int 0 into yaml.Node`) — 특수 처리가 포인터 역참조
	// 앞에 있다. 기재 여부는 `Kind == 0`(영값 노드)으로 가른다.
	MaxEffectiveDelay yaml.Node `yaml:"max_effective_delay_ms"`
}

type trustClassFile struct {
	ID   *string `yaml:"id"`
	Rank *int    `yaml:"rank"`
	// 빈 목록(`sources: []`)은 부재와 다른 선언이다 — "이 등급에 아무 출처도
	// 걸지 않았다"이고, 그 자체는 위반이 아니다. 위반은 다섯 중 하나가 **어느
	// 등급에도** 없다는 것이고 그것은 `S16g` 가 잰다.
	Sources *[]string `yaml:"sources"`
}

type horizonFile struct {
	TokenTTLMS *int `yaml:"token_ttl_ms"`
	MaxSteps   *int `yaml:"max_steps"`
}

func LoadPolicy(path string) (*Policy, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var doc policyFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		// 빈 문서와 주석뿐인 문서는 둘 다 `io.EOF` 로 온다. YAML 이 이 둘을
		// 오류로 보지 않는 것이 §3.8.1 의 뿌리다.
		if errors.Is(err, io.EOF) {
			return nil, nil, deploysec.Cfg("S16", "authz: policy file missing or empty (%s)", path)
		}
		var te *yaml.TypeError
		if errors.As(err, &te) {
			for _, e := range te.Errors {
				if m := unknownFieldRe.FindStringSubmatch(e); m != nil {
					return nil, nil, deploysec.Cfg("S16b", "policy: unknown field %q", m[1])
				}
			}
			return nil, nil, deploysec.Cfg("S16b", "policy: %s", strings.Join(te.Errors, "; "))
		}
		return nil, nil, err
	}

	if err := requireFields(&doc); err != nil {
		return nil, nil, err
	}
	if err := validateAuthz(doc.Authz); err != nil {
		return nil, nil, err
	}

	var p Policy
	p.HumanSafety.Enabled = *doc.HumanSafety.Enabled
	p.HumanSafety.EStopOnHumanDetect = *doc.HumanSafety.EStopOnHumanDetect
	p.Evidence.ConfidenceThreshold = *doc.Evidence.ConfidenceThreshold
	p.Evidence.MinTrustClass = *doc.Evidence.MinTrustClass
	p.Motion.MaxLinearSpeedMPS = *doc.Motion.MaxLinearSpeedMPS
	p.Motion.MaxAngularSpeedRPS = *doc.Motion.MaxAngularSpeedRPS
	p.Authz = *doc.Authz
	if err := materialize(&p, &doc); err != nil {
		return nil, nil, err
	}
	if err := validateGuardrails(&p, &doc); err != nil {
		return nil, nil, err
	}
	if err := validateTokenSchema(&p, &doc); err != nil {
		return nil, nil, err
	}
	// 넷을 따로 부른다. 한 함수로 접으면 규칙 하나를 지워도 나머지가 같은 사유를
	// 내어 그 죽음이 초록 아래로 지나간다(`H-B9`, `validateAuthz` 선례).
	if err := validateVocabulary(&p); err != nil {
		return nil, nil, err
	}
	if err := validateReferences(&p); err != nil {
		return nil, nil, err
	}
	if err := validateSetParity(&p); err != nil {
		return nil, nil, err
	}
	if err := validateQuantities(&p); err != nil {
		return nil, nil, err
	}
	if err := validateHorizonEnvResidue(); err != nil {
		return nil, nil, err
	}
	// EC-1: retention last — it is the one section whose absence is a profile
	// question (S24) rather than a format question, and a format error above
	// must not be masked by a profile banner here.
	if doc.Retention == nil {
		ret, err := retentionAbsent(os.Getenv("PAIL_PROFILE"), os.Stderr)
		if err != nil {
			return nil, nil, err
		}
		p.Retention = ret
	} else {
		ret, err := validateRetention(doc.Retention.BlackboxYears, doc.Retention.AnchorYears, doc.Retention.LowerBoundYears)
		if err != nil {
			return nil, nil, err
		}
		p.Retention = ret
	}
	return &p, b, nil
}

// validateHorizonEnvResidue 는 `S16j` 다(`D-L9`, §8). 지평의 출처가 정책으로
// 옮겨간 뒤 남은 `PAIL_LEASE_*` 는 **아무것도 하지 않는다** — 그런데 그것을 걸어
// 둔 운영자는 수명을 조였다고 믿는다. 조용히 무시하면 믿는 값과 도는 값이
// 갈라지고 아무 줄도 붉지 않는다. 그것이 이 트랙이 죽이려는 `P-19` 다.
//
// 파일이 아니라 프로세스 환경을 재는 유일한 `S16*` 다. 그럼에도 여기 있는 이유는
// 이 함수가 "지평이 어디서 오는가" 를 판정하는 자리이기 때문이다 — 출처를 옮긴
// 곳과 옛 출처를 거부하는 곳이 떨어져 있으면 한쪽만 되돌려도 그 되돌림이
// 관측되지 않는다.
//
// 빈 값은 잔재가 아니다. compose 가 `PAIL_LEASE_TTL_MS=` 형태로 빈 값을 주입하는
// 배치가 실재했고, 그것까지 거부하면 이전이 살아 있는 배치를 깨뜨린다.
func validateHorizonEnvResidue() error {
	// 둘을 따로 잰다. 한 줄로 접으면 한쪽 검사를 지워도 다른 쪽이 같은 사유를
	// 내어 그 죽음이 초록 아래로 지나간다(`H-B9`).
	for _, name := range []string{"PAIL_LEASE_TTL_MS", "PAIL_LEASE_MAX_STEPS"} {
		if os.Getenv(name) != "" {
			return deploysec.Cfg("S16j",
				"policy: %s is set but the issuance horizon now comes only from horizon: in the policy file; "+
					"remove it and set horizon.token_ttl_ms / horizon.max_steps instead", name)
		}
	}
	return nil
}

// materialize 는 네 절을 값으로 옮긴다. 옮기면서 판정하는 것은 **하나뿐**이다:
// `max_effective_delay_ms` 가 정수도 `unbounded` 도 아닌 경우(`S16f`). 나머지
// 어휘·참조·정합·정량 검사는 옮긴 뒤에 각자의 규칙이 잰다 — 옮기기와 판정을
// 섞으면 한 함수가 여러 사유를 내고, 그때 규칙 하나의 죽음이 관측되지 않는다.
// GuardrailLinear / GuardrailAngular / GuardrailDuration are the three names
// the v4 token's fixed fields map onto (implementation contract L6). Spelled once here so the
// issuer, the checker's TSV and the gate agree on the alias.
const (
	GuardrailLinear   = "sls.linear_mps"
	GuardrailAngular  = "sls.angular_rps"
	GuardrailDuration = "step.max_duration_s"
)

// Token schema editions the issuer can mint (implementation contract, SK-4). 4 = the class
// mask edition (AL-3); 5 = the named envelope (TokenConstraints.guardrails +
// skill + slot). Policy `token_schema` selects; absent = 4 so an upgraded
// issuer does not start minting what an un-upgraded gate refuses (ERR_SCHEMA)
// — the deployment order is gate first, then the policy switch.
const (
	TokenSchemaClassMask     = 4
	TokenSchemaNamedEnvelope = 5
	// SlotMain is the one permit slot this edition issues (L16).
	SlotMain = "main"
)

// Guardrails is the resolved envelope table.
type Guardrails struct {
	Common map[string]float64
	Zones  map[string]map[string]float64
	// Declared says whether the file carried a `guardrails:` section or the
	// table was derived from `motion:` — the journal records which.
	Declared bool
}

// Envelope resolves the bound for each name: min(common, zone value if any).
// A name with no common value is returned in `missing` — the caller refuses
// (a registry that asks for a bound the policy does not set is a deployment
// error, not an unlimited call).
func (g Guardrails) Envelope(names []string, zone string) (env map[string]float64, missing []string) {
	env = map[string]float64{}
	for _, n := range names {
		v, ok := g.Common[n]
		if !ok {
			missing = append(missing, n)
			continue
		}
		if zone != "" {
			if zv, ok := g.Zones[zone][n]; ok && zv < v {
				v = zv
			}
		}
		env[n] = v
	}
	return env, missing
}

// validateGuardrails is S34/S34b (SK-1, G-POL-10·12). Absent section: the
// table is derived from `motion:` so every deployment before SK-1 loads
// unchanged (including the U-B6 explicit-zero vocabulary). Present section:
// values are positive, zone names resolve to common names, zone values only
// tighten, and the `motion` alias agrees.
func validateGuardrails(p *Policy, doc *policyFile) error {
	p.Guardrails.Zones = map[string]map[string]float64{}
	if doc.Guardrails == nil {
		p.Guardrails.Common = map[string]float64{
			GuardrailLinear:  p.Motion.MaxLinearSpeedMPS,
			GuardrailAngular: p.Motion.MaxAngularSpeedRPS,
		}
		return nil
	}
	p.Guardrails.Declared = true
	if len(doc.Guardrails.Common) == 0 {
		return deploysec.Cfg("S16e", "policy: guardrails.common is empty — a declared envelope table must name its ceilings")
	}
	p.Guardrails.Common = map[string]float64{}
	for n, v := range doc.Guardrails.Common {
		if v <= 0 {
			return deploysec.Cfg("S16i", "policy: guardrails.common.%s is %v; a ceiling must be > 0", n, v)
		}
		p.Guardrails.Common[n] = v
	}
	for _, alias := range []struct {
		name string
		val  float64
	}{{GuardrailLinear, p.Motion.MaxLinearSpeedMPS}, {GuardrailAngular, p.Motion.MaxAngularSpeedRPS}} {
		cv, ok := p.Guardrails.Common[alias.name]
		if !ok {
			return deploysec.Cfg("S16e", "policy: guardrails.common.%s is missing — motion.* is an alias of it and the token's fixed fields read it", alias.name)
		}
		if cv != alias.val {
			return deploysec.Cfg("S34b", "policy: guardrails.common.%s (%v) and its motion alias (%v) disagree — one value, two names", alias.name, cv, alias.val)
		}
	}
	for zone, table := range doc.Guardrails.Zones {
		out := map[string]float64{}
		for n, v := range table {
			cv, ok := p.Guardrails.Common[n]
			if !ok {
				return deploysec.Cfg("S16g", "policy: guardrails.zones.%s.%s names no common ceiling — a zone can only tighten a bound that exists", zone, n)
			}
			if v <= 0 {
				return deploysec.Cfg("S16i", "policy: guardrails.zones.%s.%s is %v; a bound must be > 0", zone, n, v)
			}
			if v > cv {
				return deploysec.Cfg("S34", "policy: guardrails.zones.%s.%s (%v) exceeds guardrails.common.%s (%v) — zone values only tighten", zone, n, v, n, cv)
			}
			out[n] = v
		}
		p.Guardrails.Zones[zone] = out
	}
	return nil
}

func materialize(p *Policy, doc *policyFile) error {
	for _, pc := range *doc.Preconditions {
		p.Preconditions = append(p.Preconditions, Precondition{
			ID:                   *pc.ID,
			Class:                *pc.Class,
			FreshnessMS:          *pc.FreshnessMS,
			ExemptInProgressStep: *pc.ExemptInProgressStep,
		})
	}
	for _, rc := range *doc.RevocationClasses {
		out := RevocationClass{ID: *rc.ID, Mechanism: *rc.Mechanism}
		var n int
		switch {
		case rc.MaxEffectiveDelay.Decode(&n) == nil:
			out.MaxEffectiveDelayMS = n
		case rc.MaxEffectiveDelay.Value == "unbounded":
			out.MaxEffectiveDelayUnbounded = true
		default:
			return deploysec.Cfg("S16f",
				"policy: revocation_classes[id=%s].max_effective_delay_ms %q is neither a "+
					"non-negative integer nor \"unbounded\"", out.ID, rc.MaxEffectiveDelay.Value)
		}
		p.RevocationClasses = append(p.RevocationClasses, out)
	}
	for _, tc := range *doc.TrustClasses {
		p.TrustClasses = append(p.TrustClasses, TrustClass{
			ID:      *tc.ID,
			Rank:    *tc.Rank,
			Sources: *tc.Sources,
		})
	}
	p.Horizon = Horizon{TokenTTLMS: *doc.Horizon.TokenTTLMS, MaxSteps: *doc.Horizon.MaxSteps}
	if h := doc.RevocationHysteresis; h != nil {
		p.RevocationHysteresis = RevocationHysteresis{Declared: true, FlapWindowMS: *h.FlapWindowMS, FlapThreshold: *h.FlapThreshold, SettleMS: *h.SettleMS}
	}
	return nil
}

// requireFields 는 `S16e` 다. 결측을 0값으로 채우지 않는다 — 0 은 이 시스템에서
// **무제한**(속도)이거나 **해제**(사람 안전)를 뜻하므로, 결측을 0 으로 접는 것은
// 곧 "적지 않으면 다 허용"이다. 명시적으로 적힌 `false`·`0` 은 여기서 통과한다:
// 이 규칙이 재는 것은 값이 아니라 **운영자가 그 값을 선언했는가**이다.
func requireFields(doc *policyFile) error {
	var missing []string
	if doc.HumanSafety == nil {
		missing = append(missing, "human_safety")
	} else {
		if doc.HumanSafety.Enabled == nil {
			missing = append(missing, "human_safety.enabled")
		}
		if doc.HumanSafety.EStopOnHumanDetect == nil {
			missing = append(missing, "human_safety.estop_on_human_detect")
		}
	}
	if doc.Evidence == nil {
		missing = append(missing, "evidence")
	} else {
		if doc.Evidence.ConfidenceThreshold == nil {
			missing = append(missing, "evidence.confidence_threshold")
		}
		// 최저 신뢰 등급을 적지 않으면 "아무 출처나 통과"가 되고, 그것이 바로
		// `D-L5` 가 닫으려는 상태다. 결측을 기본값으로 접지 않는다.
		if doc.Evidence.MinTrustClass == nil {
			missing = append(missing, "evidence.min_trust_class")
		}
	}
	if doc.Motion == nil {
		missing = append(missing, "motion")
	} else {
		if doc.Motion.MaxLinearSpeedMPS == nil {
			missing = append(missing, "motion.max_linear_speed_mps")
		}
		if doc.Motion.MaxAngularSpeedRPS == nil {
			missing = append(missing, "motion.max_angular_speed_rps")
		}
	}
	// ── `D-L3` 네 절 ────────────────────────────────────────────────────────
	// 절 이름을 반드시 사유에 싣는다. 이름이 없으면 운영자는 넷 중 무엇을
	// 빠뜨렸는지 파일을 다시 읽어 찾아야 하고, 그 순간 거부는 진단이 아니라
	// 벽이 된다.
	if doc.Preconditions == nil {
		missing = append(missing, "preconditions")
	} else {
		for i, pc := range *doc.Preconditions {
			at := fmt.Sprintf("preconditions[%d]", i)
			if pc.ID == nil {
				missing = append(missing, at+".id")
			}
			if pc.Class == nil {
				missing = append(missing, at+".class")
			}
			if pc.FreshnessMS == nil {
				missing = append(missing, at+".freshness_ms")
			}
			// 면제 여부는 기본값을 두지 않는다. `false` 를 기본으로 삼으면
			// 선언하지 않은 배치가 조용히 "면제 없음"이 되는데, 그것은 지금
			// 코드가 하는 일(`gate_core.cpp:55-58` 은 면제한다)과 반대다.
			if pc.ExemptInProgressStep == nil {
				missing = append(missing, at+".exempt_in_progress_step")
			}
		}
	}
	if doc.RevocationClasses == nil {
		missing = append(missing, "revocation_classes")
	} else {
		for i, rc := range *doc.RevocationClasses {
			at := fmt.Sprintf("revocation_classes[%d]", i)
			if rc.ID == nil {
				missing = append(missing, at+".id")
			}
			if rc.Mechanism == nil {
				missing = append(missing, at+".mechanism")
			}
			if rc.MaxEffectiveDelay.Kind == 0 {
				missing = append(missing, at+".max_effective_delay_ms")
			}
		}
	}
	if doc.TrustClasses == nil {
		missing = append(missing, "trust_classes")
	} else {
		for i, tc := range *doc.TrustClasses {
			at := fmt.Sprintf("trust_classes[%d]", i)
			if tc.ID == nil {
				missing = append(missing, at+".id")
			}
			if tc.Rank == nil {
				missing = append(missing, at+".rank")
			}
			if tc.Sources == nil {
				missing = append(missing, at+".sources")
			}
		}
	}
	if doc.Horizon == nil {
		missing = append(missing, "horizon")
	} else {
		if doc.Horizon.TokenTTLMS == nil {
			missing = append(missing, "horizon.token_ttl_ms")
		}
		if doc.Horizon.MaxSteps == nil {
			missing = append(missing, "horizon.max_steps")
		}
	}
	// AS-5: the section is optional (absent = no damping, said at startup);
	// a half-written section is not "partly damped" but a format error.
	if h := doc.RevocationHysteresis; h != nil {
		if h.FlapWindowMS == nil {
			missing = append(missing, "revocation_hysteresis.flap_window_ms")
		}
		if h.FlapThreshold == nil {
			missing = append(missing, "revocation_hysteresis.flap_threshold")
		}
		if h.SettleMS == nil {
			missing = append(missing, "revocation_hysteresis.settle_ms")
		}
	}
	if len(missing) > 0 {
		return deploysec.Cfg("S16e", "policy: %s not set (absence is not a default)",
			strings.Join(missing, ", "))
	}
	return nil
}

// ── `D-L3` 의 어휘와 코드 쪽 집합  ────────────────────────

// knownPreconditions 는 **구현이 아는 술어**다. `S16h` 의 한쪽 끝이고, 정책은
// 이것과 정확히 같아야 한다 — 양방향이다. 한 방향만 재면 표를 비워도 초록이다
// (`U-B1`: 테스트는 선언을 전사하지 말고 양방향으로).
var knownPreconditions = []string{"safety_feed", "evidence_claim"}

// KnownPreconditions (SK-5) is the feed vocabulary a skill registry row may
// name: the preconditions this implementation actually checks live. A copy,
// so the caller cannot grow it.
func KnownPreconditions() []string { return append([]string(nil), knownPreconditions...) }

// knownRevocationFacts 는 구현이 실제로 재검사하는 사실이다. 여기 없는 id 를
// 정책이 적으면 그 선언에는 소비자가 없다 — 운영자는 재검사를 걸었다고 믿고,
// 아무 검사도 돌지 않는다.
var knownRevocationFacts = []string{"world_state", "operator_key", "issuer_key"}

var preconditionClasses = map[string]bool{"must_check_live": true}

var revocationMechanisms = map[string]bool{
	"recheck_at_decision": true,
	"recheck_at_use":      true,
	"reload_scoped":       true,
}

// evidenceSources 는 `pail_msgs/msg/Evidence.msg:5` 의 다섯이다. 그 파일에서는
// **주석**으로만 산다(`string source  # BARCODE|NFC|RFID|VISION|MANUAL`) —
// 어휘가 코드 어디에도 값으로 없었으므로, 이 줄은 두 번째 사본이 아니라 그
// 어휘의 첫 기계 판독 가능한 선언이다.
var evidenceSources = []string{"BARCODE", "NFC", "RFID", "VISION", "MANUAL"}

// validateVocabulary 는 `S16f` 다: 닫힌 집합 밖의 **값**. 값이 밖이라는 것과
// 참조가 안 풀린다는 것은 다른 잘못이므로 사유를 나눈다.
func validateVocabulary(p *Policy) error {
	for _, pc := range p.Preconditions {
		if !preconditionClasses[pc.Class] {
			return deploysec.Cfg("S16f", "policy: preconditions[id=%s].class %q is not in {%s}",
				pc.ID, pc.Class, strings.Join(sortedKeys(preconditionClasses), ", "))
		}
	}
	for _, rc := range p.RevocationClasses {
		if !revocationMechanisms[rc.Mechanism] {
			return deploysec.Cfg("S16f",
				"policy: revocation_classes[id=%s].mechanism %q is not in {%s}",
				rc.ID, rc.Mechanism, strings.Join(sortedKeys(revocationMechanisms), ", "))
		}
		// 음수 상한은 "얼마나 오래"라는 질문의 답이 아니다. §4.2 가 이 필드의
		// 어휘를 "음 아닌 정수 | unbounded" 로 적었으므로 어휘 위반이다.
		if !rc.MaxEffectiveDelayUnbounded && rc.MaxEffectiveDelayMS < 0 {
			return deploysec.Cfg("S16f",
				"policy: revocation_classes[id=%s].max_effective_delay_ms %d is negative",
				rc.ID, rc.MaxEffectiveDelayMS)
		}
	}
	for _, tc := range p.TrustClasses {
		for _, s := range tc.Sources {
			if !contains(evidenceSources, s) {
				return deploysec.Cfg("S16f",
					"policy: trust_classes[id=%s].sources has %q, which is not one of "+
						"Evidence.msg's {%s} — a grade on a source the wire cannot carry "+
						"reads as protection that is not there",
					tc.ID, s, strings.Join(evidenceSources, ", "))
			}
		}
	}
	return nil
}

// validateReferences 는 `S16g` 다: 파일 안에서 이름이 서로를 가리키는 자리.
func validateReferences(p *Policy) error {
	seenClass := map[string]bool{}
	for _, tc := range p.TrustClasses {
		if seenClass[tc.ID] {
			return deploysec.Cfg("S16g", "policy: trust_classes has %q twice — "+
				"min_trust_class cannot name one of two", tc.ID)
		}
		seenClass[tc.ID] = true
	}
	if !seenClass[p.Evidence.MinTrustClass] {
		return deploysec.Cfg("S16g",
			"policy: evidence.min_trust_class %q does not name any trust_classes[].id",
			p.Evidence.MinTrustClass)
	}
	// 사상은 **양방향**으로 잰다. 중복만 재면 표를 비워도 초록이고, 누락만 재면
	// 한 source 를 두 등급에 적어도 초록이다.
	gradedBy := map[string]string{}
	for _, tc := range p.TrustClasses {
		for _, s := range tc.Sources {
			if prev, dup := gradedBy[s]; dup {
				return deploysec.Cfg("S16g",
					"policy: source %s is graded by both %s and %s — a claim would have "+
						"two ranks", s, prev, tc.ID)
			}
			gradedBy[s] = tc.ID
		}
	}
	for _, s := range evidenceSources {
		if _, ok := gradedBy[s]; !ok {
			return deploysec.Cfg("S16g",
				"policy: source %s is graded by no trust class — a claim carrying it "+
					"would arrive ungraded", s)
		}
	}
	return nil
}

// validateSetParity 는 `S16h` 다. **이 규칙이 이 스키마의 심장이다**: 나머지
// 셋은 파일 안에서 닫히는 검사지만 `S16h` 만이 파일과 **코드**를 맞댄다.
func validateSetParity(p *Policy) error {
	declared := make([]string, 0, len(p.Preconditions))
	for _, pc := range p.Preconditions {
		declared = append(declared, pc.ID)
	}
	if err := exactSet("preconditions", declared, knownPreconditions,
		"the code checks it but nothing declares its freshness",
		"nothing in the code consumes it, so the declaration is decoration"); err != nil {
		return err
	}
	declared = declared[:0]
	for _, rc := range p.RevocationClasses {
		declared = append(declared, rc.ID)
	}
	return exactSet("revocation_classes", declared, knownRevocationFacts,
		"the code rechecks it but the policy says nothing about its effective delay",
		"nothing rechecks it, so the declared delay is a number no code produces")
}

// exactSet 는 중복까지 잡는다. 집합만 비교하면 같은 id 를 두 번 적어도 통과하고,
// 그때 어느 항목이 이기는지는 읽는 순서가 정한다.
func exactSet(section string, declared, known []string, missingWhy, extraWhy string) error {
	seen := map[string]bool{}
	for _, id := range declared {
		if seen[id] {
			return deploysec.Cfg("S16h", "policy: %s declares %q twice — "+
				"which entry applies would be decided by read order", section, id)
		}
		seen[id] = true
		if !contains(known, id) {
			return deploysec.Cfg("S16h", "policy: %s has %q, but %s", section, id, extraWhy)
		}
	}
	for _, id := range known {
		if !seen[id] {
			return deploysec.Cfg("S16h", "policy: %s does not declare %q, but %s",
				section, id, missingWhy)
		}
	}
	return nil
}

// validateQuantities 는 `S16i` 다: 값이 어휘 안에 있고 이름이 다 풀린 뒤에도
// 남는, **수 사이의** 잘못.
func validateQuantities(p *Policy) error {
	for _, pc := range p.Preconditions {
		// 0 은 이 시스템에서 무제한을 뜻해 왔다(`requireFields` 주석). 신선도에서
		// 0 을 허용하면 must_check_live 가 아무것도 요구하지 않게 된다.
		if pc.FreshnessMS <= 0 {
			return deploysec.Cfg("S16i",
				"policy: preconditions[id=%s].freshness_ms is %d; it must be > 0 "+
					"(0 has meant \"no bound\" everywhere else in this file)",
				pc.ID, pc.FreshnessMS)
		}
	}
	for _, rc := range p.RevocationClasses {
		// 양방향 함의다. 유한한 수를 적었는데 리로드 채널이 없으면 그 수는
		// 거짓이고, 그 거짓이 §1.1 의 min(…) 명제를 참으로 보이게 만든다.
		// 반대로 재검사 경로가 있는데 `unbounded` 를 적으면 있는 보장을 버린다.
		if (rc.Mechanism == "reload_scoped") != rc.MaxEffectiveDelayUnbounded {
			return deploysec.Cfg("S16i",
				"policy: revocation_classes[id=%s] mechanism %s and "+
					"max_effective_delay_ms disagree — reload_scoped has no recheck path, "+
					"so it is unbounded and nothing else is",
				rc.ID, rc.Mechanism)
		}
	}
	byRank := map[int]string{}
	for _, tc := range p.TrustClasses {
		// 0 은 `TrustRank` 에서 "어휘 밖"이다. 선언된 등급이 0 이면 선언된 출처와
		// 미지 출처가 같은 수로 도착한다(`H-B2`).
		if tc.Rank < 1 {
			return deploysec.Cfg("S16i",
				"policy: trust_classes[id=%s].rank is %d; ranks start at 1 because 0 is "+
					"what an unknown source gets", tc.ID, tc.Rank)
		}
		if prev, dup := byRank[tc.Rank]; dup {
			return deploysec.Cfg("S16i",
				"policy: trust_classes %s and %s share rank %d — \"at least "+
					"min_trust_class\" cannot order them", prev, tc.ID, tc.Rank)
		}
		byRank[tc.Rank] = tc.ID
	}
	if p.Horizon.TokenTTLMS <= 0 {
		return deploysec.Cfg("S16i", "policy: horizon.token_ttl_ms is %d; it must be > 0",
			p.Horizon.TokenTTLMS)
	}
	if p.Horizon.MaxSteps < 1 {
		return deploysec.Cfg("S16i",
			"policy: horizon.max_steps is %d; a token that authorises no step is not a token",
			p.Horizon.MaxSteps)
	}
	if h := p.RevocationHysteresis; h.Declared {
		if h.FlapWindowMS <= 0 {
			return deploysec.Cfg("S16i", "policy: revocation_hysteresis.flap_window_ms is %d; it must be > 0", h.FlapWindowMS)
		}
		// One mutation is a change, not a flap: a threshold of 1 would defer
		// every recompile, which is a wall in front of CR2, not hysteresis.
		if h.FlapThreshold < 2 {
			return deploysec.Cfg("S16i", "policy: revocation_hysteresis.flap_threshold is %d; a flap needs at least 2 mutations inside the window", h.FlapThreshold)
		}
		if h.SettleMS <= 0 {
			return deploysec.Cfg("S16i", "policy: revocation_hysteresis.settle_ms is %d; it must be > 0", h.SettleMS)
		}
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validateAuthz 는 `S16c`(표의 부재)와 `S16d`(축 값의 어휘)를 각각 낸다. 한 id 로
// 접으면 규칙 하나를 지워도 나머지가 같은 사유를 내어 죽음이 초록 아래로
// 지나간다(`H-B9`).
func validateAuthz(a *Authz) error {
	if a == nil || len(a.Callers) == 0 {
		return deploysec.Cfg("S16c", "authz: no callers declared")
	}
	seen := map[string]int{}
	for i, c := range a.Callers {
		form, known := callerIDForm[c.CallerKind]
		if !known {
			return deploysec.Cfg("S16d", "authz: entry %d caller_kind %q not in {mtls, uds}",
				i, c.CallerKind)
		}
		if !form.MatchString(c.CallerID) {
			return deploysec.Cfg("S16d", "authz: entry %d caller_id %q does not match %s form %s",
				i, c.CallerID, c.CallerKind, form)
		}
		if len(c.Allow) == 0 {
			return deploysec.Cfg("S16d", "authz: entry %d allow is empty "+
				"(write the methods; empty reads as both \"none\" and \"all\")", i)
		}
		for _, m := range c.Allow {
			if strings.TrimSpace(m) == "" {
				return deploysec.Cfg("S16d", "authz: entry %d allow has a blank method", i)
			}
		}
		key := c.CallerKind + ":" + c.CallerID
		if j, dup := seen[key]; dup {
			return deploysec.Cfg("S16d", "authz: entry %d duplicates entry %d (%s)", i, j, key)
		}
		seen[key] = i
	}
	return nil
}

// validateTokenSchema (SK-4): absent = 4; anything but 4 or 5 is a policy this
// issuer cannot mint under, refused at load (S16b family) rather than at the
// first plan — an edition nobody implemented must not read as "the newest".
func validateTokenSchema(p *Policy, doc *policyFile) error {
	if doc.TokenSchema == nil {
		p.TokenSchema = TokenSchemaClassMask
		return nil
	}
	switch *doc.TokenSchema {
	case TokenSchemaClassMask, TokenSchemaNamedEnvelope:
		p.TokenSchema = *doc.TokenSchema
		return nil
	}
	return deploysec.Cfg("S16b", "policy: token_schema %d is not an edition this issuer mints (4 | 5)", *doc.TokenSchema)
}
