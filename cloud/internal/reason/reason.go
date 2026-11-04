// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package reason defines shared denial codes, dispositions, severities and retry
// lower bounds. Source drift tests keep gate and northbound vocabularies aligned.
package reason

import "sort"

// Plane declares the interfaces on which a reason may occur.
type Plane uint8

const (
	PlaneNB Plane = iota
	PlaneBurst
	PlaneBoth
	PlaneLocal
)

func (p Plane) String() string {
	switch p {
	case PlaneNB:
		return "NB"
	case PlaneBurst:
		return "BURST"
	case PlaneBoth:
		return "BOTH"
	case PlaneLocal:
		return "LOCAL"
	}
	return "?"
}

// Disposition describes how a denial can be resolved, independently of severity.
type Disposition uint8

const (
	DispUnspecified Disposition = iota
	DispPermanent               // this plan cannot succeed unchanged
	DispConditional             // an external condition must change
	DispTransient               // may resolve without external intervention
)

func (d Disposition) String() string {
	switch d {
	case DispPermanent:
		return "PERMANENT"
	case DispConditional:
		return "CONDITIONAL"
	case DispTransient:
		return "TRANSIENT"
	}
	return "UNSPECIFIED"
}

// Severity describes the anomaly level, independently of retry disposition.
type Severity uint8

const (
	SevUnspecified Severity = iota
	SevNormalDefense
	SevAnomaly
	SevSuspectedTamper
)

func (s Severity) String() string {
	switch s {
	case SevNormalDefense:
		return "NORMAL_DEFENSE"
	case SevAnomaly:
		return "ANOMALY"
	case SevSuspectedTamper:
		return "SUSPECTED_TAMPER"
	}
	return "UNSPECIFIED"
}

// Unregistered is the wire value for an unknown reason and indicates a defect.
const Unregistered uint16 = 0xFF

type Entry struct {
	Code        string
	Value       uint16
	Plane       Plane
	Disposition Disposition
	Severity    Severity
	FloorMS     uint64

	// ProducerNone retains a frozen legacy value with no current producer.
	// New codes must have a producer; this is not an exemption from drift checks.
	ProducerNone bool

	// DynamicFloor marks a retry floor calculated at runtime rather than in this table.
	DynamicFloor bool

	// Issuer marks a code whose only producer lives in the PAIL-Issuer bundle
	// (cloud/issuer/, a separate license bundle). A PAIL-Core-only tree has no
	// producer for it by construction; the reverse drift check requires the
	// producer only when that bundle is present, and requires it to be THERE
	// when it is — the flag is measured in both directions, not trusted.
	Issuer bool

	// SelfFault reports issuer infrastructure failure, not a plan-specific judgment.
	// Do not memoize it by plan: disk/signer/standby recovery may occur without a
	// decision-epoch change, and cached rejection would block legitimate recovery.
	// FloorMS remains a client delay hint; transport rate limiting handles abuse.
	SelfFault bool
}

// Stable reason entries; numeric values must not be renumbered.
var table = []Entry{
	{Code: "OK", Value: 0x00, Plane: PlaneBoth},

	// 0x1X perception, world and policy
	{Code: "ERR_TARGET_MISMATCH", Value: 0x10, Plane: PlaneBurst, Disposition: DispConditional, Severity: SevNormalDefense, FloorMS: 2000},
	{Code: "ERR_GEO_FENCE", Value: 0x11, Plane: PlaneBurst, Disposition: DispConditional, Severity: SevNormalDefense, FloorMS: 2000, ProducerNone: true},
	{Code: "ERR_HUMAN_DETECT", Value: 0x12, Plane: PlaneBurst, Disposition: DispTransient, Severity: SevNormalDefense, FloorMS: 1000, ProducerNone: true},
	{Code: "ERR_SAFETY_UNSAFE", Value: 0x13, Plane: PlaneBurst, Disposition: DispConditional, Severity: SevNormalDefense, FloorMS: 2000},
	{Code: "ERR_WORLD_CHANGED", Value: 0x14, Plane: PlaneBoth, Disposition: DispConditional, Severity: SevNormalDefense, FloorMS: 500},
	{Code: "ERR_NO_EVIDENCE", Value: 0x15, Plane: PlaneBurst, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 1000},
	{Code: "ERR_SAFETY_STALE", Value: 0x16, Plane: PlaneBurst, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 1000},
	{Code: "ERR_CONSTRAINT", Value: 0x17, Plane: PlaneBurst, Disposition: DispConditional, Severity: SevNormalDefense, FloorMS: 2000},
	{Code: "ERR_CONTEXT_VIOLATION", Value: 0x18, Plane: PlaneNB, Disposition: DispConditional, Severity: SevNormalDefense, FloorMS: 2000, Issuer: true},
	// Missing world comparison is an infrastructure observation gap, not evidence
	// of a changed world. It must not inherit a revocation-trigger severity.
	{Code: "ERR_WORLD_INDETERMINATE", Value: 0x19, Plane: PlaneBurst, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 1000},
	// Evidence trust class below policy is distinct from a target mismatch.
	// Obtain stronger evidence rather than realigning the robot; this is normal
	// conditional defense, not an infrastructure fault.
	{Code: "ERR_EVIDENCE_TRUST_CLASS", Value: 0x1A, Plane: PlaneBurst, Disposition: DispConditional, Severity: SevNormalDefense, FloorMS: 2000},

	// 0x2X chain and sequence integrity
	{Code: "ERR_CHAIN_BROKEN", Value: 0x20, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper, ProducerNone: true},
	{Code: "ERR_TOKEN_CONSUMED", Value: 0x21, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevNormalDefense},
	{Code: "ERR_ACTION_MISMATCH", Value: 0x22, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper},
	{Code: "ERR_OVER_LEASE", Value: 0x23, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper, Issuer: true},
	{Code: "ERR_UNEXPLAINED_PROGRESS", Value: 0x24, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper, Issuer: true},
	{Code: "ERR_REVOKED", Value: 0x25, Plane: PlaneBurst, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 1000},

	// 0x3X token validity
	{Code: "ERR_NO_TOKEN", Value: 0x30, Plane: PlaneBurst, Disposition: DispTransient, Severity: SevNormalDefense, FloorMS: 500},
	{Code: "ERR_EXPIRED", Value: 0x31, Plane: PlaneBurst, Disposition: DispTransient, Severity: SevNormalDefense, FloorMS: 500},
	{Code: "ERR_NOT_YET_VALID", Value: 0x32, Plane: PlaneBurst, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 500},
	{Code: "ERR_BAD_TIME_WINDOW", Value: 0x33, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevAnomaly},
	{Code: "ERR_ROBOT_ID_MISMATCH", Value: 0x34, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper},
	{Code: "ERR_SCHEMA", Value: 0x35, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevAnomaly},
	{Code: "ERR_TOKEN_PARSE", Value: 0x36, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper},
	{Code: "ERR_TOKEN_VIEW_INCOMPLETE", Value: 0x37, Plane: PlaneBurst, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 500},
	{Code: "ERR_BAD_TOKEN", Value: 0x38, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper},

	// 0x4X 암호 검증
	{Code: "ERR_VERIFY", Value: 0x40, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper},
	{Code: "ERR_UNKNOWN_KEY_ID", Value: 0x41, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper},
	{Code: "ERR_BAD_SIGNATURE_SIZE", Value: 0x42, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper},
	{Code: "ERR_CRYPTO_INIT", Value: 0x43, Plane: PlaneBurst, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 5000},
	// `C-B16` : 폐기된 key_id 로 만들어진 서명이 **맞아떨어졌다**.
	//
	// `ERR_UNKNOWN_KEY_ID`(0x41)와 값을 나누는 것이 이 항목의 존재 이유 전부다.
	// 폐기 항목을 목록에서 지우기만 하면 거부는 되지만 그 거부가 0x41 로 도착하고,
	// 그러면 「유출된 키가 아직 쓰이고 있다」와 「누가 key_id 를 오타 냈다」가
	// 운영자에게 같은 바이트로 온다(`H-B2`). 앞의 것은 유출 대응을 시작해야 하는
	// 사건이고 뒤의 것은 설정 실수다.
	//
	// SUSPECTED_TAMPER: 이 사유가 나왔다는 것은 폐기된 개인키를 **누군가 아직
	// 갖고 있다**는 뜻이다. 서명 검증이 끝난 뒤에만 발행되므로(생산자 쪽 순서
	// 규율) 이 값에 추측이 섞이지 않는다.
	//
	// PERMANENT: 같은 키로 다시 보내면 언제 보내도 같은 답이다. 하한은 두지
	// 않는다(PERMANENT 항의 관례).
	{Code: "ERR_REVOKED_KEY_ID", Value: 0x44, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper},

	// 0x5X 가용성·이슈어 상태
	{Code: "ERR_ISSUER_UNREACHABLE", Value: 0x50, Plane: PlaneLocal, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 2000},
	{Code: "ERR_GRPC_DISABLED", Value: 0x51, Plane: PlaneBurst, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_ISSUER_STATE", Value: 0x52, Plane: PlaneNB, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000, Issuer: true},
	{Code: "ERR_ATTESTATION_REQUIRED", Value: 0x53, Plane: PlaneNB, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 3000, Issuer: true},
	{Code: "ERR_CENSUS_PENDING", Value: 0x54, Plane: PlaneNB, Disposition: DispTransient, Severity: SevNormalDefense, FloorMS: 2000, Issuer: true},
	{Code: "ERR_CENSUS_UNEXPLAINED", Value: 0x55, Plane: PlaneNB, Disposition: DispConditional, Severity: SevSuspectedTamper, FloorMS: 5000, Issuer: true},
	{Code: "ERR_SITE_MODEL_UNAVAILABLE", Value: 0x56, Plane: PlaneNB, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000, Issuer: true},
	{Code: "ERR_BLACKBOX_UNAVAILABLE", Value: 0x57, Plane: PlaneNB, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 2000, SelfFault: true, Issuer: true},
	{Code: "ERR_AUDIT_APPEND_FAILED", Value: 0x58, Plane: PlaneNB, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 2000, SelfFault: true, Issuer: true},
	{Code: "ERR_SIGN_FAILED", Value: 0x59, Plane: PlaneNB, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 2000, SelfFault: true, Issuer: true},
	// OI-01 (2026-10-01): the robot agent's durable report queue overflowed; this
	// code rides one ReportDecision whose detail summarises the dropped span. A
	// record about records — journaled (gap: true), never a burst, never a denial
	// the gate produced.
	{Code: "ERR_REPORT_GAP", Value: 0x5A, Plane: PlaneLocal, Disposition: DispPermanent, Severity: SevAnomaly},

	// 0x6X 계획 형식·내부
	{Code: "ERR_EMPTY_PLAN", Value: 0x60, Plane: PlaneNB, Disposition: DispPermanent, Severity: SevNormalDefense, Issuer: true},
	{Code: "ERR_UNSUPPORTED_STEP_TYPE", Value: 0x61, Plane: PlaneNB, Disposition: DispPermanent, Severity: SevNormalDefense, Issuer: true},
	// 하한값은 표에 없다 — 응답에는 남은 시간(remain)이 실린다 (LLD §3.4).
	{Code: "ERR_RETRY_TOO_SOON", Value: 0x62, Plane: PlaneNB, Disposition: DispTransient, Severity: SevNormalDefense, DynamicFloor: true, Issuer: true},
	{Code: "ERR_UNIMPLEMENTED", Value: 0x63, Plane: PlaneNB, Disposition: DispPermanent, Severity: SevNormalDefense, Issuer: true},
	{Code: "ERR_INTERNAL", Value: 0x6F, Plane: PlaneNB, Disposition: DispTransient, Severity: SevAnomaly, FloorMS: 1000, SelfFault: true, Issuer: true},

	// 0x7X 로컬 부팅(선상 미발행)
	{Code: "ERR_KEYRING_READ", Value: 0x70, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_KEYRING_EMPTY", Value: 0x71, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_KEYRING_MODE", Value: 0x72, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_ROOT_PUBKEY", Value: 0x73, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_BUNDLE_READ", Value: 0x74, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_BUNDLE_PARSE", Value: 0x75, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_BUNDLE_SCHEMA", Value: 0x76, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_BUNDLE_SIG", Value: 0x77, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevSuspectedTamper, FloorMS: 5000},
	{Code: "ERR_BUNDLE_EXPIRED", Value: 0x78, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_BUNDLE_ROLLBACK", Value: 0x79, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevSuspectedTamper, FloorMS: 5000},
	{Code: "ERR_BUNDLE_STATE", Value: 0x7A, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_BUNDLE_PAYLOAD", Value: 0x7B, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_KEYRING_PAYLOAD", Value: 0x7C, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	// 상세(`:key_id=N,...`)를 이어 붙여 발행한다. 사유는 접두어까지다.
	{Code: "ERR_KEYRING_ENTRY", Value: 0x7D, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	// DC-13 : env 정수의 파싱 실패·범위 이탈 = 기동 거부.
	// 게이트 C++(env_strict.hpp)가 stderr 로만 발행한다 — 선상 미발행.
	{Code: "ERR_BAD_ENV", Value: 0x7E, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	// DC-10 : 벽시계가 단조 기준선에서 clock_skew_ms 초과로
	// 이탈(전진/되감기/미측정 포함) = 게이트 BLOCK. 되감기 층 위반 시 기동
	// 거부(stderr)로도 발행된다.
	{Code: "ERR_CLOCK_DRIFT", Value: 0x7F, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},

	// 0x8X 신원
	// mTLS 지문이 레지스트리에 없거나 요청의 robot_id 와 어긋난다 = unbound,
	// gRPC PermissionDenied 로 거부. §2.6: 이 사유는 "설정 실수"와 "외부 침입"을
	// 겸한다 — 인터셉터는 원인을 판정하지 않고, 저널이 caller_kind 와 지문을
	// 남겨 사후 판별을 가능하게 한다.
	{Code: "ERR_IDENTITY_UNBOUND", Value: 0x80, Plane: PlaneNB, Disposition: DispConditional, Severity: SevSuspectedTamper, FloorMS: 5000},
	// E-W5 : 식별자가 `R-A` 를 위반한다 — canon 에서 필드
	// 경계를 움직이는 문자(`:`)를 품었거나 비어 있다.
	//
	// `ERR_TAMPERED` 가 아닌 이유: 그 사유는 이미 "검증 미실행"과 "변조 관측"
	// 둘을 겸하고 있고(implementation contract 미결), 셋째를 얹으면 셋 다 구별할 수 없게
	// 된다. 발급 경계에서는 생산자 결함, 게이트 경계에서는 이 검사보다 오래된
	// 이슈어의 산출 — 둘 다 변조가 아니라 이상이다.
	//
	// PERMANENT: 같은 식별자로 다시 보내면 언제 보내도 같은 답이다. 하한은
	// 두지 않는다(PERMANENT 항의 관례) — 기다림이 해소하는 것이 아니다.
	{Code: "ERR_IDENTIFIER_FORMAT", Value: 0x81, Plane: PlaneBoth, Disposition: DispPermanent, Severity: SevAnomaly},
	// `C16-C4` : 같은 key_id 가 활성 목록과 폐기 목록에 함께
	// 있다 = 신뢰 목록 자체가 자기모순이다. 기동 거부.
	//
	// 0x7X(로컬 부팅) 계열에 속할 성질이지만 그 니블은 0x7F 로 소진됐다. 값을
	// 재사용하지 않는 것이 계열 정합보다 위다 — 버스트는 증거 평면이고, 이미
	// 기록된 패킷의 해석을 바꾸는 것은 되돌릴 수 없다.
	//
	// 관용하고 "활성이 이긴다" 로 정하는 선택지는 기각했다: 그 규칙에서는 폐기
	// 선언을 게재한 사람이 자기 선언이 무효라는 것을 알 방법이 없다 — 파일은
	// 그의 의도를 그대로 담고 있고 아무도 거부하지 않는다.
	{Code: "ERR_KEYRING_REVOKED_OVERLAP", Value: 0x82, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	// Unknown requester: transport identity has no registry mapping. Reject rather
	// than default-allow; the recorded caller identity distinguishes investigation cases.
	{Code: "ERR_REQUESTER_UNKNOWN", Value: 0x83, Plane: PlaneNB, Disposition: DispPermanent, Severity: SevAnomaly, Issuer: true},
	// Reject malformed pass-through JSON before hashing; this checks syntax, not schema.
	{Code: "ERR_CONTEXT_NOT_JSON", Value: 0x84, Plane: PlaneNB, Disposition: DispPermanent, Severity: SevNormalDefense, Issuer: true},
	// The 64 KiB per-field cap protects record/storage size, not semantic validity.
	{Code: "ERR_CONTEXT_TOO_LARGE", Value: 0x85, Plane: PlaneNB, Disposition: DispPermanent, Severity: SevNormalDefense, Issuer: true},
	// Refuse issuance when content-addressed context storage, including fsync, fails.
	// Recovery depends on storage state; the client retry floor is five seconds.
	{Code: "ERR_CONTEXT_STORE", Value: 0x86, Plane: PlaneNB, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000, Issuer: true},
	// Reject action classes outside the four published class-mask values.
	{Code: "ERR_UNKNOWN_ACTION_CLASS", Value: 0x87, Plane: PlaneNB, Disposition: DispPermanent, Severity: SevNormalDefense, Issuer: true},
	// A registered action name must preserve its declared execution classes.
	{Code: "ERR_ACTION_CLASS_MISMATCH", Value: 0x88, Plane: PlaneNB, Disposition: DispPermanent, Severity: SevAnomaly, Issuer: true},
	// Undeclared targets require an explicit unverified_targets:allow policy.
	{Code: "ERR_TARGET_UNKNOWN", Value: 0x89, Plane: PlaneNB, Disposition: DispPermanent, Severity: SevNormalDefense, Issuer: true},
	// SKL v2.1: a request value above the envelope (min(policy common, zone)) is
	// refused, never shortened; Denial.exceeded[] names each bound. The gate's
	// ERR_CONSTRAINT (0x17, burst) stays the command-time verdict — this is the
	// issuance-time one, so the two planes do not share a code.
	{Code: "ERR_ENVELOPE_EXCEEDED", Value: 0x8A, Plane: PlaneNB, Disposition: DispPermanent, Severity: SevNormalDefense, Issuer: true},

	// P19-M1 (preview.19 evaluation): the keyring-bundle loader's remaining-validity
	// refusals (libpail_gate keyring_bundle.cpp; pep_gate_node.cpp S20) were issued
	// without a dictionary entry since they were added, so the public tree's own
	// source-drift test was red for eight candidates. They belong to the 0x7X local
	// boot family, whose nibble is exhausted (0x7F); values are never reused (see
	// ERR_KEYRING_REVOKED_OPERLAP's note), so they take the next free local values.
	// All three are start-up refusals, never on the wire: the system clock is before
	// the epoch (CLOCK), PAIL_KEYRING_MAX_LIFETIME_SEC is not a positive integer in
	// range (POLICY), or the bundle's remaining validity at load exceeds that ceiling
	// (LIFETIME).
	{Code: "ERR_BUNDLE_CLOCK", Value: 0x8B, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_BUNDLE_LIFETIME", Value: 0x8C, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},
	{Code: "ERR_BUNDLE_POLICY", Value: 0x8D, Plane: PlaneLocal, Disposition: DispConditional, Severity: SevAnomaly, FloorMS: 5000},

	// 0x99 tampering (frozen wire value)
	{Code: "ERR_TAMPERED", Value: 0x99, Plane: PlaneBurst, Disposition: DispPermanent, Severity: SevSuspectedTamper},
}

var byCode = func() map[string]Entry {
	m := make(map[string]Entry, len(table))
	for _, e := range table {
		m[e.Code] = e
	}
	return m
}()

func Lookup(code string) (Entry, bool) {
	e, ok := byCode[code]
	return e, ok
}

// ValueOf returns the burst wire value; unregistered reasons map to 0xFF.
func ValueOf(code string) uint16 {
	if e, ok := byCode[code]; ok {
		return e.Value
	}
	return Unregistered
}

// All returns entries ordered by their numeric values.
func All() []Entry {
	out := make([]Entry, len(table))
	copy(out, table)
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}
