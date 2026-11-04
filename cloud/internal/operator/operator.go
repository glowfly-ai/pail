// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package operator implements the M9 recovery state machine (LLD-v2 §7.2):
//
//	NORMAL -> SAFE_STOP   on a reported forgery (gate reason ERR_BAD_TOKEN family)
//	SAFE_STOP -> NORMAL   on a verified OperatorService.Unlock
//	*      -> LOCKDOWN    only on a verified RevokeIssuerKey (permanent)
//
// While not NORMAL, the issuer refuses new plans and stops serving active
// tokens (fail-closed; the PEP's 100ms recheck then drops the permit).
package operator

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/glowfly/pail/services/internal/canon"
)

type State int

const (
	StateNormal State = iota
	StateSafeStop
	StateLockdown
)

func (s State) String() string {
	switch s {
	case StateNormal:
		return "NORMAL"
	case StateSafeStop:
		return "SAFE_STOP"
	case StateLockdown:
		return "LOCKDOWN"
	default:
		return "UNKNOWN"
	}
}

const DefaultUnlockWindow = 30 * time.Second

// MinNonceBytes 는 운영자 명령 nonce 의 하한이다 (E-W4, implementation contract).
//
// **16 의 근거.** 설계서는 이 수를 "관례이지 계산이 아니다" 라고 스스로
// 적어 두었다(§12 열린 항목). 여기서 닫는다 — 다만 재생 방지에 필요한
// 엔트로피를 유도하는 방식이 아니라, **이 서버가 실제로 무엇을 기억하는가**
// 에서 유도한다. 그 둘은 다른 계산이고 앞의 것은 여기서 성립하지 않는다.
//
//   - 이 구현의 재생 방지는 `seenNonces` 맵이다. 항목은 `2*window`(기본
//     60초) 뒤에 지워진다. 즉 nonce 는 **영구 유일**할 필요가 없고 60초
//     창 안에서만 유일하면 된다. 충돌을 우연에 맡길 때 필요한 비트 수는
//     그 창 안의 명령 수로 결정되며, 운영자 명령은 사람이 내는 것이라
//     초당 수천 건이 아니다.
//   - 그러므로 16바이트(128비트)는 **엔트로피가 모자라서** 고른 하한이
//     아니다. 모자란 쪽은 언제나 짧은 값이고, 이 하한이 실제로 막는 것은
//     `[]byte("n")` 처럼 **예측 가능한 값**이다. 예측 가능한 nonce 는
//     길이와 무관하게 재생 창을 공격자가 미리 채울 수 있게 한다.
//   - 16 자체는 관례에서 온다(NIST SP 800-90A 의 최소 엔트로피 입력,
//     `crypto/rand` 를 쓰는 호출자에게 자연스러운 크기). **그것이 이 수의
//     정직한 지위다** — 안전 여유의 하한이지 필요조건의 계산값이 아니다.
//   - 대가가 0 이라는 것은 잰 사실이다: 트리 안의 nonce 생산자 둘
//     (`cmd/operator_cli`, PVS `backend_live.py`)이 이미 정확히 16바이트를
//     낸다. 이 하한은 어느 생산자에게도 새 요구를 걸지 않고, **서버가
//     그보다 짧은 것을 받아 주던 자리**만 닫는다.
//
// 하한을 늘리는 것은 구판 클라이언트를 끊으므로 동결 창의 결정 사항이다.
// 줄이는 것은 계약 위반이다(`.proto` 주석이 하한을 공표한다).
const MinNonceBytes = 16

// forgeryReasons are the gate reasons counted as token forgery attempts
// (HLD-v2 §6: signature forgery => safe stop + alarm + counter).
// ERR_TOKEN_CONSUMED (replay of a legitimately issued token) is handled by
// single-use enforcement and does not trip SAFE_STOP.
var forgeryReasons = map[string]bool{
	"ERR_BAD_TOKEN":             true,
	"ERR_TAMPERED":              true,
	"ERR_UNKNOWN_KEY_ID":        true,
	"ERR_TOKEN_VIEW_INCOMPLETE": true,
	"ERR_SCHEMA":                true,
}

func IsForgeryReason(reason string) bool { return forgeryReasons[reason] }

// UnlockCanon is the exact byte string an operator signs for Unlock
// (kept deterministic — no proto serialization ambiguity).
//
// robotID and operatorKeyID are identifier fields, so R-A applies (implementation contract
// §3.7, X23): a ':' inside one of them moves a field boundary and two different
// scopes produce the same signed bytes. Assembly refuses instead of escaping.
//
// operatorKeyID is appended, not inserted . This is a ':'
// concatenation, not a line-oriented document: inserting in the middle shifts
// the index of every field after it, which is exactly what lets an old parser
// succeed *partially* on a new string.
//
// An empty operatorKeyID is refused rather than emitted as an empty field. If
// the empty string were signable, "we do not know who signed" and "the signer
// is named the empty string" would be the same bytes, and nothing downstream
// could tell them apart afterwards.
func UnlockCanon(robotID string, unixMs int64, nonce []byte, operatorKeyID string) ([]byte, error) {
	if err := canon.RA("robot_id", robotID); err != nil {
		return nil, err
	}
	if err := canon.RA("operator_key_id", operatorKeyID); err != nil {
		return nil, err
	}
	return []byte(canon.UnlockV2 + robotID + ":" + strconv.FormatInt(unixMs, 10) +
		":" + base64.StdEncoding.EncodeToString(nonce) + ":" + operatorKeyID), nil
}

// RevokeCanon is the exact byte string an operator signs for RevokeIssuerKey.
// issuerKeyID carries the same R-A obligation as UnlockCanon's robotID.
func RevokeCanon(issuerKeyID string, unixMs int64, nonce []byte, operatorKeyID string) ([]byte, error) {
	if err := canon.RA("issuer_key_id", issuerKeyID); err != nil {
		return nil, err
	}
	if err := canon.RA("operator_key_id", operatorKeyID); err != nil {
		return nil, err
	}
	return []byte(canon.RevokeIssuerV2 + issuerKeyID + ":" + strconv.FormatInt(unixMs, 10) +
		":" + base64.StdEncoding.EncodeToString(nonce) + ":" + operatorKeyID), nil
}

// UnlockCanonV1 and RevokeCanonV1 are the frozen v1 forms. Generation ended at
// OB1; these stay because parsing does not (F8, implementation contract) — an archive
// full of v1 signatures becomes unverifiable the day the code that can rebuild
// their signed bytes is deleted.
//
// They are written out rather than expressed in terms of the v2 assembler. A
// shared body would make the frozen edition follow the live one: the next
// change to v2 would silently restate what v1 was, and the vectors that pin v1
// would be pinning the code's current opinion instead of the frozen form.
//
// A v1 verification says nothing about operator_key_id. Callers must not record
// the envelope's claim as though the signature covered it (§3.2.3) — the field
// belongs under a different name on that path.
func UnlockCanonV1(robotID string, unixMs int64, nonce []byte) ([]byte, error) {
	if err := canon.RA("robot_id", robotID); err != nil {
		return nil, err
	}
	return []byte(canon.UnlockV1 + robotID + ":" + strconv.FormatInt(unixMs, 10) +
		":" + base64.StdEncoding.EncodeToString(nonce)), nil
}

func RevokeCanonV1(issuerKeyID string, unixMs int64, nonce []byte) ([]byte, error) {
	if err := canon.RA("issuer_key_id", issuerKeyID); err != nil {
		return nil, err
	}
	return []byte(canon.RevokeIssuerV1 + issuerKeyID + ":" + strconv.FormatInt(unixMs, 10) +
		":" + base64.StdEncoding.EncodeToString(nonce)), nil
}

var (
	ErrLockdown           = errors.New("LOCKDOWN: issuer key revoked (permanent)")
	ErrWindow             = errors.New("timestamp outside allowed window")
	ErrNonceEmpty         = errors.New("nonce required")
	ErrNonceTooShort      = errors.New("nonce shorter than the contract floor")
	ErrNonceReplayed      = errors.New("nonce already used (replay rejected)")
	ErrUnknownOperatorKey = errors.New("unknown operator key_id")
	ErrRevokedOperatorKey = errors.New("revoked operator key_id")
	ErrBadSignature       = errors.New("operator signature invalid")
	ErrIssuerKeyMismatch  = errors.New("issuer_key_id mismatch")
	ErrScopeMismatch      = errors.New("unlock robot_id does not name a robot whose forgery tripped SAFE_STOP")
)

// Unlock scope verdicts (D §7.1, C-B14). Three values, not a bool: after the
// fact, "no scope was recorded" must not read as "the scope was checked and
// matched" (H-B2).
const (
	ScopeMatched  = "matched"
	ScopeNoRecord = "no_scope_recorded"
	ScopeMismatch = "mismatch"
)

type Guard struct {
	mu           sync.Mutex
	state        State
	forgeryCount uint64
	operatorKeys map[string]ed25519.PublicKey
	// revokedKeys 는 신뢰 집합이 아니다 — 여기 실린 키로 서명이 맞아떨어져도
	// 판정은 거부다. 갖고 있는 이유는 그 거부가 "모르는 키"와 **다른 값**이 되게
	// 하는 것 하나뿐이다(`C-B16`, `C16-C3`).
	revokedKeys map[string]ed25519.PublicKey
	window      time.Duration
	// seenNonces burns nonces accepted within the time window. Only successful
	// requests burn a nonce — otherwise an attacker could exhaust nonces.
	seenNonces map[string]time.Time
	// trippedRobots names the robots whose forgery reports tripped (or kept)
	// SAFE_STOP. Unlock's signed robot_id is checked against this set (D §7.1):
	// the signature says which robot the operator meant to clear, and until now
	// nothing compared that against which robot tripped the stop.
	trippedRobots map[string]bool
	now           func() time.Time
}

// NewGuard 는 폐기 맵을 **인자로** 받는다. 옵션으로 두거나 setter 로 빼면
// 넘기지 않는 호출부가 컴파일된 채 남고, 그 프로세스에서 폐기는 "모르는 키"로
// 열화한다 — `C-B16` 이 닫으려는 결함이 바로 그 형태다. 자리를 강제하면 새
// 배선이 생기는 날 컴파일러가 그 결정을 요구한다(관리가 아니라 범주 제거).
func NewGuard(operatorKeys, revokedKeys map[string]ed25519.PublicKey, window time.Duration) *Guard {
	if window <= 0 {
		window = DefaultUnlockWindow
	}
	if operatorKeys == nil {
		operatorKeys = map[string]ed25519.PublicKey{}
	}
	if revokedKeys == nil {
		revokedKeys = map[string]ed25519.PublicKey{}
	}
	return &Guard{
		state:         StateNormal,
		operatorKeys:  operatorKeys,
		revokedKeys:   revokedKeys,
		window:        window,
		seenNonces:    map[string]time.Time{},
		trippedRobots: map[string]bool{},
		now:           time.Now,
	}
}

func (g *Guard) State() State {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state
}

func (g *Guard) ForgeryCount() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.forgeryCount
}

// OnForgery records a reported forgery. Returns the resulting state and
// whether this call caused a NORMAL -> SAFE_STOP transition.
//
// robotID scopes the stop (D §7.1): every counted forgery adds its robot to
// the trip set — also while already SAFE_STOP, so a second robot's forgery
// widens the scope instead of vanishing. An empty robotID adds nothing:
// absence stays absent rather than becoming a name (H-B2).
func (g *Guard) OnForgery(reason, robotID string) (State, bool) {
	if !IsForgeryReason(reason) {
		return g.State(), false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.forgeryCount++
	if robotID != "" {
		g.trippedRobots[robotID] = true
	}
	if g.state == StateNormal {
		g.state = StateSafeStop
		return g.state, true
	}
	return g.state, false
}

// IssuanceAllowed reports whether new tokens may be issued/served.
func (g *Guard) IssuanceAllowed() (bool, State) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state == StateNormal, g.state
}

// ForceSafeStop forces SAFE_STOP outside the forgery path (HA1 D2): a journal
// append failure on a reduce-direction transition must not block the safe
// state change, but an issuer that can no longer evidence its own decisions
// may not keep granting. Recovery is the same verified Unlock as the forgery
// path. LOCKDOWN is permanent and never downgraded.
func (g *Guard) ForceSafeStop(reason string) State {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == StateLockdown {
		return g.state
	}
	if g.state != StateSafeStop {
		log.Printf("SAFE_STOP (forced): %s — issuance suspended until OperatorService.Unlock", reason)
		g.state = StateSafeStop
	}
	return g.state
}

// Restore seeds the state machine from the HA1 journal replay at startup,
// before the guard serves any request. It refuses to downgrade LOCKDOWN.
func (g *Guard) Restore(st State) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == StateLockdown {
		return
	}
	g.state = st
}

// verifyLocked checks window, nonce replay, operator key and signature.
// Caller holds g.mu. Burns the nonce on success.
func (g *Guard) verifyLocked(canon []byte, unixMs int64, nonce, sig []byte, keyID string) error {
	if len(nonce) == 0 {
		return ErrNonceEmpty
	}
	// E-W4: 하한은 여기서 집행한다. 조립 계층(canon.RA / UnlockCanon)이 아니다 —
	// 동결 벡터 `canon.vec` 의 `CV-02` 가 "조립≠수리" 를 명문으로 고정해 두었고,
	// 조립기에 길이 판단을 넣으면 그 벡터와 모순된다(= `R1` 발동).
	//
	// 빈 값과 짧은 값을 한 사유로 접지 않는다(`H-B9`). 접으면 "nonce 를 안
	// 보냈다" 와 "짧게 보냈다" 가 운영자에게 같은 줄로 도착하고, 앞의 것은
	// 클라이언트 결손이지만 뒤의 것은 **계약을 아는 클라이언트가 계약을
	// 어긴 것**이라 대응이 다르다.
	if len(nonce) < MinNonceBytes {
		return ErrNonceTooShort
	}
	now := g.now()
	d := now.Sub(time.UnixMilli(unixMs))
	if d < 0 {
		d = -d
	}
	if d > g.window {
		return ErrWindow
	}
	nk := base64.StdEncoding.EncodeToString(nonce)
	if _, seen := g.seenNonces[nk]; seen {
		return ErrNonceReplayed
	}
	// 3값 판정(`C-B16`). 폐기는 활성 조회가 빗나간 **뒤에** 본다 — 두 맵이
	// 겹치지 않는다는 것은 `crypto.Keyring.ValidateRevocation` 이 적재 시점에
	// `S15b` 로 이미 거부해 두었으므로 여기서 다시 판정하지 않는다.
	pub, active := g.operatorKeys[keyID]
	if !active {
		pub, revoked := g.revokedKeys[keyID]
		if !revoked {
			return ErrUnknownOperatorKey
		}
		// 서명이 맞아떨어진 **뒤에** 폐기를 낸다. 순서를 뒤집어 조회 직후에
		// 거부하면 이 사유는 "폐기된 키가 이 명령을 만들었다" 가 아니라
		// "누군가 그 key_id 를 적었다" 를 뜻하게 되고, 그 사유를 보고 유출
		// 대응을 시작하는 사람에게 거짓을 말하게 된다(`strict_verify.cpp` 와
		// 같은 순서).
		if !ed25519.Verify(pub, canon, sig) {
			return ErrBadSignature
		}
		return ErrRevokedOperatorKey
	}
	if !ed25519.Verify(pub, canon, sig) {
		return ErrBadSignature
	}
	g.seenNonces[nk] = now
	// Replays outside the window already fail the timestamp check, so burned
	// nonces older than 2x window can be pruned.
	for k, t := range g.seenNonces {
		if now.Sub(t) > 2*g.window {
			delete(g.seenNonces, k)
		}
	}
	return nil
}

// Unlock clears SAFE_STOP after verifying the signed operator command.
//
// keyID enters the canon (v2), so it is now checked at assembly: a keyID with a
// ':' or an empty one is refused before any key lookup. That is a stricter
// refusal than ErrUnknownOperatorKey and arrives earlier, which is the point —
// an ambiguous identifier must not reach the point where it selects a key.
//
// A signature produced against the v1 form does not verify here. Whether such a
// signature may still authorise anything is policy, not format, and this window
// does not decide it (implementation contract — D·E). Until it does, the fail-closed
// answer stands: not verified is not authorised.
//
// The returned scope verdict (D §7.1) says how the signed robot_id related to
// the trip set, so the caller can journal it. Three values, not folded:
//   - ScopeMatched: the set was non-empty and named this robot; the set is
//     cleared on the transition (a stale scope must not outlive the stop).
//   - ScopeNoRecord: the set was empty — a ForceSafeStop (journal failure) or
//     a post-restart guard has no robot scope. The unlock proceeds, but the
//     record must not read as "checked and matched" afterwards (H-B2).
//   - ScopeMismatch: the set was non-empty and did not name this robot — the
//     unlock is refused. The nonce is already burned by then (verify precedes
//     policy); the operator signs a fresh command for the right robot.
func (g *Guard) Unlock(robotID string, unixMs int64, nonce, sig []byte, keyID string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == StateLockdown {
		return "", ErrLockdown
	}
	c, err := UnlockCanon(robotID, unixMs, nonce, keyID)
	if err != nil {
		return "", err
	}
	if err := g.verifyLocked(c, unixMs, nonce, sig, keyID); err != nil {
		return "", err
	}
	scope := ScopeNoRecord
	if len(g.trippedRobots) > 0 {
		if !g.trippedRobots[robotID] {
			return ScopeMismatch, ErrScopeMismatch
		}
		scope = ScopeMatched
	}
	g.state = StateNormal
	g.trippedRobots = map[string]bool{}
	return scope, nil
}

// RevokeIssuerKey transitions to permanent LOCKDOWN. reqKeyID must name the
// currently loaded issuer key.
func (g *Guard) RevokeIssuerKey(reqKeyID, currentIssuerKeyID string, unixMs int64, nonce, sig []byte, keyID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if reqKeyID == "" || reqKeyID != currentIssuerKeyID {
		return ErrIssuerKeyMismatch
	}
	c, err := RevokeCanon(reqKeyID, unixMs, nonce, keyID)
	if err != nil {
		return err
	}
	if err := g.verifyLocked(c, unixMs, nonce, sig, keyID); err != nil {
		return err
	}
	g.state = StateLockdown
	return nil
}
