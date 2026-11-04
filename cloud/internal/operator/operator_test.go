// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package operator

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/canon"
)

// mustCanon 은 합법 식별자에 대한 조립만 감싼다. R-A 거부는 별도 테스트에서
// 값으로 검사한다 — 여기서 조용히 삼키면 거부가 통과처럼 보인다.
func mustCanon(c []byte, err error) []byte {
	if err != nil {
		panic("canon assembly refused for a legal identifier: " + err.Error())
	}
	return c
}

// okNonce 는 계약 하한(MinNonceBytes, E-W4)을 채운 nonce 를 만든다. 라벨은
// 값끼리 구분하기 위한 것이고 나머지는 0 으로 남는다.
//
// 테스트가 짧은 값을 그대로 쓰면 하한 검사가 **다른 모든 조건보다 앞서** 걸려
// 재려던 것을 재지 못한다 — 이 커밋에서 실제로 네 시험이 그렇게 깨졌고, 그중
// `TestNoOperatorKeysFailClosed` 는 "거부됐다" 만 봤다면 **다른 사유로 거부되며
// 초록으로 남았을** 것이다(`H-B9`). 사유를 값으로 대조하는 규율이 그것을 잡았다.
func okNonce(label string) []byte {
	n := make([]byte, MinNonceBytes)
	copy(n, label)
	return n
}

func newTestGuard(t *testing.T) (*Guard, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	g := NewGuard(map[string]ed25519.PublicKey{"op-key-1": pub}, nil, 30*time.Second)
	return g, priv
}

// 위조 보고 → SAFE_STOP 전이, 발급 차단. 비위조 사유는 무전이.
func TestForgeryTriggersSafeStop(t *testing.T) {
	g, _ := newTestGuard(t)

	if st, tr := g.OnForgery("ERR_NO_EVIDENCE", "robot-1"); tr || st != StateNormal {
		t.Fatalf("non-forgery reason must not transition: state=%v transitioned=%v", st, tr)
	}
	if st, tr := g.OnForgery("ERR_TOKEN_CONSUMED", "robot-1"); tr || st != StateNormal {
		t.Fatalf("ERR_TOKEN_CONSUMED must not trip SAFE_STOP: state=%v transitioned=%v", st, tr)
	}
	if ok, _ := g.IssuanceAllowed(); !ok {
		t.Fatal("issuance must be allowed in NORMAL")
	}

	st, tr := g.OnForgery("ERR_BAD_TOKEN", "robot-1")
	if !tr || st != StateSafeStop {
		t.Fatalf("forgery must transition to SAFE_STOP: state=%v transitioned=%v", st, tr)
	}
	if ok, st := g.IssuanceAllowed(); ok || st != StateSafeStop {
		t.Fatalf("issuance must be blocked in SAFE_STOP: allowed=%v state=%v", ok, st)
	}
	// second forgery: counter up, no new transition
	if _, tr := g.OnForgery("ERR_SCHEMA", "robot-1"); tr {
		t.Fatal("already SAFE_STOP: must not report a new transition")
	}
	if g.ForgeryCount() != 2 {
		t.Fatalf("forgery count: got %d want 2", g.ForgeryCount())
	}
}

// 유효 Unlock → NORMAL 복귀. 동일 nonce 재생 → 거부. 시간창 밖 → 거부.
func TestUnlockAndReplayRejection(t *testing.T) {
	g, priv := newTestGuard(t)
	g.OnForgery("ERR_BAD_TOKEN", "robot-1")

	now := time.Now().UnixMilli()
	nonce := okNonce("nonce-1")
	sig := ed25519.Sign(priv, mustCanon(UnlockCanon("robot-1", now, nonce, "op-key-1")))

	if _, err := g.Unlock("robot-1", now, nonce, sig, "op-key-1"); err != nil {
		t.Fatalf("valid unlock rejected: %v", err)
	}
	if ok, _ := g.IssuanceAllowed(); !ok {
		t.Fatal("issuance must resume after unlock")
	}

	// replay: identical message again
	g.OnForgery("ERR_BAD_TOKEN", "robot-1")
	if _, err := g.Unlock("robot-1", now, nonce, sig, "op-key-1"); err != ErrNonceReplayed {
		t.Fatalf("replayed nonce must be rejected: got %v", err)
	}

	// stale timestamp (fresh nonce, valid signature)
	old := time.Now().Add(-2 * time.Minute).UnixMilli()
	nonce2 := okNonce("nonce-2")
	sig2 := ed25519.Sign(priv, mustCanon(UnlockCanon("robot-1", old, nonce2, "op-key-1")))
	if _, err := g.Unlock("robot-1", old, nonce2, sig2, "op-key-1"); err != ErrWindow {
		t.Fatalf("stale timestamp must be rejected: got %v", err)
	}

	// wrong key / tampered signature / unknown key id
	nonce3 := okNonce("nonce-3")
	now3 := time.Now().UnixMilli()
	sig3 := ed25519.Sign(priv, mustCanon(UnlockCanon("robot-1", now3, nonce3, "op-key-1")))
	if _, err := g.Unlock("robot-1", now3, nonce3, sig3, "op-key-9"); err != ErrUnknownOperatorKey {
		t.Fatalf("unknown operator key must be rejected: got %v", err)
	}
	bad := append([]byte{}, sig3...)
	bad[0] ^= 0xFF
	if _, err := g.Unlock("robot-1", now3, nonce3, bad, "op-key-1"); err != ErrBadSignature {
		t.Fatalf("tampered signature must be rejected: got %v", err)
	}
	if _, err := g.Unlock("robot-1", now3, nil, sig3, "op-key-1"); err != ErrNonceEmpty {
		t.Fatalf("empty nonce must be rejected: got %v", err)
	}
	// still SAFE_STOP after all the failures
	if ok, st := g.IssuanceAllowed(); ok || st != StateSafeStop {
		t.Fatalf("failed unlocks must not clear SAFE_STOP: allowed=%v state=%v", ok, st)
	}
}

// RevokeIssuerKey → LOCKDOWN 영구: Unlock으로 복귀 불가, key_id 불일치 거부.
func TestRevokeIssuerKeyLockdown(t *testing.T) {
	g, priv := newTestGuard(t)

	now := time.Now().UnixMilli()
	nonce := okNonce("rk-nonce")
	sig := ed25519.Sign(priv, mustCanon(RevokeCanon("dev-key-1", now, nonce, "op-key-1")))

	if err := g.RevokeIssuerKey("other-key", "dev-key-1", now, nonce, sig, "op-key-1"); err != ErrIssuerKeyMismatch {
		t.Fatalf("issuer key mismatch must be rejected: got %v", err)
	}
	if err := g.RevokeIssuerKey("dev-key-1", "dev-key-1", now, nonce, sig, "op-key-1"); err != nil {
		t.Fatalf("valid revoke rejected: %v", err)
	}
	if ok, st := g.IssuanceAllowed(); ok || st != StateLockdown {
		t.Fatalf("must be LOCKDOWN: allowed=%v state=%v", ok, st)
	}

	// unlock cannot clear LOCKDOWN
	now2 := time.Now().UnixMilli()
	nonce2 := okNonce("ul-nonce")
	sig2 := ed25519.Sign(priv, mustCanon(UnlockCanon("robot-1", now2, nonce2, "op-key-1")))
	if _, err := g.Unlock("robot-1", now2, nonce2, sig2, "op-key-1"); err != ErrLockdown {
		t.Fatalf("unlock must not clear LOCKDOWN: got %v", err)
	}
}

// operator 키가 없으면(빈 keyring) 모든 Unlock 거부 (fail-closed).
func TestNoOperatorKeysFailClosed(t *testing.T) {
	g := NewGuard(nil, nil, 0)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UnixMilli()
	// 하한을 채운 값을 쓴다. 짧은 값이면 `ErrNonceTooShort` 가 먼저 걸려
	// **빈 keyring 이 아니라 nonce 때문에** 거부되고, 이 시험이 재려던 것은
	// 재지 못한 채 "거부됐다" 만 남는다(`H-B9`).
	nonce := okNonce("no-keys")
	sig := ed25519.Sign(priv, mustCanon(UnlockCanon("robot-1", now, nonce, "op-key-1")))
	if _, err := g.Unlock("robot-1", now, nonce, sig, "op-key-1"); err != ErrUnknownOperatorKey {
		t.Fatalf("empty keyring must reject unlock: got %v", err)
	}
}

// E1-C5 (implementation contract, `E-W4`): nonce 하한이 **서버에서** 집행된다.
//
// 하위 시험 이름이 이 배터리의 절반이다 — `RED-E12` 가 이름으로 통과를 확인한다.
// rc 만 보면 `-run` 이 0건과 매칭해도 ok 가 나와 "통과" 와 "부재" 가 같은
// 바이트로 도착한다(`H-B2`).
//
// 여섯 팔이 각각 다른 것을 본다. 한 팔로 뭉치면 하한이 살아 있는지, 빈 값과
// 짧은 값이 구별되는지, 경계가 어디인지, 조립기가 길이를 판단하지 **않는지**
// 가 한 rc 아래로 들어가고 그중 하나가 죽어도 초록이다(`H-B9`).
func TestE1C5_NonceFloorEnforced(t *testing.T) {
	// 하한 자체를 상수로 다시 적지 않는다. 적으면 `MinNonceBytes` 를 8 로 낮추는
	// 변경이 **시험까지 함께 통과시킨다** — 시험이 계약이 아니라 코드를 따라간다.
	// 대신 계약이 공표된 자리(`.proto` 주석)와 같은 수인지는 `RED-E12` 가 본다.
	if MinNonceBytes < 16 {
		t.Fatalf("계약 하한이 공표값(16) 아래로 내려갔다: MinNonceBytes=%d", MinNonceBytes)
	}

	sign := func(priv ed25519.PrivateKey, robot string, ms int64, nonce []byte) []byte {
		c, err := UnlockCanon(robot, ms, nonce, "op-key-1")
		if err != nil {
			t.Fatalf("조립 실패(합법 식별자): %v", err)
		}
		return ed25519.Sign(priv, c)
	}

	// 빈 값과 짧은 값은 **다른 사유**로 거부된다. 접으면 "nonce 를 안 보냈다"(클라
	// 이언트 결손)와 "짧게 보냈다"(계약을 아는 클라이언트의 계약 위반)가 운영자
	// 에게 같은 줄로 도착한다.
	t.Run("empty_says_empty", func(t *testing.T) {
		g, priv := newTestGuard(t)
		now := time.Now().UnixMilli()
		// 서명은 하한을 채운 값으로 만든다 — 서명 검증보다 앞선 자리를 재는
		// 시험이므로 서명 자체가 실패 원인이 되면 재려던 것을 못 잰다.
		sig := sign(priv, "robot-1", now, okNonce("e"))
		if _, err := g.Unlock("robot-1", now, nil, sig, "op-key-1"); err != ErrNonceEmpty {
			t.Fatalf("빈 nonce 는 ErrNonceEmpty 여야 한다: got %v", err)
		}
	})

	t.Run("short_says_too_short", func(t *testing.T) {
		g, priv := newTestGuard(t)
		now := time.Now().UnixMilli()
		for _, n := range [][]byte{[]byte("n"), []byte("nonce-7")} {
			sig := sign(priv, "robot-1", now, n)
			if _, err := g.Unlock("robot-1", now, n, sig, "op-key-1"); err != ErrNonceTooShort {
				t.Fatalf("%d바이트 nonce 는 ErrNonceTooShort 여야 한다: got %v", len(n), err)
			}
		}
	})

	// 경계는 위아래를 함께 잰다. 아래만 재면 하한이 32 로 올라가도 초록이고,
	// 위만 재면 검사가 통째로 사라져도 초록이다.
	t.Run("boundary_below_rejected", func(t *testing.T) {
		g, priv := newTestGuard(t)
		now := time.Now().UnixMilli()
		n := make([]byte, MinNonceBytes-1)
		copy(n, "b15")
		sig := sign(priv, "robot-1", now, n)
		if _, err := g.Unlock("robot-1", now, n, sig, "op-key-1"); err != ErrNonceTooShort {
			t.Fatalf("하한-1 바이트는 거부돼야 한다: got %v", err)
		}
	})

	t.Run("boundary_at_accepted", func(t *testing.T) {
		g, priv := newTestGuard(t)
		g.OnForgery("ERR_BAD_TOKEN", "robot-1")
		now := time.Now().UnixMilli()
		n := okNonce("b16")
		if len(n) != MinNonceBytes {
			t.Fatalf("픽스처가 하한을 안 채웠다: %d", len(n))
		}
		if _, err := g.Unlock("robot-1", now, n, sign(priv, "robot-1", now, n), "op-key-1"); err != nil {
			t.Fatalf("하한을 채운 요청이 거부됐다 — 벽이지 게이트가 아니다: %v", err)
		}
	})

	// 두 rpc 가 같은 자리(verifyLocked)를 지나지만, 그 공유는 구현 사실이지
	// 계약이 아니다. 폐기 경로를 따로 재지 않으면 누가 검사를 Unlock 쪽으로만
	// 옮기는 날 아무 줄도 붉어지지 않는다.
	t.Run("revoke_path_enforced", func(t *testing.T) {
		g, priv := newTestGuard(t)
		now := time.Now().UnixMilli()
		short := []byte("rk")
		c, err := RevokeCanon("dev-key-1", now, short, "op-key-1")
		if err != nil {
			t.Fatalf("조립 실패: %v", err)
		}
		if err := g.RevokeIssuerKey("dev-key-1", "dev-key-1", now, short,
			ed25519.Sign(priv, c), "op-key-1"); err != ErrNonceTooShort {
			t.Fatalf("폐기 경로도 하한을 집행해야 한다: got %v", err)
		}
	})

	// **조립≠수리.** 동결 벡터 `canon.vec` 의 `CV-02` 가 「조립 계층은 통과 —
	// 거부는 verifyLocked 소관」을 고정해 두었다. 조립기가 길이를 판단하기
	// 시작하면 그 동결 벡터와 모순되고 `R1` 발동이다. 이 팔은 하한이 **위로
	// 새지 않았음**을 잰다 — 없으면 그 표류는 조용히 일어난다.
	t.Run("assembly_does_not_judge_length", func(t *testing.T) {
		now := time.Now().UnixMilli()
		if _, err := UnlockCanon("robot-1", now, []byte("n"), "op-key-1"); err != nil {
			t.Fatalf("조립기가 길이를 판단하고 있다(CV-02 와 모순): %v", err)
		}
		if _, err := RevokeCanon("dev-key-1", now, []byte("n"), "op-key-1"); err != nil {
			t.Fatalf("조립기가 길이를 판단하고 있다(CV-02 와 모순): %v", err)
		}
	})
}

// R-A(implementation contract, X23): 식별자에 구분자 ':' 가 들어가면 필드 경계가 움직여
// 서로 다른 범위가 같은 바이트를 서명한다. 방어는 조립 지점에 있어야 한다 —
// 경계 검사는 그 경계를 지나는 경로만 지킨다.
func TestRA_IdentifierSeparatorRefusedAtAssembly(t *testing.T) {
	nonce := []byte("n")
	now := time.Now().UnixMilli()

	// 첫 인자(robot_id / issuer_key_id)와 마지막 인자(operator_key_id)를 **따로**
	// 돌린다. 둘을 한 번에 나쁘게 만들면 한쪽 검사만 살아 있어도 통과가 아니라
	// 거부가 나고, 죽은 검사가 초록 아래에 남는다.
	for _, bad := range []string{"ro:bot", ""} {
		if c, err := UnlockCanon(bad, now, nonce, "op-key-1"); err == nil {
			t.Fatalf("UnlockCanon(robot_id=%q) 이 조립됐다: %q", bad, c)
		} else if c != nil {
			t.Fatalf("UnlockCanon(%q): 거부하면서 바이트도 냈다 — 호출자가 서명할 수 있다", bad)
		}
		if c, err := RevokeCanon(bad, now, nonce, "op-key-1"); err == nil {
			t.Fatalf("RevokeCanon(issuer_key_id=%q) 이 조립됐다: %q", bad, c)
		} else if c != nil {
			t.Fatalf("RevokeCanon(%q): 거부하면서 바이트도 냈다", bad)
		}
		// R-A 확대분 : operator_key_id 도 식별자다.
		if c, err := UnlockCanon("robot-1", now, nonce, bad); err == nil {
			t.Fatalf("UnlockCanon(operator_key_id=%q) 이 조립됐다: %q", bad, c)
		} else if c != nil {
			t.Fatalf("UnlockCanon(op=%q): 거부하면서 바이트도 냈다", bad)
		}
		if c, err := RevokeCanon("dev-key-1", now, nonce, bad); err == nil {
			t.Fatalf("RevokeCanon(operator_key_id=%q) 이 조립됐다: %q", bad, c)
		} else if c != nil {
			t.Fatalf("RevokeCanon(op=%q): 거부하면서 바이트도 냈다", bad)
		}
		// 동결된 v1 도 자기 규칙을 계속 갖는다. 판을 올렸다고 구판의 방어가
		// 사라지면, 그 방어가 있었기에 안전했던 과거 기록의 근거가 사라진다.
		if c, err := UnlockCanonV1(bad, now, nonce); err == nil {
			t.Fatalf("UnlockCanonV1(%q) 이 조립됐다: %q", bad, c)
		}
		if c, err := RevokeCanonV1(bad, now, nonce); err == nil {
			t.Fatalf("RevokeCanonV1(%q) 이 조립됐다: %q", bad, c)
		}
	}

	// 경계 모호는 서명 검증 이전에 걸러진다 — 게이트가 서명을 보기 전에 거부한다.
	g, priv := newTestGuard(t)
	g.OnForgery("ERR_BAD_TOKEN", "robot-1")
	sig := ed25519.Sign(priv, []byte("pail-unlock:v2:ro:bot:1:bg==:op-key-1")) // 공격자가 서명했을 바이트
	if _, err := g.Unlock("ro:bot", now, nonce, sig, "op-key-1"); err == nil {
		t.Fatal("Guard.Unlock 이 모호한 robot_id 를 받아들였다")
	} else if !errors.Is(err, canon.ErrIdentifierSeparator) {
		t.Fatalf("거부 사유가 R-A 가 아니다: %v", err)
	}
	// 확대분도 같은 자리에서 걸린다. 모호한 key_id 는 키를 고르는 지점에
	// 도달하기 전에 거부되어야 한다 — 도달하면 그것은 이미 선택에 쓰인 것이다.
	if _, err := g.Unlock("robot-1", now, nonce, sig, "op:key"); err == nil {
		t.Fatal("Guard.Unlock 이 모호한 operator_key_id 를 받아들였다")
	} else if !errors.Is(err, canon.ErrIdentifierSeparator) {
		t.Fatalf("거부 사유가 R-A 가 아니다: %v", err)
	}
	if ok, st := g.IssuanceAllowed(); ok || st != StateSafeStop {
		t.Fatalf("거부 후에도 SAFE_STOP 이어야 한다: allowed=%v state=%v", ok, st)
	}

	// 두 판의 바이트를 각각 못박는다. v1 줄은 §3.7 이 약속한 "바이트 변화 없음"이
	// 판을 올린 뒤에도 유효하다는 증거이고(F8), v2 줄은 새 필드가 **끝에** 붙었다는
	// 증거다. 벡터가 같은 두 문자열을 따로 갖고 있으므로 여기서 어긋나면 둘 중
	// 하나가 먼저 운다.
	n16 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	gotV1 := mustCanon(UnlockCanonV1("robot-1", 1700000000000, n16))
	const wantV1 = "pail-unlock:v1:robot-1:1700000000000:AAECAwQFBgcICQoLDA0ODw=="
	if string(gotV1) != wantV1 {
		t.Fatalf("동결된 v1 canon 이 바뀌었다:\n got=%q\nwant=%q", gotV1, wantV1)
	}
	gotV2 := mustCanon(UnlockCanon("robot-1", 1700000000000, n16, "op-key-1"))
	const wantV2 = "pail-unlock:v2:robot-1:1700000000000:AAECAwQFBgcICQoLDA0ODw==:op-key-1"
	if string(gotV2) != wantV2 {
		t.Fatalf("v2 canon 형식이 다르다:\n got=%q\nwant=%q", gotV2, wantV2)
	}
}
