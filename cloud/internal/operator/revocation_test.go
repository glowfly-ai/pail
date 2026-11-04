// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package operator

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// PAIL-CASE: RevokedKeyIsAValue (`C-B16`, implementation contract) — 소비자 쪽 절반.
//
// 게이트(C++)에서 닫은 것과 같은 결함이 여기에도 있었다: 폐기된 operator 키를
// 목록에서 지우면 거부되긴 하되 `ErrUnknownOperatorKey` 로 도착한다. 그러면
// 「유출된 키가 아직 쓰이고 있다」와 「누가 key_id 를 오타 냈다」가 운영자에게
// **같은 줄**로 온다(`H-B2`).

func revokedGuard(t *testing.T) (g *Guard, activePriv, revokedPriv ed25519.PrivateKey) {
	t.Helper()
	aPub, aPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rPub, rPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g = NewGuard(
		map[string]ed25519.PublicKey{"op-key-1": aPub},
		map[string]ed25519.PublicKey{"op-key-0": rPub},
		30*time.Second)
	return g, aPriv, rPriv
}

func unlockWith(t *testing.T, g *Guard, priv ed25519.PrivateKey, keyID, label string) error {
	t.Helper()
	nonce := okNonce(label)
	now := time.Now().UnixMilli()
	sig := ed25519.Sign(priv, mustCanon(UnlockCanon("robot-1", now, nonce, keyID)))
	_, err := g.Unlock("robot-1", now, nonce, sig, keyID)
	return err
}

// 폐기된 키로 서명한 unlock 은 거부되고, 그 사유는 **모르는 키와 다른 값**이다.
// 두 값을 각각 재는 것만으로는 부족하다 — 기대값 두 개를 같은 에러로 맞춰
// 놓아도 각각은 통과하기 때문이다. 그래서 마지막에 둘을 직접 대조한다.
func TestRevokedOperatorKeyIsItsOwnVerdict(t *testing.T) {
	g, aPriv, rPriv := revokedGuard(t)
	g.OnForgery("ERR_BAD_TOKEN", "robot-1")

	revokedErr := unlockWith(t, g, rPriv, "op-key-0", "revoked")
	if revokedErr != ErrRevokedOperatorKey {
		t.Fatalf("revoked operator key: got %v, want ErrRevokedOperatorKey", revokedErr)
	}
	unknownErr := unlockWith(t, g, rPriv, "op-key-9", "unknown")
	if unknownErr != ErrUnknownOperatorKey {
		t.Fatalf("unknown operator key: got %v, want ErrUnknownOperatorKey", unknownErr)
	}
	if revokedErr == unknownErr {
		t.Fatalf("revoked and unknown must not be the same value: both %v", revokedErr)
	}
	if g.State() != StateSafeStop {
		t.Fatalf("a revoked key must not clear SAFE_STOP: state=%v", g.State())
	}

	// 활성 키는 그대로 통과한다 — 항상 거부하는 게이트는 게이트가 아니라 벽이다.
	if err := unlockWith(t, g, aPriv, "op-key-1", "active"); err != nil {
		t.Fatalf("active operator key must still unlock: %v", err)
	}
	if g.State() != StateNormal {
		t.Fatalf("active unlock must clear SAFE_STOP: state=%v", g.State())
	}
}

// `C16-C3`: 폐기 판정은 **서명이 맞아떨어진 뒤에만** 나온다. 조회 직후에 내면
// 그 사유는 "폐기된 키가 이 명령을 만들었다" 가 아니라 "누군가 그 key_id 를
// 적었다" 를 뜻하게 되고, 사유를 보고 유출 대응을 시작하는 사람에게 거짓을
// 말한다. 폐기된 key_id 를 사칭한 서명은 `ErrBadSignature` 여야 한다.
func TestRevokedVerdictRequiresAValidSignature(t *testing.T) {
	g, aPriv, _ := revokedGuard(t)
	g.OnForgery("ERR_BAD_TOKEN", "robot-1")

	// 폐기된 key_id 를 대되 서명은 다른(활성) 키로 만든다.
	if err := unlockWith(t, g, aPriv, "op-key-0", "impersonate"); err != ErrBadSignature {
		t.Fatalf("impersonating a revoked key_id must read as a bad signature, got %v", err)
	}
	if g.State() != StateSafeStop {
		t.Fatalf("state must stay SAFE_STOP: %v", g.State())
	}
}

// 폐기 집합에서 `true` 로 나가는 경로가 없다 — 서명이 완전히 맞아떨어져도
// 잠금은 풀리지 않는다. 위 시험이 이미 사유를 재지만, 여기서는 **부작용**을
// 따로 본다: 사유가 맞아도 상태가 풀렸다면 이 조건은 닫히지 않은 것이다.
func TestRevokedKeyNeverClearsSafeStop(t *testing.T) {
	g, _, rPriv := revokedGuard(t)
	g.OnForgery("ERR_BAD_TOKEN", "robot-1")
	for i := 0; i < 3; i++ {
		if err := unlockWith(t, g, rPriv, "op-key-0", string(rune('a'+i))); err != ErrRevokedOperatorKey {
			t.Fatalf("attempt %d: got %v", i, err)
		}
		if g.State() != StateSafeStop {
			t.Fatalf("attempt %d cleared SAFE_STOP", i)
		}
	}
}

// 폐기 맵을 넘기지 않은 guard 는 예전과 똑같이 동작한다 — 폐기가 배선되지
// 않은 배치에서 조용한 회귀가 생기지 않는지 잰다.
func TestNilRevocationKeepsUnknownVerdict(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGuard(map[string]ed25519.PublicKey{"op-key-1": pub}, nil, 30*time.Second)
	g.OnForgery("ERR_BAD_TOKEN", "robot-1")
	if err := unlockWith(t, g, priv, "op-key-9", "nil-rev"); err != ErrUnknownOperatorKey {
		t.Fatalf("got %v, want ErrUnknownOperatorKey", err)
	}
}
