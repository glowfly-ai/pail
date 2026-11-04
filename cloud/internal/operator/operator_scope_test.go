// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package operator

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// signUnlock 은 합법 식별자에 대한 서명 조립만 감싼다 (mustCanon 규율).
func signUnlock(t *testing.T, priv ed25519.PrivateKey, robotID string, nonce []byte) (int64, []byte) {
	t.Helper()
	now := time.Now().UnixMilli()
	return now, ed25519.Sign(priv, mustCanon(UnlockCanon(robotID, now, nonce, "op-key-1")))
}

// D §7.1 (C-B14 잔여 N-8): Unlock 의 서명된 robot_id 는 정지를 유발한 로봇과
// 대조된다. 판정은 3값이다 — matched / no_scope_recorded / mismatch. bool 로
// 접으면 "기록이 없어 대조 못 함"이 사후에 "대조했고 일치"로 읽힌다 (H-B2).
func TestUnlockScopeVerdict(t *testing.T) {
	// 통과한 실행도 자기가 무엇을 판정했는지 말한다 — 실패했을 때만 조건 id 를
	// 부르면 초록인 날 출력에 이름이 없고, 그 침묵은 테스트가 지워진 날의 침묵과
	// 바이트가 같다(`H-B2`). `ob4_closure.py` 가 이 대괄호 표식으로 §8 결속을 잰다.
	t.Log("[D14-C1] §8 — N-8 Unlock 범위 집행 (D §7.1)")

	g, priv := newTestGuard(t)

	// robot-1 의 위조가 정지를 유발했다.
	g.OnForgery("ERR_BAD_TOKEN", "robot-1")

	// ① mismatch: robot-2 를 지목한 유효 서명은 거부된다. 서명·시간창·nonce 가
	// 전부 유효해도 범위가 다르면 정지는 안 풀린다.
	n1 := okNonce("scope-n1")
	ms1, sig1 := signUnlock(t, priv, "robot-2", n1)
	scope, err := g.Unlock("robot-2", ms1, n1, sig1, "op-key-1")
	if !errors.Is(err, ErrScopeMismatch) || scope != ScopeMismatch {
		t.Fatalf("범위 불일치가 거부되지 않았다: scope=%q err=%v", scope, err)
	}
	if ok, st := g.IssuanceAllowed(); ok || st != StateSafeStop {
		t.Fatalf("불일치 거부 후에도 SAFE_STOP 이어야 한다: allowed=%v state=%v", ok, st)
	}
	// 검증이 범위 대조보다 앞서므로 nonce 는 이미 소모됐다 — 같은 명령의 재사용은
	// 재생으로 거부된다(의도된 순서: 운영자는 옳은 로봇으로 새로 서명한다).
	if scope, err := g.Unlock("robot-2", ms1, n1, sig1, "op-key-1"); !errors.Is(err, ErrNonceReplayed) || scope != "" {
		t.Fatalf("불일치로 소모된 nonce 의 재사용이 재생 거부가 아니다: scope=%q err=%v", scope, err)
	}

	// ② 확대: SAFE_STOP 중 robot-2 의 위조가 추가로 보고되면 집합이 넓어진다 —
	// 이미 정지 상태라는 이유로 두 번째 로봇의 이름이 증발하면 안 된다.
	g.OnForgery("ERR_TAMPERED", "robot-2")
	n2 := okNonce("scope-n2")
	ms2, sig2 := signUnlock(t, priv, "robot-2", n2)
	scope, err = g.Unlock("robot-2", ms2, n2, sig2, "op-key-1")
	if err != nil || scope != ScopeMatched {
		t.Fatalf("확대된 집합의 로봇으로 해제가 안 된다: scope=%q err=%v", scope, err)
	}
	if ok, _ := g.IssuanceAllowed(); !ok {
		t.Fatal("matched 해제 후 발급이 재개되어야 한다")
	}

	// ③ 집합 소거: 해제가 집합을 비웠다. 다음 정지가 robot-2 만 지목하면 지난
	// 정지의 robot-1 은 더 이상 유효 범위가 아니다 — 낡은 범위가 정지를 넘어
	// 살아남으면 지난 사건의 이름으로 이번 정지를 풀 수 있게 된다.
	g.OnForgery("ERR_SCHEMA", "robot-2")
	n3 := okNonce("scope-n3")
	ms3, sig3 := signUnlock(t, priv, "robot-1", n3)
	if scope, err := g.Unlock("robot-1", ms3, n3, sig3, "op-key-1"); !errors.Is(err, ErrScopeMismatch) || scope != ScopeMismatch {
		t.Fatalf("소거됐어야 할 robot-1 이 아직 유효 범위다: scope=%q err=%v", scope, err)
	}
	n4 := okNonce("scope-n4")
	ms4, sig4 := signUnlock(t, priv, "robot-2", n4)
	if scope, err := g.Unlock("robot-2", ms4, n4, sig4, "op-key-1"); err != nil || scope != ScopeMatched {
		t.Fatalf("이번 정지의 로봇으로 해제가 안 된다: scope=%q err=%v", scope, err)
	}

	// ④ no_scope_recorded: ForceSafeStop(저널 실패 경로)은 로봇 범위가 없다.
	// 해제는 진행하되 판정은 '대조 못 함'으로 남는다 — matched 로 접지 않는다.
	g.ForceSafeStop("journal append failed")
	n5 := okNonce("scope-n5")
	ms5, sig5 := signUnlock(t, priv, "robot-9", n5)
	if scope, err := g.Unlock("robot-9", ms5, n5, sig5, "op-key-1"); err != nil || scope != ScopeNoRecord {
		t.Fatalf("범위 기록 없는 정지의 해제 판정이 %q (want %q), err=%v", scope, ScopeNoRecord, err)
	}
	if ok, _ := g.IssuanceAllowed(); !ok {
		t.Fatal("no_scope_recorded 해제 후 발급이 재개되어야 한다")
	}

	// ⑤ 빈 robot_id 의 위조 보고는 이름을 만들지 않는다: 부재는 부재로 남는다.
	// 집합이 비어 있으므로 해제는 no_scope_recorded 다 — 빈 문자열이 집합에
	// 들어가면 "robot_id 없는 보고"가 "빈 이름의 로봇"이라는 실체가 된다.
	g.OnForgery("ERR_BAD_TOKEN", "")
	n6 := okNonce("scope-n6")
	ms6, sig6 := signUnlock(t, priv, "robot-1", n6)
	if scope, err := g.Unlock("robot-1", ms6, n6, sig6, "op-key-1"); err != nil || scope != ScopeNoRecord {
		t.Fatalf("빈 robot_id 보고 후 해제 판정이 %q (want %q), err=%v", scope, ScopeNoRecord, err)
	}
}
