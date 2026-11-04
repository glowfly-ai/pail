// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"encoding/hex"
	"testing"

	"github.com/glowfly/pail/services/internal/operator"
)

// TestGCTR06_OperatorCanonAssembly — G-CTR-06 의 Go 축 .
//
// 운영자 canon 문자열은 Go(operator.UnlockCanon/RevokeCanon)와 Python
// (pvs/runner/live/backend_live.py:401 f-string)이 각자 조립한다 — 이 골든이
// 두 조립기의 공통 기준점이다. 한쪽만 바뀌면 여기서 먼저 운다.
// CV-02(빈 논스)·CV-04(음수 ms)는 현재 동작 핀: 조립 계층은 통과시키고,
// 거부는 Guard.verifyLocked 소관.
//
// 2026-08-06 (implementation contract, A1-5): CV-03 은 `expect reject` 를 갖는다 —
// arg_id 는 식별자이므로 R-A 가 조립 지점에서 거부한다(X23). `expect` 가 없는
// 레코드는 종전대로 accept 다. 기대를 벡터에서 읽는 이유는, 기대가 코드 안에
// 있으면 벡터를 고쳐도 테스트가 울지 않기 때문이다(NF6).
//
// 2026-08-08 (implementation contract, OB1 A2-5): 이 벡터는 v1 을 고정한다. 판이 올라
// 갔으므로 대조 상대는 `UnlockCanonV1`/`RevokeCanonV1` 이다 — 벡터를 v2 로
// 고쳐 쓰는 것이 아니다. 구판 벡터를 신판 조립기에 맞춰 고치면 그 순간
// 벡터는 과거를 고정하는 일을 그만두고 현재를 복창하기 시작한다(§4.2 바이트
// 불변). 이 테스트가 F8("생성 종료 · 파싱 영구 유지")의 기계 증거다.
func TestGCTR06_OperatorCanonAssembly(t *testing.T) {
	recs := readVec(t, goldenPath(t, "tests/golden/token/canon.vec"))
	if len(recs) != 5 {
		t.Fatalf("canon.vec 레코드 %d건 — 5건이어야 한다 (CV-01~05)", len(recs))
	}

	for _, r := range recs {
		r := r
		t.Run(r.ID, func(t *testing.T) {
			fn := r.get(t, "func")
			argID := r.get(t, "arg_id")
			unixMs := mustInt64(t, r, "unix_ms")
			nonce, err := hex.DecodeString(r.get(t, "nonce"))
			if err != nil {
				t.Fatalf("nonce hex: %v", err)
			}
			want := r.get(t, "canon")

			var got []byte
			switch fn {
			case "unlock":
				got, err = operator.UnlockCanonV1(argID, unixMs, nonce)
			case "revoke":
				got, err = operator.RevokeCanonV1(argID, unixMs, nonce)
			default:
				t.Fatalf("미지 func %q", fn)
			}

			if r.Fields["expect"] == "reject" {
				t.Logf("GOLDEN-CANON go %s expect=reject err=%v", r.ID, err)
				if err == nil {
					t.Fatalf("%s: 거부되어야 하는데 조립됐다 (got=%q, 사유=%s)",
						r.ID, got, r.Fields["reject_reason"])
				}
				if got != nil {
					t.Fatalf("%s: 거부하면서 바이트도 냈다 — 호출자가 그것을 서명할 수 있다", r.ID)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: accept 레코드가 거부됐다: %v", r.ID, err)
			}
			t.Logf("GOLDEN-CANON go %s ok=%v", r.ID, string(got) == want)
			if string(got) != want {
				t.Fatalf("canon 불일치:\n got=%q\nwant=%q", got, want)
			}
		})
	}

	// 프리픽스 교차 방지: unlock 서명이 revoke 문맥에서 재사용될 수 없도록
	// 두 canon 은 인자가 같아도 반드시 달라야 한다. 두 판 모두에서 본다 —
	// v1 에서만 보면 v2 가 프리픽스를 잘못 붙여도 이 테스트는 침묵한다.
	n := []byte{0x00}
	u1, uerr := operator.UnlockCanonV1("x", 1, n)
	rv1, rerr := operator.RevokeCanonV1("x", 1, n)
	if uerr != nil || rerr != nil {
		t.Fatalf("합법 식별자가 거부됐다: unlock=%v revoke=%v", uerr, rerr)
	}
	if string(u1) == string(rv1) {
		t.Fatal("UnlockCanonV1 == RevokeCanonV1 — 프리픽스 도메인 분리 붕괴")
	}
	u2, uerr := operator.UnlockCanon("x", 1, n, "op-key-1")
	rv2, rerr := operator.RevokeCanon("x", 1, n, "op-key-1")
	if uerr != nil || rerr != nil {
		t.Fatalf("합법 식별자가 거부됐다(v2): unlock=%v revoke=%v", uerr, rerr)
	}
	if string(u2) == string(rv2) {
		t.Fatal("UnlockCanon == RevokeCanon — 프리픽스 도메인 분리 붕괴(v2)")
	}
	// 판 사이의 교차도 막는다. v1 서명이 v2 문맥에서(또는 그 반대로) 재사용되면
	// 판을 올린 이유 자체가 사라진다.
	if string(u1) == string(u2) || string(rv1) == string(rv2) {
		t.Fatal("v1 과 v2 의 서명 대상이 같다 — 판이 바이트에 나타나지 않는다")
	}
}
