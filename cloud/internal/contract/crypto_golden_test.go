// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"crypto/ed25519"
	"encoding/hex"
	"strconv"
	"testing"
)

// TestGCTR01_GoRawVerifyMatchesGolden — G-CTR-01 의 Go 축 .
//
// Go 는 사전 보유자/서명자다: ERR_* 어휘가 없고, 원시 ed25519.Verify 만 안다.
// 판정 규약(§2.3): crypto 벡터 = 원시 검증이 expect_valid 와 일치해야 한다.
// semantic 벡터 = 원시 서명은 반드시 유효(거부는 C++ 의미 계층의 몫이다 —
// 여기서 원시 검증이 깨지면 벡터 분류 자체가 틀린 것).
// 서명 길이 != 64 는 언어 무관 거부(크기 검사가 검증보다 앞선다).
func TestGCTR01_GoRawVerifyMatchesGolden(t *testing.T) {
	recs := readVec(t, goldenPath(t, "tests/golden/token/tokens.vec"))
	if len(recs) != 29 { // AL-3: TV-18~20
		t.Fatalf("tokens.vec 레코드 %d건 — 29건이어야 한다 (TV-01~27, TV-90, TV-91 — AL-3 으로 +3, SK-4 로 +7)", len(recs))
	}

	for _, r := range recs {
		r := r
		t.Run(r.ID, func(t *testing.T) {
			pub := mustHex(t, r, "pubkey")
			if len(pub) != ed25519.PublicKeySize {
				t.Fatalf("pubkey 길이 %d", len(pub))
			}
			bytes := mustHex(t, r, "action_token_bytes")
			sig := mustHex(t, r, "signature")
			expectValid := r.get(t, "expect_valid") == "1"
			layer := r.get(t, "verify_layer")

			raw := len(sig) == ed25519.SignatureSize &&
				ed25519.Verify(ed25519.PublicKey(pub), bytes, sig)

			want := expectValid
			if layer == "semantic" {
				want = true
			}
			if len(sig) != ed25519.SignatureSize {
				want = false
			}

			verdict(t, "go", r.ID, raw, "-")
			if raw != want {
				t.Fatalf("%s(%s): 원시 검증=%v, 기대=%v (expect_valid=%v)",
					r.ID, layer, raw, want, expectValid)
			}
		})
	}
}

func mustHex(t *testing.T, r vecRecord, key string) []byte {
	t.Helper()
	v := r.get(t, key)
	b, err := hex.DecodeString(v)
	if err != nil {
		t.Fatalf("%s: %s hex 해독 실패: %v", r.ID, key, err)
	}
	return b
}

func mustInt64(t *testing.T, r vecRecord, key string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(r.get(t, key), 10, 64)
	if err != nil {
		t.Fatalf("%s: %s 정수 파싱 실패: %v", r.ID, key, err)
	}
	return n
}
