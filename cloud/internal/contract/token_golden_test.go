// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/glowfly/pail/services/proto/pailv1"
)

// TestGISS03_SignatureBindsToExactBytes — G-ISS-03 .
//
// 서명은 action_token_bytes "그 바이트"에 붙는다 — 의미(파싱 결과)가 아니라.
// 발급 경로가 정확히 Marshal 원문에 서명함은 generated_server_test.go:72
// (TestIssueV3TokenSignatureOverExactBytes) 가 발급 측에서 이미 소유한다
// (also_touched_by). 여기서는 골든 벡터로 소비 측 불변식을 고정한다:
//
//  1. TV-14(C-B5 이후 정상 기준선) 서명은 정확한 바이트에 유효하고, 어느
//     1바이트만 바뀌어도 무효. (구 기준선 TV-01 은 OB4/C-B5 개정으로 거부
//     벡터가 됐다 — 서명 결박 자체는 유효성과 무관하지만, TV-90/91 이 TV-14
//     파생으로 옮겨졌으므로 정규 짝도 TV-14 다.)
//  2. TV-90/TV-91 쌍: 같은 의미·같은 길이·다른 바이트. 서명은 각자의
//     바이트에만 붙는다 — 교차하면 무효 (TV-91 이 그 교차).
//  3. 재직렬화 함정의 실증: parse(비정규)→Marshal = 정규 바이트. 검증기가
//     재직렬화를 하는 순간 TV-91 의 서명이 "맞아 버린다". 그래서 검증은
//     원문 기준이어야 한다 (MEMORY: 재직렬화 금지 규약의 골든화).
func TestGISS03_SignatureBindsToExactBytes(t *testing.T) {
	recs := readVec(t, goldenPath(t, "tests/golden/token/tokens.vec"))
	byID := map[string]vecRecord{}
	for _, r := range recs {
		byID[r.ID] = r
	}
	need := func(id string) vecRecord {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("tokens.vec 에 %s 없음", id)
		}
		return r
	}

	tv14 := need("TV-14")
	pub := ed25519.PublicKey(mustHex(t, tv14, "pubkey"))
	canonical := mustHex(t, tv14, "action_token_bytes")
	sigCanonical := mustHex(t, tv14, "signature")

	// 1) 정확한 바이트에 유효.
	if !ed25519.Verify(pub, canonical, sigCanonical) {
		t.Fatal("TV-14: 정본 바이트에 서명이 무효 — 벡터 파일 손상")
	}
	// 어느 1바이트든 바뀌면 무효 (앞/중간/끝 3지점 샘플).
	for _, pos := range []int{0, len(canonical) / 2, len(canonical) - 1} {
		mut := append([]byte(nil), canonical...)
		mut[pos] ^= 0x01
		if ed25519.Verify(pub, mut, sigCanonical) {
			t.Fatalf("바이트 %d 반전 후에도 서명 유효 — 결박이 바이트가 아니다", pos)
		}
	}

	// 2) TV-90/TV-91: 같은 의미, 다른 바이트, 서명은 각자에게만.
	tv90 := need("TV-90")
	tv91 := need("TV-91")
	reordered := mustHex(t, tv90, "action_token_bytes")
	sigReordered := mustHex(t, tv90, "signature")

	if bytes.Equal(reordered, canonical) {
		t.Fatal("TV-90 바이트가 정규와 동일 — 재배열 벡터가 아니다")
	}
	if len(reordered) != len(canonical) {
		t.Fatal("TV-90 길이 편차 — 같은 의미·같은 길이 전제 붕괴")
	}
	if !bytes.Equal(mustHex(t, tv91, "action_token_bytes"), reordered) {
		t.Fatal("TV-91 바이트가 TV-90 과 달라야 할 이유가 없다 (D-D9: 같은 비정규 바이트)")
	}
	if !bytes.Equal(mustHex(t, tv91, "signature"), sigCanonical) {
		t.Fatal("TV-91 서명은 정규 바이트에 대한 서명이어야 한다 (D-D9)")
	}
	if !ed25519.Verify(pub, reordered, sigReordered) {
		t.Fatal("TV-90: 재배열 바이트에 대한 서명이 무효")
	}
	if ed25519.Verify(pub, reordered, sigCanonical) {
		t.Fatal("TV-91: 정규 서명이 재배열 바이트에 유효 — ed25519 가 깨졌거나 벡터가 틀렸다")
	}

	// 3) 재직렬화 함정: 두 바이트열은 파싱하면 같은 메시지, Marshal 하면 정규로 수렴.
	var mCanon, mReord pb.ActionToken
	if err := proto.Unmarshal(canonical, &mCanon); err != nil {
		t.Fatalf("정규 바이트 파싱 실패: %v", err)
	}
	if err := proto.Unmarshal(reordered, &mReord); err != nil {
		t.Fatalf("재배열 바이트 파싱 실패: %v", err)
	}
	if !proto.Equal(&mCanon, &mReord) {
		t.Fatal("TV-90 파싱 결과가 TV-14 와 의미 동일하지 않다 — '같은 의미' 전제 붕괴")
	}
	remarshaled, err := proto.Marshal(&mReord)
	if err != nil {
		t.Fatalf("재직렬화 실패: %v", err)
	}
	if !bytes.Equal(remarshaled, canonical) {
		// 결정론 전제가 깨지면 R1 함정 실증이 무효가 되므로 명시 실패.
		t.Fatal("remarshal(parse(재배열)) != 정규 — protobuf 직렬화 결정론 전제 붕괴")
	}
	if !ed25519.Verify(pub, remarshaled, sigCanonical) {
		t.Fatal("재직렬화 바이트에 정규 서명이 무효 — 함정 실증 실패")
	}
	t.Log("재직렬화 함정 실증: 검증기가 재직렬화하면 TV-91 서명이 유효해져 버린다 — 원문 기준 검증만이 안전")

	// 기준 토큰 의미 고정 (사전 보유자 역할): 파싱 결과가 문서화된 기준 토큰과 일치.
	if mCanon.GetTokenId() != "tok-golden-01" || mCanon.GetRobotId() != "robot-1" ||
		mCanon.GetSchemaVersion() != 3 || mCanon.GetActionType() != pb.ActionType_ACTION_MOVE {
		t.Fatalf("TV-14 파싱 결과가 기준 토큰과 다름: %+v", &mCanon)
	}
}
