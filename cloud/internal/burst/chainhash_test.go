// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package burst

import (
	"encoding/hex"
	"testing"
)

// E-W3  — 버스트 패킷의 32:48 바이트는 세 종류의 값을 나른다:
// 토큰 id 의 해시 · 체인 id 의 해시 · CHECKPOINT 의 head_hash 절단. 셋이 같은
// 유도식을 쓰면 같은 문자열이 두 뜻으로 같은 바이트를 낸다.
//
// 이 파일이 고정하는 것은 **두 유도식이 서로 다르다**는 성질이다. 유도식이
// 다르기만 하면 도메인 분리는 성립한다 — 양쪽에 접두어가 필요한 것이 아니다.
// 그래서 `TokenHash16` 은 손대지 않았다(implementation contract 의 무변경 결정과
// `TestB3C7_DerivationDeliberatelyUnchanged` 가 그것을 지킨다). 새로 생기는
// 값에만 접두어를 둔다. 상세 근거는 packet_v2.go 의 ChainHash16 주석.

func TestEW3_ChainHash16Derivation(t *testing.T) {
	got := ChainHash16("chain-abc")
	// sha256("pail-burstchain:v1:chain-abc")[:16].
	// Go 로 산출하지 않았다 — `printf 'pail-burstchain:v1:chain-abc' |
	// shasum -a 256` 로 이 패키지 밖에서 얻었다. 구현으로 기대값을 만들면
	// 이 검사는 대조가 아니라 구현이 자기 자신과 같음을 확인하는 항등식이 된다.
	const want = "a5c6a035b5ffea8348acc5a7cb5ce8a9"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("chain_hash16 유도식이 기대와 다르다\n  got  %x\n  want %s", got, want)
	}
}

// 도메인 분리의 본체. 같은 문자열이 두 이름공간에서 다른 바이트를 내야 한다 —
// 이것이 성립하지 않으면 `census.go` 가 체인 id 를 넘기든 이슈어가 토큰 id 를
// 넘기든 수신자에게 같은 값이 도착한다.
func TestEW3_TokenAndChainNamespacesDiffer(t *testing.T) {
	const same = "collide-me"
	th := TokenHash16(same)
	ch := ChainHash16(same)
	if th == ch {
		t.Fatalf("같은 문자열이 두 이름공간에서 같은 바이트를 냈다 — 도메인 분리가 없다 (%x)", th)
	}
}

// `TokenHash16` 의 무변경을 이 패키지의 일반 테스트에서도 붙든다.
// `TestB3C7_DerivationDeliberatelyUnchanged` 는 `red_lldb` 태그 뒤에 있어
// 평시 `go test` 에서 돌지 않는다 — E-W3 이 접두어를 다루는 변경이므로
// "고치는 김에" 토큰 쪽까지 번지는 것을 태그 없는 자리에서 막는다.
func TestEW3_TokenHash16StillUnprefixed(t *testing.T) {
	got := TokenHash16("tok-abc")
	const want = "0b9f31c5403adf5a5676eafcf2ed391d" // sha256("tok-abc")[:16], 외부 산출
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("token_hash16 유도식이 바뀌었다 — implementation contract 은 무변경을 결정했다\n  got  %x\n  want %s", got, want)
	}
}
