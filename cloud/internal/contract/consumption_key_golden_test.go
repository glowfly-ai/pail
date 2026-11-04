// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"testing"

	"github.com/glowfly/pail/services/internal/canon"
)

// TestB3C3_ConsumptionKeyMatchesGolden — implementation contract / B3-C3.
//
// consumption_key 는 제3자 구현체가 재현해야 하는 공개 스펙이다(A §3.5).
// 두 구현이 같은 값을 낸다는 증명이 없으면 그것은 스펙이 아니라 구현 세부다.
// 이 파일은 그 대조의 Go 쪽 절반이다 — C++ 쪽 절반은
// pail_ws/src/pail_pep_gate/test/test_contract_golden.cpp 가 **같은 벡터 파일**을
// 읽어 수행한다. 두 절반이 같은 파일을 향하는 것이 대조의 성립 조건이다.
//
// 벡터의 기대값은 canon 패키지를 부르지 않고 산출됐다(MKVEC.md 생성기가
// 접두어를 직접 이어 붙인다). 그러지 않으면 이 테스트는 대조가 아니라
// 구현이 자기 자신과 같음을 확인하는 항등식이 된다.
func TestB3C3_ConsumptionKeyMatchesGolden(t *testing.T) {
	recs := readVec(t, goldenPath(t, "tests/golden/token/tokens.vec"))
	if len(recs) == 0 {
		t.Fatal("tokens.vec 가 비었다")
	}
	n := 0
	for _, r := range recs {
		want, ok := r.Fields["consumption_key"]
		if !ok {
			t.Fatalf("%s: consumption_key 열이 없다 — §4.3 확장이 벡터에서 빠졌다", r.ID)
		}
		got := canon.ConsumptionKeyHex(mustHex(t, r, "action_token_bytes"))
		if got != want {
			t.Fatalf("%s: consumption_key 불일치\n  got  %s\n  want %s", r.ID, got, want)
		}
		n++
	}
	t.Logf("GREEN: %d개 벡터에서 Go 산출 consumption_key 가 골든과 일치", n)

	// 같은 값이 A 의 동결 벡터에도 박혀 있다. 두 파일이 갈라지면 하나는
	// 거짓이므로, 갈라짐 자체를 실패로 만든다.
	tk := readVec(t, goldenPath(t, "tests/golden/canon/tokenkey_v1.vec"))
	var frozen string
	for _, r := range tk {
		if r.ID == "TK1-01" {
			frozen = r.Fields["consumption_key_hex"]
		}
	}
	if frozen == "" {
		t.Fatal("tokenkey_v1.vec 에서 TK1-01 을 찾지 못했다")
	}
	var tv01 string
	for _, r := range recs {
		if r.ID == "TV-01" {
			tv01 = r.Fields["consumption_key"]
		}
	}
	if tv01 != frozen {
		t.Fatalf("TV-01(%s) != 동결 TK1-01(%s) — 두 벡터가 같은 바이트를 두고 다른 답을 말한다", tv01, frozen)
	}
	t.Logf("GREEN: TV-01 consumption_key == 동결 canon TK1-01 (%s)", frozen)
}

// TestB3C3_ConsumptionKeyIdentifiesBytesNotEnvelope — 같은 원문 바이트를 가진
// 벡터들은 봉투(signature·key_id)가 달라도 같은 키를 가져야 하고, 바이트가
// 다르면 달라야 한다. X12② 가 고치려는 성질을 벡터 수준에서 못박는다.
func TestB3C3_ConsumptionKeyIdentifiesBytesNotEnvelope(t *testing.T) {
	recs := readVec(t, goldenPath(t, "tests/golden/token/tokens.vec"))
	keyByBytes := map[string]string{}
	for _, r := range recs {
		b := r.Fields["action_token_bytes"]
		ck := r.Fields["consumption_key"]
		if prev, ok := keyByBytes[b]; ok {
			if prev != ck {
				t.Fatalf("%s: 같은 원문 바이트가 다른 consumption_key 를 낸다", r.ID)
			}
			continue
		}
		for pb, pck := range keyByBytes {
			if pb != b && pck == ck {
				t.Fatalf("%s: 다른 원문 바이트가 같은 consumption_key 를 낸다 — 단일사용이 서로 다른 토큰을 하나로 본다", r.ID)
			}
		}
		keyByBytes[b] = ck
	}
	t.Logf("GREEN: %d개 서로 다른 원문 바이트가 각각 고유한 consumption_key 를 가진다", len(keyByBytes))
}
