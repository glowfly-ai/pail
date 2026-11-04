// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package reason

import "testing"

// LLD §1.5 "표 자체의 불변식".

func TestTableInvariants(t *testing.T) {
	seenCode := map[string]bool{}
	seenVal := map[uint16]string{}

	for _, e := range table {
		if seenCode[e.Code] {
			t.Errorf("코드 중복: %s", e.Code)
		}
		seenCode[e.Code] = true

		if prev, dup := seenVal[e.Value]; dup {
			t.Errorf("값 중복: 0x%02X 가 %s 와 %s 에 붙어 있다", e.Value, prev, e.Code)
		}
		seenVal[e.Value] = e.Code

		if e.Value == Unregistered {
			t.Errorf("%s: 0xFF 는 미등록 예약값이라 항목에 쓸 수 없다", e.Code)
		}

		if e.Code == "OK" {
			continue
		}

		if e.Disposition == DispUnspecified {
			t.Errorf("%s: 처분 미지정", e.Code)
		}
		if e.Severity == SevUnspecified {
			t.Errorf("%s: 등급 미지정", e.Code)
		}

		switch {
		case e.Disposition == DispPermanent && e.FloorMS != 0:
			t.Errorf("%s: PERMANENT 인데 하한이 %dms — 영구 거부에 재시도 하한은 모순이다",
				e.Code, e.FloorMS)
		case e.Disposition != DispPermanent && !e.DynamicFloor && e.FloorMS == 0:
			t.Errorf("%s: %s 인데 하한이 0 — 하한 없는 재시도 허용은 O-17 이 막으려던 것이다",
				e.Code, e.Disposition)
		}

		if e.ProducerNone && !frozenValues[e.Value] {
			t.Errorf("%s: ProducerNone 은 동결 레거시에만 붙일 수 있다 (값 0x%02X)", e.Code, e.Value)
		}
	}
}

// frozenValues — 버스트는 증거 평면이다. 이미 기록된 패킷의 해석이 바뀌면 안 된다.
var frozenValues = map[uint16]bool{
	0x00: true, 0x10: true, 0x11: true, 0x12: true,
	0x13: true, 0x14: true, 0x20: true, 0x99: true,
}

func TestFrozenValuesPinned(t *testing.T) {
	want := map[string]uint16{
		"OK":                  0x00,
		"ERR_TARGET_MISMATCH": 0x10,
		"ERR_GEO_FENCE":       0x11,
		"ERR_HUMAN_DETECT":    0x12,
		"ERR_SAFETY_UNSAFE":   0x13,
		"ERR_WORLD_CHANGED":   0x14,
		"ERR_CHAIN_BROKEN":    0x20,
		"ERR_TAMPERED":        0x99,
	}
	for code, val := range want {
		e, ok := Lookup(code)
		if !ok {
			t.Fatalf("동결 코드 %s 가 사전에서 사라졌다", code)
		}
		if e.Value != val {
			t.Errorf("동결 위반: %s 가 0x%02X 여야 하는데 0x%02X — 과거 버스트 증거의 해석이 달라진다",
				code, val, e.Value)
		}
	}
}

func TestValueOfUnregistered(t *testing.T) {
	if got := ValueOf("ERR_NOT_A_REAL_CODE"); got != Unregistered {
		t.Errorf("미등록 사유는 0xFF 여야 한다, got 0x%02X", got)
	}
}

func TestAllSortedByValue(t *testing.T) {
	all := All()
	if len(all) != len(table) {
		t.Fatalf("All() 이 %d개, 표는 %d개", len(all), len(table))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Value >= all[i].Value {
			t.Fatalf("All() 이 Value 오름차순이 아니다: 0x%02X 다음 0x%02X",
				all[i-1].Value, all[i].Value)
		}
	}
}

// TestDictionaryPopulation — 단계별 등재(LLD §1.3)의 현재 단계를 못박는다.
// 신규 사유는 자기 생산자와 함께 들어와야 하며, 이 숫자도 같이 올린다.
func TestDictionaryPopulation(t *testing.T) {
	// 2026-08-10 `B6-2`: `ERR_KEYRING_PAYLOAD`(0x7C) · `ERR_KEYRING_ENTRY`(0x7D) 등재. 57 → 59.
	// 2026-08-12 `DC-13`(OB3): `ERR_BAD_ENV`(0x7E) 등재. 59 → 60.
	// 2026-08-12 `DC-10`(OB3): `ERR_CLOCK_DRIFT`(0x7F) 등재. 60 → 61.
	// 2026-08-12 `C2-C3`(OB3): `ERR_IDENTITY_UNBOUND`(0x80) 등재. 61 → 62.
	// 2026-08-13 `C-B8`(OB4): `ERR_WORLD_INDETERMINATE`(0x19) 등재. 62 → 63.
	// 2026-08-14 `E-W5`(OB5): `ERR_IDENTIFIER_FORMAT`(0x81) 등재. 63 → 64.
	// 2026-08-16 `C-B16`: `ERR_REVOKED_KEY_ID`(0x44) · `ERR_KEYRING_REVOKED_OVERLAP`(0x82) 등재. 64 → 66.
	// 2026-08-22 `D-L6`(POLCLASS): `ERR_EVIDENCE_TRUST_CLASS`(0x1A) 등재. 66 → 67.
	// 2026-09-04 `AL-2`: `ERR_REQUESTER_UNKNOWN`(0x83) · `ERR_CONTEXT_NOT_JSON`(0x84)
	//   · `ERR_CONTEXT_TOO_LARGE`(0x85) · `ERR_CONTEXT_STORE`(0x86) 등재. 67 → 71.
	// 2026-09-04 `AL-3`: `ERR_UNKNOWN_ACTION_CLASS`(0x87) · `ERR_ACTION_CLASS_MISMATCH`(0x88)
	//   · `ERR_TARGET_UNKNOWN`(0x89) 등재. 71 → 74.
	// 2026-09-14 `SKL v2.1`: `ERR_ENVELOPE_EXCEEDED`(0x8A) 등재 — 한도 초과 요청을
	//   줄여 발급하던 것을 거부로. 74 → 75.
	// 2026-10-01 OI-01: ERR_REPORT_GAP (0x5A, LOCAL) — the robot agent's durable report
	//   queue overflowed; one summary of the dropped span. 75 → 76.
	// 2026-10-18 P19-M1 (preview.19 evaluation): ERR_BUNDLE_CLOCK (0x8B) · ERR_BUNDLE_LIFETIME (0x8C)
	//   · ERR_BUNDLE_POLICY (0x8D), LOCAL — the keyring-bundle remaining-validity refusals that the
	//   gate had been issuing without an entry. 76 → 79.
	const want = 79
	if len(table) != want {
		t.Errorf("DN3 등재는 %d항목이어야 한다, got %d — 마일스톤과 사전이 어긋났다",
			want, len(table))
	}
}
