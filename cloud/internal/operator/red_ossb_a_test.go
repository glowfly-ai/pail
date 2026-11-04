// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

//go:build red_ossb_a

// RED-OSSB-A 운영자 정규문 2건 (implementation contract, 제2 동결 창 OB1).
//
//	RA-7  C-B11  unlock 서명이 operator_key_id 를 덮지 않는다.
//	RA-8  C-B11  revoke 서명이 동상.
//
// 두 케이스를 하나로 묶지 않는 이유는 §2.3 그대로다 — UnlockCanon 과 RevokeCanon 은
// 같은 형태의 같은 결손을 따로 갖고 있고, 한쪽만 고치면 결함이 형제에 그대로 남는다.
// 묶어서 관측하면 그 잔존이 초록 아래에서 일어난다.
//
// **왜 reflect 인가.** A2-5 는 조립기의 시그니처를 바꾼다(operator_key_id 인자 추가).
// 인자를 직접 적으면 이 파일은 수정 전에는 4-인자 호출로 컴파일되지 않고, 수정 후에는
// 3-인자 호출로 컴파일되지 않는다. 어느 쪽이든 러너가 보는 것은 빌드 실패 = N/A 이고,
// N/A 는 RED 보다 위험하다 — 붉은 줄은 사람을 부르지만 N/A 는 "아직 볼 수 없음"으로
// 읽힌다. 시그니처 자체가 관측 대상이므로 시그니처에 의존하지 않는 호출을 쓴다.
//
// 실행: go test -count=1 -tags red_ossb_a -run 'TestRED_RA[78]' ./internal/operator -v

package operator

import (
	"reflect"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/canon"
)

// v2Prefix 는 v1 상수에서 판만 올려 조립한다. 신판 접두어를 리터럴로 적으면 검사 1
// 에게 그것은 레지스트리 밖 접두어의 **실제 출현**이다 — F1 표는 A2-7 이 갱신하고,
// 그 전까지 소스에 놓인 리터럴은 스캐너에게 의도가 아니라 사실로 보인다
// (E6 bb126c7 · OB1 커밋1 선례).
func v2Prefix(v1 string) string { return strings.TrimSuffix(v1, "v1:") + "v2:" }

// canonArity 는 조립기가 서명 대상 안에 operator_key_id 를 받을 자리를 갖는지 센다.
func canonArity(fn interface{}) int { return reflect.TypeOf(fn).NumIn() }

// callCanon 은 3-인자·4-인자 어느 쪽이든 호출한다. 4번째 인자가 string 이 아니면
// 호출하지 않고 그 사실을 돌려준다 — panic 은 판정이 아니다.
func callCanon(t *testing.T, fn interface{}, id string, unixMs int64, nonce []byte,
	opKeyID string) ([]byte, error) {
	t.Helper()
	v := reflect.ValueOf(fn)
	args := []reflect.Value{reflect.ValueOf(id), reflect.ValueOf(unixMs), reflect.ValueOf(nonce)}
	if v.Type().NumIn() >= 4 {
		if v.Type().In(3).Kind() != reflect.String {
			t.Fatalf("RED CONFIRMED: 4번째 인자가 string 이 아니다 (%s) — "+
				"operator_key_id 를 실을 자리로 읽을 수 없다", v.Type().In(3))
		}
		args = append(args, reflect.ValueOf(opKeyID))
	}
	out := v.Call(args)
	var b []byte
	if !out[0].IsNil() {
		b = out[0].Bytes()
	}
	var err error
	if !out[1].IsNil() {
		err = out[1].Interface().(error)
	}
	return b, err
}

// assertKeyIDBound 은 두 케이스가 공유하는 판정이다. 공유하는 것은 **판정의 형태**이지
// 관측점이 아니다 — 호출자가 다른 조립기를 넘기고, 한쪽이 고쳐져도 다른 쪽은 자기
// 조립기로 자기 결론을 낸다.
func assertKeyIDBound(t *testing.T, caseID, field string, fn interface{}, v1Prefix, ident string) {
	t.Helper()
	nonce := []byte{1, 2, 3, 4}
	const ms = int64(1700000000000)

	if canonArity(fn) < 4 {
		t.Fatalf("RED CONFIRMED (%s): 조립기가 인자 %d개다 — 서명 대상 문자열에 "+
			"operator_key_id 가 들어갈 자리가 없다. 봉투로만 실려 오는 값을 "+
			"기록이 서명된 것처럼 보이게 한다(§3.2.3)", caseID, canonArity(fn))
	}

	a, err := callCanon(t, fn, ident, ms, nonce, "op-key-1")
	if err != nil {
		t.Fatalf("RED CONFIRMED (%s): 정상 입력이 거부됐다: %v — 항상 붉은 게이트는 "+
			"게이트가 아니라 벽이다", caseID, err)
	}
	b, err := callCanon(t, fn, ident, ms, nonce, "op-key-2")
	if err != nil {
		t.Fatalf("RED CONFIRMED (%s): 정상 입력이 거부됐다: %v", caseID, err)
	}
	if string(a) == string(b) {
		t.Fatalf("RED CONFIRMED (%s): operator_key_id 만 바꿨는데 서명 대상 바이트가 "+
			"같다 — 서명이 서명자를 덮지 않는다", caseID)
	}

	want := v2Prefix(v1Prefix)
	if !strings.HasPrefix(string(a), want) {
		t.Fatalf("RED CONFIRMED (%s): 서명 대상이 %q 로 시작하지 않는다: %q — "+
			"필드를 더했으면 판이 올라가야 한다(F2)", caseID, want, string(a))
	}
	if !strings.HasSuffix(string(a), ":op-key-1") {
		t.Fatalf("RED CONFIRMED (%s): operator_key_id 가 끝에 붙어 있지 않다: %q — "+
			"중간 삽입은 구판 파서에 부분 성공 파싱의 여지를 준다(§3.2.2)",
			caseID, string(a))
	}

	// R-A 확대분. operator_key_id 도 식별자이므로 ':' 는 조립 거부다. 이스케이프하지
	// 않는다 — 두 값이 같은 바이트로 접히는 것을 막는 것이 목적이고, 여기서 예외를
	// 열면 R-C 가 이 canon 의 유일 예외라는 지위가 깨진다.
	if _, err := callCanon(t, fn, ident, ms, nonce, "op:key"); err == nil {
		t.Fatalf("RED CONFIRMED (%s): operator_key_id 에 ':' 가 들어가는데 조립이 "+
			"성공한다 — R-A 가 %s 를 닫지 않는다", caseID, field)
	}
	// 빈 값. "서명자를 모른다"와 "서명자가 빈 이름이다"가 같은 바이트가 되면 안 된다.
	if _, err := callCanon(t, fn, ident, ms, nonce, ""); err == nil {
		t.Fatalf("RED CONFIRMED (%s): 빈 operator_key_id 로 조립이 성공한다 — "+
			"부재와 빈 이름이 같은 바이트가 된다", caseID)
	}
	// 만족 시 위반 0. 위의 정상 조립 두 건이 그 증거이고, 여기서 한 번 더 못박는다.
	if _, err := callCanon(t, fn, ident, ms, nonce, "op-key-1"); err != nil {
		t.Fatalf("RED CONFIRMED (%s): 어휘 안의 값이 거부된다: %v", caseID, err)
	}

	t.Logf("GREEN: %s — %s 가 서명 대상 안에 있고, ':' 와 빈 값은 조립 거부된다",
		caseID, field)
	t.Logf("GREEN: 서명 대상 실측 = %q", string(a))
}

// RA-7 — UnlockCanon.
func TestRED_RA7_UnlockSignatureOmitsOperatorKeyID(t *testing.T) {
	assertKeyIDBound(t, "RA-7", "operator_key_id", UnlockCanon, canon.UnlockV1, "robot-1")
}

// RA-8 — RevokeCanon. §2.3: 한쪽만 올리면 결함이 형제에 그대로 남는다.
func TestRED_RA8_RevokeSignatureOmitsOperatorKeyID(t *testing.T) {
	assertKeyIDBound(t, "RA-8", "operator_key_id", RevokeCanon, canon.RevokeIssuerV1, "dev-key-1")
}
