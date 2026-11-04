// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/glowfly/pail/services/internal/blackbox"
)

// TestDUR_RecoveryTruncateCanonPin — `pail-bb-recovery:v1` 의 핀 (implementation contract, DUR-L3).
//
// 이 접두어는 **서명 입력**이라 canon 값 문자열에 나타나지 않는다. 그래서 동결 벡터로
// 고정할 자리가 없고, 게다가 제2 동결 창은 `A2-9`(태그 OB1-FREEZE-2026-08-17)로 이미
// 닫혀 있어 벡터를 신설하는 것 자체가 `R1` 발동이다. `UNPINNED.tsv` 에 `GOTEST_NOVEC`
// 로 등록하고 그 핀이 여기다 — 벡터가 없으므로 기대 바이트를 들고 있을 곳이 이 파일뿐이다.
//
// 여기 적힌 hex 는 사본이 아니라 **정본**이다. 벡터가 있는 축(checkpoint_v2 등)에서
// 테스트 안에 hex 를 다시 적는 것이 금지인 이유(F7: 두 번째 정본이 생긴다)는 여기에
// 해당하지 않는다. 대신 그 대가로 이 기대값은 벡터 세트 밖이고, 따라서 프로파일 적합성
// 주장에는 실리지 않는다 — 검사 5 가 그 사실을 WARN 으로 계속 말한다.
func TestDUR_RecoveryTruncateCanonPin(t *testing.T) {
	// ① 접두어 리터럴. F1 레지스트리·매핑표·이 상수 셋이 같은 문자열이어야 한다.
	if blackbox.RecoveryTruncatePrefix != "pail-bb-recovery:v1:" {
		t.Fatalf("접두어가 바뀌었다: %q — F1 표와 spec_prefix_map.tsv 를 함께 고쳐야 한다",
			blackbox.RecoveryTruncatePrefix)
	}

	const (
		discarded = uint64(1111)
		segSeq    = uint64(7)
		unixMs    = uint64(1723600000000)
	)
	tail := make([]byte, 32)
	for i := range tail {
		tail[i] = byte(0x20 + i)
	}

	// ② 서명 입력 바이트. 길이·필드 순서·엔디언이 전부 여기에 굳는다.
	const wantSigned = "7061696c2d62622d7265636f766572793a76313a" +
		"0000000000000457" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
		"0000000000000007" +
		"000001914e90d400"
	got := blackbox.RecoveryTruncateSignedInput(discarded, tail, segSeq, unixMs)
	if hex.EncodeToString(got) != wantSigned {
		t.Fatalf("signed_input 불일치\n got=%s\nwant=%s", hex.EncodeToString(got), wantSigned)
	}
	if len(got) != len(blackbox.RecoveryTruncatePrefix)+8+32+8+8 {
		t.Fatalf("signed_input 길이 %d", len(got))
	}

	// ③ 온디스크 페이로드. 접두어는 여기 **없다** — 서명 입력에만 있다. 그 차이가
	//    사라지면 검증자는 접두어를 두 번 붙이거나 아예 안 붙이게 된다.
	sig := bytes.Repeat([]byte{0xAB}, 64)
	const wantPayload = "0000000000000457" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
		"0000000000000007" +
		"000001914e90d400" +
		"abababababababababababababababababababababababababababababababab" +
		"abababababababababababababababababababababababababababababababab"
	pl := blackbox.RecoveryTruncatePayload(discarded, tail, segSeq, unixMs, sig)
	if hex.EncodeToString(pl) != wantPayload {
		t.Fatalf("payload 불일치\n got=%s\nwant=%s", hex.EncodeToString(pl), wantPayload)
	}
	if len(pl) != blackbox.RecoveryTruncatePayloadLen {
		t.Fatalf("payload 길이 %d — %d 이어야 한다", len(pl), blackbox.RecoveryTruncatePayloadLen)
	}
	if bytes.Contains(pl, []byte(blackbox.RecoveryTruncatePrefix)) {
		t.Fatal("페이로드가 접두어를 담고 있다 — 접두어는 서명 입력에만 있어야 한다")
	}

	// ④ 네 필드가 전부 서명 안에 있는가. 옆에 있는 수는 고쳐 써도 서명이 깨지지
	//    않는다(체크포인트 v1 이 정확히 그랬다). 복구 레코드에서 그것이 일어나면
	//    "1111 바이트를 버렸다"를 "0 바이트를 버렸다"로 고쳐 쓸 수 있고, 그 레코드는
	//    자기가 폭로해야 할 절단을 세탁하게 된다.
	base := blackbox.RecoveryTruncateSignedInput(discarded, tail, segSeq, unixMs)
	other := make([]byte, 32)
	copy(other, tail)
	other[0] ^= 0xFF
	for name, v := range map[string][]byte{
		"discarded": blackbox.RecoveryTruncateSignedInput(discarded+1, tail, segSeq, unixMs),
		"tail":      blackbox.RecoveryTruncateSignedInput(discarded, other, segSeq, unixMs),
		"segSeq":    blackbox.RecoveryTruncateSignedInput(discarded, tail, segSeq+1, unixMs),
		"unixMs":    blackbox.RecoveryTruncateSignedInput(discarded, tail, segSeq, unixMs+1),
	} {
		if bytes.Equal(base, v) {
			t.Errorf("%s 를 바꿔도 서명 입력이 같다 — 그 필드는 서명 밖에 있다", name)
		}
	}
}
