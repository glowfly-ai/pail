// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/glowfly/pail/services/internal/blackbox"
)

// TestOB6_CheckpointCanonV2 — implementation contract (E-C3) 의 벡터 축.
//
// tests/golden/canon/checkpoint_v2.vec 는 OR1 에서 동결됐는데 **아무도 읽지
// 않고 있었다**. 서명 입력을 재구현한 곳이 다섯이었고(로봇 writer · 검증 도구 ·
// anchor_saas chain.go · segment_chain.py · golden.py) 전부 주석으로만 이
// 파일을 인용했다. 인용은 대조가 아니다 — 다섯이 함께 틀려도 아무 테스트도
// 울지 않는다. 동결은 읽는 사람이 있을 때만 동결이다.
//
// 이 파일은 로봇측(blackbox 패키지) 축을 고정한다. anchor_saas 는 별 모듈이라
// 이 테스트가 닿지 못하므로 그쪽에 같은 축이 따로 선다(chain 패키지) — 사본이
// 아니라 **다른 구현에 대한 같은 기준점**이다.
//
// 기대값은 전부 .vec 에서 읽는다. 여기에 hex 를 다시 적으면 그 사본이 두 번째
// 정본이 되고(F7), 벡터를 고쳐도 이 테스트는 조용하다(NF6).
func TestOB6_CheckpointCanonV2(t *testing.T) {
	recs := readVec(t, goldenPath(t, "tests/golden/canon/checkpoint_v2.vec"))
	// 건수 고정: 레코드가 조용히 사라지면 남은 것들은 여전히 통과하고, 지워진
	// 주장은 초록 아래에서 사라진다.
	if len(recs) != 4 {
		t.Fatalf("checkpoint_v2.vec 레코드 %d건 — 4건이어야 한다 (CP2-01~03 + CP1-90)", len(recs))
	}

	sawV2Baseline, sawV1 := false, false

	for _, r := range recs {
		r := r
		t.Run(r.ID, func(t *testing.T) {
			recType := mustInt64(t, r, "record_type")
			head := mustHex(t, r, "head_hash_hex")
			count := uint64(mustInt64(t, r, "record_count"))
			pub := ed25519.PublicKey(mustHex(t, r, "pubkey"))
			sig := mustHex(t, r, "sig")
			wantPayload := mustHex(t, r, "payload_hex")
			expectVerify := r.get(t, "expect_verify") == "1"

			switch uint32(recType) {
			case blackbox.RecordCheckpointV2:
				segSeq := uint64(mustInt64(t, r, "segment_seq"))

				// ① 페이로드 조립: 프로덕션 조립기가 동결 바이트를 재현하는가.
				//    벡터의 record_count/segment_seq 로 조립하므로, 변조 레코드
				//    (CP2-02/03)에서는 **변조된 페이로드**가 나와야 맞다.
				gotPayload := blackbox.CheckpointV2Payload(head, count, segSeq, sig)
				if hex.EncodeToString(gotPayload) != hex.EncodeToString(wantPayload) {
					t.Fatalf("payload 불일치\n got=%s\nwant=%s",
						hex.EncodeToString(gotPayload), hex.EncodeToString(wantPayload))
				}
				if len(gotPayload) != blackbox.CheckpointV2PayloadLen {
					t.Fatalf("payload 길이 %d — %d 이어야 한다", len(gotPayload), blackbox.CheckpointV2PayloadLen)
				}

				// ② 서명 입력: signed_input_hex 가 있는 레코드에서만 대조한다.
				//    변조 레코드에는 그 줄이 없다 — 변조된 값으로 다시 조립한
				//    바이트를 "정본 서명 입력"이라 부를 수 없기 때문이다.
				signed := blackbox.CheckpointV2SignedInput(head, count, segSeq)
				if want, ok := r.Fields["signed_input_hex"]; ok {
					if hex.EncodeToString(signed) != want {
						t.Fatalf("signed_input 불일치\n got=%s\nwant=%s",
							hex.EncodeToString(signed), want)
					}
					sawV2Baseline = true
				}

				// ③ 판정: 기준선은 검증되고, count/seg_seq 를 건드린 두 레코드는
				//    검증에 실패해야 한다. 이것이 X13a·NF4 의 실물이다 —
				//    페이로드에서 읽은 값으로 서명 입력을 다시 만들면 서명이
				//    깨진다.
				got := ed25519.Verify(pub, signed, sig)
				if got != expectVerify {
					t.Fatalf("verify=%v — expect_verify=%v (%s)", got, expectVerify, r.get(t, "desc"))
				}
				verdict(t, "go", r.ID, got, "checkpoint_v2")

			case blackbox.RecordCheckpoint:
				// CP1-90: F8. 구판은 영원히 검증 가능해야 한다. 서명 대상은
				// head 32바이트 뿐이고 count 는 u64 **LE** 로 서명 밖에 있다 —
				// 그래서 이 레코드가 검증된다는 사실은 count 에 대해 아무것도
				// 말하지 않는다(그것이 chain.go 의 CountAttested=false 다).
				if e := r.get(t, "count_endian"); e != "le" {
					t.Fatalf("CP1-90 count_endian=%q — v1 은 LE 다", e)
				}
				if want := r.get(t, "signed_input_hex"); want != hex.EncodeToString(head) {
					t.Fatalf("v1 서명 입력은 head 그대로여야 한다\n got=%s\nwant=%s",
						hex.EncodeToString(head), want)
				}
				if len(wantPayload) != blackbox.CheckpointV1PayloadLen {
					t.Fatalf("v1 payload 길이 %d — %d 이어야 한다",
						len(wantPayload), blackbox.CheckpointV1PayloadLen)
				}
				got := ed25519.Verify(pub, head, sig)
				if got != expectVerify {
					t.Fatalf("v1 verify=%v — expect_verify=%v", got, expectVerify)
				}
				sawV1 = true
				verdict(t, "go", r.ID, got, "checkpoint_v1")

			default:
				t.Fatalf("미지 record_type %d", recType)
			}
		})
	}

	// 벡터가 두 형식을 **함께** 들고 있다는 것이 이 파일의 주장이다. 한쪽만
	// 남으면 "구판도 검증된다"(F8)나 "신판이 canon 이다" 중 하나가 조용히
	// 사라진다.
	if !sawV2Baseline {
		t.Error("v2 기준선(signed_input_hex 를 가진 레코드)이 없다")
	}
	if !sawV1 {
		t.Error("v1 레코드(CP1-90)가 없다 — F8 축이 사라졌다")
	}
}
