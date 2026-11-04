// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"encoding/hex"
	"testing"

	"github.com/glowfly/pail/services/internal/canon"
)

// 고정 본문 (context_v1.vec 머리말). 벡터 안에는 본문 필드가 없고 그 해시만
// 있으므로, 본문은 여기에 적고 해시는 벡터에서 읽는다 — 그래야 본문→해시
// 단계도 대조 대상이 된다. 본문까지 벡터에서 읽으면 이 시험은 해시 함수를
// 두 번 부르는 항등식이 된다.
const (
	cxNodeID   = "node-7"
	cxKindName = "CONTEXT_EVENT_HUMAN_PRESENT"
	cxArg      = "zone:z7" // ':' 는 의도 — 자유 텍스트는 R-B(LP)라 안전하다.
	cxClaimMs  = uint64(1700000000000)
)

// TestOR2_ContextProvenanceCanon — 동결된 context_v1.vec 대조 .
//
// 얼린 것은 형식이다. 이 시험이 하는 일은 Go 조립기가 그 형식을 바이트로
// 재현하는지 확인하는 것뿐이고, 기대값은 전부 벡터에서 읽는다(NF6).
func TestOR2_ContextProvenanceCanon(t *testing.T) {
	recs := readVec(t, goldenPath(t, "tests/golden/canon/context_v1.vec"))
	if len(recs) != 5 {
		t.Fatalf("context_v1.vec 레코드 %d건 — 5건이어야 한다 (CX1-01~05)", len(recs))
	}

	for _, r := range recs {
		r := r
		t.Run(r.ID, func(t *testing.T) {
			callerKind := r.get(t, "caller_kind")

			if r.Fields["expect"] == "reject" {
				got, err := canon.ContextProvenancePayload(
					"CONTEXT_EVENT_HUMAN_PRESENT", callerKind, "", false, "00")
				t.Logf("GOLDEN-CONTEXT go %s expect=reject err=%v", r.ID, err)
				if err == nil {
					t.Fatalf("%s: caller_kind %q 는 거부되어야 한다 (사유=%s)",
						r.ID, callerKind, r.Fields["reject_reason"])
				}
				if got != nil {
					t.Fatalf("%s: 거부하면서 바이트도 냈다 — 호출자가 그것을 기록할 수 있다", r.ID)
				}
				return
			}

			// ① 본문 해시: 고정 본문 → 벡터의 event_body_hash_hex.
			wantBody := r.get(t, "event_body_hash_hex")
			gotBody := canon.ContextBodyHashHex(cxNodeID, cxKindName, cxArg, cxClaimMs)
			if gotBody != wantBody {
				t.Fatalf("%s: event_body_hash 불일치\n got=%s\nwant=%s", r.ID, gotBody, wantBody)
			}

			// ② payload 조립.
			verified := r.get(t, "context_verified")
			if verified != "0" && verified != "1" {
				t.Fatalf("%s: context_verified %q — 0/1 이어야 한다", r.ID, verified)
			}
			got, err := canon.ContextProvenancePayload(
				r.get(t, "event_kind"), callerKind, r.get(t, "caller_id"),
				verified == "1", wantBody)
			if err != nil {
				t.Fatalf("%s: accept 레코드가 거부됐다: %v", r.ID, err)
			}
			wantHex := r.get(t, "payload_hex")
			gotHex := hex.EncodeToString(got)
			t.Logf("GOLDEN-CONTEXT go %s len=%d ok=%v", r.ID, len(got), gotHex == wantHex)
			if gotHex != wantHex {
				t.Fatalf("%s: payload 불일치\n got=%s\nwant=%s", r.ID, gotHex, wantHex)
			}
			if l := mustInt64(t, r, "payload_len"); int64(len(got)) != l {
				t.Fatalf("%s: payload_len %d — 벡터는 %d", r.ID, len(got), l)
			}
		})
	}

	// caller_kind 세 값은 서로 다른 바이트를 내야 한다. 하나로 뭉개지면
	// "모른다"와 "해당 없음"이 같은 기록이 되고, 그것이 FB-1 이 겨냥한 H7
	// 위반 자체다.
	seen := map[string]string{}
	for _, k := range canon.CallerKinds {
		p, err := canon.ContextProvenancePayload("K", k, "", false, "ab")
		if err != nil {
			t.Fatalf("동결 어휘 %q 가 거부됐다: %v", k, err)
		}
		h := hex.EncodeToString(p)
		if prev, dup := seen[h]; dup {
			t.Fatalf("caller_kind %q 와 %q 가 같은 바이트를 낸다", prev, k)
		}
		seen[h] = k
	}
}

// TestOR2_ConsumptionKeyCanon — 동결된 tokenkey_v1.vec 대조 .
//
// 이 키가 대체하려는 것은 봉투 token_id 다: 서명 대상 밖의 값을 단일사용
// 캐시 키로 쓰던 X12② 를 원문 바이트 유래 값으로 바꾼다. C++ 쪽에 같은 이름의
// 독립 구현이 있고, 둘을 정직하게 유지하는 것은 이 벡터다.
func TestOR2_ConsumptionKeyCanon(t *testing.T) {
	recs := readVec(t, goldenPath(t, "tests/golden/canon/tokenkey_v1.vec"))
	if len(recs) != 2 {
		t.Fatalf("tokenkey_v1.vec 레코드 %d건 — 2건이어야 한다 (TK1-01/02)", len(recs))
	}

	keys := map[string]string{}
	for _, r := range recs {
		raw, err := hex.DecodeString(r.get(t, "action_token_bytes"))
		if err != nil {
			t.Fatalf("%s: action_token_bytes hex: %v", r.ID, err)
		}
		want := r.get(t, "consumption_key_hex")
		got := canon.ConsumptionKeyHex(raw)
		t.Logf("GOLDEN-TOKENKEY go %s ok=%v", r.ID, got == want)
		if got != want {
			t.Fatalf("%s: consumption_key 불일치\n got=%s\nwant=%s", r.ID, got, want)
		}
		if prev, dup := keys[got]; dup {
			t.Fatalf("%s 와 %s 가 같은 소비 키를 낸다 — 단일사용이 두 토큰을 하나로 본다",
				prev, r.ID)
		}
		keys[got] = r.ID
	}
}
