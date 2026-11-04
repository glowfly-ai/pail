// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package contract

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/operator"
)

// TestOB1_OperatorCanonV2 — implementation contract / §4.1, 완료조건 A2-5 의 벡터 축.
//
// canon_golden_test.go 가 v1 을 고정하고 이 파일이 v2 를 고정한다. 둘을 한 테스트로
// 합치지 않는 이유는 벡터가 서로 다른 것을 주장하기 때문이다 — 구판 벡터는 "과거에
// 서명된 바이트가 무엇이었나"를, 신판 벡터는 "설계서 §3.2.2 가 무엇을 적었나"를
// 고정한다. 한 표에 섞으면 신판을 고칠 때 구판 기대까지 손대게 된다.
//
// 기대값은 전부 .vec 에서 읽는다. 여기에 canon 문자열을 리터럴로 다시 적으면 그
// 사본이 두 번째 정본이 되고(F7), 벡터를 고쳐도 테스트가 울지 않는다(NF6).
func TestOB1_OperatorCanonV2(t *testing.T) {
	for _, tc := range []struct {
		rel   string
		count int
	}{
		{"tests/golden/canon/unlock_v2.vec", 6},
		{"tests/golden/canon/revoke_issuer_v2.vec", 6},
	} {
		tc := tc
		t.Run(tc.rel, func(t *testing.T) {
			recs := readVec(t, goldenPath(t, tc.rel))
			// 건수를 못 박는다. 레코드가 조용히 사라지면 남은 것들은 여전히 통과하고,
			// 지워진 조건은 초록 아래에서 사라진다.
			if len(recs) != tc.count {
				t.Fatalf("%s 레코드 %d건 — %d건이어야 한다", tc.rel, len(recs), tc.count)
			}

			type acc struct {
				key   string // arg_id/unix_ms/nonce (operator_key_id 제외)
				opKey string
				canon string
				id    string
			}
			var accepted []acc

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
					expect := r.get(t, "expect")

					var got []byte
					switch fn {
					case "unlock":
						got, err = operator.UnlockCanon(argID, unixMs, nonce, r.get(t, "operator_key_id"))
					case "revoke":
						got, err = operator.RevokeCanon(argID, unixMs, nonce, r.get(t, "operator_key_id"))
					case "unlock_v1":
						got, err = operator.UnlockCanonV1(argID, unixMs, nonce)
					case "revoke_v1":
						got, err = operator.RevokeCanonV1(argID, unixMs, nonce)
					default:
						t.Fatalf("미지 func %q", fn)
					}

					switch expect {
					case "reject":
						t.Logf("GOLDEN-CANON go %s expect=reject err=%v", r.ID, err)
						if err == nil {
							t.Fatalf("%s: 거부되어야 하는데 조립됐다 (got=%q, 사유=%s)",
								r.ID, got, r.Fields["reject_reason"])
						}
						if got != nil {
							t.Fatalf("%s: 거부하면서 바이트도 냈다 — 호출자가 그것을 서명할 수 있다", r.ID)
						}
						if _, ok := r.Fields["canon"]; ok {
							t.Fatalf("%s: reject 레코드에 canon 이 있다 — 거부되는 입력의 '정답 바이트'는 존재하지 않는다", r.ID)
						}

					case "accept":
						if err != nil {
							t.Fatalf("%s: accept 레코드가 거부됐다: %v", r.ID, err)
						}
						want := r.get(t, "canon")
						t.Logf("GOLDEN-CANON go %s ok=%v", r.ID, string(got) == want)
						if string(got) != want {
							t.Fatalf("canon 불일치:\n got=%q\nwant=%q", got, want)
						}
						accepted = append(accepted, acc{
							key:   argID + "\x00" + r.get(t, "unix_ms") + "\x00" + r.get(t, "nonce"),
							opKey: r.get(t, "operator_key_id"),
							canon: want,
							id:    r.ID,
						})

					case "parse_only":
						// F8: 생성은 OB1 에서 끝났지만 파싱·검증은 영원히 유지된다.
						// 구판 서명 바이트를 다시 만들어낼 수 있어야 과거 기록을
						// 검증할 수 있다 — 이 레코드가 그 능력의 기계 증거다.
						if err != nil {
							t.Fatalf("%s: 구판 조립기가 거부했다 — 이미 서명된 기록이 검증 불가가 된다: %v", r.ID, err)
						}
						want := r.get(t, "canon")
						t.Logf("GOLDEN-CANON go %s parse_only ok=%v", r.ID, string(got) == want)
						if string(got) != want {
							t.Fatalf("구판 canon 불일치:\n got=%q\nwant=%q", got, want)
						}
						if !strings.Contains(want, ":v1:") {
							t.Fatalf("%s: parse_only 레코드가 v1 문자열이 아니다: %q", r.ID, want)
						}
						// 판이 바이트에 나타나야 한다. 같은 인자로 신판을 조립했을 때
						// 구판과 같은 문자열이 나오면 v1 서명이 v2 문맥에서 그대로
						// 재사용되고, 판을 올린 이유가 사라진다.
						var v2 []byte
						switch fn {
						case "unlock_v1":
							v2, err = operator.UnlockCanon(argID, unixMs, nonce, "op-key-1")
						case "revoke_v1":
							v2, err = operator.RevokeCanon(argID, unixMs, nonce, "op-key-1")
						}
						if err != nil {
							t.Fatalf("%s: 신판 조립 실패: %v", r.ID, err)
						}
						if string(v2) == want {
							t.Fatalf("%s: v1 과 v2 의 서명 대상이 같다 — 판이 바이트에 나타나지 않는다", r.ID)
						}

					default:
						t.Fatalf("%s: 미지 expect %q", r.ID, expect)
					}
				})
			}

			// C-B11 의 본체. 나머지가 모두 같고 operator_key_id 만 다른 두 레코드가
			// 같은 바이트를 내면 서명은 서명자를 덮지 않는 것이고, 그것이 v1 의 결손
			// 그 자체다. 레코드 하나만으로는 "필드가 문자열에 있다"까지만 보이고
			// "그 값이 실제로 바이트를 가른다"는 보이지 않는다.
			pairs := 0
			for i := range accepted {
				for j := i + 1; j < len(accepted); j++ {
					a, b := accepted[i], accepted[j]
					if a.key != b.key || a.opKey == b.opKey {
						continue
					}
					pairs++
					if a.canon == b.canon {
						t.Fatalf("%s 와 %s 는 operator_key_id 만 다른데 canon 이 같다 — 서명이 서명자를 덮지 않는다 (C-B11)", a.id, b.id)
					}
				}
			}
			if pairs == 0 {
				t.Fatalf("%s: operator_key_id 만 다른 짝이 없다 — C-B11 을 실제로 시험하는 레코드가 사라졌다", tc.rel)
			}
			t.Logf("GOLDEN-CANON go %s signer-pairs=%d", tc.rel, pairs)
		})
	}
}
