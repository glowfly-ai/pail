// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

// implementation contract (`DUR-L1`) — 세그먼트 바이트 문법의 단일 판정 함수.
//
// 이 파일이 생긴 이유(F-DUR-1): 절단 판정이 두 곳에 있었고 둘이 **다른 답을
// 냈다**. `reader.walkSegment` 는 꼬리 절단을 관용하는데 `writer.segmentTailHash`
// 는 같은 바이트에 기동을 거부했다 — 전원 상실 뒤 영구 미기동.
//
// 여기서 하는 것은 **문법**뿐이다. "찢김을 어떻게 처분하는가"는 정책이고, 정책은
// 호출자에 남는다:
//
//	reader.WalkDir  — 최종 세그먼트면 관용, 아니면 이력 중간 손상
//	writer.OpenDir  — 잘라내고 복구 레코드를 남긴 뒤 진행
//
// `cmd/blackbox_verify` 는 이 함수를 **공유하지 않는다**(LLD D3 유지) — 독립
// 감사자는 자기가 감사하는 코드와 파서를 나눠 쓰지 않는다. 단일화하는 것은 같은
// 프로세스 안의 두 벌이지 감사자가 아니다.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
)

// maxTornBytes — 찢긴 꼬리로 인정하는 상한.
//
// write(2) 한 번이 한 레코드를 쓰므로 전원 상실이 남길 수 있는 미완성 레코드는
// 하나다. 그보다 큰 잔여는 "전원이 나갔다"가 아니라 매체 손상이거나 누군가
// 덧붙인 바이트이며, 둘 다 fail-closed 대상이다. 상한을 좁게 두는 두 번째 이유:
// 복구는 파괴적이므로 **공격자가 지울 수 있는 창**을 최소화한다.
const maxTornBytes = int64(1) << 20

type scanResult struct {
	segSeq uint64
	// prevTail — 세그먼트 헤더가 선언한 상속 tail.
	prevTail [32]byte
	// cleanTail — 마지막 **완전한** 레코드의 this_hash. 레코드가 없으면
	// prevTail(빈 세그먼트는 체인 상속에 투명하다).
	cleanTail [32]byte
	records   int
	// cleanSize — 찢긴 꼬리를 뺀 파일 길이. 복구가 잘라낼 지점.
	cleanSize int64
	// tornBytes — 완전한 레코드를 이루지 못하는 말미 바이트 수. 0 이면 정상 종단.
	tornBytes int64
	// tornWhat — 무엇이 잘렸는지("record header" | "record" | "segment header").
	// 오류 문면 보존용.
	tornWhat string
	// abortedHeader — 세그먼트 **헤더 자체**가 끝까지 착지하지 못했다(F-DUR-7).
	//
	// 이 상태의 세그먼트는 레코드를 담을 수 없다. 쓰기 순서가 create → 헤더 →
	// 레코드이므로 헤더가 미완이면 그 뒤로 아무것도 쓰이지 않았다. 즉 이 파일은
	// **없었던 것과 같다** — 체인에 기여한 바가 없고, 상속할 tail 도 없다.
	//
	// 이것을 오류로 내면 세그먼트 생성 직후의 전원 상실이 영구 미기동이 되고
	// (DUR-06), 매체가 가득 차 헤더 쓰기가 실패한 자리에 남은 0바이트 시체가
	// **그 뒤 모든 재생을 CHAIN_ERROR 로 만든다**(DUR-01 실측). 후자가 더 나쁘다:
	// 디스크가 찬 사건 하나가 이미 기록된 이력 전체를 읽을 수 없게 만든다.
	//
	// 처분은 여기서 정하지 않는다 — 이 파일은 문법만 답한다.
	abortedHeader bool
}

// scanSegment 는 세그먼트를 처음부터 해시 체인을 검증하며 읽는다.
//
// expectTail 이 nil 이 아니면 헤더의 상속 tail 을 대조하고, 어긋나면 **레코드를
// 하나도 방출하기 전에** 오류를 낸다. 기동 경로는 앞선 세그먼트 문맥을 갖고 있지
// 않으므로 nil 을 준다.
//
// 찢긴 꼬리는 오류가 아니라 결과값이다 — 그것이 이 단일화의 요점이다.
func scanSegment(path string, expectTail *[32]byte, fn func(Record) error) (scanResult, error) {
	var res scanResult
	data, err := os.ReadFile(path)
	if err != nil {
		return res, err
	}
	if len(data) < segHeaderSize {
		// 미완성 헤더는 결과값이지 오류가 아니다(위 abortedHeader 참조). 상한은
		// 자명하다 — segHeaderSize 미만이므로 한 레코드 상한을 넘을 수 없다.
		res.abortedHeader = true
		res.tornBytes = int64(len(data))
		res.tornWhat = "segment header"
		return res, nil
	}
	hdr := data[:segHeaderSize]
	if string(hdr[0:4]) != segMagic {
		return res, fmt.Errorf("bad segment magic %q", hdr[0:4])
	}
	if v := binary.LittleEndian.Uint32(hdr[4:8]); v != segVersion {
		return res, fmt.Errorf("unsupported segment version=%d", v)
	}
	res.segSeq = binary.LittleEndian.Uint64(hdr[8:16])
	copy(res.prevTail[:], hdr[16:48])
	if expectTail != nil && !bytes.Equal(res.prevTail[:], expectTail[:]) {
		return res, fmt.Errorf("prev_segment_tail_hash mismatch (chain broken across segments)")
	}
	res.cleanTail = res.prevTail
	res.cleanSize = int64(segHeaderSize)

	prev := sha256.Sum256(hdr) // 헤더가 체인에 참여한다
	off := int64(segHeaderSize)
	size := int64(len(data))
	for off < size {
		rem := size - off
		if rem < 20 {
			return res, res.setTorn(rem, "record header")
		}
		rhdr := data[off : off+16]
		if v := binary.LittleEndian.Uint32(rhdr[0:4]); v != recVersion {
			return res, fmt.Errorf("unsupported record version=%d at offset=%d", v, off)
		}
		rtype := binary.LittleEndian.Uint32(rhdr[4:8])
		unixMs := binary.LittleEndian.Uint64(rhdr[8:16])
		payloadLen := int64(binary.LittleEndian.Uint32(data[off+16 : off+20]))
		total := 20 + payloadLen + 64
		if rem < total {
			return res, res.setTorn(rem, "record")
		}
		payload := data[off+20 : off+20+payloadLen]
		prevStored := data[off+20+payloadLen : off+20+payloadLen+32]
		thisStored := data[off+20+payloadLen+32 : off+total]
		if !bytes.Equal(prevStored, prev[:]) {
			return res, fmt.Errorf("prev_hash mismatch at offset=%d (chain broken)", off)
		}
		h := sha256.New()
		h.Write(rhdr)
		h.Write(payload)
		h.Write(prev[:])
		if !bytes.Equal(h.Sum(nil), thisStored) {
			return res, fmt.Errorf("this_hash mismatch at offset=%d (record tampered)", off)
		}
		copy(prev[:], thisStored)
		res.records++
		res.cleanTail = prev
		res.cleanSize = off + total
		if fn != nil {
			if err := fn(Record{SegmentSeq: res.segSeq, Type: rtype, UnixMs: unixMs, Payload: payload, Offset: off}); err != nil {
				return res, err
			}
		}
		off += total
	}
	return res, nil
}

// setTorn 은 찢김을 결과에 적고, 상한을 넘으면 오류로 승격한다.
func (r *scanResult) setTorn(rem int64, what string) error {
	if rem > maxTornBytes {
		return fmt.Errorf("truncated %s at offset=%d: %d trailing bytes exceed the one-record torn-tail bound (%d) — this is corruption, not a power loss",
			what, r.cleanSize, rem, maxTornBytes)
	}
	r.tornBytes = rem
	r.tornWhat = what
	return nil
}
