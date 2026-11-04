// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// permit 생존 미러 (implementation contract D11).
//
// 게이트는 개인키를 갖지 않고 burst 를 내지 않는다(실측: keyring_bundle.hpp 에
// private/seed/Sign 0건, 게이트 .cpp 의 burst 참조 0건). 그래서 permit 생존은
// 게이트가 아니라 **사이드카**가 자기 신원으로 증언한다 — 화면의 초록은
// "누군가 허용이라더라"가 아니라 "이 키가 서명해 말했다"여야 한다.
//
// 패킷은 burst v2 와 같은 120B/56B 서명 접두 형상이되 매직이 다르다('PMIR').
// burst 이벤트 열거를 늘리지 않는 이유는 그 채널이 **예외 사건 감사용**이기
// 때문이다: 10~20Hz 생존 틱을 같은 채널에 부으면 차단·정지 기록이 정상 틱에
// 묻힌다(D11).
//
//	off  field                                    size
//	0    magic 'PMIR'                             4
//	4    ver = 1                                  1
//	5    mode (0 미관찰 | 1 enforce | 2 observe)    1
//	6    tick_ms (u16 LE)  미러 자기 발신 주기       2
//	8    unix_ms (u64 LE)  미러 발신 시각(참고값)    8
//	16   robot_id_hash = sha256(robot_id)[:16]    16
//	32   permit_age_ms (u32 LE)                    4
//	36   deadman_window_ms (u16 LE)                2
//	38   reserved                                  2
//	40   permit_seq (u32 LE)                       4
//	44   mirror_seq (u32 LE)                       4
//	48   reserved                                  8
//	56   ed25519_sig = Sign(pkt[0:56])            64
//	120  total
//
// permit_age_ms 를 미러가 **자기 시계에서** 재서 싣는 것은 의도다: 수신측이
// 미러의 unix_ms 와 자기 시각을 빼면 두 시계의 차이가 나이에 섞인다. 나이는
// 한 시계 안의 차이여야 한다.
const (
	MirrorPacketSize   = 120
	MirrorSignedPrefix = 56

	// permit 을 부팅 후 한 번도 못 받았다는 진술. 0(방금 받았다)과 다른 값이어야
	// 한다 — 같은 바이트를 쓰면 "무수신"이 "최신"으로 도착한다.
	PermitAgeNever uint32 = 0xFFFFFFFF

	ModeUnobserved = ""
	ModeEnforce    = "enforce"
	ModeObserve    = "observe"
)

func mirrorModeName(b byte) string {
	switch b {
	case 1:
		return ModeEnforce
	case 2:
		return ModeObserve
	default:
		return ModeUnobserved
	}
}

// MirrorIngester turns received mirror packets into permit records.
//
// 키 집합은 **미러 역할 전용**이다(VerifyMirrorKeys). issuer·burst 키로의
// 폴백은 두지 않는다: 아무 신뢰 키나 permit 생존을 주장할 수 있으면 초록이
// 누구의 증언인지를 잃는다.
type MirrorIngester struct {
	keys []ed25519.PublicKey
}

func NewMirrorIngester(keys []ed25519.PublicKey) *MirrorIngester {
	return &MirrorIngester{keys: keys}
}

// sigVerdict classifies a mirror packet against the mirror-role anchor set.
// 3값이다 — 키가 없으면 "검증 못 했다"이지 "검증했고 틀렸다"가 아니다(H-B2).
func (m *MirrorIngester) sigVerdict(pkt []byte) string {
	if len(m.keys) == 0 {
		return SigUnverifiable
	}
	for _, k := range m.keys {
		if ed25519.Verify(k, pkt[0:MirrorSignedPrefix], pkt[MirrorSignedPrefix:MirrorPacketSize]) {
			return SigOK
		}
	}
	return SigBad
}

// Observe records one received mirror packet at receipt time now.
func (m *MirrorIngester) Observe(pkt []byte, now time.Time) (Record, error) {
	if len(pkt) != MirrorPacketSize {
		return Record{}, fmt.Errorf("mirror packet size %d, want %d", len(pkt), MirrorPacketSize)
	}
	if string(pkt[0:4]) != "PMIR" || pkt[4] != 1 {
		return Record{}, fmt.Errorf("bad mirror magic/version")
	}
	return Record{
		V:           1,
		Kind:        KindPermit,
		Ms:          uint64(now.UnixMilli()),
		Robot:       hex.EncodeToString(pkt[16:32]),
		Sig:         m.sigVerdict(pkt),
		Mode:        mirrorModeName(pkt[5]),
		TickMs:      binary.LittleEndian.Uint16(pkt[6:8]),
		PermitAgeMs: binary.LittleEndian.Uint32(pkt[32:36]),
		DeadmanMs:   binary.LittleEndian.Uint16(pkt[36:38]),
		PermitSeq:   binary.LittleEndian.Uint32(pkt[40:44]),
		MirrorSeq:   binary.LittleEndian.Uint32(pkt[44:48]),
		Raw:         hex.EncodeToString(pkt),
	}, nil
}

// PermitVerdict is one robot's permit-liveness judgment: the material travels
// beside the verdict (anchor probe Report grammar), never folded into it.
type PermitVerdict struct {
	Robot       string `json:"robot"`
	State       string `json:"state"`
	KeyRole     string `json:"key_role"`
	MirrorAgeMs uint64 `json:"mirror_age_ms"`
	PermitAgeMs uint32 `json:"permit_age_ms"`
	DeadmanMs   uint16 `json:"deadman_window_ms"`
	Mode        string `json:"mode"`
	Why         string `json:"why"`
}

const (
	PermitAlive   = "alive"
	PermitAbsent  = "absent"
	PermitUnknown = "unknown"
)

// PermitState judges one robot's permit state from mirror records.
//
// 신선도는 **두 개**다. 미러가 아직 말하고 있는가(수신 시계)와 미러가 본
// permit 이 아직 신선한가(미러 시계). 둘을 한 값으로 합치면 두 시계의 차이가
// 나이에 섞이고, 화면은 회색과 초록 사이에서 떤다.
//
// 어느 한계도 발명하지 않는다: 미러 침묵 한계는 미러가 스스로 실은 tick_ms 의
// 2배(motion_bridge_node.cpp:112 의 `2 * permit_deadline_ms` 와 같은 식)이고,
// permit 신선도 창은 브리지가 실은 deadman_window_ms 다. 창을 모르면 재지
// 않는다 — 모르는 채로 잰 값은 "확인 못 했다"를 "확인했고 살아 있다"로
// 도착시킨다(H-B2).
func PermitState(recs []Record, robot string, now time.Time) PermitVerdict {
	var last *Record
	for i := range recs {
		if recs[i].Kind == KindPermit && recs[i].Robot == robot {
			last = &recs[i]
		}
	}
	if last == nil {
		return PermitVerdict{Robot: robot, State: PermitUnknown,
			Why: "미러 레코드 없음"}
	}
	v := PermitVerdict{
		Robot:       robot,
		KeyRole:     "mirror",
		MirrorAgeMs: uint64(now.UnixMilli()) - last.Ms,
		PermitAgeMs: last.PermitAgeMs,
		DeadmanMs:   last.DeadmanMs,
		Mode:        last.Mode,
	}
	// 미검증 진술은 허용 재료가 아니다. key_role 을 비우는 것이 화면 쪽
	// 계약이다 — 신원 없는 초록은 아무 UDP 발신자나 켤 수 있다.
	if last.Sig != SigOK {
		v.KeyRole = ""
		v.State = PermitUnknown
		v.Why = "미러 서명 " + last.Sig
		return v
	}
	if last.TickMs == 0 {
		v.State = PermitUnknown
		v.Why = "미러가 자기 발신 주기를 밝히지 않음"
		return v
	}
	if v.MirrorAgeMs > 2*uint64(last.TickMs) {
		v.State = PermitUnknown
		v.Why = "미러 침묵"
		return v
	}
	if last.DeadmanMs == 0 {
		v.State = PermitUnknown
		v.Why = "브리지 침묵 창 미관찰"
		return v
	}
	if last.PermitAgeMs == PermitAgeNever {
		v.State = PermitAbsent
		v.Why = "부팅 후 permit 무수신"
		return v
	}
	if last.PermitAgeMs <= uint32(last.DeadmanMs) {
		v.State = PermitAlive
		v.Why = "permit 생존"
	} else {
		v.State = PermitAbsent
		v.Why = "permit 끊김"
	}
	return v
}

// PermitStates judges every robot that appears in the mirror records.
//
// 표에 실리는 로봇 목록은 **도착한 레코드에서만** 나온다. 설정 파일에서 읽으면
// 두 방향으로 틀린다: 등록됐지만 한 번도 말한 적 없는 로봇이 초록 옆에 서고,
// 등록되지 않은 채 말하고 있는 로봇은 표에서 통째로 사라진다. 뒤엣것이 더
// 위험하다 — 없는 행은 회색조차 아니다.
//
// 정렬은 로봇 해시 오름차순이다. 순서를 도착 순으로 두면 같은 재료가 재시작
// 뒤 다른 표를 만들고, 화면의 행 이동이 상태 변화로 읽힌다.
func PermitStates(recs []Record, now time.Time) []PermitVerdict {
	seen := map[string]bool{}
	robots := make([]string, 0, 4)
	for i := range recs {
		if recs[i].Kind != KindPermit || seen[recs[i].Robot] {
			continue
		}
		seen[recs[i].Robot] = true
		robots = append(robots, recs[i].Robot)
	}
	sort.Strings(robots)
	out := make([]PermitVerdict, 0, len(robots))
	for _, r := range robots {
		out = append(out, PermitState(recs, r, now))
	}
	return out
}
