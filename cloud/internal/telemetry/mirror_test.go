// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// permit 생존 미러의 판정 의미론 (G-DSH-05, implementation contract D11).
//
// 각 의미를 정확히 하나의 테스트가 잰다(H-B9) — "미러가 대충 동작한다"가
// 아니라 어느 의미가 죽었는지가 이름으로 붉어야 한다.

const testMirrorTickMs = 500

// buildMirror 는 시험용 발신기다. 정본 생산기는 Python 사이드카이고 Go 는
// 검증만 한다 — 생산기와 검증기를 공유하면 둘이 함께 틀려도 초록이다.
func buildMirror(key ed25519.PrivateKey, robot string, mode byte, tickMs uint16,
	permitAgeMs uint32, deadmanMs uint16, permitSeq, mirrorSeq uint32,
	unixMs uint64) []byte {
	pkt := make([]byte, MirrorPacketSize)
	copy(pkt[0:4], []byte("PMIR"))
	pkt[4] = 1
	pkt[5] = mode
	binary.LittleEndian.PutUint16(pkt[6:8], tickMs)
	binary.LittleEndian.PutUint64(pkt[8:16], unixMs)
	rh := sha256.Sum256([]byte(robot))
	copy(pkt[16:32], rh[:16])
	binary.LittleEndian.PutUint32(pkt[32:36], permitAgeMs)
	binary.LittleEndian.PutUint16(pkt[36:38], deadmanMs)
	binary.LittleEndian.PutUint32(pkt[40:44], permitSeq)
	binary.LittleEndian.PutUint32(pkt[44:48], mirrorSeq)
	sig := ed25519.Sign(key, pkt[0:MirrorSignedPrefix])
	copy(pkt[56:120], sig)
	return pkt
}

func robotHash(robot string) string {
	h := sha256.Sum256([]byte(robot))
	return hex.EncodeToString(h[:16])
}

func mirrorKeypair(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

// 관측점 1 — 미러가 말을 멈추면 초록이 꺼진다.
//
// 설계서 DB-2 행이 요구하는 바로 그 실측이다: "미러 프로세스 kill → 초록이
// 회색으로 강하(초록 고정이면 FAIL)". 마지막 레코드의 내용만 보면 그 레코드는
// 영원히 "permit 살아 있었다"고 말한다 — 죽은 미러가 마지막으로 본 허용을
// 계속 주장하는 형태다.
func TestMirrorSilenceDropsToUnknown(t *testing.T) {
	pub, priv := mirrorKeypair(t, 7)
	in := NewMirrorIngester([]ed25519.PublicKey{pub})
	t0 := time.UnixMilli(1_700_000_000_000)
	pkt := buildMirror(priv, "robot-1", 1, testMirrorTickMs, 10, 200, 5, 1,
		uint64(t0.UnixMilli()))
	rec, err := in.Observe(pkt, t0)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// 틱 주기의 2배(=미러가 스스로 선언한 침묵 한계)를 넘겨 판정한다.
	late := t0.Add(10 * time.Second)
	v := PermitState([]Record{rec}, robotHash("robot-1"), late)
	if v.State != PermitUnknown {
		t.Fatalf("미러 침묵 %dms 뒤 state=%q (%s) — 죽은 미러의 마지막 진술이 "+
			"살아 있는 허용으로 남았다", late.Sub(t0).Milliseconds(), v.State, v.Why)
	}
}

// 관측점 2 — 신선도 창을 모르면 신선도를 판정하지 않는다.
//
// deadman_window_ms 는 브리지가 실제로 지키는 침묵 창이고 0 은 "미관찰"이라는
// 진술이다(BridgeState.msg 의 규약). 창을 모르는데 발명한 상수로 재면
// "확인 못 했다"가 "확인했고 살아 있다"로 도착한다(H-B2).
func TestUnobservedDeadmanWindowIsUnknown(t *testing.T) {
	pub, priv := mirrorKeypair(t, 7)
	in := NewMirrorIngester([]ed25519.PublicKey{pub})
	now := time.UnixMilli(1_700_000_000_000)
	pkt := buildMirror(priv, "robot-1", 1, testMirrorTickMs, 10, 0, 5, 1,
		uint64(now.UnixMilli()))
	rec, err := in.Observe(pkt, now)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	v := PermitState([]Record{rec}, robotHash("robot-1"), now)
	if v.State != PermitUnknown {
		t.Fatalf("deadman_window_ms=0 인데 state=%q (%s) — 창을 모르는 채 "+
			"신선도를 판정했다", v.State, v.Why)
	}
}

// 관측점 3 — 미러 역할 키로 검증되지 않은 진술은 허용 재료가 아니다.
//
// 아무 UDP 발신자나 permit 생존을 주장할 수 있으면 초록은 신원을 잃는다.
func TestUnsignedMirrorIsNotAlive(t *testing.T) {
	trusted, _ := mirrorKeypair(t, 7)
	_, foreign := mirrorKeypair(t, 9)
	in := NewMirrorIngester([]ed25519.PublicKey{trusted})
	now := time.UnixMilli(1_700_000_000_000)
	pkt := buildMirror(foreign, "robot-1", 1, testMirrorTickMs, 10, 200, 5, 1,
		uint64(now.UnixMilli()))
	rec, err := in.Observe(pkt, now)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if rec.Sig != SigBad {
		t.Fatalf("남의 키 서명이 sig=%q — 위조 진술이 검증된 것처럼 적혔다", rec.Sig)
	}
	v := PermitState([]Record{rec}, robotHash("robot-1"), now)
	if v.State == PermitAlive {
		t.Fatalf("미검증 진술로 state=alive — 초록이 신원 없이 켜졌다")
	}
}

// 관측점 4 — 키가 없으면 "검증했고 틀렸다"가 아니라 "검증 못 했다"다.
func TestNoMirrorKeyIsUnverifiable(t *testing.T) {
	_, priv := mirrorKeypair(t, 7)
	in := NewMirrorIngester(nil)
	now := time.UnixMilli(1_700_000_000_000)
	pkt := buildMirror(priv, "robot-1", 1, testMirrorTickMs, 10, 200, 5, 1,
		uint64(now.UnixMilli()))
	rec, err := in.Observe(pkt, now)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if rec.Sig != SigUnverifiable {
		t.Fatalf("키 0개인데 sig=%q — 미검증이 검증의 값을 입었다", rec.Sig)
	}
}

// 관측점 5 — 살아 있는 미러 + 신선한 permit 은 alive 다(반증 가능성 확보).
// 위 넷이 전부 unknown 을 요구하므로, 이 케이스가 없으면 "무조건 unknown"이
// 전건 초록이 된다 — 항상 붉지 않은 게이트가 아니라 항상 회색인 게이트가 된다.
func TestFreshMirrorAndPermitIsAlive(t *testing.T) {
	pub, priv := mirrorKeypair(t, 7)
	in := NewMirrorIngester([]ed25519.PublicKey{pub})
	now := time.UnixMilli(1_700_000_000_000)
	pkt := buildMirror(priv, "robot-1", 1, testMirrorTickMs, 10, 200, 5, 1,
		uint64(now.UnixMilli()))
	rec, err := in.Observe(pkt, now)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	v := PermitState([]Record{rec}, robotHash("robot-1"), now)
	if v.State != PermitAlive {
		t.Fatalf("신선한 미러+permit 인데 state=%q (%s)", v.State, v.Why)
	}
	if v.Mode != ModeEnforce {
		t.Fatalf("mode=%q, want enforce", v.Mode)
	}
}

// 관측점 6 — permit 무수신 sentinel 은 absent 이고 "모름"이 아니다.
// 미러는 보고 있었고, 본 결과가 "허용 아님"이다 — 두 회색을 가르는 쪽의
// Go 측 관측점이다.
func TestPermitNeverSeenIsAbsentNotUnknown(t *testing.T) {
	pub, priv := mirrorKeypair(t, 7)
	in := NewMirrorIngester([]ed25519.PublicKey{pub})
	now := time.UnixMilli(1_700_000_000_000)
	pkt := buildMirror(priv, "robot-1", 1, testMirrorTickMs, PermitAgeNever, 200,
		0, 1, uint64(now.UnixMilli()))
	rec, err := in.Observe(pkt, now)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	v := PermitState([]Record{rec}, robotHash("robot-1"), now)
	if v.State != PermitAbsent {
		t.Fatalf("permit 무수신인데 state=%q (%s) — 봤는데 없더라와 "+
			"아무도 안 봤다가 접혔다", v.State, v.Why)
	}
}

// 관측점 7 — 레코드 왕복(JSONL) 이 permit 칸을 보존한다. 저장을 거치며
// deadman_window_ms 나 sig 가 떨어지면 조회 API 의 판정이 조용히 unknown 으로
// 주저앉는다.
func TestPermitRecordRoundTrip(t *testing.T) {
	pub, priv := mirrorKeypair(t, 7)
	in := NewMirrorIngester([]ed25519.PublicKey{pub})
	now := time.UnixMilli(1_700_000_000_000)
	pkt := buildMirror(priv, "robot-1", 2, testMirrorTickMs, 42, 200, 5, 9,
		uint64(now.UnixMilli()))
	rec, err := in.Observe(pkt, now)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	line, err := rec.MarshalPermit()
	if err != nil {
		t.Fatalf("MarshalPermit: %v", err)
	}
	got, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine(%s): %v", line, err)
	}
	if got.Kind != KindPermit || got.DeadmanMs != 200 || got.PermitAgeMs != 42 ||
		got.TickMs != testMirrorTickMs || got.MirrorSeq != 9 || got.PermitSeq != 5 ||
		got.Mode != ModeObserve || got.Sig != rec.Sig {
		t.Fatalf("왕복 손실: %+v", got)
	}
}
