// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"crypto/ed25519"
	"encoding/hex"
	"github.com/glowfly/pail/services/internal/testlayout"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// DB-2 (G-DSH-05): 와이어 배치의 정본은 **파이썬 사이드카**이고 이 패키지는
// 검증기다. 두 쪽이 각자 배치를 적으면 함께 틀려도 초록이다 — 그래서 실제
// 생산기를 불러 접두어를 받아 조립하고, 되읽은 칸을 요청한 값과 대조한다.
//
// `--emit-prefix` 는 서명 없는 56바이트 접두어만 낸다. 서명은 이쪽에서
// 얹는다 — 두 언어에 ed25519 라이브러리를 각각 요구하지 않으면서도 배치의
// 정본은 한 파일에 남는다.
func mirrorProducer(t *testing.T) string {
	return testlayout.Path(t, "services/permit_mirror/permit_mirror.py")
}

func pythonPrefix(t *testing.T, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("python3", append([]string{mirrorProducer(t), "--emit-prefix"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// python3 부재는 SKIP 이 아니다. 건너뛰면 "생산기와 검증기가 어긋났다"가
		// "아직 볼 수 없음"으로 요약에 실려 몇 주가 지나간다(H-B2).
		t.Fatalf("생산기를 부르지 못했다: %v\n%s", err, out)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("접두어 hex 가 아니다: %v (%q)", err, out)
	}
	if len(raw) != MirrorSignedPrefix {
		t.Fatalf("접두어 %d바이트, want %d", len(raw), MirrorSignedPrefix)
	}
	return raw
}

// 관측점 — 파이썬 생산기가 적은 배치를 Go 검증기가 같은 뜻으로 읽는다.
func TestDB2_PythonProducerAgreesOnWire(t *testing.T) {
	pub, priv := mirrorKeypair(t, 0x51)
	now := time.UnixMilli(1_700_000_000_000)
	prefix := pythonPrefix(t,
		"robot=robot-1", "effective_mode=enforce", "tick_ms=500", "permit_age_ms=40",
		"deadman_window_ms=100", "permit_seq=9", "mirror_seq=3",
		"unix_ms=1700000000000")

	pkt := make([]byte, MirrorPacketSize)
	copy(pkt, prefix)
	copy(pkt[MirrorSignedPrefix:], ed25519.Sign(priv, prefix))

	rec, err := NewMirrorIngester([]ed25519.PublicKey{pub}).Observe(pkt, now)
	if err != nil {
		t.Fatalf("생산기 패킷이 거부됐다: %v", err)
	}
	if rec.Sig != SigOK {
		t.Fatalf("sig=%q — 생산기 접두어에 서명이 맞지 않는다", rec.Sig)
	}
	if rec.Robot != robotHash("robot-1") {
		t.Fatalf("robot=%q, want %q", rec.Robot, robotHash("robot-1"))
	}
	if rec.Mode != ModeEnforce {
		t.Fatalf("mode=%q, want %q", rec.Mode, ModeEnforce)
	}
	if rec.TickMs != 500 || rec.PermitAgeMs != 40 || rec.DeadmanMs != 100 {
		t.Fatalf("창·나이 칸이 어긋났다: tick=%d age=%d deadman=%d",
			rec.TickMs, rec.PermitAgeMs, rec.DeadmanMs)
	}
	if rec.PermitSeq != 9 || rec.MirrorSeq != 3 {
		t.Fatalf("seq 칸이 어긋났다: permit=%d mirror=%d", rec.PermitSeq, rec.MirrorSeq)
	}
	if v := PermitState([]Record{rec}, rec.Robot, now); v.State != PermitAlive {
		t.Fatalf("state=%s why=%s", v.State, v.Why)
	}
}

// 관측점 — 「한 번도 못 받음」은 생산기에서 **다른 바이트**로 나가고 수신측
// 판정이 `absent` 다. 0(방금 받았다)과 같은 바이트로 나가면 무수신이 최신으로
// 도착한다 — 이 대조가 없으면 위 케이스만으로는 그 혼동이 보이지 않는다.
func TestDB2_PythonNeverSeenPermitIsDistinct(t *testing.T) {
	pub, priv := mirrorKeypair(t, 0x52)
	now := time.UnixMilli(1_700_000_000_000)
	prefix := pythonPrefix(t,
		"robot=robot-1", "effective_mode=enforce", "tick_ms=500",
		"permit_age_ms=4294967295", "deadman_window_ms=100",
		"permit_seq=0", "mirror_seq=1", "unix_ms=1700000000000")

	pkt := make([]byte, MirrorPacketSize)
	copy(pkt, prefix)
	copy(pkt[MirrorSignedPrefix:], ed25519.Sign(priv, prefix))

	rec, err := NewMirrorIngester([]ed25519.PublicKey{pub}).Observe(pkt, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.PermitAgeMs != PermitAgeNever {
		t.Fatalf("permit_age_ms=%d, want %d(무수신)", rec.PermitAgeMs, PermitAgeNever)
	}
	v := PermitState([]Record{rec}, rec.Robot, now)
	if v.State != PermitAbsent {
		t.Fatalf("state=%s, want %s (why=%s)", v.State, PermitAbsent, v.Why)
	}
}

// 관측점 — 모르는 `effective_mode` 는 미관찰로 나간다. 아는 값 하나로 접으면
// 다음에 늘어나는 모드가 옛 모드를 사칭한다.
//
// 여기 싣는 것은 바이트가 아니라 **아직 없는 모드 이름**이다. 바이트 0 을
// 직접 주면 생산기의 매핑을 비켜 가서 Go 쪽 해석만 재게 된다 — 그 상태로는
// 매핑이 통째로 죽어도 이 관측점이 초록이다(`DF-DB2-4`).
func TestDB2_PythonUnknownModeIsUnobserved(t *testing.T) {
	pub, priv := mirrorKeypair(t, 0x53)
	now := time.UnixMilli(1_700_000_000_000)
	prefix := pythonPrefix(t,
		"robot=robot-1", "effective_mode=degraded_v3", "tick_ms=500", "permit_age_ms=40",
		"deadman_window_ms=100", "permit_seq=9", "mirror_seq=3",
		"unix_ms=1700000000000")

	pkt := make([]byte, MirrorPacketSize)
	copy(pkt, prefix)
	copy(pkt[MirrorSignedPrefix:], ed25519.Sign(priv, prefix))

	rec, err := NewMirrorIngester([]ed25519.PublicKey{pub}).Observe(pkt, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Mode != ModeUnobserved {
		t.Fatalf("mode=%q, want 미관찰(빈 문자열)", rec.Mode)
	}
}
