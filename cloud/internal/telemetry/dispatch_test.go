// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/burst"
)

// 한 소켓에 두 형식이 도착한다(D11: 미러는 게이트 수신기 옆 같은 수집 포트로
// 보낸다). 라우팅 판단과 직렬화 판단은 **한 자리**에 있어야 한다 — 갈라 두면
// 매직은 permit 인데 burst 로 적히는 조합이 조용히 산다.

func dispatchFixture(t *testing.T) (*Dispatcher, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	bPub, bPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mPub, mPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return NewDispatcher([]ed25519.PublicKey{bPub}, []ed25519.PublicKey{mPub}), bPriv, mPriv
}

// 관측점 1 — PMIR 은 permit 레코드가 된다. as-is 에서는 burst 인제스터가
// "매직이 틀렸다"로 버리고, 버려진 미러는 화면에서 "미러 없음"과 같은 회색으로
// 도착한다.
func TestDispatchRoutesMirrorToPermit(t *testing.T) {
	d, _, mPriv := dispatchFixture(t)
	now := time.UnixMilli(1_700_000_000_000)
	pkt := buildMirror(mPriv, "robot-1", 1, testMirrorTickMs, 10, 200, 5, 1,
		uint64(now.UnixMilli()))
	line, rec, err := d.Observe(pkt, now)
	if err != nil {
		t.Fatalf("PMIR 이 버려졌다: %v", err)
	}
	if rec.Kind != KindPermit {
		t.Fatalf("kind=%q, want %q", rec.Kind, KindPermit)
	}
	if rec.Sig != SigOK {
		t.Fatalf("미러 키로 서명했는데 sig=%q", rec.Sig)
	}
	got, err := ParseLine(line)
	if err != nil {
		t.Fatalf("적힌 줄이 다시 읽히지 않는다: %v (%s)", err, line)
	}
	if got.Kind != KindPermit || got.DeadmanMs != 200 {
		t.Fatalf("permit 칸이 적히지 않았다: %+v", got)
	}
}

// 관측점 2 — PAIL(버스트)은 그대로 burst 레코드다. 위 라우팅이 "무조건 permit"
// 으로 통과하는 것을 막는 반증 케이스다.
func TestDispatchRoutesBurstToBurst(t *testing.T) {
	d, bPriv, _ := dispatchFixture(t)
	now := time.UnixMilli(1_700_000_000_000)
	pkt := burst.BuildPacketV2(bPriv, burst.EventBlock, 0x13, 1_000, "robot-1",
		burst.TokenHash16("tok-1"), 7)
	line, rec, err := d.Observe(pkt, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Kind != KindBurst || rec.Sig != SigOK {
		t.Fatalf("kind=%q sig=%q", rec.Kind, rec.Sig)
	}
	got, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindBurst {
		t.Fatalf("적힌 줄의 kind=%q", got.Kind)
	}
}

// 관측점 3 — 미러 키는 burst 를 증언하지 못하고, burst 키는 미러를 증언하지
// 못한다. 라우팅이 생겨도 인제스터가 앵커 집합을 공유하면 역할 분리는 소실된다.
func TestDispatchDoesNotCrossVerifyRoles(t *testing.T) {
	d, bPriv, mPriv := dispatchFixture(t)
	now := time.UnixMilli(1_700_000_000_000)

	// burst 키로 서명한 미러 패킷
	_, rec, err := d.Observe(buildMirror(bPriv, "robot-1", 1, testMirrorTickMs,
		10, 200, 5, 1, uint64(now.UnixMilli())), now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Sig == SigOK {
		t.Fatal("burst 키가 permit 생존을 증언했다")
	}

	// 미러 키로 서명한 burst 패킷
	_, rec, err = d.Observe(burst.BuildPacketV2(mPriv, burst.EventBlock, 0x13,
		1_000, "robot-1", burst.TokenHash16("tok-1"), 7), now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Sig == SigOK {
		t.Fatal("미러 키가 차단 버스트를 증언했다")
	}
}

// 관측점 4 — 아는 매직이 아니면 오류다. 아무 쪽으로도 넘기지 않는다: 모르는
// 바이트를 한쪽 파서에 먹이면 그 파서의 오류 문구가 "무엇이 왔는지"를 덮는다.
func TestDispatchUnknownMagicIsError(t *testing.T) {
	d, _, _ := dispatchFixture(t)
	pkt := make([]byte, MirrorPacketSize)
	copy(pkt[0:4], []byte("XXXX"))
	_, _, err := d.Observe(pkt, time.UnixMilli(1))
	if err == nil {
		t.Fatal("모르는 매직이 통과했다")
	}
	// 오류의 **출처**를 잰다. 한쪽 파서에 먹여서 나온 "bad magic/version" 도
	// err != nil 이므로, 문구를 보지 않으면 이 관측점은 라우팅이 없어도 초록이다.
	if !strings.Contains(err.Error(), "unknown magic") {
		t.Fatalf("디스패처가 판정하지 않고 파서 오류를 흘렸다: %v", err)
	}
}
