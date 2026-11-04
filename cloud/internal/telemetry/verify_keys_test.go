// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package telemetry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/burst"
	"github.com/glowfly/pail/services/internal/crypto"
)

func ringEntry(t *testing.T, id, role string, pub ed25519.PublicKey) crypto.KeyringEntry {
	t.Helper()
	return crypto.KeyringEntry{
		KeyID:        id,
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub),
		Role:         role,
	}
}

// DB-1 RED (실측 2026-09-02): the live demo keyring holds issuer keys AND a
// burst-role key; the SUT signs bursts with the burst key (D2 role split).
// A verifier that loads only issuer-role anchors writes `sig=bad` for genuine
// packets — a forgery alarm masking a key-selection defect.
func TestDB1_BurstRoleKeyVerifiesBurstSignedPacket(t *testing.T) {
	issPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	burstPub, burstPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kr := &crypto.Keyring{Keys: []crypto.KeyringEntry{
		ringEntry(t, "iss-1", "issuer", issPub),
		ringEntry(t, "burst-1", "burst", burstPub),
	}}

	keys, role, err := VerifyKeys(kr)
	if err != nil {
		t.Fatal(err)
	}
	if role != "burst" {
		t.Fatalf("anchor role = %q, want %q (bursts are signed by the burst-role key)", role, "burst")
	}

	pkt := burst.BuildPacketV2(burstPriv, burst.EventBlock, 0x13, 1_000, "robot-1", burst.TokenHash16("tok-1"), 7)
	rec, err := NewIngester(keys).Observe(pkt, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Sig != SigOK {
		t.Fatalf("burst-role-signed packet verdict = %q, want %q", rec.Sig, SigOK)
	}
}

// Pre-split combined binaries sign bursts with the issuer key; a keyring
// without a burst role must fall back to issuer anchors (keymod.burst_pub 짝).
func TestDB1_NoBurstRoleFallsBackToIssuer(t *testing.T) {
	issPub, issPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kr := &crypto.Keyring{Keys: []crypto.KeyringEntry{
		ringEntry(t, "iss-1", "issuer", issPub),
	}}

	keys, role, err := VerifyKeys(kr)
	if err != nil {
		t.Fatal(err)
	}
	if role != "issuer" {
		t.Fatalf("anchor role = %q, want %q", role, "issuer")
	}
	pkt := burst.BuildPacketV2(issPriv, burst.EventBlock, 0x13, 1_000, "robot-1", burst.TokenHash16("tok-1"), 7)
	rec, err := NewIngester(keys).Observe(pkt, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Sig != SigOK {
		t.Fatalf("issuer-signed packet verdict = %q, want %q", rec.Sig, SigOK)
	}
}

// DB-2 (G-DSH-05): 미러 앵커 집합은 **미러 역할 전용**이다. burst·issuer 로의
// 폴백을 두면 아무 신뢰 키나 permit 생존을 증언할 수 있고, 초록은 누구의
// 증언인지를 잃는다. 폴백은 편의가 아니라 **역할 분리의 소실**이다.
func TestDB2_MirrorAnchorsDoNotFallBackToBurstOrIssuer(t *testing.T) {
	issPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	burstPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kr := &crypto.Keyring{Keys: []crypto.KeyringEntry{
		ringEntry(t, "iss-1", "issuer", issPub),
		ringEntry(t, "burst-1", "burst", burstPub),
	}}
	if keys, role, err := VerifyMirrorKeys(kr); err == nil {
		t.Fatalf("미러 역할 키가 없는데 앵커 %d개를 role=%q 로 내줬다 — "+
			"burst/issuer 키가 permit 생존을 증언할 수 있게 된다", len(keys), role)
	}
}

// 미러 역할 키가 있으면 그것만 낸다 — 위 케이스가 "무조건 거부"로 통과하는
// 것을 막는 반증 케이스다(항상 붉은 게이트는 게이트가 아니다).
func TestDB2_MirrorRoleKeyIsSelected(t *testing.T) {
	issPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mirPub, mirPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kr := &crypto.Keyring{Keys: []crypto.KeyringEntry{
		ringEntry(t, "iss-1", "issuer", issPub),
		ringEntry(t, "mirror-key-1", "mirror", mirPub),
	}}
	keys, role, err := VerifyMirrorKeys(kr)
	if err != nil {
		t.Fatal(err)
	}
	if role != "mirror" {
		t.Fatalf("anchor role = %q, want %q", role, "mirror")
	}
	if len(keys) != 1 {
		t.Fatalf("앵커 %d개 — 미러 역할 밖의 키가 섞였다", len(keys))
	}
	pkt := buildMirror(mirPriv, "robot-1", 1, testMirrorTickMs, 10, 200, 5, 1,
		uint64(time.UnixMilli(1).UnixMilli()))
	rec, err := NewMirrorIngester(keys).Observe(pkt, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Sig != SigOK {
		t.Fatalf("미러 키 서명 판정 = %q, want %q", rec.Sig, SigOK)
	}
}

// Neither role present → refuse, never an empty anchor set ("빈 목록"은
// 모든 패킷을 unverifiable 로 내리며 그 밑에서 검증기는 영원히 초록이다).
func TestDB1_EmptyAnchorSetRefused(t *testing.T) {
	opPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kr := &crypto.Keyring{Keys: []crypto.KeyringEntry{
		ringEntry(t, "op-1", "operator", opPub),
	}}
	if _, _, err := VerifyKeys(kr); err == nil {
		t.Fatal("keyring with neither burst nor issuer role must refuse")
	}
}
