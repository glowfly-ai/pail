// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package burst

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestBuildPacketV2Layout(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	th := TokenHash16("token-abc")
	pkt := BuildPacketV2(priv, EventBlock, 0x12, 1234567890, "robot-1", th, 42)

	if len(pkt) != 120 {
		t.Fatalf("packet len=%d, want exactly 120 (LLD-v2 §6 / §9 M6)", len(pkt))
	}
	if string(pkt[0:4]) != "PAIL" || pkt[4] != 2 || pkt[5] != EventBlock {
		t.Fatal("bad magic/ver/event")
	}
	if binary.LittleEndian.Uint16(pkt[6:8]) != 0x12 {
		t.Fatal("bad reason")
	}
	if binary.LittleEndian.Uint64(pkt[8:16]) != 1234567890 {
		t.Fatal("bad unix_ms")
	}
	rh := sha256.Sum256([]byte("robot-1"))
	for i := 0; i < 16; i++ {
		if pkt[16+i] != rh[i] {
			t.Fatal("bad robot_id_hash")
		}
		if pkt[32+i] != th[i] {
			t.Fatal("bad token_hash")
		}
	}
	if binary.LittleEndian.Uint32(pkt[48:52]) != 42 {
		t.Fatal("bad burst_seq")
	}
	if pkt[52] != 0 || pkt[53] != 0 || pkt[54] != 0 || pkt[55] != 0 {
		t.Fatal("reserved must be zero")
	}
	if !VerifyPacketV2(pub, pkt) {
		t.Fatal("signature must verify with issuer key")
	}
}

func TestVerifyPacketV2RejectsForgery(t *testing.T) {
	_, issuer, _ := ed25519.GenerateKey(rand.Reader)
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	issuerPub := issuer.Public().(ed25519.PublicKey)

	th := TokenHash16("token-abc")

	// signed by a non-issuer key
	forged := BuildPacketV2(attacker, EventEstop, 0x99, 1, "robot-1", th, 1)
	if VerifyPacketV2(issuerPub, forged) {
		t.Fatal("packet signed by non-issuer key must be rejected")
	}

	// genuine packet, then tamper one signed byte
	pkt := BuildPacketV2(issuer, EventEstop, 0x99, 1, "robot-1", th, 1)
	pkt[5] = EventBlock
	if VerifyPacketV2(issuerPub, pkt) {
		t.Fatal("tampered packet must be rejected")
	}

	// wrong length
	if VerifyPacketV2(issuerPub, pkt[:119]) {
		t.Fatal("short packet must be rejected")
	}

	// v1 packet is never valid
	v1 := BuildPacket(2, "token-abc", 0x20, 1)
	if VerifyPacketV2(issuerPub, v1) {
		t.Fatal("v1 packet must be rejected by v2 verifier")
	}
}

func TestSenderSeqMonotonic(t *testing.T) {
	s := New("127.0.0.1:1")
	a, b := s.NextSeq(), s.NextSeq()
	if b <= a {
		t.Fatalf("seq not monotonic: %d then %d", a, b)
	}
}
