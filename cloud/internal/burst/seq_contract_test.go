// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// G-EVI-05 : one event keeps ONE burst_seq across all 5
// retransmissions; distinct events get distinct seqs; the seq lives inside the
// signed prefix so a receiver deduplicating on it is deduplicating on a value
// the issuer vouched for. The 0/50/200/500/1000ms schedule itself is NOT
// tested here — timing belongs to native-Linux remeasurement (HLD §9), the
// packet-identity contract does not.
package burst

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestBurstSeq_OneSeqPerEvent(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := New("127.0.0.1:1")
	seq := s.NextSeq() // exactly one NextSeq per event
	th := TokenHash16("token-abc")

	first := BuildPacketV2(priv, EventEstop, 0x13, 1234567890, "robot-1", th, seq)
	if got := binary.LittleEndian.Uint32(first[48:52]); got != seq {
		t.Fatalf("G-EVI-05: packet seq=%d, want the event's NextSeq %d", got, seq)
	}
	// Ed25519 is deterministic, so all 5 retransmissions of one event must be
	// byte-identical packets — same identity on the wire, receiver-side dedup
	// by burst_seq is sound.
	for i := 1; i < 5; i++ {
		pkt := BuildPacketV2(priv, EventEstop, 0x13, 1234567890, "robot-1", th, seq)
		if !bytes.Equal(pkt, first) {
			t.Fatalf("G-EVI-05: retransmission %d differs from the first packet of the same event", i)
		}
	}
}

func TestBurstSeq_DistinctEventsDistinctSeq(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := New("127.0.0.1:1")
	th := TokenHash16("token-abc")

	seqA, seqB := s.NextSeq(), s.NextSeq()
	if seqA == seqB {
		t.Fatalf("G-EVI-05: two events drew the same seq %d", seqA)
	}
	pktA := BuildPacketV2(priv, EventBlock, 0x12, 1, "robot-1", th, seqA)
	pktB := BuildPacketV2(priv, EventBlock, 0x12, 1, "robot-1", th, seqB)
	a := binary.LittleEndian.Uint32(pktA[48:52])
	b := binary.LittleEndian.Uint32(pktB[48:52])
	if a == b {
		t.Fatalf("G-EVI-05: distinct events share burst_seq %d on the wire", a)
	}
}

func TestBurstSeq_SeqSurvivesVerify(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	th := TokenHash16("token-abc")

	pkt := BuildPacketV2(priv, EventChainRevoked, 0x21, 42, "robot-1", th, 7)
	if !VerifyPacketV2(pub, pkt) {
		t.Fatal("G-EVI-05: genuine packet must verify")
	}
	// burst_seq (offset 48) sits inside the signed prefix [0:56]: an attacker
	// cannot re-number an event to defeat receiver-side deduplication.
	pkt[48] ^= 0x01
	if VerifyPacketV2(pub, pkt) {
		t.Fatal("G-EVI-05: packet with altered burst_seq must fail verification — seq must be signed")
	}
}
