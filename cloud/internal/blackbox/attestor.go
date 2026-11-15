// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
)

// Coverage says how much of a walked journal is under a verified signature.
//
// The hash chain can be recomputed by anyone who can write the files; a signed
// CHECKPOINT cannot. A checkpoint signs the head hash, and the head is bound to
// every earlier record — across segments, through the inherited tail in each
// segment header, which the walk has already checked. So one verified
// checkpoint attests every record before it.
type Coverage struct {
	Records         int // records observed
	Attested        int // records up to and including the last verified checkpoint
	Checkpoints     int // checkpoints whose signature verified
	UnderRevokedKey int // of those, verified only by a revoked issuer key
}

// Tail is the number of records after the last verified checkpoint.
func (c Coverage) Tail() int { return c.Records - c.Attested }

// Attestor verifies the CHECKPOINT records of a journal as they are walked
// (SEC-H08). Feed it every record, in order, from WalkDir.
//
// Trusted holds the issuer keys in force. Revoked holds the public halves of
// revoked issuer keys: history written before a revocation must stay readable,
// so their signatures are accepted for the walk and counted apart — the caller
// decides what to say about relying on them. A checkpoint that verifies under
// neither is indistinguishable from a forged one and is an error.
type Attestor struct {
	Trusted []ed25519.PublicKey
	Revoked []ed25519.PublicKey

	cov Coverage
}

func (a *Attestor) Coverage() Coverage { return a.cov }

// Observe takes the next record of the walk. A non-checkpoint record only
// counts. A checkpoint must sit where it claims to (head, count, segment) and
// carry a signature by a known issuer key; anything else is an error, and the
// caller refuses the journal.
func (a *Attestor) Observe(r Record) error {
	a.cov.Records++
	if r.Type != RecordCheckpoint && r.Type != RecordCheckpointV2 {
		return nil
	}
	v2 := r.Type == RecordCheckpointV2
	want := CheckpointV1PayloadLen
	if v2 {
		want = CheckpointV2PayloadLen
	}
	where := fmt.Sprintf("segment %d record[%d]", r.SegmentSeq, r.Index)
	if len(r.Payload) != want {
		return fmt.Errorf("%s: checkpoint payload length %d, want %d", where, len(r.Payload), want)
	}
	head := r.Payload[0:32]
	if !bytes.Equal(head, r.PrevHash[:]) {
		return fmt.Errorf("%s: checkpoint head does not match the chain", where)
	}
	var (
		count       uint64
		signed, sig []byte
	)
	if v2 {
		count = binary.BigEndian.Uint64(r.Payload[32:40])
		seq := binary.BigEndian.Uint64(r.Payload[40:48])
		if seq != r.SegmentSeq {
			return fmt.Errorf("%s: checkpoint segment_seq=%d, but it sits in segment %d", where, seq, r.SegmentSeq)
		}
		signed, sig = CheckpointV2SignedInput(head, count, seq), r.Payload[48:112]
	} else {
		// v1: only the head is inside the signature. The count is still
		// compared with the walk, as the offline verifier does.
		count = binary.LittleEndian.Uint64(r.Payload[32:40])
		signed, sig = head, r.Payload[40:104]
	}
	if count != r.Index {
		return fmt.Errorf("%s: checkpoint record_count=%d, want %d", where, count, r.Index)
	}
	switch {
	case verifiesUnder(a.Trusted, signed, sig):
	case verifiesUnder(a.Revoked, signed, sig):
		a.cov.UnderRevokedKey++
	default:
		return fmt.Errorf("%s: checkpoint signature is not valid under any trusted issuer key", where)
	}
	a.cov.Checkpoints++
	a.cov.Attested = a.cov.Records
	return nil
}

func verifiesUnder(keys []ed25519.PublicKey, msg, sig []byte) bool {
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig) {
			return true
		}
	}
	return false
}
