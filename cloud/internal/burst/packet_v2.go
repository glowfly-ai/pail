// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package burst

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
)

// Burst v2 packet per LLD-v2 §6 (corrected offset table, reserved=4B):
//
//	off  field                                size
//	0    magic 'PAIL'                         4
//	4    ver = 2                              1
//	5    event                                1
//	6    reason (u16 LE)                      2
//	8    unix_ms (u64 LE)                     8
//	16   robot_id_hash = sha256(robot_id)[:16] 16
//	32   token_hash                           16
//	48   burst_seq (u32 LE)                   4
//	52   reserved                             4
//	56   ed25519_sig = Sign(pkt[0:56])        64
//	120  total
//
// The same burst_seq is reused across the 5 retransmissions of one event so
// receivers can deduplicate.
//
// [implementation contract] token_hash is a CORRELATION HINT, not an identity claim.
// It is derived from an unsigned envelope field (token_id), so signing the
// packet does not make the name it points at verified. A receiver MUST NOT
// treat two packets as concerning the same token because this value matches,
// and MUST NOT feed it into an authorization decision. Identity of a token is
// consumption_key = sha256("pail-tokenkey:v1:" ‖ action_token_bytes), which is
// derived from SIGNED bytes . The derivation here is left
// unchanged on purpose: it has 6 copies and is not used in any verdict, so
// changing it would widen the canon freeze window for no decision-path gain.
// An undisclosed weakness is worse than a disclosed one (H7).
//
// [implementation contract] The 16 bytes at 32:48 carry THREE different kinds of value.
// The event code, not the value, is what says which one arrived:
//
//	event                     bytes 32:48                       derivation
//	BLOCK / ESTOP             token hash                        TokenHash16(token_id)
//	CHAIN_REVOKED             token hash OR chain hash          TokenHash16 / ChainHash16
//	CHECKPOINT                head_hash[:16]                    truncation, NOT a hash
//	AUTHORITY_WITHHELD        zero                              robot-scoped, names no object
//
// CHAIN_REVOKED is emitted with a token id from generated_server.go and with a
// chain id from census.go, so its event code alone does not disambiguate. A
// receiver that must know which one it holds has to test a candidate preimage
// against the matching derivation — that is what makes the derivations differ
// on purpose (see ChainHash16). CHECKPOINT's value gets no prefix because it is
// a truncation of an already-hashed value; prefixing it would change the
// checkpoint_v2 record format, which is OR1-frozen (an R1 trigger).

const (
	V2PacketSize   = 120
	V2SignedPrefix = 56

	EventBlock        byte = 1
	EventChainRevoked byte = 2 // keeps the as-built v1 code for this event
	EventEstop        byte = 3
	EventCheckpoint   byte = 4
	// EventAuthorityWithheld (OI-04): the issuer no longer serves this robot
	// because its gate's attestation is invalid or expired. The chain is NOT
	// revoked — serving is withheld until the gate attests again. Robot-scoped:
	// bytes 32:48 are zero (there is no token or chain to name). A gateway
	// treats it as revoking (its delegated window must not outlive the
	// issuer's refusal); a build that predates the code revokes on it anyway
	// (unknown codes revoke).
	EventAuthorityWithheld byte = 5
)

func EventName(e byte) string {
	switch e {
	case EventBlock:
		return "BLOCK"
	case EventChainRevoked:
		return "CHAIN_REVOKED"
	case EventEstop:
		return "ESTOP"
	case EventCheckpoint:
		return "CHECKPOINT"
	case EventAuthorityWithheld:
		return "AUTHORITY_WITHHELD"
	default:
		return "UNKNOWN"
	}
}

// BuildPacketV2 assembles and signs a 120B v2 burst packet.
// tokenHash16 carries sha256(token_id)[:16]; CHECKPOINT events, which have no
// token, carry head_hash[:16] there instead (correlates with the chain head).
func BuildPacketV2(signKey ed25519.PrivateKey, event byte, reason uint16, unixMs uint64, robotID string, tokenHash16 [16]byte, burstSeq uint32) []byte {
	pkt := make([]byte, V2PacketSize)
	copy(pkt[0:4], []byte{'P', 'A', 'I', 'L'})
	pkt[4] = 2
	pkt[5] = event
	binary.LittleEndian.PutUint16(pkt[6:8], reason)
	binary.LittleEndian.PutUint64(pkt[8:16], unixMs)
	rh := sha256.Sum256([]byte(robotID))
	copy(pkt[16:32], rh[:16])
	copy(pkt[32:48], tokenHash16[:])
	binary.LittleEndian.PutUint32(pkt[48:52], burstSeq)
	// pkt[52:56] reserved = 0
	sig := ed25519.Sign(signKey, pkt[0:V2SignedPrefix])
	copy(pkt[56:120], sig)
	return pkt
}

func TokenHash16(tokenID string) [16]byte {
	var out [16]byte
	h := sha256.Sum256([]byte(tokenID))
	copy(out[:], h[:16])
	return out
}

// ChainHash16 derives the 32:48 value for events that correlate a CHAIN rather
// than a token: sha256("pail-burstchain:v1:" ‖ chain_id)[:16].
//
// [implementation contract, deviation recorded in that section] The design asked for a
// prefix on BOTH namespaces. Only this one gets it, and that is sufficient:
// domain separation is the property that the two derivations DIFFER, not that
// both carry a prefix. Prefixing the new value alone achieves it while leaving
// TokenHash16 byte-identical, which matters because implementation contract decided that
// derivation must not change (it has producers in Go v1, Go v2 and the Python
// golden builder, and TestB3C7_DerivationDeliberatelyUnchanged exists to make
// changing it fail). The new value has no existing producer, so no peer can
// disagree about it.
//
// The same correlation-hint limits as TokenHash16 apply: chain_id is an
// unsigned envelope field, so this is a hint and MUST NOT enter an
// authorization decision.
func ChainHash16(chainID string) [16]byte {
	var out [16]byte
	h := sha256.Sum256([]byte("pail-burstchain:v1:" + chainID))
	copy(out[:], h[:16])
	return out
}

// VerifyPacketV2 checks framing and the issuer signature over pkt[0:56].
func VerifyPacketV2(pub ed25519.PublicKey, pkt []byte) bool {
	if len(pkt) != V2PacketSize {
		return false
	}
	if string(pkt[0:4]) != "PAIL" || pkt[4] != 2 {
		return false
	}
	return ed25519.Verify(pub, pkt[0:V2SignedPrefix], pkt[56:120])
}
