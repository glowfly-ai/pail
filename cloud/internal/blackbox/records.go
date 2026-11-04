// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package blackbox

import "encoding/binary"

// Core-comm-v1 state/receipt records. Unknown prepared state must never authorize.
const (
	RecordCoreOperation uint32 = 100
	RecordCoreReport    uint32 = 101
)

// RecordType values for phase 1.
// Keep stable (versioned) because they are written to disk.
const (
	RecordTokenIssued  uint32 = 10
	RecordPlanAccepted uint32 = 11
	// AL-2 (implementation contract D5): RecordContextSealed journals the pass-through bytes'
	// digests and the content-addressed store key, once per accepted plan,
	// immediately before PLAN_ACCEPTED. JSON payload {v:2, kind:"CONTEXT_SEALED",
	// unix_ms, robot_id, plan_id, context_hash_hex, constraints_hash_hex,
	// context_bytes, constraints_bytes, store_key}. The chain testifies that
	// *something with this digest* was submitted even after the store is gone.
	RecordContextSealed uint32 = 12
	// RecordPlanRejected journals a refused plan with its requester and reject
	// code — "who tried to order what and was refused" is audit material as
	// much as an acceptance. Best-effort append: the refusal stands whether or
	// not it could be written (journaling a refusal is evidence, not
	// authorization). Never written for R-A boundary refusals: the refused
	// identifiers must not enter the journal.
	RecordPlanRejected uint32 = 13
	RecordGateDecision uint32 = 20
	RecordChainRevoked uint32 = 21
	// RecordCheckpoint payload: head_hash(32) | record_count(u64 LE) | ed25519_sig(64)
	// sig = Sign(head_hash) — the count sits next to a signature that does not
	// cover it (X13a). Kept forever as a READ format (F8); the writer no longer
	// emits it.
	RecordCheckpoint uint32 = 30
	// E-C3 (implementation contract; canon frozen in A §3 / tests/golden/canon/checkpoint_v2.vec):
	// RecordCheckpointV2 payload(112B):
	//   head_hash(32) | record_count(u64 BE) | segment_seq(u64 BE) | ed25519_sig(64)
	//   sig = Sign("pail-checkpoint:v2:" ‖ head_hash ‖ record_count ‖ segment_seq)
	// Three changes, each closing one hole in 30:
	//   - record_count is inside the signed input, so forging it now needs the
	//     issuer key rather than a sha256 recompute (X13a);
	//   - the domain-separation prefix makes a ring match mean "this key attested
	//     THIS checkpoint" rather than "this key signed these 32 bytes" (X13b);
	//   - segment_seq pins the checkpoint to its segment, so a valid checkpoint
	//     cannot be replayed into a different one.
	RecordCheckpointV2 uint32 = 31
	// CheckpointV1PayloadLen / CheckpointV2PayloadLen are the on-disk payload
	// sizes of the two formats. They live here, next to the type numbers, so a
	// reader that knows the type also knows the length from one place — the
	// verify tool used to carry its own copy of both.
	CheckpointV1PayloadLen = 32 + 8 + 64
	CheckpointV2PayloadLen = 32 + 8 + 8 + 64
	// implementation contract (`DUR-L3`): RecordRecoveryTruncate declares bytes the startup
	// path DISCARDED. Payload(120B):
	//   discarded_bytes(u64 BE) | recovered_tail_hash(32) | segment_seq(u64 BE)
	//   | unix_ms(u64 BE) | ed25519_sig(64)
	//   sig = Sign("pail-bb-recovery:v1:" ‖ discarded ‖ tail ‖ seg ‖ unix_ms)
	//
	// Recovery is destructive, and a silent destruction is H-B2: "we recovered"
	// and "nothing happened" would be the same bytes. It is signed because an
	// unsigned recovery declaration is something an attacker can also write —
	// the record would then launder the truncation it is supposed to expose.
	// It is written as the FIRST record of a NEW segment, never back into the
	// segment that was cut: that file already failed once.
	RecordRecoveryTruncate     uint32 = 32
	RecoveryTruncatePayloadLen        = 8 + 32 + 8 + 8 + 64
	// M9 (LLD-v2 §7.2) operator recovery state machine, JSON payloads:
	// RecordSafeStop = NORMAL->SAFE_STOP transition on a reported forgery;
	// RecordOperatorEvent = every Unlock/RevokeIssuerKey attempt (incl. failures).
	RecordSafeStop      uint32 = 40
	RecordOperatorEvent uint32 = 41
	// CG1 (§3.6): RecordGraphMutation logs each context-graph mutation
	// (node state/version change from CG-E1 event ingest), JSON payload
	// {epoch, node_id, old_version, new_version, mutation_kind}. Reserved now so
	// the record-type number is stable on disk before CG-E1 emits them; CG3's
	// snapshot recompute replays these to reconstruct an issuance snapshot.
	RecordGraphMutation uint32 = 50
	// OR2 (implementation contract; payload frozen in implementation contract):
	// RecordContextProvenance records WHO said a context event arrived — 50
	// records what changed, 51 records the cause. Binary payload:
	//   "pail-context:v1:" ‖ LP(event_kind) ‖ LP(caller_kind) ‖ LP(caller_id)
	//                      ‖ u8(context_verified) ‖ LP(event_body_hash_hex)
	// Written BEFORE the mutation is attempted, inside the same siteMu critical
	// section as the 50 that may follow (§1.4). A rejected event therefore
	// leaves a 51 with no 50 behind it — that ordering is what makes an
	// outcome field unnecessary and a correlation id unnecessary.
	// Record-first strict: an event whose provenance cannot be journaled is
	// refused, because it would otherwise change future issuance with no
	// cause on record.
	RecordContextProvenance uint32 = 51
	// AS-2 (HA/AT LLD §6.3): RecordAttestation logs each verified Attest RPC,
	// JSON payload {kind:"ATTESTATION", unix_ms, robot_id, component,
	// measurement_sha256_hex, verdict, build_info}. Replay (§3.2) rebuilds the
	// in-memory attestation table from these so PAIL_ATTESTATION=required
	// survives restart/promotion.
	RecordAttestation uint32 = 60
	// SD4 (설정봉인 LLD §3.2): RecordConfigSealed logs the security
	// configuration a gate declared it is running under — {kind:"CONFIG_SEALED",
	// unix_ms, robot_id, component, seal_v, config_digest_hex,
	// verifies_authorization, degraded[], canonical, build_info}.
	// The digest is the issuer's own sha256 of the canonical text it received,
	// so the record cannot claim a digest that does not match its own contents.
	// Attestation says the binary is the expected one; this says what that
	// binary was configured to check. Record-first strict: a seal the journal
	// cannot hold must not be answered OK, or "sealed" would mean nothing.
	RecordConfigSealed uint32 = 61
	// AV2 (AV LLD §2.3): RecordLeaseGranted logs each edge-lease grant —
	// {kind:"LEASE_GRANTED", journal_v, unix_ms, robot_id, chain_id, max_index,
	//  expiry_ms, issuer_epoch}. A lease IS an authorization grant, so the
	// append is record-first strict; an append failure degrades to the
	// single-token response rather than granting unjournaled offline authority.
	RecordLeaseGranted uint32 = 70
	// AV2: RecordLeaseReconciled logs the gateway's consumption report against
	// an outstanding lease — {kind:"LEASE_RECONCILED", journal_v, unix_ms,
	//  robot_id, chain_id, reported_index, lease_max_index, verdict}.
	// verdict is "OK" or "OVER_LEASE" (progress beyond what was authorized).
	RecordLeaseReconciled uint32 = 71
	// AV3 (AV LLD §4.6): RecordFleetCensus logs the promotion-time census —
	// {kind:"CENSUS_ARMED"|"CENSUS_OK"|"CENSUS_UNEXPLAINED"|"CENSUS_UNKNOWN_CHAIN"
	//  |"CENSUS_STALE_ISSUER"|"CENSUS_OVERRIDE", journal_v, unix_ms, robot_id |
	//  robot_ids, chain_id, declared_consumed_index, declared_lease_max_index,
	//  known_expected_index, known_lease_max_index, issuer_epoch}.
	// Both directions open or hold issuance => record-first strict.
	RecordFleetCensus uint32 = 72
	// AV7 (AV LLD §9.4): RecordLeaseRetracted logs the withdrawal of an
	// unconsumed edge lease — {kind:"LEASE_RETRACTED", journal_v, unix_ms,
	// robot_id, chain_id, from_max_index, to_max_index,
	// declared_consumed_index, issuer_epoch}. The journal, not the
	// declaration, names to_max_index. Record-first: a restart must not
	// resurrect the window this record closed.
	RecordLeaseRetracted uint32 = 73
	// AV4/AV5 (AV LLD §4·§5): RecordHaMembership logs sync-set changes —
	// {kind:"EJECTED"|"REJOINED"|"BELOW_FLOOR"|"SOLO_OVERRIDE"|"EPOCH_BUMP",
	//  unix_ms, replica, failures, window_ms, insync_size, floor, issuer_epoch}.
	RecordHaMembership uint32 = 80
	// C2-C6 : RecordIdentityRefused journals an unbound
	// refusal at the identity interceptor — JSON payload
	// {kind:"IDENTITY_REFUSED", journal_v, unix_ms, method, robot_id,
	//  caller_kind, caller_id, robot_id_bound:"unbound", reason, suppressed}.
	// The pass verdicts ride records 10/20 (§2.8, map-key addition); a refusal
	// produces neither — the handler never runs — so without this type the
	// journal answers "who was turned away" with silence, which reads the same
	// as "nobody" (H-B2). issuer_key_fingerprint is deliberately absent:
	// nothing was signed, and the absence is the record. Best-effort append —
	// journaling a refusal is evidence, not authorization; the refusal stands
	// whether or not it could be written.
	RecordIdentityRefused uint32 = 90
)

// CheckpointV2Prefix is the domain separator of the v2 signed input. Without it
// a ring match proves only "this key signed these 32 bytes" (X13b) — the same
// signature would be equally valid over any other structure that happens to be
// 32 bytes of hash.
const CheckpointV2Prefix = "pail-checkpoint:v2:"

// CheckpointV2SignedInput builds the signed bytes of a v2 CHECKPOINT, frozen in
// tests/golden/canon/checkpoint_v2.vec (CP2-01):
//
//	"pail-checkpoint:v2:" ‖ head(32) ‖ record_count(u64 BE) ‖ segment_seq(u64 BE)
//
// Exported because the writer and the verify tool are two programs that must
// agree byte for byte. They each had their own copy until E-C3; a copy is a
// second original the day one of them changes (F7).
func CheckpointV2SignedInput(head []byte, recordCount, segSeq uint64) []byte {
	in := make([]byte, 0, len(CheckpointV2Prefix)+32+8+8)
	in = append(in, CheckpointV2Prefix...)
	in = append(in, head...)
	in = binary.BigEndian.AppendUint64(in, recordCount)
	return binary.BigEndian.AppendUint64(in, segSeq)
}

// CheckpointV2Payload assembles the on-disk payload, also frozen in CP2-01:
//
//	head(32) ‖ record_count(u64 BE) ‖ segment_seq(u64 BE) ‖ sig(64)
//
// The layout is a function rather than four offset literals in writeCheckpoint
// because the golden test can only pin what it can call. Offsets written inline
// are pinned by nothing but the reader's attention.
func CheckpointV2Payload(head []byte, recordCount, segSeq uint64, sig []byte) []byte {
	p := make([]byte, 0, CheckpointV2PayloadLen)
	p = append(p, head...)
	p = binary.BigEndian.AppendUint64(p, recordCount)
	p = binary.BigEndian.AppendUint64(p, segSeq)
	return append(p, sig...)
}

// RecoveryTruncatePrefix is the domain separator of the recovery record's signed
// input . It exists for the reason CheckpointV2Prefix does: without
// it the signature proves only "this key signed these bytes", and a recovery
// declaration that could be replayed as some other structure is not a
// declaration. Registered in tests/spec_prefix_map.tsv and, because a signing
// input never appears in a canon VALUE, in tests/golden/canon/UNPINNED.tsv.
const RecoveryTruncatePrefix = "pail-bb-recovery:v1:"

// RecoveryTruncateSignedInput builds the signed bytes of a recovery record:
//
//	"pail-bb-recovery:v1:" ‖ discarded(u64 BE) ‖ tail(32) ‖ seg(u64 BE) ‖ unix_ms(u64 BE)
//
// Exported for the same reason as CheckpointV2SignedInput: the writer and any
// auditor are two programs that must agree byte for byte, and a copy is a second
// original the day one of them changes (F7).
func RecoveryTruncateSignedInput(discarded uint64, tail []byte, segSeq, unixMs uint64) []byte {
	in := make([]byte, 0, len(RecoveryTruncatePrefix)+8+32+8+8)
	in = append(in, RecoveryTruncatePrefix...)
	in = binary.BigEndian.AppendUint64(in, discarded)
	in = append(in, tail...)
	in = binary.BigEndian.AppendUint64(in, segSeq)
	return binary.BigEndian.AppendUint64(in, unixMs)
}

// RecoveryTruncatePayload assembles the on-disk payload:
//
//	discarded(u64 BE) ‖ tail(32) ‖ seg(u64 BE) ‖ unix_ms(u64 BE) ‖ sig(64)
func RecoveryTruncatePayload(discarded uint64, tail []byte, segSeq, unixMs uint64, sig []byte) []byte {
	p := make([]byte, 0, RecoveryTruncatePayloadLen)
	p = binary.BigEndian.AppendUint64(p, discarded)
	p = append(p, tail...)
	p = binary.BigEndian.AppendUint64(p, segSeq)
	p = binary.BigEndian.AppendUint64(p, unixMs)
	return append(p, sig...)
}
