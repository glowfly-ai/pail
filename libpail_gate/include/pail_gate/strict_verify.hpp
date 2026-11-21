// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "pail_gate/token_provider.hpp"

namespace pail_pep_gate {

// Where a keyring came from, kept so that a running gate can take up a newer bundle
// through the same checks as a start (SEC-H02). Fixed when the gate starts: the
// environment is read once, never again while the process runs.
struct TrustSource {
  std::string bundle_path;                 // empty = nothing to take up while running
  std::string state_path;
  std::vector<unsigned char> root_pub;
  // Production profile: a missing state file is not a first load, and the validity
  // ceiling must be declared (PAIL_KEYRING_MAX_LIFETIME_SEC).
  bool require_state{false};
  bool require_declared_ceiling{false};
  // The validity ceiling resolved at the first load, in seconds. -1 = not resolved yet
  // (the loader reads PAIL_KEYRING_MAX_LIFETIME_SEC once and records the result here).
  long long max_remaining_sec{-1};
};

struct Keyring {
  // key_id (raw bytes) -> pubkey bytes (32)
  std::unordered_map<std::string, std::vector<unsigned char>> pubkeys;

  // Revoked public keys are retained for attribution, never as trusted keys.
  // A matching signature is still rejected, but can be distinguished from an
  // unknown key ID. Removing this evidence would hide use of a disclosed key.

  std::unordered_map<std::string, std::vector<unsigned char>> revoked;
  // Captured by the accepted loader, not reconstructed by a status read.
  std::string loaded_trust_json{R"({"schema_version":1,"load_verdict":"NOT_OBSERVED"})"};

  // The accepted bundle's version and expiry (SEC-H02). 0 = not bundle trust
  // (unsigned-dev): no version to raise and no expiry to honour. A gate stops
  // judging with these keys once the wall clock passes expires_at_unix — while it
  // runs, not only at its next start.
  uint64_t bundle_version{0};
  long long expires_at_unix{0};
  TrustSource source;
};

// Load keyring JSON from /etc/pail/keys/keyring.json.
// Expected format:
// {"keys":[{"key_id":"dev-key-1","ed25519_public_key_base64":"..."}],
//  "revoked_keys":[{"key_id":"dev-key-2","ed25519_public_key_base64":"..."}]}
//
// revoked_keys is a separate array outside keys. Legacy readers that do not
// understand revocation metadata cannot find these keys in the active array
// and reject them. A status flag inside the active array would fail open for
// readers that ignore unknown fields.

//
// Returns empty keyring on failure; reason filled.
Keyring LoadKeyringJSON(const std::string &path, std::string *reason);

// pail.v1.ActionType values mirrored for non-grpc translation units
// (pail.pb.h only exists in PAIL_ENABLE_GRPC builds).
constexpr int kActionTypeUnspecified = 0;
constexpr int kActionMove = 1;
// AL-3 (implementation contract D3): from schema_version 4 the same field is a CLASS MASK.
// MOVE keeps the value 1, so a v3 reader that compares `== kActionMove` still
// drives on a MOVE-only v4 token; every other combination is judged by the
// version-aware check in gate_core. NONE is bit 8, not 0 — 0 stays UNSPECIFIED
// (fail-closed) in every version.
constexpr int kClassMove = 1;
constexpr int kClassManipulate = 2;
constexpr int kClassActuate = 4;
constexpr int kClassNone = 8;
constexpr int kClassMaskAll = 15;
constexpr int kTokenSchemaMask = 4;  // first schema_version whose action_type is a mask
// SK-4 : first schema_version whose envelope is the named list
// (TokenConstraints.guardrails) and whose authorization is the skill NAME
// (ActionToken.skill) rather than the class mask. v<=4 stays parseable (F8).
constexpr int kTokenSchemaNamedEnvelope = 5;
constexpr const char *kGuardrailDuration = "step.max_duration_s";
constexpr const char *kSlotMain = "main";

// SK-2 : one named bound of the token envelope. `has_max` /
// `has_min` say which side is bounded; a name with neither is not a bound and
// strict_verify never emits one. Names are GUARDRAILS.tsv words.
struct Guardrail {
  std::string name;
  double max{0.0};
  double min{0.0};
  bool has_max{false};
  bool has_min{false};
};

// The two names the v4 fixed fields spell (issuer: config.GuardrailLinear /
// GuardrailAngular). Spelled once here so the seam and the core agree.
constexpr const char *kGuardrailLinear = "sls.linear_mps";
constexpr const char *kGuardrailAngular = "sls.angular_rps";

// Decision-relevant fields extracted from the verified ActionToken bytes.
// Values here come exclusively from Unmarshal(action_token_bytes).
struct VerifiedTokenInfo {
  std::string target_object_id;
  int action_type{0};  // pail.v1.ActionType numeric value; 0 = UNSPECIFIED.
                       // schema_version >= 4: class mask (kClass*).
  // AL-3: the token's schema_version — the key that says how action_type is
  // read. 0 here means "not parsed", which the version-aware check treats as
  // the legacy enum (a v4 semantics applied to an unversioned value would be
  // the one way to widen authority by accident).
  int schema_version{0};
  double max_linear_speed_mps{0.0};   // 0 = no per-token limit
  double max_angular_speed_rps{0.0};
  double max_duration_sec{0.0};
  // SK-2: the envelope as a named list. v<=4 tokens: the two fixed speed
  // fields spelled by name (filled by strict_verify); v5 (SK-4) carries the
  // list itself. Empty means "not filled" — the core then derives the same two
  // entries from the fixed fields, so a caller that only sets those is judged
  // exactly as before.
  std::vector<Guardrail> guardrails;
  // SK-4: v5 only. `skill` is the registry name the token authorizes; `slot`
  // the permit slot ("main" in this edition). Both empty on v<=4.
  std::string skill;
  std::string slot;
  int64_t not_after_unix_ms{0};  // 0 = no expiry (step-deadline fallback, M3)
  // [AG-2/CR3] Token-embedded authorization-subgraph snapshot hash (field 61),
  // covered by the issuer signature. Empty on pre-v3 tokens.
  std::string subgraph_snapshot_hash;

  // [OR3/X12②] Identity taken from the VERIFIED bytes, never from the response
  // envelope. These three live in ActionToken (fields 1-3) and were always
  // inside the signature; this struct simply did not hand them out, which is
  // why callers reached for the envelope copy instead. Widening the view is
  // the fix — patching call sites one at a time reopens on the next caller.
  std::string token_id;       // ActionToken.token_id       (field 1)
  std::string chain_id;       // ActionToken.chain_id       (field 2)
  int32_t sequence_index{0};  // ActionToken.sequence_index (field 3)

  // Single-use key, canon A §3.5: hex(SHA-256("pail-tokenkey:v1:" ‖ bytes)).
  // Keying off the bytes rather than token_id makes the same authorization the
  // same key no matter what name the envelope puts on it.
  std::string consumption_key;
};

// D §3.1 (C-B5): 0 is not a value the issuer ever legitimately mints for these
// fields — proto3 omits defaults on the wire, so a deleted field arrives as 0,
// and the old `> 0.0` gate guards read exactly that as "unlimited". Speeds and
// expiry at 0 are refused; max_duration_sec 0 stays a legitimate value (a
// twist-less step has no duration) and is deliberately not an argument here —
// its enforcement lives on the command path (gate_core step_overrun), not in
// verification. Pure and std-only so the L1 tier can table-test it.
// Returns nullptr when well-formed, else the ERR_* reason to refuse with.
inline const char *ConstraintZeroReason(bool has_constraints,
                                        double max_linear_speed_mps,
                                        double max_angular_speed_rps,
                                        int64_t not_after_unix_ms) {
  // Permanent tokens first: an absent expiry is refused regardless of the
  // constraints message, so the two refusals stay separately observable.
  if (not_after_unix_ms <= 0) return "ERR_BAD_TOKEN";
  // proto3: an absent constraints message and an all-zero one are the same
  // bytes on the wire — both mean "no limits", which is not issuable.
  if (!has_constraints) return "ERR_BAD_TOKEN";
  if (max_linear_speed_mps <= 0.0) return "ERR_BAD_TOKEN";
  if (max_angular_speed_rps <= 0.0) return "ERR_BAD_TOKEN";
  return nullptr;
}

// ConsumptionKeyHex derives the A §3.5 single-use key from the issuer-signed
// bytes. Lowercase hex, 64 chars. Callers must pass action_token_bytes exactly
// as received: the prefix exists so this hash cannot collide with another use
// of the same bytes (F1), and re-serializing would silently change the key.
std::string ConsumptionKeyHex(const std::string &action_token_bytes);

// Strictly verify a grpc-provided token view (M2, LLD-v2 §1.1).
// - Verify ed25519 signature over the exact issuer-signed action_token_bytes
//   (no re-serialization).
// - Parse ActionToken; reject schema_version < 2 or unknown fields (ERR_SCHEMA)
//   and action_type UNSPECIFIED (ERR_BAD_TOKEN) — old-stub bypass prevention.
// - Validate time window and robot_id binding.
//
// clock_skew_ms (deployment clock allowance): bounded allowance for cross-host clock skew
// between the issuer (cloud) and this verifier (robot). The time window is
// widened by ±skew; anything beyond stays fail-closed. Negative values clamp
// to 0 (zero tolerance).
//
// Key lookup distinguishes active, revoked (ERR_REVOKED_KEY_ID) and unknown
// (ERR_UNKNOWN_KEY_ID). Attribution to a revoked key requires a matching
// signature; otherwise return ERR_TAMPERED, not a claimed-key attribution.
bool StrictVerifyActiveTokenView(const ActiveTokenView &tv,
                                const std::string &expected_robot_id,
                                const Keyring &keyring,
                                int64_t clock_skew_ms,
                                VerifiedTokenInfo *out_info,
                                std::string *reason_code);

} // namespace pail_pep_gate
