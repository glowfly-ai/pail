// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_gate/strict_verify.hpp"

#if PAIL_ENABLE_GRPC == 1

#include <set>
#include <sodium.h>

#include "pail.pb.h" // generated when grpc enabled

#include "pail_gate/wall_clock.hpp"

// NOTE: LoadKeyringJSON moved to src/crypto/keyring_bundle.cpp (KM2-1) —
// keyring loading is sodium-only and shares its JSON extraction with the
// signed-bundle loader; this file keeps the protobuf-dependent verification.

namespace pail_pep_gate {

// [OR3/X12②] canon A §3.5. The prefix is 17 ASCII bytes and is part of the
// frozen definition — it keeps this digest distinct from the issuer's
// unprefixed sha256(action_token_bytes), which is a correlation id, not a
// decision key .
std::string ConsumptionKeyHex(const std::string &action_token_bytes) {
  static const char kPrefix[] = "pail-tokenkey:v1:";
  crypto_hash_sha256_state st;
  crypto_hash_sha256_init(&st);
  crypto_hash_sha256_update(&st, reinterpret_cast<const unsigned char *>(kPrefix),
                            sizeof(kPrefix) - 1);
  crypto_hash_sha256_update(&st,
                            reinterpret_cast<const unsigned char *>(action_token_bytes.data()),
                            action_token_bytes.size());
  unsigned char out[crypto_hash_sha256_BYTES];
  crypto_hash_sha256_final(&st, out);

  static const char kHex[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(sizeof(out) * 2);
  for (unsigned char b : out) {
    hex.push_back(kHex[b >> 4]);
    hex.push_back(kHex[b & 0x0f]);
  }
  return hex;
}

// `R-A` 게이트 경계 (E-W5, implementation contract).
//
// 발급 경계(Go `raIssueBoundary`)와 **일부러 따로 구현한다.** 여기서 잡히는 것은
// 이 검사보다 오래된 이슈어가 낸 토큰 — 즉 발급 경계가 없던 시절의 산출이다.
// 발급 쪽 구현을 공유하면 두 관문이 같은 결함을 공유하게 되고, 이 관문이 서는
// 이유("생산자를 믿지 않는다")가 사라진다. 규칙은 canon.go 의 `R-A` 와 같다:
// 비어 있거나 ':' 를 품으면 거부.
//
// 사유는 `ERR_TAMPERED` 가 아니다. 그 사유는 이미 "검증 미실행"과 "변조 관측"
// 둘을 겸하고 있고(implementation contract 미결), 셋째를 얹으면 셋 다 구별할 수 없게 된다.
// 여기서 관측되는 것은 변조가 아니다 — 서명은 방금 통과했다. 이슈어가 만들지
// 말았어야 할 값을 만든 것이고, 그것은 이상(anomaly)이지 공격이 아니다.
static bool RAIdentifierOK(const std::string &v) {
  return !v.empty() && v.find(':') == std::string::npos;
}

// SK-4 : read a v5 token's named envelope into `info->guardrails`
// and its skill/slot. Refusals, each its own reason (H-B9):
//   ERR_BAD_TOKEN — an entry with an empty name, a duplicate name, neither max
//                   nor min, max <= 0, or min > max (a bound nobody can satisfy
//                   or that widens nothing is not an issuable value, C-B5 shape).
//   ERR_SCHEMA    — a fixed field (1~3) disagreeing with its list entry, or an
//                   empty skill / slot: the token says two things, or too few,
//                   and this gate does not pick one.
// `info->max_*` must already hold the fixed fields when called.
// Presence of a bound rides in a single-member oneof (pail.proto): the case
// accessor is what every protoc edition in the tree generates (3.12 on the
// robot image has no has_max()).
static bool HasMax(const pail::v1::Guardrail &g) { return g.max_bound_case() == pail::v1::Guardrail::kMax; }
static bool HasMin(const pail::v1::Guardrail &g) { return g.min_bound_case() == pail::v1::Guardrail::kMin; }

static bool ReadNamedEnvelopeV5(const pail::v1::ActionToken &tok, VerifiedTokenInfo *info,
                                std::string *reason) {
  const auto &c = tok.constraints();
  std::set<std::string> seen;
  for (const auto &g : c.guardrails()) {
    if (g.name().empty() || !seen.insert(g.name()).second) { *reason = "ERR_BAD_TOKEN"; return false; }
    if (!HasMax(g) && !HasMin(g)) { *reason = "ERR_BAD_TOKEN"; return false; }
    if (HasMax(g) && !(g.max() > 0.0)) { *reason = "ERR_BAD_TOKEN"; return false; }
    if (HasMax(g) && HasMin(g) && g.min() > g.max()) { *reason = "ERR_BAD_TOKEN"; return false; }
    Guardrail out;
    out.name = g.name();
    out.has_max = HasMax(g); out.max = HasMax(g) ? g.max() : 0.0;
    out.has_min = HasMin(g); out.min = HasMin(g) ? g.min() : 0.0;
    info->guardrails.push_back(out);
  }
  // The three fixed fields and their named entries must agree. An entry absent
  // from the list is allowed (the registry row did not put that name on this
  // skill); a present entry must equal the fixed field exactly — the fixed
  // field is a copy for old readers, never a second bound.
  auto fixed_agrees = [&](const char *name, double fixed) {
    for (const auto &g : info->guardrails) {
      if (g.name == name) return g.has_max && g.max == fixed;
    }
    return true;
  };
  if (!fixed_agrees(kGuardrailLinear, info->max_linear_speed_mps) ||
      !fixed_agrees(kGuardrailAngular, info->max_angular_speed_rps) ||
      !fixed_agrees(kGuardrailDuration, info->max_duration_sec)) {
    *reason = "ERR_SCHEMA";
    return false;
  }
  if (tok.skill().empty() || tok.slot().empty()) { *reason = "ERR_SCHEMA"; return false; }
  info->skill = tok.skill();
  info->slot = tok.slot();
  return true;
}

bool StrictVerifyActiveTokenView(const ActiveTokenView &tv,
                                const std::string &expected_robot_id,
                                const Keyring &keyring,
                                int64_t clock_skew_ms,
                                VerifiedTokenInfo *out_info,
                                std::string *reason_code) {
  if (out_info) *out_info = VerifiedTokenInfo{};
  if (reason_code) *reason_code = "ERR_VERIFY";

  if (sodium_init() < 0) {
    if (reason_code) *reason_code = "ERR_CRYPTO_INIT";
    return false;
  }

  if (tv.action_token_bytes.empty() || tv.signature_bytes.empty() || tv.key_id_bytes.empty()) {
    if (reason_code) *reason_code = "ERR_TOKEN_VIEW_INCOMPLETE";
    return false;
  }

  // key_id in SignedToken is bytes; we treat it as UTF-8 string for keyring lookup.
  //
  // `C-B16` : 조회는 3값이다. 폐기 집합은 신뢰 집합이 아니므로
  // 활성 조회가 **먼저**이고, 활성에서 찾은 키는 폐기 집합을 보지 않는다 —
  // 적재기가 두 집합의 교집합을 이미 거부했기 때문이다(`C16-C4`). 여기서 다시
  // 겹침을 판정하면 같은 규칙이 두 자리에 살고, 한쪽만 고쳐지는 날이 온다.
  std::string key_id_str = tv.key_id_bytes;
  auto it = keyring.pubkeys.find(key_id_str);
  bool key_is_revoked = false;
  if (it == keyring.pubkeys.end()) {
    it = keyring.revoked.find(key_id_str);
    if (it == keyring.revoked.end()) {
      if (reason_code) *reason_code = "ERR_UNKNOWN_KEY_ID";
      return false;
    }
    key_is_revoked = true;
  }

  const auto &pub = it->second;
  if (tv.signature_bytes.size() != crypto_sign_BYTES) {
    if (reason_code) *reason_code = "ERR_BAD_SIGNATURE_SIZE";
    return false;
  }

  // Verify signature over ActionToken bytes.
  if (crypto_sign_ed25519_verify_detached(
          reinterpret_cast<const unsigned char *>(tv.signature_bytes.data()),
          reinterpret_cast<const unsigned char *>(tv.action_token_bytes.data()),
          tv.action_token_bytes.size(),
          pub.data()) != 0) {
    if (reason_code) *reason_code = "ERR_TAMPERED";
    return false;
  }

  // `C-B16`: 서명이 맞아떨어진 **뒤에** 폐기를 낸다. 순서를 뒤집어 조회 직후에
  // 거부하면 `ERR_REVOKED_KEY_ID` 는 "폐기된 키가 이 토큰을 만들었다"가 아니라
  // "누군가 그 key_id 를 적었다"를 뜻하게 되고, 그 사유를 보고 유출 대응을
  // 시작하는 사람에게 거짓을 말하게 된다. 폐기 키의 공개 절반은 **식별 전용**
  // 이며, 여기서 true 가 반환되는 경로는 없다(`C16-C3`).
  if (key_is_revoked) {
    if (reason_code) *reason_code = "ERR_REVOKED_KEY_ID";
    return false;
  }

  // Parse ActionToken.
  pail::v1::ActionToken tok;
  if (!tok.ParseFromString(tv.action_token_bytes)) {
    if (reason_code) *reason_code = "ERR_TOKEN_PARSE";
    return false;
  }

  // Old-stub rejection (M2, LLD-v2 §1.1): a v1/foreign token must never gate motion.
  if (tok.schema_version() < 2) {
    if (reason_code) *reason_code = "ERR_SCHEMA";
    return false;
  }
  // Unknown fields surviving parse mean the token was built by a newer/foreign
  // schema this verifier cannot fully enforce — fail closed.
  if (!tok.GetReflection()->GetUnknownFields(tok).empty() ||
      (tok.has_constraints() &&
       !tok.constraints().GetReflection()->GetUnknownFields(tok.constraints()).empty())) {
    if (reason_code) *reason_code = "ERR_SCHEMA";
    return false;
  }
  // `R-A` (E-W5, §3.4): 식별자 넷은 canon 에 이어 붙는 값이라 ':' 하나가 필드
  // 경계를 옮긴다. 파싱 직후에 본다 — 뒤의 검사들이 이 값들을 쓰기 전에.
  //
  // `step_id`·`target_object_id` 는 넣지 않는다. 전자는 계획 안의 순서표이지
  // canon 식별자가 아니고 비어 있는 것이 정상이며, 후자는 내용이라 `R-B`
  // (길이 접두어)가 경계를 지킨다. 빠뜨린 것이 아니라 규칙의 대상이 아니다.
  if (!RAIdentifierOK(tok.token_id()) || !RAIdentifierOK(tok.chain_id()) ||
      !RAIdentifierOK(tok.robot_id()) || !RAIdentifierOK(tok.plan_id())) {
    if (reason_code) *reason_code = "ERR_IDENTIFIER_FORMAT";
    return false;
  }
  if (tok.action_type() == pail::v1::ACTION_TYPE_UNSPECIFIED) {
    if (reason_code) *reason_code = "ERR_BAD_TOKEN";
    return false;
  }
  // AL-3 (implementation contract D3): a v4 token's action_type is a class mask over exactly
  // four bits. A bit outside the specification is not "a class we do not know"
  // — it is a token this gate cannot judge, so it is refused here, before any
  // path reads the value as authority.
  if (tok.schema_version() >= static_cast<uint32_t>(kTokenSchemaMask) &&
      (static_cast<int>(tok.action_type()) & ~kClassMaskAll) != 0) {
    if (reason_code) *reason_code = "ERR_BAD_TOKEN";
    return false;
  }

  // Robot binding.
  if (!expected_robot_id.empty() && tok.robot_id() != expected_robot_id) {
    if (reason_code) *reason_code = "ERR_ROBOT_ID_MISMATCH";
    return false;
  }

  // Time window, widened by the bounded clock-skew allowance (D4): the issuer
  // stamps not_before/not_after on the CLOUD clock while this check runs on
  // the ROBOT clock. Skew beyond the allowance stays fail-closed.
  const int64_t now_ms = WallNowMs();  // DC-8: shared judgment clock (wall_clock.hpp)
  const int64_t skew_ms = clock_skew_ms > 0 ? clock_skew_ms : 0;
  if (tok.not_before_unix_ms() != 0 && now_ms + skew_ms < tok.not_before_unix_ms()) {
    if (reason_code) *reason_code = "ERR_NOT_YET_VALID";
    return false;
  }
  if (tok.not_after_unix_ms() != 0 && now_ms - skew_ms > tok.not_after_unix_ms()) {
    if (reason_code) *reason_code = "ERR_EXPIRED";
    return false;
  }
  if (tok.not_after_unix_ms() != 0 && tok.not_before_unix_ms() != 0 && tok.not_after_unix_ms() < tok.not_before_unix_ms()) {
    if (reason_code) *reason_code = "ERR_BAD_TIME_WINDOW";
    return false;
  }

  // D §3.1 (C-B5): zero speeds / zero expiry are not issuable values. The `!= 0`
  // leniency two checks up survives for the WINDOW comparison only; a token
  // that actually carries not_after=0 (permanent) is refused here. v1 tokens
  // never reach this line (ERR_SCHEMA above), so a 0 seen here is an erased
  // field on a v2+ token, and erasure must not widen authority (§3.3).
  if (const char *zero_reason = ConstraintZeroReason(
          tok.has_constraints(),
          tok.constraints().max_linear_speed_mps(),
          tok.constraints().max_angular_speed_rps(),
          tok.not_after_unix_ms())) {
    if (reason_code) *reason_code = zero_reason;
    return false;
  }

  if (out_info) {
    out_info->target_object_id = tok.target_object_id();
    out_info->action_type = static_cast<int>(tok.action_type());
    out_info->schema_version = static_cast<int>(tok.schema_version());
    out_info->not_after_unix_ms = tok.not_after_unix_ms();
    out_info->subgraph_snapshot_hash = tok.subgraph_snapshot_hash();
    // [OR3/X12②] Filled only here, and only after the signature check and the
    // parse have both succeeded — so by construction these come from bytes the
    // issuer signed, not from the response envelope.
    out_info->token_id = tok.token_id();
    out_info->chain_id = tok.chain_id();
    out_info->sequence_index = tok.sequence_index();
    out_info->consumption_key = ConsumptionKeyHex(tv.action_token_bytes);
    if (tok.has_constraints()) {
      out_info->max_linear_speed_mps = tok.constraints().max_linear_speed_mps();
      out_info->max_angular_speed_rps = tok.constraints().max_angular_speed_rps();
      out_info->max_duration_sec = tok.constraints().max_duration_sec();
      out_info->guardrails.clear();
      if (tok.schema_version() >= static_cast<uint32_t>(kTokenSchemaNamedEnvelope)) {
        // SK-4 : v5 — the list IS the envelope. The fixed fields are
        // carried for v<=4 readers and must say the same thing; a disagreement is
        // a token this gate cannot judge (ERR_SCHEMA), not a choice between two.
        std::string v5_reason;
        if (!ReadNamedEnvelopeV5(tok, out_info, &v5_reason)) {
          if (reason_code) *reason_code = v5_reason;
          return false;
        }
      } else {
        // SK-2: the v<=4 envelope by name — the two speeds the fixed fields spell.
        Guardrail lin; lin.name = kGuardrailLinear; lin.max = out_info->max_linear_speed_mps; lin.has_max = true;
        Guardrail ang; ang.name = kGuardrailAngular; ang.max = out_info->max_angular_speed_rps; ang.has_max = true;
        out_info->guardrails.push_back(lin);
        out_info->guardrails.push_back(ang);
      }
    }
  } else if (tok.schema_version() >= static_cast<uint32_t>(kTokenSchemaNamedEnvelope)) {
    // The caller asked for no info but a v5 token still has to be judgeable.
    VerifiedTokenInfo scratch;
    std::string v5_reason;
    scratch.max_linear_speed_mps = tok.constraints().max_linear_speed_mps();
    scratch.max_angular_speed_rps = tok.constraints().max_angular_speed_rps();
    scratch.max_duration_sec = tok.constraints().max_duration_sec();
    if (!ReadNamedEnvelopeV5(tok, &scratch, &v5_reason)) {
      if (reason_code) *reason_code = v5_reason;
      return false;
    }
  }
  if (reason_code) *reason_code = "OK";
  return true;
}

} // namespace pail_pep_gate

#else

namespace pail_pep_gate {
bool StrictVerifyActiveTokenView(const ActiveTokenView &, const std::string &, const Keyring &, int64_t, VerifiedTokenInfo *, std::string *) {
  return false;
}
// No sodium in the GRPC=OFF flavor. Returning empty rather than a plausible
// digest matters: an empty consumption key is unusable as a cache key, and the
// only path that reaches it is one where verification already returned false.
std::string ConsumptionKeyHex(const std::string &) { return std::string(); }
} // namespace pail_pep_gate

#endif
