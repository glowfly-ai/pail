// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//
// SK-4 : token v5 at the verifier seam. Owner of G-ENF-29 (the
// named envelope is read from the list and refused on the values nobody can
// satisfy) and G-ENF-30 (the v<=4 path is unchanged: the fixed fields still
// unfold into the two speed names). Every refusal row violates exactly one
// rule (H-B9) — each is TV5-01 (the valid baseline) with one thing wrong.

#include <sodium.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "pail.pb.h"
#include "pail_gate/strict_verify.hpp"
#include "pail_gate/token_provider.hpp"

using pail_pep_gate::ActiveTokenView;
using pail_pep_gate::Keyring;
using pail_pep_gate::StrictVerifyActiveTokenView;
using pail_pep_gate::VerifiedTokenInfo;

namespace {

int g_failures = 0;
unsigned char g_sk[crypto_sign_SECRETKEYBYTES];
std::vector<unsigned char> g_pk(crypto_sign_PUBLICKEYBYTES);
constexpr const char *kRobot = "robot-1";
constexpr const char *kKey = "v5-key-1";

void Row(const char *id, bool ok, const std::string &got) {
  std::printf("%s %s%s%s\n", ok ? "ok  " : "FAIL", id, got.empty() ? "" : " — ", got.c_str());
  if (!ok) ++g_failures;
}

// The valid v5 baseline: the twist row of config/skills.diff_drive_amr.yaml —
// three names, each an upper bound, fixed fields equal, skill twist, slot main.
pail::v1::ActionToken Baseline() {
  pail::v1::ActionToken t;
  t.set_token_id("tok-v5");
  t.set_chain_id("chain-v5");
  t.set_robot_id(kRobot);
  t.set_plan_id("plan-v5");
  t.set_step_id("s1");
  t.set_sequence_index(1);
  const int64_t now = 1750000000000LL;
  t.set_issued_at_unix_ms(now);
  t.set_not_before_unix_ms(0);
  t.set_not_after_unix_ms(now + 86400000LL * 3650);
  t.set_action_type(pail::v1::ACTION_MOVE);  // minted, not judged (L15)
  t.set_schema_version(5);
  t.set_skill("twist");
  t.set_slot("main");
  auto *c = t.mutable_constraints();
  c->set_max_linear_speed_mps(0.5);
  c->set_max_angular_speed_rps(1.0);
  c->set_max_duration_sec(10.0);
  auto add = [&](const char *n, double v) { auto *g = c->add_guardrails(); g->set_name(n); g->set_max(v); };
  add("sls.angular_rps", 1.0);
  add("sls.linear_mps", 0.5);
  add("step.max_duration_s", 10.0);
  return t;
}

bool Verify(const pail::v1::ActionToken &t, VerifiedTokenInfo *info, std::string *reason) {
  const std::string bytes = t.SerializeAsString();
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, nullptr, reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size(), g_sk);
  ActiveTokenView tv;
  tv.action_token_bytes = bytes;
  tv.signature_bytes.assign(reinterpret_cast<const char *>(sig), sizeof(sig));
  tv.key_id_bytes = kKey;
  Keyring kr;
  kr.pubkeys[kKey] = g_pk;
  return StrictVerifyActiveTokenView(tv, kRobot, kr, 0, info, reason);
}

// One mutation, one expected reason.
void Refuses(const char *id, const char *want, void (*mutate)(pail::v1::ActionToken *)) {
  pail::v1::ActionToken t = Baseline();
  mutate(&t);
  VerifiedTokenInfo info;
  std::string reason;
  const bool ok = Verify(t, &info, &reason);
  Row(id, !ok && reason == want, ok ? "accepted" : reason);
}

const pail_pep_gate::Guardrail *Find(const VerifiedTokenInfo &info, const char *n) {
  for (const auto &g : info.guardrails) if (g.name == n) return &g;
  return nullptr;
}

}  // namespace

int main() {
  if (sodium_init() < 0) { std::fprintf(stderr, "sodium_init failed\n"); return 2; }
  crypto_sign_keypair(g_pk.data(), g_sk);

  {  // PAIL-CASE: token_v5_baseline_reads_list
    VerifiedTokenInfo info;
    std::string reason;
    const bool ok = Verify(Baseline(), &info, &reason);
    const auto *lin = Find(info, "sls.linear_mps");
    const auto *dur = Find(info, "step.max_duration_s");
    Row("token_v5_baseline_reads_list",
        ok && info.schema_version == 5 && info.skill == "twist" && info.slot == "main" &&
            info.guardrails.size() == 3 && lin && lin->has_max && lin->max == 0.5 && !lin->has_min &&
            dur && dur->max == 10.0,
        ok ? "" : reason);
  }
  {  // PAIL-CASE: token_v5_min_only_is_lower_bound
    pail::v1::ActionToken t = Baseline();
    auto *g = t.mutable_constraints()->add_guardrails();
    g->set_name("sdh.human_distance_m"); g->set_min(1.0);
    VerifiedTokenInfo info; std::string reason;
    const bool ok = Verify(t, &info, &reason);
    const auto *d = Find(info, "sdh.human_distance_m");
    Row("token_v5_min_only_is_lower_bound", ok && d && d->has_min && !d->has_max && d->min == 1.0, ok ? "" : reason);
  }
  // G-ENF-29 — refusals, one rule each.
  // PAIL-CASE: token_v5_max_zero_refused — on the duration entry: C-B5 (fixed
  // speeds) does not look at duration, so the refusal can only come from the
  // list rule (H-B9: one rule per row; a zero speed would be caught twice).
  Refuses("token_v5_max_zero_refused", "ERR_BAD_TOKEN",
          [](pail::v1::ActionToken *t) { t->mutable_constraints()->mutable_guardrails(2)->set_max(0.0); t->mutable_constraints()->set_max_duration_sec(0.0); });
  // PAIL-CASE: token_v5_min_above_max_refused
  Refuses("token_v5_min_above_max_refused", "ERR_BAD_TOKEN",
          [](pail::v1::ActionToken *t) { t->mutable_constraints()->mutable_guardrails(1)->set_min(0.9); });
  // PAIL-CASE: token_v5_entry_without_bound_refused
  Refuses("token_v5_entry_without_bound_refused", "ERR_BAD_TOKEN",
          [](pail::v1::ActionToken *t) { auto *g = t->mutable_constraints()->add_guardrails(); g->set_name("sfc.contact_n"); });
  // PAIL-CASE: token_v5_duplicate_name_refused
  Refuses("token_v5_duplicate_name_refused", "ERR_BAD_TOKEN",
          [](pail::v1::ActionToken *t) { auto *g = t->mutable_constraints()->add_guardrails(); g->set_name("sls.linear_mps"); g->set_max(0.5); });
  // PAIL-CASE: token_v5_fixed_field_disagrees_refused
  Refuses("token_v5_fixed_field_disagrees_refused", "ERR_SCHEMA",
          [](pail::v1::ActionToken *t) { t->mutable_constraints()->set_max_linear_speed_mps(0.7); });
  // PAIL-CASE: token_v5_empty_skill_refused
  Refuses("token_v5_empty_skill_refused", "ERR_SCHEMA", [](pail::v1::ActionToken *t) { t->set_skill(""); });
  // PAIL-CASE: token_v5_empty_slot_refused
  Refuses("token_v5_empty_slot_refused", "ERR_SCHEMA", [](pail::v1::ActionToken *t) { t->set_slot(""); });

  {  // G-ENF-30 — PAIL-CASE: token_v4_path_unchanged
    pail::v1::ActionToken t = Baseline();
    t.set_schema_version(4);
    t.clear_skill(); t.clear_slot();
    t.mutable_constraints()->clear_guardrails();
    VerifiedTokenInfo info; std::string reason;
    const bool ok = Verify(t, &info, &reason);
    const auto *lin = Find(info, "sls.linear_mps");
    const auto *ang = Find(info, "sls.angular_rps");
    Row("token_v4_path_unchanged",
        ok && info.guardrails.size() == 2 && lin && lin->max == 0.5 && ang && ang->max == 1.0 && info.skill.empty(),
        ok ? "" : reason);
  }
  {  // PAIL-CASE: token_v4_with_list_ignores_it — a v4 token carrying field 4 is a
     // newer/foreign schema to a v4 reading and is refused by the unknown-field rule
     // on gates that predate SK-4; on this gate the list is a known field, and the
     // edition is what schema_version says — v4 semantics ignore the list.
    pail::v1::ActionToken t = Baseline();
    t.set_schema_version(4);
    VerifiedTokenInfo info; std::string reason;
    const bool ok = Verify(t, &info, &reason);
    Row("token_v4_with_list_ignores_it", ok && info.guardrails.size() == 2 && info.skill.empty(), ok ? "" : reason);
  }

  std::printf("%s: %d failure(s)\n", g_failures ? "RED" : "GREEN", g_failures);
  return g_failures ? 1 : 0;
}
