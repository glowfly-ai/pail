// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//
// AD-1 (see spec/ARCHITECTURE.md): the TWO DOORS battery.
//
// The same scenario is driven through (a) the C++ GateSession directly and (b) the C ABI
// with protobuf bytes, in lockstep. Every step asserts (1) the stated expectation and (2)
// that both doors gave the same state/reason/forward/permit/step. A deformation that touches
// only the ABI translation shows up as a door disagreement; one that touches the session shows
// up as an expectation failure on both. Neither door talks to a network: the token service
// answer is minted here with a fresh ed25519 key (sodium) and pushed in as bytes, which is
// exactly how an adapter feeds the library.
//
// What this battery does NOT claim: equality with the ROS node's runtime. The node is untouched
// in AD-1 and keeps its own TB-7 batteries; the session cites the node lines it restates, and
// the adapter conformance harness (AD-0) is where node and library meet on the same scenarios.
//
// PAIL-CASE markers sit directly above their ROW .

#include <sodium.h>

#include <cstdio>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include "pail.pb.h"
#include "pail_gate_abi.pb.h"
#include "token_service.pb.h"

#include "pail_gate/pail_gate.h"
#include "pail_gate/gate_session.hpp"
#include "pail_gate/policy_load.hpp"
#include "pail_gate/strict_verify.hpp"
#include "pail_gate/wall_clock.hpp"

namespace abi = pail::gate::abi::v1;
using namespace pail_pep_gate;

namespace {
int g_failures = 0;
#define ROW(name, cond, detail)                                                   \
  do {                                                                            \
    if (cond) {                                                                   \
      std::printf("PASS %s\n", name);                                             \
    } else {                                                                      \
      std::printf("FAIL %s — %s\n", name, detail);                                \
      ++g_failures;                                                               \
    }                                                                             \
  } while (0)

constexpr const char *kRobot = "robot-1";
constexpr const char *kKeyId = "two-doors-key";
// 32 bytes standing in for sha256 of the site-model subgraph (issuer-computed in production).
const std::string kWorld(32, '\x5a');

struct Minter {
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  Minter() { crypto_sign_keypair(pk, sk); }

  Keyring keyring() const {
    Keyring k;
    k.pubkeys[kKeyId] = std::vector<unsigned char>(pk, pk + crypto_sign_PUBLICKEYBYTES);
    return k;
  }

  std::string keyring_json() const {
    char b64[128];
    sodium_bin2base64(b64, sizeof(b64), pk, crypto_sign_PUBLICKEYBYTES, sodium_base64_VARIANT_ORIGINAL);
    return std::string("{\"keys\":[{\"key_id\":\"") + kKeyId + "\",\"ed25519_public_key_base64\":\"" + b64 + "\"}]}\n";
  }

  // A v4 (class-mask) MOVE token for kRobot, valid for `ttl_ms` from now, 1 s max duration.
  // `skill` non-empty mints a v5 token (SK-4): named envelope list, skill, slot main.
  pail::token::v1::GetActiveTokenResponse response(const std::string &token_id, const std::string &chain_id,
                                                   int64_t now_ms, int64_t ttl_ms, double max_duration_s,
                                                   bool tamper = false, int mask = kClassMove,
                                                   const std::string &skill = "") const {
    pail::v1::ActionToken t;
    t.set_token_id(token_id);
    t.set_chain_id(chain_id);
    t.set_sequence_index(1);
    t.set_robot_id(kRobot);
    t.set_plan_id("plan-two-doors");
    t.set_step_id("s1");
    t.set_target_object_id("");
    t.set_issued_at_unix_ms(now_ms);
    t.set_not_before_unix_ms(now_ms - 1000);
    t.set_not_after_unix_ms(now_ms + ttl_ms);
    t.set_action_type(static_cast<pail::v1::ActionType>(mask));
    t.set_schema_version(4);
    t.mutable_constraints()->set_max_linear_speed_mps(0.5);
    t.mutable_constraints()->set_max_angular_speed_rps(1.0);
    t.mutable_constraints()->set_max_duration_sec(max_duration_s);
    if (!skill.empty()) {
      t.set_schema_version(5);
      t.set_skill(skill);
      t.set_slot("main");
      auto add = [&](const char *n, double v) { auto *g = t.mutable_constraints()->add_guardrails(); g->set_name(n); g->set_max(v); };
      add("sls.angular_rps", 1.0);
      add("sls.linear_mps", 0.5);
      add("step.max_duration_s", max_duration_s);
    }
    // AG-2/CR3 world hash: the issuer signs the authorization-subgraph snapshot into the
    // token and re-derives it per answer. Both sides present and equal = kMatch; an empty
    // side is C-B8 "never compared" and blocks (ERR_WORLD_INDETERMINATE) — measured on the
    // first run of this battery, which is exactly the fail-closed shape the core promises.
    t.set_subgraph_snapshot_hash(kWorld);
    const std::string bytes = t.SerializeAsString();
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr, reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size(), sk);
    if (tamper) sig[0] ^= 0x01;

    pail::token::v1::GetActiveTokenResponse r;
    r.set_status(pail::token::v1::OK);
    r.set_chain_id(chain_id);
    r.set_expected_sequence_index(1);
    r.set_current_subgraph_hash(kWorld);
    auto *st = r.mutable_token();
    st->mutable_token()->set_token_id(token_id);
    st->set_action_token_bytes(bytes);
    st->set_signature(std::string(reinterpret_cast<const char *>(sig), crypto_sign_BYTES));
    st->set_key_id(kKeyId);
    return r;
  }
};

pail::token::v1::GetActiveTokenResponse no_token() {
  pail::token::v1::GetActiveTokenResponse r;
  r.set_status(pail::token::v1::NO_TOKEN);
  return r;
}

// ---- the two doors -----------------------------------------------------------------------

struct Lite {
  std::string path, state, reason;
  bool forward{false}, report{false}, permit{false}, step{false}, estop{false}, hold{false}, fired{false};
  int streak{0};
  std::string chain, token, mode;
  bool same(const Lite &o) const {
    return path == o.path && state == o.state && reason == o.reason && forward == o.forward &&
           report == o.report && permit == o.permit && step == o.step && estop == o.estop &&
           hold == o.hold && fired == o.fired && streak == o.streak && chain == o.chain &&
           token == o.token && mode == o.mode;
  }
  std::string str() const {
    return path + ":" + state + "/" + reason + " fwd=" + (forward ? "1" : "0") + " rep=" + (report ? "1" : "0") +
           " permit=" + (permit ? "1" : "0") + " step=" + (step ? "1" : "0") + " estop=" + (estop ? "1" : "0") +
           " hold=" + (hold ? "1" : "0") + " streak=" + std::to_string(streak) + " mode=" + mode;
  }
};

Lite lite(const SessionOutcome &s) {
  Lite l;
  l.path = s.path; l.state = s.decision.state; l.reason = s.decision.reason; l.forward = s.decision.forward;
  l.report = s.decision.report; l.permit = s.permit_active; l.step = s.step_active; l.estop = s.estop_active;
  l.hold = s.decision.hold_permit; l.fired = s.fired; l.streak = s.unreachable_streak;
  l.chain = s.report_chain_id; l.token = s.report_token_id; l.mode = s.effective_mode;
  return l;
}
Lite lite(const abi::Outcome &o) {
  Lite l;
  l.path = o.path(); l.state = o.state(); l.reason = o.reason(); l.forward = o.forward(); l.report = o.report();
  l.permit = o.permit_active(); l.step = o.step_active(); l.estop = o.estop_active(); l.hold = o.hold_permit();
  l.fired = o.fired(); l.streak = o.unreachable_streak(); l.chain = o.report_chain_id();
  l.token = o.report_token_id(); l.mode = o.effective_mode();
  return l;
}

struct SessionDoor {
  GateSession s;
  SessionDoor(const SessionConfig &c, const SessionPolicy &p, const Keyring &k) : s(c, p, k) {}
  void token(bool reachable, const pail::token::v1::GetActiveTokenResponse &r) {
    // Same translation the ABI applies (ViewFromResponse) — restated minimally for the direct door.
    ActiveTokenView v;
    if (!reachable) { v.ok = false; v.status = "UNREACHABLE"; s.SetTokenView(v); return; }
    if (r.status() != pail::token::v1::OK) {
      v.ok = false; v.status = r.status() == pail::token::v1::NO_TOKEN ? "NO_TOKEN" : r.status() == pail::token::v1::REVOKED ? "REVOKED" : "ERROR";
      v.chain_id = r.chain_id(); s.SetTokenView(v); return;
    }
    v.ok = true; v.status = "OK"; v.chain_id = r.chain_id(); v.expected_sequence_index = r.expected_sequence_index();
    v.current_subgraph_hash = r.current_subgraph_hash();
    v.action_token_bytes = r.token().action_token_bytes(); v.signature_bytes = r.token().signature();
    v.key_id_bytes = r.token().key_id(); v.signed_token_bytes = r.token().SerializeAsString();
    pail::v1::ActionToken t; if (t.ParseFromString(v.action_token_bytes)) v.token_id = t.token_id(); else { v.ok = false; v.status = "ERROR"; }
    s.SetTokenView(v);
  }
  Lite safety(const std::string &level, int64_t now) { SafetyObservation o; o.level = level; o.source = "TEST"; o.observed_ms = now; return lite(s.ObserveSafety(o)); }
  void evidence(const std::string &src, const std::string &id, double conf, int64_t now) { EvidenceObservation e; e.source = src; e.object_id = id; e.confidence = conf; e.received_ms = now; s.ObserveEvidence(e); }
  Lite command(double lin, double ang, int64_t now, int cls = kClassMove, const std::string &skill = "") { CommandRequest c; c.linear_norm = lin; c.angular_norm = ang; c.requested_class = cls; c.skill = skill; return lite(s.OnCommand(c, now)); }
  Lite recheck(int64_t now) { return lite(s.OnRecheck(now)); }
  Lite step(int64_t now) { return lite(s.OnStepTimer(now)); }
  Lite complete(int64_t now, const std::string &skill) { return lite(s.CompleteStep(now, skill)); }  // SK-3
  std::string detail_of(int64_t now, const std::string &skill) { return s.CompleteStep(now, skill).decision.detail; }
};

struct AbiDoor {
  pail_gate_t *h{nullptr};
  std::string err;
  AbiDoor(const std::string &robot, const std::string &policy_path, const std::string &keyring_path, int grace, int64_t skew,
          const std::string &skills_file = "", const std::string &robot_class = "") {
    abi::Config c; c.set_robot_id(robot); c.set_policy_path(policy_path); c.set_keyring_path(keyring_path);
    c.set_permit_grace_n(grace); c.set_clock_skew_ms(skew);
    c.set_skills_file(skills_file); c.set_robot_class(robot_class);  // SK-3
    const std::string b = c.SerializeAsString();
    char *e = nullptr;
    h = pail_gate_new(reinterpret_cast<const uint8_t *>(b.data()), b.size(), &e);
    if (e) { err = e; pail_gate_free_buf(e); }
  }
  ~AbiDoor() { pail_gate_free(h); }
  template <class M> static std::string bytes(const M &m) { return m.SerializeAsString(); }
  static abi::Outcome parse(uint8_t *p, size_t n) { abi::Outcome o; o.ParseFromArray(p, static_cast<int>(n)); pail_gate_free_buf(p); return o; }
  void token(bool reachable, const pail::token::v1::GetActiveTokenResponse &r) {
    abi::TokenInput t; t.set_reachable(reachable); *t.mutable_response() = r; const auto b = bytes(t);
    pail_gate_set_token(h, reinterpret_cast<const uint8_t *>(b.data()), b.size());
  }
  Lite safety(const std::string &level, int64_t now) {
    abi::SafetyInput s; s.set_level(level); s.set_source("TEST"); s.set_observed_ms(now); const auto b = bytes(s);
    uint8_t *p = nullptr; size_t n = 0; pail_gate_observe_safety(h, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    return lite(parse(p, n));
  }
  void evidence(const std::string &src, const std::string &id, double conf, int64_t now) {
    abi::EvidenceInput e; e.set_source(src); e.set_object_id(id); e.set_confidence(conf); e.set_received_ms(now); const auto b = bytes(e);
    pail_gate_observe_evidence(h, reinterpret_cast<const uint8_t *>(b.data()), b.size());
  }
  Lite command(double lin, double ang, int64_t now, int cls = kClassMove, const std::string &skill = "") {
    abi::CommandInput c; c.set_linear_norm(lin); c.set_angular_norm(ang); c.set_now_ms(now); c.set_requested_class(cls); c.set_skill(skill); const auto b = bytes(c);
    uint8_t *p = nullptr; size_t n = 0; pail_gate_command(h, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    return lite(parse(p, n));
  }
  abi::TickOutcome tick(int64_t now) {
    abi::TickInput t; t.set_now_ms(now); const auto b = bytes(t);
    uint8_t *p = nullptr; size_t n = 0; pail_gate_tick(h, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    abi::TickOutcome o; o.ParseFromArray(p, static_cast<int>(n)); pail_gate_free_buf(p); return o;
  }
  Lite recheck(int64_t now) { return lite(tick(now).recheck()); }
  Lite step(int64_t now) { return lite(tick(now).step()); }
  abi::Outcome complete_raw(int64_t now, const std::string &skill) {  // SK-3
    abi::CompleteInput c; c.set_now_ms(now); c.set_skill(skill); const auto b = bytes(c);
    uint8_t *p = nullptr; size_t n = 0; pail_gate_complete_step(h, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    return parse(p, n);
  }
  Lite complete(int64_t now, const std::string &skill) { return lite(complete_raw(now, skill)); }
  abi::Info info() { uint8_t *p = nullptr; size_t n = 0; pail_gate_info(h, &p, &n); abi::Info i; i.ParseFromArray(p, static_cast<int>(n)); pail_gate_free_buf(p); return i; }
};

// Assert both doors agree, then return the session door's view for the expectation checks.
Lite both(const char *name, const Lite &a, const Lite &b) {
  if (!a.same(b)) {
    std::printf("FAIL %s — doors disagree: session[%s] abi[%s]\n", name, a.str().c_str(), b.str().c_str());
    ++g_failures;
  }
  return a;
}

std::string write_temp(const std::string &name, const std::string &content) {
  const std::string path = std::string("/tmp/pail_two_doors_") + name;
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f << content;
  return path;
}

}  // namespace

int main() {
  if (sodium_init() < 0) { std::printf("FAIL sodium_init\n"); return 2; }
  const std::string policy_path = PAIL_TB7_POLICY_FIXTURE;
  const std::string policy_observe = PAIL_TB7_POLICY_OBSERVE_FIXTURE;

  // ---- G-ADP-04: the library loads the node's fixture to the node's numbers ----
  SessionPolicy pol;
  std::string perr;
  const bool loaded = LoadSessionPolicy(policy_path, &pol, &perr);
  // PAIL-CASE: two_doors_policy_fixture_loads
  ROW("two_doors_policy_fixture_loads", loaded, perr.c_str());
  // PAIL-CASE: two_doors_policy_numbers
  ROW("two_doors_policy_numbers",
      loaded && pol.gate_mode == "enforce" && pol.human_safety_enabled && pol.evidence_conf_threshold == 0.90 &&
          pol.min_trust_rank == 2 && pol.trust_rank_by_source.at("RFID") == 3 && pol.trust_rank_by_source.at("VISION") == 2 &&
          pol.safety_stale_ms == 1000 && pol.evidence_window_ms == 2000 && pol.safety_exempt_in_progress_step,
      "fixture policy_min.yaml must map to enforce/true/0.90/rank2/1000/2000/exempt=true");
  {
    SessionPolicy po; std::string e;
    const bool ok = LoadSessionPolicy(policy_observe, &po, &e);
    // PAIL-CASE: two_doors_policy_observe_mode
    ROW("two_doors_policy_observe_mode", ok && po.gate_mode == "observe", e.c_str());
    SessionPolicy pa; std::string ea;
    // PAIL-CASE: two_doors_policy_absent_refused
    ROW("two_doors_policy_absent_refused", !LoadSessionPolicy("/nonexistent/policy.yaml", &pa, &ea) && ea.find("POLICY_ABSENT") == 0, ea.c_str());
  }

  Minter m;
  const std::string keyring_path = write_temp("keyring.json", m.keyring_json());
  setenv("PAIL_KEYRING_MODE", "unsigned-dev", 1);

  SessionConfig cfg; cfg.robot_id = kRobot; cfg.permit_grace_n = 3; cfg.clock_skew_ms = 500;
  SessionDoor sd(cfg, pol, m.keyring());
  AbiDoor ad(kRobot, policy_path, keyring_path, 3, 500);
  // PAIL-CASE: two_doors_abi_new
  ROW("two_doors_abi_new", ad.h != nullptr, ad.err.c_str());
  if (!ad.h) return 1;
  {
    const auto info = ad.info();
    // PAIL-CASE: two_doors_abi_info_keyring
    ROW("two_doors_abi_info_keyring", info.abi_version() == PAIL_GATE_ABI_VERSION && info.keys() == 1 && info.keyring_error().empty() && info.gate_mode() == "enforce",
        ("abi=" + std::to_string(info.abi_version()) + " keys=" + std::to_string(info.keys()) + " err=" + info.keyring_error()).c_str());
  }

  const int64_t t0 = WallNowMs();

  // ---- S1: no token, no feeds → BLOCK, nothing forwarded (CA-01) ----
  sd.token(true, no_token()); ad.token(true, no_token());
  {
    const Lite r = both("S1", sd.command(0.1, 0.0, t0), ad.command(0.1, 0.0, t0));
    // PAIL-CASE: two_doors_no_token_blocks
    ROW("two_doors_no_token_blocks", r.state == "BLOCK" && !r.forward && r.reason == "ERR_NO_TOKEN", r.str().c_str());
  }

  // ---- S2: valid token but no safety/evidence feed → still BLOCK (CA-10) ----
  const auto tok = m.response("tok-1", "chain-1", t0, 60000, 1.0);
  sd.token(true, tok); ad.token(true, tok);
  {
    const Lite r = both("S2", sd.command(0.1, 0.0, t0), ad.command(0.1, 0.0, t0));
    // PAIL-CASE: two_doors_feeds_absent_blocks
    ROW("two_doors_feeds_absent_blocks", r.state == "BLOCK" && !r.forward && r.reason.rfind("ERR_", 0) == 0, r.str().c_str());
  }

  // ---- S3: feeds fresh → PERMIT, forward, permit+step enter (CA-07 precondition) ----
  sd.safety("OK", t0); ad.safety("OK", t0);
  sd.evidence("RFID", "obj-1", 0.99, t0); ad.evidence("RFID", "obj-1", 0.99, t0);
  {
    const Lite r = both("S3", sd.command(0.1, 0.0, t0 + 10), ad.command(0.1, 0.0, t0 + 10));
    // PAIL-CASE: two_doors_permit_forward
    ROW("two_doors_permit_forward", r.state == "PERMIT" && r.forward && r.report && r.permit && r.step && r.reason == "OK" && r.chain == "chain-1" && r.token == "tok-1" && r.mode == "enforce", r.str().c_str());
  }

  // ---- S4: over the token's speed limit → BLOCK (CA-06, clamp is not an option) ----
  {
    const Lite r = both("S4", sd.command(0.9, 0.0, t0 + 20), ad.command(0.9, 0.0, t0 + 20));
    // PAIL-CASE: two_doors_speed_limit_blocks
    ROW("two_doors_speed_limit_blocks", r.state == "BLOCK" && !r.forward && r.reason == "ERR_CONSTRAINT", r.str().c_str());
  }

  // ---- S5: within limits again → PERMIT re-enters ----
  {
    const Lite r = both("S5", sd.command(0.1, 0.0, t0 + 30), ad.command(0.1, 0.0, t0 + 30));
    // PAIL-CASE: two_doors_permit_reenters
    ROW("two_doors_permit_reenters", r.state == "PERMIT" && r.forward && r.permit, r.str().c_str());
  }

  // ---- S6: recheck while reachable → hold continues (no publication) ----
  {
    const Lite r = both("S6", sd.recheck(t0 + 40), ad.recheck(t0 + 40));
    // PAIL-CASE: two_doors_recheck_ok_keeps_permit
    ROW("two_doors_recheck_ok_keeps_permit", r.permit && r.state != "BLOCK" && r.streak == 0, r.str().c_str());
  }

  // ---- S7: issuer unreachable → grace ladder: hold ×grace_n, then BLOCK (CA-08/09) ----
  sd.token(false, no_token()); ad.token(false, no_token());
  {
    // Measured shape (first run of this battery): with permit_grace_n=3 the core HOLDS on the
    // 1st and 2nd unanswered recheck and BLOCKS on the 3rd — the ladder is "fewer than n
    // consecutive misses", i.e. the robot drives at most (n-1)×recheck_ms without the issuer.
    Lite r1 = both("S7a", sd.recheck(t0 + 50), ad.recheck(t0 + 50));
    Lite r2 = both("S7b", sd.recheck(t0 + 60), ad.recheck(t0 + 60));
    // PAIL-CASE: two_doors_grace_holds
    ROW("two_doors_grace_holds", r1.hold && r1.permit && r1.streak == 1 && r2.hold && r2.permit && r2.streak == 2,
        (r1.str() + " | " + r2.str()).c_str());
    Lite r3 = both("S7c", sd.recheck(t0 + 70), ad.recheck(t0 + 70));
    // PAIL-CASE: two_doors_grace_exhausted_blocks
    ROW("two_doors_grace_exhausted_blocks", !r3.hold && r3.state == "BLOCK" && r3.reason == "ERR_ISSUER_UNREACHABLE" && !r3.permit && r3.streak == 3, r3.str().c_str());
    Lite r4 = both("S7d", sd.recheck(t0 + 80), ad.recheck(t0 + 80));
    // PAIL-CASE: two_doors_recheck_without_permit_is_silent
    ROW("two_doors_recheck_without_permit_is_silent", r4.state.empty() && !r4.permit, r4.str().c_str());
    // And a command while unreachable is not forwarded.
    Lite r5 = both("S7e", sd.command(0.1, 0.0, t0 + 90), ad.command(0.1, 0.0, t0 + 90));
    // PAIL-CASE: two_doors_unreachable_command_blocks
    ROW("two_doors_unreachable_command_blocks", r5.state == "BLOCK" && !r5.forward, r5.str().c_str());
  }

  // ---- S8: back reachable → PERMIT; step deadline passes → step_complete report; replay → consumed ----
  sd.token(true, tok); ad.token(true, tok);
  {
    Lite r = both("S8a", sd.command(0.1, 0.0, t0 + 100), ad.command(0.1, 0.0, t0 + 100));
    // PAIL-CASE: two_doors_permit_after_recovery
    ROW("two_doors_permit_after_recovery", r.state == "PERMIT" && r.forward && r.step, r.str().c_str());
    Lite s0 = both("S8b", sd.step(t0 + 500), ad.step(t0 + 500));
    // PAIL-CASE: two_doors_step_not_yet_due
    ROW("two_doors_step_not_yet_due", !s0.fired && s0.step, s0.str().c_str());
    // Wall-time injection no longer advances a local duration. Let it elapse.
    std::this_thread::sleep_for(std::chrono::milliseconds(1020));
    Lite s1 = both("S8c", sd.step(t0 + 100 + 1000 + 1), ad.step(t0 + 100 + 1000 + 1));
    // PAIL-CASE: two_doors_step_completes_and_reports
    ROW("two_doors_step_completes_and_reports", s1.fired && s1.report && s1.state == "PERMIT" && s1.chain == "chain-1" && s1.token == "tok-1" && !s1.permit && !s1.step, s1.str().c_str());
    // PAIL-CASE: two_doors_consumed_written
    ROW("two_doors_consumed_written", sd.s.consumed_size() == 1 && ad.info().consumed_size() == 1, "consumption key must be in the cache on both doors");
    Lite r2 = both("S8d", sd.command(0.1, 0.0, t0 + 1200), ad.command(0.1, 0.0, t0 + 1200));
    // PAIL-CASE: two_doors_replay_blocked
    ROW("two_doors_replay_blocked", r2.state == "BLOCK" && !r2.forward && r2.reason == "ERR_TOKEN_CONSUMED", r2.str().c_str());
  }

  // ---- S9: a fresh token on the same chain → PERMIT again; tampered signature → BLOCK (CA-02) ----
  // The safety feed observed at t0 is stale by now (safety_stale_ms=1000; measured: the
  // first run blocked here with ERR_SAFETY_STALE, exactly as it should). Refresh both feeds.
  sd.safety("OK", t0 + 1290); ad.safety("OK", t0 + 1290);
  sd.evidence("RFID", "obj-1", 0.99, t0 + 1290); ad.evidence("RFID", "obj-1", 0.99, t0 + 1290);
  const auto tok2 = m.response("tok-2", "chain-1", t0, 60000, 5.0);
  sd.token(true, tok2); ad.token(true, tok2);
  {
    Lite r = both("S9a", sd.command(0.1, 0.0, t0 + 1300), ad.command(0.1, 0.0, t0 + 1300));
    // PAIL-CASE: two_doors_second_token_permits
    ROW("two_doors_second_token_permits", r.state == "PERMIT" && r.forward && r.token == "tok-2", r.str().c_str());
    const auto bad = m.response("tok-3", "chain-1", t0, 60000, 5.0, /*tamper=*/true);
    sd.token(true, bad); ad.token(true, bad);
    Lite rb = both("S9b", sd.command(0.1, 0.0, t0 + 1400), ad.command(0.1, 0.0, t0 + 1400));
    // PAIL-CASE: two_doors_tampered_blocks
    ROW("two_doors_tampered_blocks", rb.state == "BLOCK" && !rb.forward && rb.reason == "ERR_TAMPERED", rb.str().c_str());
  }

  // ---- S10: safety UNSAFE → ESTOP latch, fatal report; command under latch is not forwarded ----
  sd.token(true, tok2); ad.token(true, tok2);
  both("S10-pre", sd.command(0.1, 0.0, t0 + 1500), ad.command(0.1, 0.0, t0 + 1500));
  {
    Lite e = both("S10a", sd.safety("UNSAFE", t0 + 1510), ad.safety("UNSAFE", t0 + 1510));
    // PAIL-CASE: two_doors_estop_latches
    ROW("two_doors_estop_latches", e.state == "ESTOP" && e.reason == "ERR_SAFETY_UNSAFE" && e.report && e.estop && !e.permit && !e.step && e.token == "tok-2", e.str().c_str());
    Lite c = both("S10b", sd.command(0.1, 0.0, t0 + 1520), ad.command(0.1, 0.0, t0 + 1520));
    // PAIL-CASE: two_doors_estop_command_blocked
    ROW("two_doors_estop_command_blocked", c.state != "PERMIT" && !c.forward && c.estop, c.str().c_str());
    Lite rel = both("S10c", sd.safety("OK", t0 + 1530), ad.safety("OK", t0 + 1530));
    // PAIL-CASE: two_doors_estop_release_no_permit
    ROW("two_doors_estop_release_no_permit", !rel.estop && rel.state.empty() && !rel.permit, rel.str().c_str());
  }

  // ---- S12: action classes — a MOVE-only token does not cover ACTUATE; a MOVE|ACTUATE token does ----
  // P15-H1 (2026-10-16): the E-STOP in S10 latched chain-1 in both doors. The issuer may still
  // serve tok-2 (its revoking report can be in flight, or lost — the judge2 defect), and that
  // token must not grant again after the release. New authority arrives as a NEW chain, which
  // is how the issuer issues it after a revocation; the class scenarios run on chain-2.
  sd.safety("OK", t0 + 1590); ad.safety("OK", t0 + 1590);
  sd.evidence("RFID", "obj-1", 0.99, t0 + 1590); ad.evidence("RFID", "obj-1", 0.99, t0 + 1590);
  {
    Lite latched = both("S12-latched", sd.command(0.1, 0.0, t0 + 1595), ad.command(0.1, 0.0, t0 + 1595));
    // PAIL-CASE: two_doors_estop_latched_chain_refused_after_release
    ROW("two_doors_estop_latched_chain_refused_after_release", latched.state == "BLOCK" && !latched.forward && latched.reason == "ERR_REVOKED" && !latched.permit, latched.str().c_str());
    const auto tokN = m.response("tok-5", "chain-2", t0, 60000, 5.0);
    sd.token(true, tokN); ad.token(true, tokN);
    Lite ok = both("S12-pre", sd.command(0.1, 0.0, t0 + 1600), ad.command(0.1, 0.0, t0 + 1600));
    // PAIL-CASE: two_doors_class_move_permits_after_release
    ROW("two_doors_class_move_permits_after_release", ok.state == "PERMIT" && ok.forward && ok.chain == "chain-2", ok.str().c_str());
    Lite a = both("S12a", sd.command(0.0, 0.0, t0 + 1610, kClassActuate), ad.command(0.0, 0.0, t0 + 1610, kClassActuate));
    // PAIL-CASE: two_doors_class_actuate_not_covered
    ROW("two_doors_class_actuate_not_covered", a.state == "BLOCK" && !a.forward && a.reason == "ERR_ACTION_MISMATCH", a.str().c_str());
    const auto tok3 = m.response("tok-4", "chain-2", t0, 60000, 5.0, false, kClassMove | kClassActuate);
    sd.token(true, tok3); ad.token(true, tok3);
    Lite b = both("S12b", sd.command(0.0, 0.0, t0 + 1620, kClassActuate), ad.command(0.0, 0.0, t0 + 1620, kClassActuate));
    // PAIL-CASE: two_doors_class_actuate_covered_by_mask
    ROW("two_doors_class_actuate_covered_by_mask", b.state == "PERMIT" && b.forward && b.token == "tok-4", b.str().c_str());
    // Class 0 is the one place the doors legitimately differ, and the test says so instead
    // of hiding it in `both`: the C++ door takes 0 literally (asks for nothing → refused,
    // fail-closed), the ABI maps proto3's default 0 to MOVE (the node's implicit class).
    Lite zs = sd.command(0.0, 0.0, t0 + 1630, 0);
    // PAIL-CASE: two_doors_class_zero_session_refuses
    ROW("two_doors_class_zero_session_refuses", zs.state == "BLOCK" && zs.reason == "ERR_ACTION_MISMATCH", zs.str().c_str());
    Lite za = ad.command(0.0, 0.0, t0 + 1640, 0);
    // PAIL-CASE: two_doors_class_zero_abi_is_move
    ROW("two_doors_class_zero_abi_is_move", za.state == "PERMIT" && za.forward, za.str().c_str());
    // Bring the direct door back in step with the ABI door before S11 (its permit was stopped).
    both("S12d", sd.command(0.0, 0.0, t0 + 1650, kClassMove), ad.command(0.0, 0.0, t0 + 1650, kClassMove));
  }

  // ---- S11: ABI parse errors are errors, not silent passes ----
  {
    uint8_t *p = nullptr; size_t n = 0;
    const uint8_t junk[] = {0xff, 0xff, 0xff, 0xff};
    const int rc = pail_gate_command(ad.h, junk, sizeof(junk), &p, &n);
    // PAIL-CASE: two_doors_abi_parse_error
    ROW("two_doors_abi_parse_error", rc == PAIL_GATE_EPARSE && p == nullptr, "junk CommandInput must return EPARSE and no buffer");
    const int rc2 = pail_gate_command(nullptr, junk, sizeof(junk), &p, &n);
    // PAIL-CASE: two_doors_abi_null_handle
    ROW("two_doors_abi_null_handle", rc2 == PAIL_GATE_EHANDLE, "null handle must return EHANDLE");
  }

  // ---- SK-3 : completion signals, both doors, on a registry with the three rows ----
  {
    const std::string skills_path = PAIL_SK3_SKILLS_FIXTURE;
    SessionConfig c3 = cfg; c3.skills_file = skills_path; c3.robot_class = "test_class";
    SessionDoor sd3(c3, pol, m.keyring());
    AbiDoor ad3(kRobot, policy_path, keyring_path, 3, 500, skills_path, "test_class");
    // PAIL-CASE: two_doors_skills_registry_loaded
    ROW("two_doors_skills_registry_loaded", sd3.s.skills_error().empty() && sd3.s.skills_rows() == 4 && ad3.err.empty(), sd3.s.skills_error().c_str());
    // Tokens are minted AT t0 (issued_at must not run ahead of the wall clock — strict time);
    // the scenario's own clock runs from t0 + 200 ms, after the earlier scenario's last step.
    const int64_t t3 = t0 + 200;
    const auto tok3 = m.response("tok-3", "chain-3", t0, 30000, 5.0);
    sd3.token(true, tok3); ad3.token(true, tok3);
    sd3.safety("OK", t3); ad3.safety("OK", t3);
    {
      const Lite r0 = both("K0", sd3.command(0.1, 0.0, t3 + 10), ad3.command(0.1, 0.0, t3 + 10));
      // PAIL-CASE: two_doors_sk3_permit_enters
      ROW("two_doors_sk3_permit_enters", r0.state == "PERMIT" && r0.step && r0.permit, r0.str().c_str());
    }
    // a `duration` row: the report is ignored, the step stays active (the deadline is the signal)
    {
      const Lite r = both("K1", sd3.complete(t3 + 20, "twist"), ad3.complete(t3 + 20, "twist"));
      const std::string d = sd3.s.CompleteStep(t3 + 21, "twist").decision.detail;
      // PAIL-CASE: two_doors_complete_duration_row_ignored
      ROW("two_doors_complete_duration_row_ignored", r.state.empty() && !r.fired && r.step && d.find("completes by duration") != std::string::npos, d.c_str());
    }
    // an unknown skill: ignored, said so
    {
      const std::string d = ad3.complete_raw(t3 + 22, "fly").detail();
      // PAIL-CASE: two_doors_complete_unknown_skill_ignored
      ROW("two_doors_complete_unknown_skill_ignored", d.find("not in the registry") != std::string::npos, d.c_str());
    }
    // a `robot_report` row: consumed now, reported with the signal, step over
    {
      const Lite r = both("K2", sd3.complete(t3 + 30, "pick"), ad3.complete(t3 + 30, "pick"));
      const std::string d = ad3.complete_raw(t3 + 31, "pick").detail();  // second report: no active step
      // PAIL-CASE: two_doors_complete_robot_report_consumes
      ROW("two_doors_complete_robot_report_consumes", r.state == "PERMIT" && r.fired && r.report && r.reason == "OK" && !r.step && !r.permit && r.chain == "chain-3" && r.token == "tok-3" && d.find("no active step") != std::string::npos, (r.str() + " / " + d).c_str());
    }
    // a `robot_report+evidence` row: no fresh evidence → BLOCK ERR_NO_EVIDENCE (at_complete), step kept
    const auto tok4 = m.response("tok-4", "chain-4", t0, 30000, 5.0);
    sd3.token(true, tok4); ad3.token(true, tok4);
    both("K3", sd3.command(0.1, 0.0, t3 + 110), ad3.command(0.1, 0.0, t3 + 110));
    {
      const Lite r = both("K4", sd3.complete(t3 + 120, "place"), ad3.complete(t3 + 120, "place"));
      const std::string d = ad3.complete_raw(t3 + 121, "place").detail();
      // PAIL-CASE: two_doors_complete_at_complete_needs_evidence
      ROW("two_doors_complete_at_complete_needs_evidence", r.state == "BLOCK" && r.reason == "ERR_NO_EVIDENCE" && r.report && !r.fired && r.step && d.find("at_complete") != std::string::npos, (r.str() + " / " + d).c_str());
    }
    // …with fresh evidence read now → consumed with the +evidence signal
    sd3.evidence("RFID", "obj-1", 0.99, t3 + 130); ad3.evidence("RFID", "obj-1", 0.99, t3 + 130);
    {
      const Lite r = both("K5", sd3.complete(t3 + 131, "place"), ad3.complete(t3 + 131, "place"));
      // PAIL-CASE: two_doors_complete_with_evidence_consumes
      ROW("two_doors_complete_with_evidence_consumes", r.state == "PERMIT" && r.fired && r.report && !r.step, r.str().c_str());
    }
    // ---- SK-5 : a v5 token's row feeds — evidence_claim binds the permit ----
    {
      // control: the twist row feeds on safety only — no evidence, still PERMIT (v5, by name)
      const auto tokT = m.response("tok-6", "chain-6", t0, 30000, 5.0, false, kClassMove, "twist");
      sd3.token(true, tokT); ad3.token(true, tokT);
      sd3.safety("OK", t3 + 4000); ad3.safety("OK", t3 + 4000);
      const Lite c = both("K6", sd3.command(0.1, 0.0, t3 + 4010, kClassMove, "twist"), ad3.command(0.1, 0.0, t3 + 4010, kClassMove, "twist"));
      // PAIL-CASE: two_doors_feed_row_without_evidence_permits
      ROW("two_doors_feed_row_without_evidence_permits", c.state == "PERMIT" && c.permit, c.str().c_str());
      std::this_thread::sleep_for(std::chrono::milliseconds(5020));
      sd3.step(t3 + 9100); ad3.step(t3 + 9100);  // consume by deadline (5 s)
      // the inspect row feeds on evidence_claim: the K5 evidence (t3+130) is stale by now
      const auto tokI = m.response("tok-7", "chain-7", t0, 30000, 5.0, false, kClassMove, "inspect");
      sd3.token(true, tokI); ad3.token(true, tokI);
      sd3.safety("OK", t3 + 9200); ad3.safety("OK", t3 + 9200);
      const Lite r = both("K7", sd3.command(0.1, 0.0, t3 + 9210, kClassMove, "inspect"), ad3.command(0.1, 0.0, t3 + 9210, kClassMove, "inspect"));
      // PAIL-CASE: two_doors_feed_row_needs_fresh_evidence
      ROW("two_doors_feed_row_needs_fresh_evidence", r.state == "BLOCK" && r.reason == "ERR_NO_EVIDENCE" && r.report, r.str().c_str());
      sd3.evidence("RFID", "obj-9", 0.99, t3 + 9300); ad3.evidence("RFID", "obj-9", 0.99, t3 + 9300);
      const Lite r2 = both("K8", sd3.command(0.1, 0.0, t3 + 9310, kClassMove, "inspect"), ad3.command(0.1, 0.0, t3 + 9310, kClassMove, "inspect"));
      // PAIL-CASE: two_doors_feed_row_with_fresh_evidence_permits
      ROW("two_doors_feed_row_with_fresh_evidence_permits", r2.state == "PERMIT" && r2.permit, r2.str().c_str());
    }
    // no registry at all: every report is ignored with the reason
    {
      const std::string d = sd.s.CompleteStep(t3 + 200, "pick").decision.detail;
      // PAIL-CASE: two_doors_complete_without_registry_ignored
      ROW("two_doors_complete_without_registry_ignored", d.find("no skill registry") != std::string::npos || d.find("no active step") != std::string::npos, d.c_str());
    }
  }

  std::printf("%s: %d failure(s)\n", g_failures ? "RED" : "GREEN", g_failures);
  return g_failures ? 1 : 0;
}
