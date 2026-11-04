// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//
// P15-H1 (preview.15 evaluation, TB3 judge2 scene 8, 2026-10-16): a plan the gate
// stopped with ESTOP (safety UNSAFE) moved again on the SAME token after safety
// returned to OK, without an operator. The fatal report that revokes the chain at
// the issuer had been sent on one 50 ms RPC and its result discarded; the issuer
// kept the chain active, served the same token, and the gate granted it.
//
// This battery pins the session-side half of the fix — the local fatal latch:
// every fatal the session produces (ESTOP, fatal BLOCK) kills that chain and token
// in this session, and a view, verified token or held permit naming them is refused
// with ERR_REVOKED whatever the issuer answers. The node-side half (the report is
// retried until the issuer confirms it) is pinned by test_fatal_report_worker in
// pail_pep_gate. Both doors (C++ session, C ABI) are driven in lockstep, as in
// test_gate_two_doors, so an adapter built on the ABI gets the same latch.
//
// Fail-first: on the preview.15 runtime, S3 below is PERMIT (the defect).

#include <sodium.h>

#include <cstdio>
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
constexpr const char *kKeyId = "fatal-latch-key";
const std::string kWorld(32, '\x5a');
const std::string kWorldMoved(32, '\x5b');

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
  // A v4 MOVE token, valid for 60 s, with the issuer's current world hash as given.
  pail::token::v1::GetActiveTokenResponse response(const std::string &token_id, const std::string &chain_id,
                                                   int64_t now_ms, const std::string &current_world = kWorld) const {
    pail::v1::ActionToken t;
    t.set_token_id(token_id);
    t.set_chain_id(chain_id);
    t.set_sequence_index(1);
    t.set_robot_id(kRobot);
    t.set_plan_id("plan-" + chain_id);
    t.set_step_id("s1");
    t.set_issued_at_unix_ms(now_ms);
    t.set_not_before_unix_ms(now_ms - 1000);
    t.set_not_after_unix_ms(now_ms + 60000);
    t.set_action_type(static_cast<pail::v1::ActionType>(kClassMove));
    t.set_schema_version(4);
    t.mutable_constraints()->set_max_linear_speed_mps(0.5);
    t.mutable_constraints()->set_max_angular_speed_rps(1.0);
    t.mutable_constraints()->set_max_duration_sec(5.0);
    t.set_subgraph_snapshot_hash(kWorld);
    const std::string bytes = t.SerializeAsString();
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr, reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size(), sk);
    pail::token::v1::GetActiveTokenResponse r;
    r.set_status(pail::token::v1::OK);
    r.set_chain_id(chain_id);
    r.set_expected_sequence_index(1);
    r.set_current_subgraph_hash(current_world);
    auto *st = r.mutable_token();
    st->mutable_token()->set_token_id(token_id);
    st->set_action_token_bytes(bytes);
    st->set_signature(std::string(reinterpret_cast<const char *>(sig), crypto_sign_BYTES));
    st->set_key_id(kKeyId);
    return r;
  }
};

struct Lite {
  std::string path, state, reason, detail, chain, token;
  bool forward{false}, report{false}, fatal{false}, permit{false}, estop{false}, hold{false};
  bool same(const Lite &o) const {
    return path == o.path && state == o.state && reason == o.reason && detail == o.detail && chain == o.chain &&
           token == o.token && forward == o.forward && report == o.report && fatal == o.fatal &&
           permit == o.permit && estop == o.estop && hold == o.hold;
  }
  std::string str() const {
    return path + ":" + state + "/" + reason + " [" + detail + "] fwd=" + (forward ? "1" : "0") +
           " rep=" + (report ? "1" : "0") + " fatal=" + (fatal ? "1" : "0") + " permit=" + (permit ? "1" : "0") +
           " estop=" + (estop ? "1" : "0") + " hold=" + (hold ? "1" : "0") + " chain=" + chain + " token=" + token;
  }
};
Lite lite(const SessionOutcome &s) {
  Lite l;
  l.path = s.path; l.state = s.decision.state; l.reason = s.decision.reason; l.detail = s.decision.detail;
  l.forward = s.decision.forward; l.report = s.decision.report; l.fatal = s.decision.fatal;
  l.permit = s.permit_active; l.estop = s.estop_active; l.hold = s.decision.hold_permit;
  l.chain = s.report_chain_id; l.token = s.report_token_id;
  return l;
}
Lite lite(const abi::Outcome &o) {
  Lite l;
  l.path = o.path(); l.state = o.state(); l.reason = o.reason(); l.detail = o.detail();
  l.forward = o.forward(); l.report = o.report(); l.fatal = o.fatal();
  l.permit = o.permit_active(); l.estop = o.estop_active(); l.hold = o.hold_permit();
  l.chain = o.report_chain_id(); l.token = o.report_token_id();
  return l;
}

struct SessionDoor {
  GateSession s;
  SessionDoor(const SessionConfig &c, const SessionPolicy &p, const Keyring &k) : s(c, p, k) {}
  void token(const pail::token::v1::GetActiveTokenResponse &r) {
    ActiveTokenView v;
    v.ok = true; v.status = "OK"; v.chain_id = r.chain_id(); v.expected_sequence_index = r.expected_sequence_index();
    v.current_subgraph_hash = r.current_subgraph_hash();
    v.action_token_bytes = r.token().action_token_bytes(); v.signature_bytes = r.token().signature();
    v.key_id_bytes = r.token().key_id(); v.signed_token_bytes = r.token().SerializeAsString();
    pail::v1::ActionToken t;
    if (t.ParseFromString(v.action_token_bytes)) v.token_id = t.token_id(); else { v.ok = false; v.status = "ERROR"; }
    s.SetTokenView(v);
  }
  Lite safety(const std::string &level, int64_t now) { SafetyObservation o; o.level = level; o.source = "TEST"; o.observed_ms = now; return lite(s.ObserveSafety(o)); }
  void evidence(int64_t now) { EvidenceObservation e; e.source = "RFID"; e.object_id = "obj-1"; e.confidence = 0.99; e.received_ms = now; s.ObserveEvidence(e); }
  Lite command(int64_t now) { CommandRequest c; c.linear_norm = 0.1; c.angular_norm = 0.0; c.requested_class = kClassMove; return lite(s.OnCommand(c, now)); }
  Lite recheck(int64_t now) { return lite(s.OnRecheck(now)); }
};

struct AbiDoor {
  pail_gate_t *h{nullptr};
  std::string err;
  AbiDoor(const std::string &policy_path, const std::string &keyring_path) {
    abi::Config c; c.set_robot_id(kRobot); c.set_policy_path(policy_path); c.set_keyring_path(keyring_path);
    c.set_permit_grace_n(3); c.set_clock_skew_ms(500);
    const std::string b = c.SerializeAsString();
    char *e = nullptr;
    h = pail_gate_new(reinterpret_cast<const uint8_t *>(b.data()), b.size(), &e);
    if (e) { err = e; pail_gate_free_buf(e); }
  }
  ~AbiDoor() { pail_gate_free(h); }
  template <class M> static std::string bytes(const M &m) { return m.SerializeAsString(); }
  static abi::Outcome parse(uint8_t *p, size_t n) { abi::Outcome o; o.ParseFromArray(p, static_cast<int>(n)); pail_gate_free_buf(p); return o; }
  void token(const pail::token::v1::GetActiveTokenResponse &r) {
    abi::TokenInput t; t.set_reachable(true); *t.mutable_response() = r; const auto b = bytes(t);
    pail_gate_set_token(h, reinterpret_cast<const uint8_t *>(b.data()), b.size());
  }
  Lite safety(const std::string &level, int64_t now) {
    abi::SafetyInput s; s.set_level(level); s.set_source("TEST"); s.set_observed_ms(now); const auto b = bytes(s);
    uint8_t *p = nullptr; size_t n = 0; pail_gate_observe_safety(h, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    return lite(parse(p, n));
  }
  void evidence(int64_t now) {
    abi::EvidenceInput e; e.set_source("RFID"); e.set_object_id("obj-1"); e.set_confidence(0.99); e.set_received_ms(now); const auto b = bytes(e);
    pail_gate_observe_evidence(h, reinterpret_cast<const uint8_t *>(b.data()), b.size());
  }
  Lite command(int64_t now) {
    abi::CommandInput c; c.set_linear_norm(0.1); c.set_angular_norm(0.0); c.set_now_ms(now); c.set_requested_class(kClassMove); const auto b = bytes(c);
    uint8_t *p = nullptr; size_t n = 0; pail_gate_command(h, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    return lite(parse(p, n));
  }
  Lite recheck(int64_t now) {
    abi::TickInput t; t.set_now_ms(now); const auto b = bytes(t);
    uint8_t *p = nullptr; size_t n = 0; pail_gate_tick(h, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    abi::TickOutcome o; o.ParseFromArray(p, static_cast<int>(n)); pail_gate_free_buf(p); return lite(o.recheck());
  }
};

Lite both(const char *name, const Lite &a, const Lite &b) {
  if (!a.same(b)) {
    std::printf("FAIL %s — doors disagree: session[%s] abi[%s]\n", name, a.str().c_str(), b.str().c_str());
    ++g_failures;
  }
  return a;
}

std::string write_temp(const std::string &name, const std::string &content) {
  const std::string path = std::string("/tmp/pail_fatal_latch_") + name;
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f << content;
  return path;
}

bool has(const std::string &s, const char *needle) { return s.find(needle) != std::string::npos; }
}  // namespace

int main() {
  if (sodium_init() < 0) { std::printf("FAIL sodium_init\n"); return 2; }
  SessionPolicy pol;
  std::string perr;
  if (!LoadSessionPolicy(PAIL_TB7_POLICY_FIXTURE, &pol, &perr)) { std::printf("FAIL policy: %s\n", perr.c_str()); return 2; }
  Minter m;
  const std::string keyring_path = write_temp("keyring.json", m.keyring_json());
  setenv("PAIL_KEYRING_MODE", "unsigned-dev", 1);
  SessionConfig cfg; cfg.robot_id = kRobot; cfg.permit_grace_n = 3; cfg.clock_skew_ms = 500;
  SessionDoor sd(cfg, pol, m.keyring());
  AbiDoor ad(PAIL_TB7_POLICY_FIXTURE, keyring_path);
  ROW("fatal_latch_abi_new", ad.h != nullptr, ad.err.c_str());
  if (!ad.h) return 1;

  int64_t t = WallNowMs();
  const auto tok1 = m.response("tok-1", "chain-1", t);

  // ---- S1: the plan is granted (judge2 scene 8 at 10:19:03.672: gate PERMIT OK token 249495ac) ----
  sd.safety("OK", t); ad.safety("OK", t);
  sd.evidence(t); ad.evidence(t);
  sd.token(tok1); ad.token(tok1);
  {
    const Lite r = both("S1", sd.command(t + 10), ad.command(t + 10));
    // PAIL-CASE: fatal_latch_permit_baseline
    ROW("fatal_latch_permit_baseline", r.state == "PERMIT" && r.forward && r.permit && r.chain == "chain-1" && r.token == "tok-1", r.str().c_str());
  }

  // ---- S2: safety UNSAFE → ESTOP, fatal report against chain-1/tok-1 (10:19:04.882) ----
  {
    const Lite r = both("S2", sd.safety("UNSAFE", t + 100), ad.safety("UNSAFE", t + 100));
    // PAIL-CASE: fatal_latch_estop_reports_fatal
    ROW("fatal_latch_estop_reports_fatal", r.state == "ESTOP" && r.report && r.fatal && r.chain == "chain-1" && r.token == "tok-1" && !r.permit, r.str().c_str());
    ROW("fatal_latch_session_latched", sd.s.fatal_latched("chain-1", "") && sd.s.fatal_latched("", "tok-1") && sd.s.fatal_latch_size() == 2,
        std::to_string(sd.s.fatal_latch_size()).c_str());
  }

  // ---- S3: safety returns to OK; the issuer never heard the fatal and still serves tok-1 ----
  //      (10:19:08.490 inputs safety=OK → 10:19:08.565 gate PERMIT OK token 249495ac — the defect)
  {
    const Lite rel = both("S3-release", sd.safety("OK", t + 4000), ad.safety("OK", t + 4000));
    ROW("fatal_latch_estop_released", !rel.estop, rel.str().c_str());
    sd.evidence(t + 4000); ad.evidence(t + 4000);
    sd.token(tok1); ad.token(tok1);  // the same answer the issuer gave before, unrevoked
    const Lite r = both("S3", sd.command(t + 4010), ad.command(t + 4010));
    // PAIL-CASE: fatal_latch_refuses_resumed_token
    ROW("fatal_latch_refuses_resumed_token",
        r.state == "BLOCK" && !r.forward && !r.permit && r.reason == "ERR_REVOKED" && has(r.detail, "fatal_latched chain:chain-1") && !r.report,
        r.str().c_str());
    // Repeated commands stay refused (the judge counted 22 drives after OK).
    const Lite r2 = both("S3b", sd.command(t + 4100), ad.command(t + 4100));
    ROW("fatal_latch_refusal_is_stable", r2.state == "BLOCK" && r2.reason == "ERR_REVOKED", r2.str().c_str());
  }

  // ---- S4: a NEW plan (new chain, new token) is not latched → PERMIT ----
  // (tokens are minted at the wall clock `t`: strict verification checks the validity
  //  window against the wall clock, the scenario offsets below are judgment-time only)
  const auto tok2 = m.response("tok-2", "chain-2", t);
  sd.safety("OK", t + 5000); ad.safety("OK", t + 5000);
  sd.evidence(t + 5000); ad.evidence(t + 5000);
  sd.token(tok2); ad.token(tok2);
  {
    const Lite r = both("S4", sd.command(t + 5010), ad.command(t + 5010));
    // PAIL-CASE: fatal_latch_new_chain_permits
    ROW("fatal_latch_new_chain_permits", r.state == "PERMIT" && r.forward && r.permit && r.chain == "chain-2", r.str().c_str());
  }

  // ---- S5: a fatal BLOCK (ERR_WORLD_CHANGED on recheck) latches too; the world moving back does not revive it ----
  {
    const auto moved = m.response("tok-2", "chain-2", t, kWorldMoved);
    sd.token(moved); ad.token(moved);
    const Lite r = both("S5-recheck", sd.recheck(t + 5100), ad.recheck(t + 5100));
    // PAIL-CASE: fatal_latch_world_changed_is_fatal
    ROW("fatal_latch_world_changed_is_fatal", r.state == "BLOCK" && r.reason == "ERR_WORLD_CHANGED" && r.report && r.fatal && !r.permit, r.str().c_str());
    sd.token(tok2); ad.token(tok2);  // the issuer's world hash matches again, same token
    sd.evidence(t + 5200); ad.evidence(t + 5200);
    const Lite r2 = both("S5-command", sd.command(t + 5210), ad.command(t + 5210));
    // PAIL-CASE: fatal_latch_world_changed_latches
    ROW("fatal_latch_world_changed_latches", r2.state == "BLOCK" && r2.reason == "ERR_REVOKED" && has(r2.detail, "chain:chain-2"), r2.str().c_str());
  }

  // ---- S6: the caller may latch an identity it learned after the stop (E-STOP with no live permit) ----
  {
    sd.s.LatchFatal("chain-3", "tok-3");
    const auto tok3 = m.response("tok-3", "chain-3", t);
    sd.evidence(t + 6000);
    sd.token(tok3);
    const Lite r = lite(sd.s.OnCommand(CommandRequest{}, t + 6010));
    // PAIL-CASE: fatal_latch_caller_latch
    ROW("fatal_latch_caller_latch", r.state == "BLOCK" && r.reason == "ERR_REVOKED" && has(r.detail, "chain:chain-3"), r.str().c_str());
    sd.s.LatchFatal("", "");  // empty ids are ignored
    ROW("fatal_latch_empty_ignored", !sd.s.fatal_latched("", ""), std::to_string(sd.s.fatal_latch_size()).c_str());
  }

  // ---- S7: the latch is bounded and rolls over oldest-first ----
  {
    GateSession s(cfg, pol, m.keyring());
    for (int i = 0; i < 70; ++i) s.LatchFatal("c-" + std::to_string(i), "t-" + std::to_string(i));
    // PAIL-CASE: fatal_latch_bounded
    ROW("fatal_latch_bounded", s.fatal_latch_size() == 128 && !s.fatal_latched("c-0", "") && !s.fatal_latched("c-5", "") &&
                                   s.fatal_latched("c-6", "") && s.fatal_latched("c-69", "") && s.fatal_latched("", "t-69"),
        std::to_string(s.fatal_latch_size()).c_str());
  }

  // ---- S8 (P18-H1, preview.18 evaluation E-wb4.0): E-STOP while the gate holds NO live permit
  //      because the issuer is unreachable. The pushed view is empty; before the fix the ESTOP
  //      reported empty ids, latched nothing, and the same token was permitted again after OK. ----
  {
    SessionDoor s8(cfg, pol, m.keyring());
    AbiDoor a8(PAIL_TB7_POLICY_FIXTURE, keyring_path);
    const int64_t t8 = WallNowMs();
    const auto tok8 = m.response("tok-8", "chain-8", t8);
    s8.safety("OK", t8); a8.safety("OK", t8);
    s8.evidence(t8); a8.evidence(t8);
    s8.token(tok8); a8.token(tok8);
    const Lite p = both("S8-permit", s8.command(t8 + 10), a8.command(t8 + 10));
    ROW("p18h1_permit_baseline", p.state == "PERMIT" && p.permit && p.chain == "chain-8", p.str().c_str());
    // The issuer goes away: three unreachable rechecks exhaust the grace (permit_grace_n = 3).
    {
      ActiveTokenView down; down.ok = false; down.status = "UNREACHABLE";
      s8.s.SetTokenView(down);
      abi::TokenInput ti; ti.set_reachable(false); const auto b = AbiDoor::bytes(ti);
      pail_gate_set_token(a8.h, reinterpret_cast<const uint8_t *>(b.data()), b.size());
    }
    Lite r;
    for (int i = 1; i <= 3; ++i) r = both("S8-recheck", s8.recheck(t8 + 200 * i), a8.recheck(t8 + 200 * i));
    // PAIL-CASE: p18h1_unreachable_blocks_without_permit
    ROW("p18h1_unreachable_blocks_without_permit", r.state == "BLOCK" && r.reason == "ERR_ISSUER_UNREACHABLE" && !r.permit, r.str().c_str());
    // E-STOP now: no live permit, empty view. The report must still name chain-8 / tok-8.
    const Lite e = both("S8-estop", s8.safety("UNSAFE", t8 + 700), a8.safety("UNSAFE", t8 + 700));
    // PAIL-CASE: p18h1_estop_without_permit_names_the_running_chain
    ROW("p18h1_estop_without_permit_names_the_running_chain",
        e.state == "ESTOP" && e.report && e.fatal && e.chain == "chain-8" && e.token == "tok-8", e.str().c_str());
    ROW("p18h1_estop_without_permit_latches", s8.s.fatal_latched("chain-8", "") && s8.s.fatal_latched("", "tok-8"),
        std::to_string(s8.s.fatal_latch_size()).c_str());
    // Safety OK, the issuer is back and still serves tok-8 (its revocation report may not have landed).
    s8.safety("OK", t8 + 1500); a8.safety("OK", t8 + 1500);
    s8.evidence(t8 + 1500); a8.evidence(t8 + 1500);
    s8.token(tok8); a8.token(tok8);
    const Lite back = both("S8-resume", s8.command(t8 + 1510), a8.command(t8 + 1510));
    // PAIL-CASE: p18h1_interrupted_chain_refused_after_outage
    ROW("p18h1_interrupted_chain_refused_after_outage",
        back.state == "BLOCK" && !back.forward && back.reason == "ERR_REVOKED" && has(back.detail, "fatal_latched chain:chain-8"), back.str().c_str());
    // A new plan is not affected.
    const auto tok9 = m.response("tok-9", "chain-9", t8);
    s8.evidence(t8 + 2000); a8.evidence(t8 + 2000);
    s8.token(tok9); a8.token(tok9);
    const Lite fresh = both("S8-new", s8.command(t8 + 2010), a8.command(t8 + 2010));
    ROW("p18h1_new_chain_permits_after_outage", fresh.state == "PERMIT" && fresh.chain == "chain-9", fresh.str().c_str());
  }

  // ---- S9 (P18-H1): a session that never saw a token or a permit still has nothing to name
  //      (the robot-wide revocation is then the issuer's and the agent's job). ----
  {
    SessionDoor s9(cfg, pol, m.keyring());
    const int64_t t9 = WallNowMs();
    s9.safety("OK", t9);
    const Lite e = s9.safety("UNSAFE", t9 + 10);
    // PAIL-CASE: p18h1_estop_with_nothing_known_names_nothing
    ROW("p18h1_estop_with_nothing_known_names_nothing", e.state == "ESTOP" && e.chain.empty() && e.token.empty() && s9.s.fatal_latch_size() == 0,
        e.str().c_str());
  }

  std::printf("%s (%d failure%s)\n", g_failures == 0 ? "ALL PASS" : "FAILURES", g_failures, g_failures == 1 ? "" : "s");
  return g_failures == 0 ? 0 : 1;
}
