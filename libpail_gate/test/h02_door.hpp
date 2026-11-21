// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//
// SEC-H02 (issuer key revocation reaching a running gate) — shared test material and the
// one seam between the batteries and the product ("the door").
//
// Everything above the line marked DOOR is test material: a root key, bundle payloads, a
// token minter, the two decision doors (C++ session and C ABI, driven in lockstep as in
// test_gate_two_doors / test_fatal_latch). The DOOR section is the only code whose body
// differs before and after the fix; the batteries call nothing of the product's trust
// path except through it, so they compile on the unfixed tree and fail in their
// assertions, not in the build. (The DOOR below is the fixed tree's: ApplyPlaced reaches the
// product through GateSession::PollTrust and pail_gate_tick.)

#pragma once

#include <sodium.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "pail.pb.h"
#include "pail_gate_abi.pb.h"
#include "token_service.pb.h"

#include "pail_gate/gate_session.hpp"
#include "pail_gate/keyring_bundle.hpp"
#include "pail_gate/pail_gate.h"
#include "pail_gate/policy_load.hpp"
#include "pail_gate/strict_verify.hpp"
#include "pail_gate/wall_clock.hpp"

namespace h02 {

namespace abi = pail::gate::abi::v1;
using namespace pail_pep_gate;

inline int g_failures = 0;

#define H02_ROW(name, cond, detail)                                               \
  do {                                                                            \
    if (cond) {                                                                   \
      std::printf("PASS %s\n", name);                                             \
    } else {                                                                      \
      std::printf("FAIL %s — %s\n", name, std::string(detail).c_str());           \
      ++h02::g_failures;                                                          \
    }                                                                             \
  } while (0)

constexpr const char *kRobot = "robot-1";
constexpr const char *kK1 = "h02-issuer-1";
constexpr const char *kK2 = "h02-issuer-2";
constexpr const char *kO1 = "h02-operator-1";
const std::string kWorld(32, '\x5a');

inline bool has(const std::string &s, const std::string &needle) { return s.find(needle) != std::string::npos; }
inline bool starts(const std::string &s, const std::string &prefix) { return s.rfind(prefix, 0) == 0; }

inline std::string b64(const unsigned char *data, size_t len) {
  std::string out(sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL), '\0');
  sodium_bin2base64(&out[0], out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
  out.resize(std::strlen(out.c_str()));
  return out;
}

inline std::string readAll(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

inline bool exists(const std::string &path) { return ::access(path.c_str(), F_OK) == 0; }

inline void writeAll(const std::string &path, const std::string &content) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f << content;
}

struct KeyPair {
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  KeyPair() { crypto_sign_keypair(pk, sk); }
  std::string pub_b64() const { return b64(pk, sizeof pk); }
};

// One keyring entry of a payload. An empty role writes no "role" member at all (the
// role-less case of T06e / T13 — a signer other than pail-keyring-sign can produce it).
struct Entry {
  std::string key_id;
  std::string pub_b64;
  std::string role;
};

inline std::string entriesJSON(const std::vector<Entry> &es) {
  std::string s = "[";
  for (size_t i = 0; i < es.size(); ++i) {
    if (i) s += ",";
    s += "{\"key_id\":\"" + es[i].key_id + "\",\"ed25519_public_key_base64\":\"" + es[i].pub_b64 + "\"";
    if (!es[i].role.empty()) s += ",\"role\":\"" + es[i].role + "\"";
    s += "}";
  }
  return s + "]";
}

inline std::string payload(uint64_t version, long long expires_at, const std::vector<Entry> &keys,
                           const std::vector<Entry> &revoked = {}) {
  std::string s = "{\"bundle_version\":" + std::to_string(version) +
                  ",\"issued_at_unix\":" + std::to_string(static_cast<long long>(std::time(nullptr))) +
                  ",\"expires_at_unix\":" + std::to_string(expires_at) + ",\"keys\":" + entriesJSON(keys);
  if (!revoked.empty()) s += ",\"revoked_keys\":" + entriesJSON(revoked);
  return s + "}";
}

// Envelope over the exact payload bytes (same construction as Go BuildBundle and the
// helper of test_keyring_bundle.cpp).
inline std::string signBundle(const KeyPair &root, const std::string &p) {
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, nullptr, reinterpret_cast<const unsigned char *>(p.data()), p.size(), root.sk);
  return "{\"schema_version\":1,\"payload_b64\":\"" +
         b64(reinterpret_cast<const unsigned char *>(p.data()), p.size()) +
         "\",\"root_key_id\":\"h02-root\",\"root_sig_b64\":\"" + b64(sig, sizeof sig) + "\"}";
}

inline long long nowS() { return static_cast<long long>(std::time(nullptr)); }

// The trust directory of one case: a root, the three files a gate reads, and the keys the
// cases put into bundles.
struct Trust {
  std::string dir, bundle, state, root_pub;
  KeyPair root, k1, k2, o1;

  Trust() {
    char tmpl[] = "/tmp/h02trust.XXXXXX";
    char *d = mkdtemp(tmpl);
    dir = d ? d : "/tmp/h02trust.fallback";
    bundle = dir + "/keyring_bundle.json";
    state = dir + "/keyring_bundle.state.json";
    root_pub = dir + "/root_pub.b64";
    writeAll(root_pub, root.pub_b64() + "\n");
  }

  Entry e1(const std::string &role = "issuer") const { return {kK1, k1.pub_b64(), role}; }
  Entry e2(const std::string &role = "issuer") const { return {kK2, k2.pub_b64(), role}; }
  Entry eo() const { return {kO1, o1.pub_b64(), "operator"}; }

  // B1: version 1, K1 active. B2r: version 2, same material (a renewal).
  // B2x: version 2, K2 active and K1 revoked (a revocation).
  std::string B1(long long life_s, uint64_t version = 1) const {
    return signBundle(root, payload(version, nowS() + life_s, {e1(), eo()}));
  }
  std::string B2r(long long life_s) const { return signBundle(root, payload(2, nowS() + life_s, {e1(), eo()})); }
  std::string B2x(long long life_s) const {
    return signBundle(root, payload(2, nowS() + life_s, {e2(), eo()}, {e1()}));
  }

  // Atomic placement, the way the robot agent places a pulled bundle (write tmp, rename).
  void place(const std::string &bytes) const {
    const std::string tmp = bundle + ".tmp";
    writeAll(tmp, bytes);
    std::rename(tmp.c_str(), bundle.c_str());
  }

  // The explicit floor initialisation a production install performs (decision 3).
  void initFloor(uint64_t version) const { writeAll(state, "{\"last_version\": " + std::to_string(version) + "}\n"); }

  long long floor() const {
    if (!exists(state)) return -1;
    const std::string s = readAll(state);
    const auto pos = s.find("\"last_version\"");
    if (pos == std::string::npos) return -2;
    const auto colon = s.find(':', pos);
    if (colon == std::string::npos) return -2;
    return std::strtoll(s.c_str() + colon + 1, nullptr, 10);
  }

  // Points the process environment at this directory. profile: "production" | "dev".
  // max_lifetime: "" unsets PAIL_KEYRING_MAX_LIFETIME_SEC.
  void env(const char *profile, const char *max_lifetime = "86400") const {
    setenv("PAIL_KEYRING_MODE", "bundle", 1);
    setenv("PAIL_KEYRING_BUNDLE", bundle.c_str(), 1);
    setenv("PAIL_ROOT_PUBKEY_FILE", root_pub.c_str(), 1);
    setenv("PAIL_KEYRING_STATE", state.c_str(), 1);
    setenv("PAIL_PROFILE", profile, 1);
    if (max_lifetime[0] == '\0') unsetenv("PAIL_KEYRING_MAX_LIFETIME_SEC");
    else setenv("PAIL_KEYRING_MAX_LIFETIME_SEC", max_lifetime, 1);
  }
};

// A v4 MOVE token signed by one issuer key, valid for 60 s from now_ms. The step may run
// 20 s so that a held permit survives the few seconds an expiry case waits.
inline pail::token::v1::GetActiveTokenResponse mint(const KeyPair &key, const char *key_id,
                                                    const std::string &token_id, const std::string &chain_id,
                                                    int64_t now_ms) {
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
  t.mutable_constraints()->set_max_duration_sec(20.0);
  t.set_subgraph_snapshot_hash(kWorld);
  const std::string bytes = t.SerializeAsString();
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, nullptr, reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size(), key.sk);
  pail::token::v1::GetActiveTokenResponse r;
  r.set_status(pail::token::v1::OK);
  r.set_chain_id(chain_id);
  r.set_expected_sequence_index(1);
  r.set_current_subgraph_hash(kWorld);
  auto *st = r.mutable_token();
  st->mutable_token()->set_token_id(token_id);
  st->set_action_token_bytes(bytes);
  st->set_signature(std::string(reinterpret_cast<const char *>(sig), crypto_sign_BYTES));
  st->set_key_id(key_id);
  return r;
}

struct Lite {
  std::string path, state, reason, detail, chain, token;
  bool forward{false}, report{false}, fatal{false}, permit{false}, estop{false}, hold{false};
  bool same(const Lite &o) const {
    return path == o.path && state == o.state && reason == o.reason && chain == o.chain && token == o.token &&
           forward == o.forward && report == o.report && fatal == o.fatal && permit == o.permit &&
           estop == o.estop && hold == o.hold;
  }
  std::string str() const {
    return path + ":" + state + "/" + reason + " [" + detail + "] fwd=" + (forward ? "1" : "0") +
           " rep=" + (report ? "1" : "0") + " fatal=" + (fatal ? "1" : "0") + " permit=" + (permit ? "1" : "0") +
           " hold=" + (hold ? "1" : "0") + " chain=" + chain + " token=" + token;
  }
};

inline Lite lite(const SessionOutcome &s) {
  Lite l;
  l.path = s.path; l.state = s.decision.state; l.reason = s.decision.reason; l.detail = s.decision.detail;
  l.forward = s.decision.forward; l.report = s.decision.report; l.fatal = s.decision.fatal;
  l.permit = s.permit_active; l.estop = s.estop_active; l.hold = s.decision.hold_permit;
  l.chain = s.report_chain_id; l.token = s.report_token_id;
  return l;
}

inline Lite lite(const abi::Outcome &o) {
  Lite l;
  l.path = o.path(); l.state = o.state(); l.reason = o.reason(); l.detail = o.detail();
  l.forward = o.forward(); l.report = o.report(); l.fatal = o.fatal();
  l.permit = o.permit_active(); l.estop = o.estop_active(); l.hold = o.hold_permit();
  l.chain = o.report_chain_id(); l.token = o.report_token_id();
  return l;
}

struct Apply {
  bool applied{false};      // the placed bundle is now what the gate judges with
  std::string reason;       // why it was not applied (ERR_BUNDLE_* / ERR_KEYRING_*)
  uint64_t version{0};      // version in force after the call
  long long expires_at{0};  // expiry in force after the call
};

// The gate under test: one C++ session and one C ABI handle opened on the same trust
// directory and driven with the same inputs. A disagreement between the two is a failure
// of its own (an adapter built on the ABI must get what the ROS node gets).
class Gate {
 public:
  // ======================================= DOOR =========================================
  // Open: the trust path exactly as a gate starts (environment → LoadTrustedKeyring →
  // session; pail_gate_new for the ABI).
  static std::unique_ptr<Gate> Open(const Trust &t, const char *profile, const char *policy_path,
                                    std::string *reason, const char *max_lifetime = "86400") {
    t.env(profile, max_lifetime);
    auto g = std::unique_ptr<Gate>(new Gate());
    std::string mode;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, reason);
    SessionPolicy pol;
    std::string perr;
    if (!LoadSessionPolicy(policy_path, &pol, &perr)) {
      if (reason) *reason = "POLICY: " + perr;
      return nullptr;
    }
    SessionConfig cfg;
    cfg.robot_id = kRobot;
    cfg.permit_grace_n = 3;
    cfg.clock_skew_ms = 500;
    g->session_.reset(new GateSession(cfg, pol, kr));

    abi::Config c;
    c.set_robot_id(kRobot);
    c.set_policy_path(policy_path);
    c.set_keyring_path(t.dir + "/keyring.json");
    c.set_permit_grace_n(3);
    c.set_clock_skew_ms(500);
    const std::string b = c.SerializeAsString();
    char *e = nullptr;
    g->abi_ = pail_gate_new(reinterpret_cast<const uint8_t *>(b.data()), b.size(), &e);
    if (e) {
      g->abi_err_ = e;
      pail_gate_free_buf(e);
    }
    return g;
  }

  // ApplyPlaced: let the gate take up whatever is placed at the bundle path now.
  // The C ABI has no call of its own for this — an adapter's tick does it — so both doors
  // are ticked: the session door polls its trust and runs the step timer and the recheck
  // a tick runs, the ABI door gets pail_gate_tick. The result is the session's.
  Apply ApplyPlaced(int64_t now_ms) {
    const TrustApplyResult r = session_->PollTrust();
    session_->OnStepTimer(now_ms);
    session_->OnRecheck(now_ms);
    abi::TickInput ti; ti.set_now_ms(now_ms);
    const std::string b = ti.SerializeAsString();
    uint8_t *p = nullptr; size_t n = 0;
    pail_gate_tick(abi_, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    pail_gate_free_buf(p);
    Apply a;
    a.applied = r.outcome == TrustApply::Applied;
    a.reason = r.reason;
    a.version = r.version;
    a.expires_at = r.expires_at_unix;
    return a;
  }

  // The gate's loaded-trust record (what the status snapshot serves).
  std::string TrustJson() const { return session_->keyring().loaded_trust_json; }
  // ===================================== END DOOR =======================================

  ~Gate() { pail_gate_free(abi_); }
  bool abi_ok() const { return abi_ != nullptr; }
  const std::string &abi_err() const { return abi_err_; }

  // Fresh safety and evidence at now_ms, on both doors.
  void Fresh(int64_t now_ms) {
    SafetyObservation so; so.level = "OK"; so.source = "TEST"; so.observed_ms = now_ms;
    session_->ObserveSafety(so);
    EvidenceObservation ev; ev.source = "RFID"; ev.object_id = "obj-1"; ev.confidence = 0.99; ev.received_ms = now_ms;
    session_->ObserveEvidence(ev);

    abi::SafetyInput s; s.set_level("OK"); s.set_source("TEST"); s.set_observed_ms(now_ms);
    std::string b = s.SerializeAsString();
    uint8_t *p = nullptr; size_t n = 0;
    pail_gate_observe_safety(abi_, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    pail_gate_free_buf(p);
    abi::EvidenceInput e; e.set_source("RFID"); e.set_object_id("obj-1"); e.set_confidence(0.99); e.set_received_ms(now_ms);
    b = e.SerializeAsString();
    pail_gate_observe_evidence(abi_, reinterpret_cast<const uint8_t *>(b.data()), b.size());
  }

  void Token(const pail::token::v1::GetActiveTokenResponse &r) {
    ActiveTokenView v;
    v.ok = true; v.status = "OK"; v.chain_id = r.chain_id(); v.expected_sequence_index = r.expected_sequence_index();
    v.current_subgraph_hash = r.current_subgraph_hash();
    v.action_token_bytes = r.token().action_token_bytes(); v.signature_bytes = r.token().signature();
    v.key_id_bytes = r.token().key_id(); v.signed_token_bytes = r.token().SerializeAsString();
    pail::v1::ActionToken t;
    if (t.ParseFromString(v.action_token_bytes)) v.token_id = t.token_id();
    else { v.ok = false; v.status = "ERROR"; }
    session_->SetTokenView(v);

    abi::TokenInput ti; ti.set_reachable(true); *ti.mutable_response() = r;
    const std::string b = ti.SerializeAsString();
    pail_gate_set_token(abi_, reinterpret_cast<const uint8_t *>(b.data()), b.size());
  }

  Lite Command(const char *name, int64_t now_ms) {
    CommandRequest c; c.linear_norm = 0.1; c.angular_norm = 0.0; c.requested_class = kClassMove;
    const Lite a = lite(session_->OnCommand(c, now_ms));
    abi::CommandInput ci; ci.set_linear_norm(0.1); ci.set_angular_norm(0.0); ci.set_now_ms(now_ms);
    ci.set_requested_class(kClassMove);
    const std::string b = ci.SerializeAsString();
    uint8_t *p = nullptr; size_t n = 0;
    pail_gate_command(abi_, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    abi::Outcome o; o.ParseFromArray(p, static_cast<int>(n)); pail_gate_free_buf(p);
    return both(name, a, lite(o));
  }

  Lite Recheck(const char *name, int64_t now_ms) {
    const Lite a = lite(session_->OnRecheck(now_ms));
    abi::TickInput ti; ti.set_now_ms(now_ms);
    const std::string b = ti.SerializeAsString();
    uint8_t *p = nullptr; size_t n = 0;
    pail_gate_tick(abi_, reinterpret_cast<const uint8_t *>(b.data()), b.size(), &p, &n);
    abi::TickOutcome o; o.ParseFromArray(p, static_cast<int>(n)); pail_gate_free_buf(p);
    return both(name, a, lite(o.recheck()));
  }

  // Trust keys as the ABI reports them (keys, revoked_keys).
  void AbiCounts(uint32_t *keys, uint32_t *revoked) const {
    uint8_t *p = nullptr; size_t n = 0;
    pail_gate_info(abi_, &p, &n);
    abi::Info i; i.ParseFromArray(p, static_cast<int>(n)); pail_gate_free_buf(p);
    *keys = i.keys(); *revoked = i.revoked_keys();
  }
  size_t SessionKeys() const { return session_->keyring().pubkeys.size(); }
  size_t SessionRevoked() const { return session_->keyring().revoked.size(); }

 private:
  Gate() = default;
  static Lite both(const char *name, const Lite &a, const Lite &b) {
    if (!a.same(b)) {
      std::printf("FAIL %s — doors disagree: session[%s] abi[%s]\n", name, a.str().c_str(), b.str().c_str());
      ++g_failures;
    }
    return a;
  }
  std::unique_ptr<GateSession> session_;
  pail_gate_t *abi_{nullptr};
  std::string abi_err_;
};

// Sleeps until the wall clock is one second past a unix time.
inline void waitPast(long long expires_at) {
  while (nowS() <= expires_at) ::usleep(100 * 1000);
  ::usleep(1000 * 1000);
}

}  // namespace h02
