// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//
// SEC-H02 — issuer key revocation reaching a running gate (test LLD §3.2).
//
// What these rows pin:
//   R1  a running gate refuses once the bundle it loaded has expired (T03, T04, T06f)
//   R2  a higher-version valid bundle placed beside a running gate is applied without a
//       restart; a candidate that fails any load check changes nothing (T05, T06, T07)
//   R3  a key the applied bundle revokes is refused from the next judgement on, and a
//       permit held on its token ends at the next recheck (T08)
//   R5  an expired gate verifies again after a valid bundle is applied (T09)
//   R6  production does not read a missing state file as a first load (T10, T11)
//   R7  a role-less entry is no issuer key, an undeclared lifetime ceiling is refused in
//       production (T13, T14)
//   R10 what must stay: load refusals, revoked-key verdict, dev profile (T01, T02, T12)
//
// Expiry rows wait in real time on 3 s bundles: token validity and the gate's drift guard
// read the wall clock themselves, so a caller-supplied time is not a way to "advance" it —
// and T04 pins exactly that a caller-supplied past time does not revive an expired bundle.
//
// `--interop <dir>` (T11f): loads <dir>/keyring_bundle.json under the production profile
// with the state file a Go initialisation wrote at <dir>/keyring_bundle.state.json.

#include "h02_door.hpp"

using namespace h02;

namespace {

const char *kPolicy = PAIL_H02_POLICY_FIXTURE;

std::unique_ptr<Gate> openOrFail(const char *row, const Trust &t, const char *profile = "production") {
  std::string reason;
  auto g = Gate::Open(t, profile, kPolicy, &reason);
  if (!g || !g->abi_ok() || !reason.empty()) {
    std::printf("FAIL %s — open: reason=%s abi=%s\n", row, reason.c_str(), g ? g->abi_err().c_str() : "(no gate)");
    ++g_failures;
    return nullptr;
  }
  return g;
}

int g_seq = 0;
// A fresh, never-used token of one issuer key on a chain of its own.
pail::token::v1::GetActiveTokenResponse tok(const KeyPair &key, const char *key_id, int64_t now_ms) {
  const std::string n = std::to_string(++g_seq);
  return mint(key, key_id, "tok-" + n, "chain-" + n, now_ms);
}

// Presents a fresh token of `key` and commands once.
Lite command(Gate &g, const char *row, const KeyPair &key, const char *key_id) {
  const int64_t now = WallNowMs();
  g.Fresh(now);
  g.Token(tok(key, key_id, now));
  return g.Command(row, now + 10);
}

// ---- T01 (R10): the revoked-key verdict after an ordinary load --------------------------
void t01() {
  Trust t;
  t.initFloor(1);
  t.place(t.B2x(3600));
  auto g = openOrFail("T01_open", t);
  if (!g) return;
  const Lite a = command(*g, "T01_k2", t.k2, kK2);
  H02_ROW("T01_active_key_permits", a.state == "PERMIT" && a.forward, a.str());
  const Lite b = command(*g, "T01_k1", t.k1, kK1);
  H02_ROW("T01_revoked_key_refused", b.state == "BLOCK" && !b.forward && b.reason == "ERR_REVOKED_KEY_ID", b.str());
}

// ---- T02 (R10): the load refusals that must stay ----------------------------------------
void t02() {
  {
    Trust t; t.initFloor(1);
    KeyPair other;
    t.place(signBundle(other, payload(1, nowS() + 3600, {t.e1(), t.eo()})));
    t.env("production");
    std::string mode, reason;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
    H02_ROW("T02_forged_signature", reason == "ERR_BUNDLE_SIG" && kr.pubkeys.empty(), reason);
  }
  {
    Trust t; t.initFloor(1);
    t.place(signBundle(t.root, payload(1, nowS() - 10, {t.e1(), t.eo()})));
    t.env("production");
    std::string mode, reason;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
    H02_ROW("T02_expired", reason == "ERR_BUNDLE_EXPIRED" && kr.pubkeys.empty(), reason);
  }
  {
    Trust t; t.initFloor(5);
    t.place(t.B1(3600, 4));
    t.env("production");
    std::string mode, reason;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
    H02_ROW("T02_rollback", reason == "ERR_BUNDLE_ROLLBACK" && kr.pubkeys.empty(), reason);
  }
  {
    Trust t; t.initFloor(1);
    t.place(t.B1(2 * 86400));
    t.env("production");
    std::string mode, reason;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
    H02_ROW("T02_lifetime_ceiling", reason == "ERR_BUNDLE_LIFETIME" && kr.pubkeys.empty(), reason);
  }
}

// ---- T03 / T04 (R1): a running gate honours the expiry of the bundle it loaded ----------
void t03_t04() {
  Trust t;
  t.initFloor(1);
  const long long expires = nowS() + 3;
  t.place(signBundle(t.root, payload(1, expires, {t.e1(), t.eo()})));
  auto g = openOrFail("T03_open", t);
  if (!g) return;

  int64_t now = WallNowMs();
  g->Fresh(now);
  g->Token(tok(t.k1, kK1, now));
  const Lite pre = g->Command("T03_pre", now + 10);
  // Precondition from evidence: the same key and bundle permit before the expiry.
  H02_ROW("T03_precondition_permit_before_expiry", pre.state == "PERMIT" && pre.forward && pre.permit, pre.str());
  const Lite held = g->Recheck("T03_pre_recheck", WallNowMs());
  H02_ROW("T03_precondition_permit_held", held.permit, held.str());

  waitPast(expires);

  now = WallNowMs();
  g->Fresh(now);
  const Lite rc = g->Recheck("T03_recheck", now);
  H02_ROW("T03_held_permit_ends_at_expiry", !rc.permit && !rc.hold, rc.str());
  const Lite c = command(*g, "T03_command", t.k1, kK1);
  H02_ROW("T03_command_refused_after_expiry", c.state == "BLOCK" && !c.forward, c.str());
  H02_ROW("T03_reason_names_the_bundle", c.reason == "ERR_BUNDLE_EXPIRED", c.str());
  H02_ROW("T03_reason_is_not_token_expiry", c.reason != "ERR_EXPIRED", c.str());
  // P024T-L1 (0.2.4 test candidate): the refusals of an expired bundle reached nobody but the
  // gate's own log — 157 of them in one run, none in the Issuer's decision record, so the
  // audit trail ended at the last PERMIT and said nothing about why the robot stopped. The
  // refusal is reported, with the token it refused; and it is NOT fatal: a renewal has to be
  // able to bring the same session back (T09).
  H02_ROW("T03_expiry_refusal_is_reported", c.report && !c.chain.empty() && !c.token.empty(), c.str());
  H02_ROW("T03_expiry_ends_the_hold_with_a_report", rc.report && rc.reason == "ERR_BUNDLE_EXPIRED", rc.str());
  H02_ROW("T03_expiry_refusal_is_not_fatal", !c.fatal && !rc.fatal, c.str() + " | " + rc.str());

  // T04: a caller-supplied time before the expiry must not revive the bundle (an adapter
  // hands now_ms to the C ABI; a stale or rewound value is not a way around the expiry).
  const int64_t past = WallNowMs() - 10000;
  g->Fresh(past);
  g->Token(tok(t.k1, kK1, WallNowMs()));
  const Lite r = g->Command("T04_command", past);
  H02_ROW("T04_past_now_does_not_revive", !r.forward && r.state != "PERMIT", r.str());
}

// ---- T05 (R2): a renewal is applied without a restart -----------------------------------
void t05() {
  Trust t;
  t.initFloor(1);
  t.place(t.B1(3600));
  auto g = openOrFail("T05_open", t);
  if (!g) return;
  const Lite pre = command(*g, "T05_pre", t.k1, kK1);
  H02_ROW("T05_precondition_permit", pre.state == "PERMIT" && pre.forward, pre.str());

  const long long new_expiry = nowS() + 7200;
  t.place(signBundle(t.root, payload(2, new_expiry, {t.e1(), t.eo()})));
  const Apply a = g->ApplyPlaced(WallNowMs());
  H02_ROW("T05_applied", a.applied && a.version == 2 && a.expires_at == new_expiry,
          "applied=" + std::to_string(a.applied) + " reason=" + a.reason + " version=" + std::to_string(a.version));
  const std::string tj = g->TrustJson();
  H02_ROW("T05_trust_record_follows", has(tj, "\"bundle_version\":2") && has(tj, "\"expires_at_unix\":" + std::to_string(new_expiry)), tj);
  H02_ROW("T05_floor_advanced", t.floor() == 2, std::to_string(t.floor()));
  const Lite post = command(*g, "T05_post", t.k1, kK1);
  H02_ROW("T05_same_key_still_permits", post.state == "PERMIT" && post.forward, post.str());
}

// ---- T06a–e (R2): a candidate that fails a load check changes nothing ---------------------
void t06_one(const char *id, const char *want_prefix, uint64_t open_version,
             std::string (*make)(const Trust &)) {
  Trust t;
  t.initFloor(open_version);
  t.place(t.B1(3600, open_version));
  const std::string row = std::string("T06") + id;
  auto g = openOrFail((row + "_open").c_str(), t);
  if (!g) return;
  const std::string before = g->TrustJson();
  const long long floor_before = t.floor();

  t.place(make(t));
  const Apply a = g->ApplyPlaced(WallNowMs());
  H02_ROW((row + "_not_applied").c_str(), !a.applied, "applied");
  H02_ROW((row + "_reason").c_str(), starts(a.reason, want_prefix), "reason=" + a.reason + " want prefix " + want_prefix);
  H02_ROW((row + "_trust_record_unchanged").c_str(), g->TrustJson() == before, g->TrustJson());
  H02_ROW((row + "_floor_unchanged").c_str(), t.floor() == floor_before, std::to_string(t.floor()));
  const Lite c = command(*g, (row + "_command").c_str(), t.k1, kK1);
  H02_ROW((row + "_old_key_still_permits").c_str(), c.state == "PERMIT" && c.forward, c.str());
}

std::string candForged(const Trust &t) {
  KeyPair other;
  return signBundle(other, payload(2, nowS() + 3600, {t.e2(), t.eo()}, {t.e1()}));
}
std::string candExpired(const Trust &t) { return signBundle(t.root, payload(2, nowS() - 10, {t.e2(), t.eo()}, {t.e1()})); }
std::string candLower(const Trust &t) { return signBundle(t.root, payload(4, nowS() + 3600, {t.e2(), t.eo()}, {t.e1()})); }
std::string candTooLong(const Trust &t) { return signBundle(t.root, payload(2, nowS() + 2 * 86400, {t.e2(), t.eo()}, {t.e1()})); }
std::string candRoleless(const Trust &t) { return signBundle(t.root, payload(2, nowS() + 3600, {t.e2(""), t.eo()}, {t.e1()})); }

void t06() {
  t06_one("a", "ERR_BUNDLE_SIG", 1, candForged);
  t06_one("b", "ERR_BUNDLE_EXPIRED", 1, candExpired);
  t06_one("c", "ERR_BUNDLE_ROLLBACK", 5, candLower);
  t06_one("d", "ERR_BUNDLE_LIFETIME", 1, candTooLong);
  t06_one("e", "ERR_KEYRING_ENTRY", 1, candRoleless);
}

// ---- T06f (R1 + R2): a failed application does not extend the life of the bundle in use --
void t06f() {
  Trust t;
  t.initFloor(1);
  const long long expires = nowS() + 3;
  t.place(signBundle(t.root, payload(1, expires, {t.e1(), t.eo()})));
  auto g = openOrFail("T06f_open", t);
  if (!g) return;
  const Lite pre = command(*g, "T06f_pre", t.k1, kK1);
  H02_ROW("T06f_precondition_permit", pre.state == "PERMIT" && pre.forward, pre.str());
  t.place(candForged(t));
  const Apply a = g->ApplyPlaced(WallNowMs());
  H02_ROW("T06f_forged_not_applied", !a.applied, "applied");
  waitPast(expires);
  const Lite c = command(*g, "T06f_command", t.k1, kK1);
  H02_ROW("T06f_old_expiry_still_binds", c.state == "BLOCK" && !c.forward && c.reason == "ERR_BUNDLE_EXPIRED", c.str());
}

// ---- T07 (R2): the same version is not applied -------------------------------------------
void t07() {
  Trust t;
  t.initFloor(1);
  const std::string b1 = t.B1(3600);
  t.place(b1);
  auto g = openOrFail("T07_open", t);
  if (!g) return;
  const std::string before = g->TrustJson();

  t.place(b1);
  Apply a = g->ApplyPlaced(WallNowMs());
  H02_ROW("T07_same_bytes_no_change", !a.applied && g->TrustJson() == before && t.floor() == 1,
          "applied=" + std::to_string(a.applied) + " floor=" + std::to_string(t.floor()));

  // Same version, different content (K2 instead of K1): still not applied.
  t.place(signBundle(t.root, payload(1, nowS() + 3600, {t.e2(), t.eo()})));
  a = g->ApplyPlaced(WallNowMs());
  H02_ROW("T07_same_version_other_content_no_change", !a.applied && g->TrustJson() == before && t.floor() == 1,
          "applied=" + std::to_string(a.applied) + " floor=" + std::to_string(t.floor()));
  const Lite c = command(*g, "T07_command", t.k1, kK1);
  H02_ROW("T07_old_key_still_permits", c.state == "PERMIT" && c.forward, c.str());
}

// ---- T08 (R3): the applied bundle revokes the key a permit is held on -------------------
void t08() {
  Trust t;
  t.initFloor(1);
  t.place(t.B1(3600));
  auto g = openOrFail("T08_open", t);
  if (!g) return;

  int64_t now = WallNowMs();
  g->Fresh(now);
  g->Token(tok(t.k1, kK1, now));
  const Lite pre = g->Command("T08_pre", now + 10);
  H02_ROW("T08_precondition_permit", pre.state == "PERMIT" && pre.forward && pre.permit, pre.str());
  const Lite held = g->Recheck("T08_pre_recheck", WallNowMs());
  H02_ROW("T08_precondition_permit_held", held.permit, held.str());

  t.place(t.B2x(3600));
  const Apply a = g->ApplyPlaced(WallNowMs());
  H02_ROW("T08_applied", a.applied && a.version == 2, "applied=" + std::to_string(a.applied) + " reason=" + a.reason);
  uint32_t keys = 0, revoked = 0;
  g->AbiCounts(&keys, &revoked);
  H02_ROW("T08_both_doors_hold_the_new_keys",
          g->SessionKeys() == 1 && g->SessionRevoked() == 1 && keys == 1 && revoked == 1,
          "session " + std::to_string(g->SessionKeys()) + "/" + std::to_string(g->SessionRevoked()) +
              " abi " + std::to_string(keys) + "/" + std::to_string(revoked));

  now = WallNowMs();
  g->Fresh(now);
  const Lite rc = g->Recheck("T08_recheck", now);
  H02_ROW("T08_held_permit_ends", !rc.permit && !rc.hold, rc.str());
  const Lite k1 = command(*g, "T08_k1", t.k1, kK1);
  H02_ROW("T08_revoked_key_refused", k1.state == "BLOCK" && !k1.forward && k1.reason == "ERR_REVOKED_KEY_ID", k1.str());
  const Lite k2 = command(*g, "T08_k2", t.k2, kK2);
  H02_ROW("T08_new_key_permits", k2.state == "PERMIT" && k2.forward, k2.str());
}

// ---- T09 (R5): an expired gate verifies again after a valid bundle is applied -----------
void t09() {
  Trust t;
  t.initFloor(1);
  const long long expires = nowS() + 3;
  t.place(signBundle(t.root, payload(1, expires, {t.e1(), t.eo()})));
  auto g = openOrFail("T09_open", t);
  if (!g) return;
  waitPast(expires);
  const Lite stopped = command(*g, "T09_stopped", t.k1, kK1);
  H02_ROW("T09_precondition_stopped_at_expiry", stopped.state == "BLOCK" && stopped.reason == "ERR_BUNDLE_EXPIRED", stopped.str());

  t.place(t.B2r(3600));
  const Apply a = g->ApplyPlaced(WallNowMs());
  H02_ROW("T09_applied", a.applied && a.version == 2, "applied=" + std::to_string(a.applied) + " reason=" + a.reason);
  const Lite c = command(*g, "T09_command", t.k1, kK1);
  H02_ROW("T09_verifies_again", c.state == "PERMIT" && c.forward, c.str());
}

// ---- T10 / T11a / T11b / T12 (R6): the version floor's state file -----------------------
void t10_t12() {
  {
    Trust t;  // no initFloor
    t.place(t.B1(3600));
    t.env("production");
    std::string mode, reason;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
    H02_ROW("T10_production_refuses_missing_state", starts(reason, "ERR_BUNDLE_STATE") && kr.pubkeys.empty(),
            "reason=" + reason + " keys=" + std::to_string(kr.pubkeys.size()));
    H02_ROW("T10_no_state_file_created", !exists(t.state), "state file appeared");
  }
  {
    Trust t;
    t.initFloor(1);
    t.place(t.B1(3600));
    t.env("production");
    std::string mode, reason;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
    H02_ROW("T11a_production_loads_with_initialised_state", reason.empty() && kr.pubkeys.count(kK1) == 1, reason);
  }
  {
    Trust t;  // no initFloor
    t.place(t.B1(3600));
    t.env("dev");
    std::string mode, reason;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
    H02_ROW("T11b_dev_first_load_as_before", reason.empty() && kr.pubkeys.count(kK1) == 1 && t.floor() == 1,
            "reason=" + reason + " floor=" + std::to_string(t.floor()));
  }
  {
    Trust t;
    writeAll(t.state, "this is not json");
    t.place(t.B1(3600));
    t.env("production");
    std::string mode, reason;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
    H02_ROW("T12_garbled_state_refused", reason == "ERR_BUNDLE_STATE" && kr.pubkeys.empty(), reason);
  }
}

// ---- T13 (R7): a role-less entry is no issuer key ---------------------------------------
void t13() {
  Trust t;
  t.initFloor(1);
  t.place(signBundle(t.root, payload(1, nowS() + 3600, {t.e1(""), t.eo()})));
  t.env("production");
  std::string mode, reason;
  Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
  H02_ROW("T13_roleless_bundle_refused", starts(reason, "ERR_KEYRING_ENTRY") && kr.pubkeys.empty(),
          "reason=" + reason + " keys=" + std::to_string(kr.pubkeys.size()));
  H02_ROW("T13_roleless_key_is_no_anchor", kr.pubkeys.count(kK1) == 0, "K1 became a token trust anchor");
}

// ---- T14 (R7): the lifetime ceiling must be declared in production ----------------------
void t14() {
  {
    Trust t;
    t.initFloor(1);
    t.place(t.B1(3600));
    t.env("production", "");
    std::string mode, reason;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
    H02_ROW("T14a_production_refuses_undeclared_ceiling", reason == "ERR_BUNDLE_POLICY" && kr.pubkeys.empty(),
            "reason=" + reason + " keys=" + std::to_string(kr.pubkeys.size()));
  }
  {
    Trust t;
    t.place(t.B1(3600));
    t.env("dev", "");
    std::string mode, reason;
    Keyring kr = LoadTrustedKeyring(t.dir + "/keyring.json", &mode, &reason);
    H02_ROW("T14b_dev_keeps_the_default_ceiling", reason.empty() && kr.pubkeys.count(kK1) == 1, reason);
  }
}

// ---- self checks: the material means what the rows assume --------------------------------
bool selfCheck() {
  const int before = g_failures;
  Trust t;
  t.initFloor(1);
  const std::string b1 = t.B1(3600);
  t.place(b1);
  H02_ROW("SELF_place_is_byte_exact", readAll(t.bundle) == b1, "placed bytes differ");
  auto g = openOrFail("SELF_open", t);
  if (g) {
    const Lite c = command(*g, "SELF_command", t.k1, kK1);
    H02_ROW("SELF_minted_token_permits", c.state == "PERMIT" && c.forward && c.permit, c.str());
    H02_ROW("SELF_trust_record_loaded", has(g->TrustJson(), "\"load_verdict\":\"LOADED\"") && has(g->TrustJson(), "\"bundle_version\":1"), g->TrustJson());
  }
  return g_failures == before;
}

int runInterop(const std::string &dir) {
  setenv("PAIL_KEYRING_MODE", "bundle", 1);
  setenv("PAIL_KEYRING_BUNDLE", (dir + "/keyring_bundle.json").c_str(), 1);
  setenv("PAIL_ROOT_PUBKEY_FILE", (dir + "/root_pub.b64").c_str(), 1);
  setenv("PAIL_KEYRING_STATE", (dir + "/keyring_bundle.state.json").c_str(), 1);
  setenv("PAIL_PROFILE", "production", 1);
  if (!std::getenv("PAIL_KEYRING_MAX_LIFETIME_SEC")) setenv("PAIL_KEYRING_MAX_LIFETIME_SEC", "86400", 1);
  std::string mode, reason;
  Keyring kr = LoadTrustedKeyring(dir + "/keyring.json", &mode, &reason);
  if (!reason.empty() || kr.pubkeys.empty()) {
    std::printf("INTEROP FAIL: reason=%s keys=%zu\n", reason.c_str(), kr.pubkeys.size());
    return 1;
  }
  std::printf("INTEROP OK: keys=%zu revoked=%zu", kr.pubkeys.size(), kr.revoked.size());
  for (const auto &kv : kr.pubkeys) std::printf(" key:%s", kv.first.c_str());
  for (const auto &kv : kr.revoked) std::printf(" revoked:%s", kv.first.c_str());
  std::printf("\n");
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (sodium_init() < 0) { std::printf("FAIL sodium_init\n"); return 2; }
  if (argc == 3 && std::strcmp(argv[1], "--interop") == 0) return runInterop(argv[2]);

  if (!selfCheck()) {
    std::printf("SELF CHECK FAILED — the rows below are not judged\n");
    return 2;
  }
  t01();
  t02();
  t03_t04();
  t05();
  t06();
  t06f();
  t07();
  t08();
  t09();
  t10_t12();
  t13();
  t14();

  if (g_failures > 0) {
    std::printf("TRUST LIVE: %d row(s) failed\n", g_failures);
    return 1;
  }
  std::printf("ALL TRUST LIVE ROWS PASSED\n");
  return 0;
}
