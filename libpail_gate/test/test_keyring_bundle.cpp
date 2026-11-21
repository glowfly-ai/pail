// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// KM2-1 (§6.5) battery for the C++ signed keyring bundle loader.
// Plain executable (no gtest dependency): returns 0 only if every check
// passes. Also supports `--interop <dir>` to load a bundle produced by the
// Go CLI (tools/pail-keyring-sign) — cross-language format proof.

#include <sodium.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>

#include <iostream>
#include "pail_gate/keyring_bundle.hpp"

using pail_pep_gate::Keyring;
using pail_pep_gate::LoadKeyringBundle;
using pail_pep_gate::LoadKeyringJSON;
using pail_pep_gate::LoadTrustedKeyring;
using pail_pep_gate::ReadRootPubFile;

static int g_failures = 0;

#define CHECK(cond, msg)                                                  \
  do {                                                                    \
    if (!(cond)) {                                                        \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);  \
      ++g_failures;                                                       \
    }                                                                     \
  } while (0)

namespace {

std::string b64(const unsigned char *data, size_t len) {
  std::string out(sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL), '\0');
  sodium_bin2base64(&out[0], out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
  out.resize(std::strlen(out.c_str()));
  return out;
}

void writeFile(const std::string &path, const std::string &content) {
  std::ofstream f(path, std::ios::trunc);
  f << content;
}

std::string readFileStr(const std::string &path) {
  std::ifstream f(path);
  std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  return s;
}

struct RootKey {
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
};

RootKey makeRoot() {
  RootKey r;
  crypto_sign_keypair(r.pk, r.sk);
  return r;
}

std::vector<unsigned char> pubVec(const unsigned char *pk) {
  return std::vector<unsigned char>(pk, pk + crypto_sign_PUBLICKEYBYTES);
}

// Payload with one issuer key (plus an optional operator key).
std::string makePayload(uint64_t version, long long expires_at, bool with_operator = false) {
  unsigned char ipk[crypto_sign_PUBLICKEYBYTES], isk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(ipk, isk);
  std::string s = "{\"bundle_version\":" + std::to_string(version) +
                  ",\"issued_at_unix\":" + std::to_string((long long)std::time(nullptr)) +
                  ",\"expires_at_unix\":" + std::to_string(expires_at) +
                  ",\"keys\":[{\"key_id\":\"prod-issuer-1\",\"ed25519_public_key_base64\":\"" +
                  b64(ipk, sizeof ipk) + "\",\"role\":\"issuer\"}";
  if (with_operator) {
    unsigned char opk[crypto_sign_PUBLICKEYBYTES], osk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(opk, osk);
    s += ",{\"key_id\":\"op-key-1\",\"ed25519_public_key_base64\":\"" + b64(opk, sizeof opk) +
         "\",\"role\":\"operator\"}";
  }
  s += "]}";
  return s;
}

// Envelope over the exact payload bytes (same construction as Go BuildBundle).
std::string signBundle(const RootKey &root, const std::string &payload,
                       const std::string &root_key_id = "root-1") {
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, nullptr,
                       reinterpret_cast<const unsigned char *>(payload.data()),
                       payload.size(), root.sk);
  return "{\"schema_version\":1,\"payload_b64\":\"" +
         b64(reinterpret_cast<const unsigned char *>(payload.data()), payload.size()) +
         "\",\"root_key_id\":\"" + root_key_id + "\",\"root_sig_b64\":\"" +
         b64(sig, sizeof sig) + "\"}";
}

long long future() { return (long long)std::time(nullptr) + 24 * 3600; }

std::string tempDir() {
  char tmpl[] = "/tmp/kbtest.XXXXXX";
  char *d = mkdtemp(tmpl);
  if (d == nullptr) {
    std::fprintf(stderr, "mkdtemp failed\n");
    std::exit(2);
  }
  return std::string(d);
}

void clearEnv() {
  unsetenv("PAIL_KEYRING_MODE");
  unsetenv("PAIL_KEYRING_BUNDLE");
  unsetenv("PAIL_ROOT_PUBKEY_FILE");
  unsetenv("PAIL_KEYRING_STATE");
}

// --- B6-2 helpers ---------------------------------------------------------

// One legacy keyring entry. An empty field is omitted, which is how the
// "field missing" corruptions are built.
std::string legacyEntry(const std::string &key_id, const std::string &pub_b64,
                        const std::string &role) {
  std::string e = "{";
  if (!key_id.empty() || role == "@empty_id") {
    e += "\"key_id\":\"" + (role == "@empty_id" ? std::string() : key_id) + "\",";
  }
  if (!pub_b64.empty()) e += "\"ed25519_public_key_base64\":\"" + pub_b64 + "\",";
  e += "\"role\":\"" + (role == "@empty_id" ? std::string("issuer") : role) + "\"}";
  return e;
}

// Reads one per-cause count out of the reason string. Returns -1 when the
// cause is absent — "not reported" must not read as zero (H-B2).
int reasonCount(const std::string &reason, const std::string &cause) {
  const std::string needle = cause + "=";
  size_t p = reason.find(needle);
  if (p == std::string::npos) return -1;
  return std::atoi(reason.c_str() + p + needle.size());
}

// --- cases ---------------------------------------------------------------

// B6-2 : the legacy unsigned parser must hold the same
// posture as the bundle parser — count read failures by cause, and reject the
// file if there is even one. Measured on a 4-entry keyring so that "3 of 4
// entries were read" and "all 3 entries were read" are forced apart.
void testLegacyEntryCountedAndRejected() {
  const auto dir = tempDir();
  unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(pk, sk);
  const std::string P = b64(pk, sizeof pk);
  const std::string path = dir + "/keyring.json";

  const std::string ok1 = legacyEntry("k1", P, "issuer");
  const std::string ok2 = legacyEntry("k2", P, "issuer");
  const std::string op = legacyEntry("op-1", P, "operator");
  auto file = [&](const std::string &fourth) {
    return "{\"keys\":[" + ok1 + "," + ok2 + "," + op + "," + fourth + "]}";
  };

  // Positive control first. A gate that is never satisfied is a wall, not a
  // gate: the shipped keyring carries non-issuer entries and must still load.
  std::string reason;
  writeFile(path, file(legacyEntry("k3", P, "issuer")));
  Keyring kr = LoadKeyringJSON(path, &reason);
  CHECK(reason.empty(), "well-formed 4-entry keyring must load");
  CHECK(kr.pubkeys.size() == 3, "3 issuer anchors expected (operator is not one)");
  CHECK(kr.pubkeys.count("op-1") == 0, "operator entry must not become an anchor");

  // One corrupted entry out of four, per cause. Each must reject the file and
  // report exactly 1 in its own bucket and 0 in the others — a single tally
  // would let one cause disappear while another covers for it.
  struct Case {
    const char *cause;
    std::string fourth;
  } cases[] = {
      {"key_id", legacyEntry("", P, "issuer")},
      {"key_id_empty", legacyEntry("k3", P, "@empty_id")},
      {"pubkey", legacyEntry("k3", "", "issuer")},
      {"b64", legacyEntry("k3", "!!!not-base64!!!", "issuer")},
      {"pubkey_len", legacyEntry("k3", b64(pk, crypto_sign_PUBLICKEYBYTES - 1), "issuer")},
  };
  for (const auto &c : cases) {
    writeFile(path, file(c.fourth));
    reason.clear();
    kr = LoadKeyringJSON(path, &reason);
    CHECK(kr.pubkeys.empty(), "one bad entry must reject the whole keyring");
    CHECK(reason.rfind("ERR_KEYRING_ENTRY", 0) == 0, "rejection must name the cause class");
    CHECK(reasonCount(reason, c.cause) == 1, "the corrupted cause must count exactly 1");
    int others = 0;
    for (const auto &o : cases) {
      if (std::strcmp(o.cause, c.cause) != 0) others += reasonCount(reason, o.cause);
    }
    CHECK(others == 0, "no other cause may count");
  }

  // Scan bound. An object outside the keys array is not an entry; reading it
  // as one would make an unrelated field reject a valid keyring.
  writeFile(path, "{\"keys\":[" + ok1 + "],\"metadata\":{\"generated_by\":\"tool\"}}");
  reason.clear();
  kr = LoadKeyringJSON(path, &reason);
  CHECK(reason.empty() && kr.pubkeys.count("k1") == 1,
        "an object outside the keys array must not be read as an entry");

  // A file with no keys array at all is malformed, not empty.
  writeFile(path, "{\"note\":\"no keys here\"}");
  reason.clear();
  kr = LoadKeyringJSON(path, &reason);
  CHECK(reason == "ERR_KEYRING_PAYLOAD" && kr.pubkeys.empty(),
        "a keyring without a keys array must be refused as malformed");

  // An empty array is well-formed but carries no anchor — a different fact
  // from "the file was unreadable", and it keeps its own reason.
  writeFile(path, "{\"keys\":[]}");
  reason.clear();
  kr = LoadKeyringJSON(path, &reason);
  CHECK(reason == "ERR_KEYRING_EMPTY" && kr.pubkeys.empty(),
        "an empty keys array must report EMPTY, not ENTRY");
}

void testTrustMaterialDigestGolden() {
  const auto dir=tempDir();const auto root=makeRoot();
  std::string payload=R"PAYLOAD({"bundle_version":7,"issued_at_unix":1,"expires_at_unix":EXPIRES,"keys":[{"key_id":"i","role":"issuer","ed25519_public_key_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},{"key_id":"o","role":"operator","ed25519_public_key_base64":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}],"revoked_keys":[{"key_id":"r","role":"issuer","ed25519_public_key_base64":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}]})PAYLOAD";
  const auto at=payload.find("EXPIRES");payload.replace(at,7,std::to_string(future()));
  writeFile(dir+"/b.json",signBundle(root,payload));std::string reason;
  const auto kr=LoadKeyringBundle(dir+"/b.json",pubVec(root.pk),dir+"/state.json",&reason);
  CHECK(reason.empty(),"material golden bundle must load");
  std::cout << "TRUST_MATERIAL_GOLDEN " << kr.loaded_trust_json << "\n";
  CHECK(kr.loaded_trust_json.find("d7df5df418103d3096dd7be7210f735842ca20bcbbab432971abeb635f8dfc6d")!=std::string::npos,"loaded active/operator/revoked material digest must match Go/Python golden");
}

void testValidLoadsAndAdvancesVersion() {
  const auto dir = tempDir();
  const auto root = makeRoot();
  writeFile(dir + "/b.json", signBundle(root, makePayload(7, future())));
  std::string reason;
  Keyring kr = LoadKeyringBundle(dir + "/b.json", pubVec(root.pk), dir + "/state.json", &reason);
  CHECK(reason.empty(), "valid bundle must load");
  CHECK(kr.pubkeys.count("prod-issuer-1") == 1, "issuer key must be present");
  CHECK(kr.loaded_trust_json.find("\"bundle_version\":7") != std::string::npos, "loaded version must be captured");
  CHECK(kr.loaded_trust_json.find("\"load_verdict\":\"LOADED\"") != std::string::npos, "accepted bundle must expose loaded metadata");
  const auto loaded = kr.loaded_trust_json;
  writeFile(dir + "/b.json", "replaced after load");
  CHECK(kr.loaded_trust_json == loaded, "metadata must not follow disk replacement");
  const std::string st = readFileStr(dir + "/state.json");
  CHECK(st.find("\"last_version\": 7") != std::string::npos, "state floor must be 7");
}

// PAIL-CASE: ForgedBundleRejected
void testForgedSignatureRejected() {
  const auto dir = tempDir();
  const auto attacker = makeRoot();
  const auto real_root = makeRoot();
  writeFile(dir + "/b.json", signBundle(attacker, makePayload(1, future())));
  std::string reason;
  Keyring kr = LoadKeyringBundle(dir + "/b.json", pubVec(real_root.pk), dir + "/state.json", &reason);
  CHECK(reason == "ERR_BUNDLE_SIG", "forged signature must be rejected");
  CHECK(kr.pubkeys.empty(), "forged bundle must yield no keys");
}

void testPayloadTamperRejected() {
  const auto dir = tempDir();
  const auto root = makeRoot();
  const std::string payload = makePayload(1, future());
  std::string bundle = signBundle(root, payload);

  // Re-encode payload_b64 with one flipped byte, keeping the signature.
  std::string tampered = payload;
  tampered[0] ^= 0x01;
  const std::string old_b64 =
      b64(reinterpret_cast<const unsigned char *>(payload.data()), payload.size());
  const std::string new_b64 =
      b64(reinterpret_cast<const unsigned char *>(tampered.data()), tampered.size());
  const size_t pos = bundle.find(old_b64);
  CHECK(pos != std::string::npos, "payload_b64 must be present in bundle");
  bundle.replace(pos, old_b64.size(), new_b64);

  writeFile(dir + "/b.json", bundle);
  std::string reason;
  Keyring kr = LoadKeyringBundle(dir + "/b.json", pubVec(root.pk), dir + "/state.json", &reason);
  CHECK(reason == "ERR_BUNDLE_SIG", "tampered payload must be rejected");
  CHECK(kr.pubkeys.empty(), "tampered bundle must yield no keys");
}

void testRollbackRejected() {
  const auto dir = tempDir();
  const auto root = makeRoot();
  const std::string state = dir + "/state.json";
  std::string reason;

  writeFile(dir + "/new.json", signBundle(root, makePayload(8, future())));
  LoadKeyringBundle(dir + "/new.json", pubVec(root.pk), state, &reason);
  CHECK(reason.empty(), "v8 must load");

  writeFile(dir + "/old.json", signBundle(root, makePayload(6, future())));
  Keyring kr = LoadKeyringBundle(dir + "/old.json", pubVec(root.pk), state, &reason);
  CHECK(reason == "ERR_BUNDLE_ROLLBACK", "v6 after v8 must be rejected");
  CHECK(kr.pubkeys.empty(), "rolled-back bundle must yield no keys");

  // Same version re-presented must LOAD: §6.3 applies bundles by restart, so
  // a plain restart re-reads the unchanged bundle. Only strictly-smaller
  // versions are rollbacks.
  kr = LoadKeyringBundle(dir + "/new.json", pubVec(root.pk), state, &reason);
  CHECK(reason.empty() && kr.pubkeys.count("prod-issuer-1") == 1,
        "re-loading v8 (restart with unchanged bundle) must succeed");
  const std::string st = readFileStr(state);
  CHECK(st.find("\"last_version\": 8") != std::string::npos,
        "floor must remain 8 after equal-version reload");
}

void testExpiredRejected() {
  const auto dir = tempDir();
  const auto root = makeRoot();
  writeFile(dir + "/b.json",
            signBundle(root, makePayload(1, (long long)std::time(nullptr) - 3600)));
  std::string reason;
  Keyring kr = LoadKeyringBundle(dir + "/b.json", pubVec(root.pk), dir + "/state.json", &reason);
  CHECK(reason == "ERR_BUNDLE_EXPIRED", "expired bundle must be rejected");
  CHECK(kr.pubkeys.empty(), "expired bundle must yield no keys");
}

void testOperatorRoleNotTrustAnchor() {
  const auto dir = tempDir();
  const auto root = makeRoot();
  writeFile(dir + "/b.json", signBundle(root, makePayload(1, future(), /*with_operator=*/true)));
  std::string reason;
  Keyring kr = LoadKeyringBundle(dir + "/b.json", pubVec(root.pk), dir + "/state.json", &reason);
  CHECK(reason.empty(), "bundle with operator key must still load");
  CHECK(kr.pubkeys.size() == 1 && kr.pubkeys.count("prod-issuer-1") == 1,
        "only the issuer key may become a trust anchor");
}

void testCorruptStateRejected() {
  const auto dir = tempDir();
  const auto root = makeRoot();
  writeFile(dir + "/b.json", signBundle(root, makePayload(9, future())));
  writeFile(dir + "/state.json", "not json at all");
  std::string reason;
  Keyring kr = LoadKeyringBundle(dir + "/b.json", pubVec(root.pk), dir + "/state.json", &reason);
  CHECK(reason == "ERR_BUNDLE_STATE", "corrupt state file must reject, not reset the floor");
  CHECK(kr.pubkeys.empty(), "corrupt state must yield no keys");
}

// DC-10 / C3-C7 : wall-clock rewind floor in the SAME state
// file as the version floor. Two writers now share the file; each direction
// of the merge is asserted, because either writer clobbering the other
// silently reopens the window the other one closed.
void testWallFloor() {
  using pail_pep_gate::CheckWallFloor;
  using pail_pep_gate::PersistWallFloor;
  using pail_pep_gate::WallFloor;
  const auto dir = tempDir();
  const std::string state = dir + "/state.json";

  // Missing file: first boot, no floor — not an error.
  CHECK(CheckWallFloor(state, 12345) == WallFloor::NoFloor,
        "missing state file must be NoFloor");

  // Pre-DC10 state file carries only last_version. Key absence is NoFloor,
  // not StateError — existing deployments must keep starting.
  writeFile(state, "{\n  \"last_version\": 7\n}\n");
  CHECK(CheckWallFloor(state, 12345) == WallFloor::NoFloor,
        "version-only (pre-DC10) state file must be NoFloor");

  // Writer 2 must preserve writer 1's key.
  CHECK(PersistWallFloor(state, 100000), "persist must succeed");
  {
    const std::string st = readFileStr(state);
    CHECK(st.find("\"last_version\": 7") != std::string::npos,
          "persisting the floor must keep last_version");
    CHECK(st.find("\"wall_ms0\": 100000") != std::string::npos,
          "persisting the floor must write wall_ms0");
  }

  CHECK(CheckWallFloor(state, 100000) == WallFloor::Ok, "boot == stored is not a rewind");
  CHECK(CheckWallFloor(state, 100001) == WallFloor::Ok, "boot after stored is Ok");
  CHECK(CheckWallFloor(state, 99999) == WallFloor::Rewind, "boot behind stored is Rewind");

  // Writer 1 (version bump) must preserve writer 2's key — an erased floor
  // is indistinguishable from a first boot.
  const auto root = makeRoot();
  writeFile(dir + "/b.json", signBundle(root, makePayload(9, future())));
  std::string reason;
  Keyring kr = LoadKeyringBundle(dir + "/b.json", pubVec(root.pk), state, &reason);
  CHECK(reason.empty() && kr.pubkeys.size() == 1, "v9 bundle must load over the v7 floor");
  {
    const std::string st = readFileStr(state);
    CHECK(st.find("\"last_version\": 9") != std::string::npos,
          "the bump must advance the version");
    CHECK(st.find("\"wall_ms0\": 100000") != std::string::npos,
          "the bump must keep wall_ms0");
  }
  CHECK(CheckWallFloor(state, 99999) == WallFloor::Rewind,
        "the floor must survive the version bump");

  // Present-but-unreadable is StateError, not NoFloor: a rewind cannot be
  // ruled out from a floor that cannot be read (H-B2).
  writeFile(state, "junk with a \"wall_ms0\" and no value");
  CHECK(CheckWallFloor(state, 12345) == WallFloor::StateError,
        "garbled floor must be StateError");
  CHECK(!PersistWallFloor(state, 200000),
        "a writer must not clobber what it cannot read");
  writeFile(state, "{\n  \"last_version\": 9,\n  \"wall_ms0\": -5\n}\n");
  CHECK(CheckWallFloor(state, 12345) == WallFloor::StateError,
        "negative floor must be StateError");

  writeFile(state, "{\n  \"last_version\": 9\n}\n");
  CHECK(!PersistWallFloor(state, -1), "a negative floor must be refused at the write");
}

void testSelector() {
  const auto dir = tempDir();
  const auto root = makeRoot();

  // Legacy unsigned keyring on disk.
  unsigned char ipk[crypto_sign_PUBLICKEYBYTES], isk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(ipk, isk);
  const std::string legacy = dir + "/keyring.json";
  writeFile(legacy, "{\"keys\":[{\"key_id\":\"dev-key-1\",\"ed25519_public_key_base64\":\"" +
                        b64(ipk, sizeof ipk) + "\",\"role\":\"issuer\"}]}");

  // Default mode with no root pubkey configured => refuse (fail-closed).
  clearEnv();
  std::string mode, reason;
  Keyring kr = LoadTrustedKeyring(legacy, &mode, &reason);
  CHECK(mode == "bundle", "default mode must be bundle");
  CHECK(reason == "ERR_ROOT_PUBKEY", "default mode without root pubkey must refuse");
  CHECK(kr.pubkeys.empty(), "refused selector must yield no keys");

  // Explicit dev mode loads the unsigned keyring.
  setenv("PAIL_KEYRING_MODE", "unsigned-dev", 1);
  kr = LoadTrustedKeyring(legacy, &mode, &reason);
  CHECK(mode == "unsigned-dev" && reason.empty() && kr.pubkeys.count("dev-key-1") == 1,
        "unsigned-dev must load the legacy keyring");

  // Unknown mode refused.
  setenv("PAIL_KEYRING_MODE", "bogus", 1);
  kr = LoadTrustedKeyring(legacy, &mode, &reason);
  CHECK(reason == "ERR_KEYRING_MODE" && kr.pubkeys.empty(), "unknown mode must refuse");

  // Bundle mode e2e via env. SEC-H02: the selector applies two production rules (a
  // missing state file is not a first load; the lifetime ceiling must be declared) —
  // test_trust_live T10/T14 pin them. This section measures the selector's wiring on a
  // first load with the default ceiling, which is the dev profile's behaviour.
  setenv("PAIL_PROFILE", "dev", 1);
  writeFile(dir + "/keyring_bundle.json", signBundle(root, makePayload(3, future())));
  writeFile(dir + "/root_pub.b64", b64(root.pk, sizeof root.pk) + "\n");
  setenv("PAIL_KEYRING_MODE", "bundle", 1);
  setenv("PAIL_KEYRING_BUNDLE", (dir + "/keyring_bundle.json").c_str(), 1);
  setenv("PAIL_ROOT_PUBKEY_FILE", (dir + "/root_pub.b64").c_str(), 1);
  setenv("PAIL_KEYRING_STATE", (dir + "/state.json").c_str(), 1);
  kr = LoadTrustedKeyring(legacy, &mode, &reason);
  CHECK(mode == "bundle" && reason.empty() && kr.pubkeys.count("prod-issuer-1") == 1,
        "bundle mode must load a signed bundle end to end");
  const auto before_policy=readFileStr(dir + "/state.json");
  writeFile(dir + "/keyring_bundle.json", signBundle(root, makePayload(4, future())));
  setenv("PAIL_KEYRING_MAX_LIFETIME_SEC", "1", 1);
  kr = LoadTrustedKeyring(legacy, &mode, &reason);
  CHECK(kr.pubkeys.empty() && reason == "ERR_BUNDLE_LIFETIME", "configured short remaining lifetime must refuse");
  CHECK(readFileStr(dir + "/state.json") == before_policy, "refused lifetime must not advance version");
  for (const char *bad : {"0", "-1", "bad", "999999999999999999999999"}) {
    setenv("PAIL_KEYRING_MAX_LIFETIME_SEC", bad, 1);
    kr = LoadTrustedKeyring(legacy, &mode, &reason);
    CHECK(kr.pubkeys.empty() && reason == "ERR_BUNDLE_POLICY", "invalid lifetime policy refuses");
  }
  setenv("PAIL_KEYRING_MAX_LIFETIME_SEC", "86400", 1);
  kr = LoadTrustedKeyring(legacy, &mode, &reason);
  CHECK(reason.empty() && !kr.pubkeys.empty(), "valid explicit lifetime loads");
  unsetenv("PAIL_KEYRING_MAX_LIFETIME_SEC");
  unsetenv("PAIL_PROFILE");
  clearEnv();
}

// Load a Go-CLI-produced bundle: <dir>/root_pub.b64 + <dir>/keyring_bundle.json.
int runInterop(const std::string &dir) {
  std::vector<unsigned char> root_pub;
  std::string reason;
  if (!ReadRootPubFile(dir + "/root_pub.b64", &root_pub, &reason)) {
    std::fprintf(stderr, "INTEROP FAIL: root pub: %s\n", reason.c_str());
    return 1;
  }
  Keyring kr = LoadKeyringBundle(dir + "/keyring_bundle.json", root_pub,
                                 dir + "/interop_state.json", &reason);
  if (!reason.empty() || kr.pubkeys.empty()) {
    std::fprintf(stderr, "INTEROP FAIL: reason=%s keys=%zu\n", reason.c_str(), kr.pubkeys.size());
    return 1;
  }
  std::printf("INTEROP OK: keys=%zu", kr.pubkeys.size());
  for (const auto &kv : kr.pubkeys) std::printf(" %s", kv.first.c_str());
  std::printf("\n");
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (sodium_init() < 0) {
    std::fprintf(stderr, "sodium_init failed\n");
    return 2;
  }
  if (argc == 3 && std::strcmp(argv[1], "--interop") == 0) {
    return runInterop(argv[2]);
  }

  testLegacyEntryCountedAndRejected();
  testTrustMaterialDigestGolden();
  testValidLoadsAndAdvancesVersion();
  testForgedSignatureRejected();
  testPayloadTamperRejected();
  testRollbackRejected();
  testExpiredRejected();
  testOperatorRoleNotTrustAnchor();
  testCorruptStateRejected();
  testWallFloor();
  testSelector();

  if (g_failures > 0) {
    std::fprintf(stderr, "FAILED: %d check(s)\n", g_failures);
    return 1;
  }
  std::printf("ALL KEYRING BUNDLE CHECKS PASSED\n");
  return 0;
}
