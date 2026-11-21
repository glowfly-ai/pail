// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//
// SEC-H02 — keyring bundle parity vectors, C++ gate loader side (test LLD §3.3, T15/T16).
//
// tests/golden/keyring_bundle/vectors.json (spec/vectors/keyring_bundle/ in a delivered
// Core) is read by this runner and by the Go loader's
// runner (internal/crypto, TestH02Vectors). Each vector must get the same verdict from
// both: accepted or not, the cause class of a refusal, the issuer and revoked key sets of
// an acceptance. Wording is not compared — a reason code is mapped to one of seven
// classes here, an error to the same seven classes on the Go side.
//
// The file is JSON; yaml-cpp reads it (JSON is YAML), so the gate needs no JSON library.

#include <sodium.h>
#include <unistd.h>
#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "pail_gate/keyring_bundle.hpp"

using pail_pep_gate::Keyring;
using pail_pep_gate::LoadTrustedKeyring;

namespace {
int g_failures = 0;

bool starts(const std::string &s, const char *p) { return s.rfind(p, 0) == 0; }

// Reason code -> cause class. A code outside this table is its own class, so a new or
// unexpected refusal shows as a mismatch instead of passing as a neighbour.
std::string classOf(const std::string &reason) {
  if (reason.empty()) return "";
  if (reason == "ERR_BUNDLE_SIG") return "SIG";
  if (reason == "ERR_BUNDLE_EXPIRED") return "EXPIRED";
  if (reason == "ERR_BUNDLE_ROLLBACK") return "ROLLBACK";
  if (reason == "ERR_BUNDLE_LIFETIME") return "LIFETIME";
  if (starts(reason, "ERR_BUNDLE_STATE")) return "STATE";
  if (reason == "ERR_BUNDLE_POLICY") return "POLICY";
  if (starts(reason, "ERR_KEYRING_ENTRY") || reason == "ERR_KEYRING_REVOKED_OVERLAP" ||
      reason == "ERR_BUNDLE_PAYLOAD" || reason == "ERR_KEYRING_PAYLOAD" ||
      reason == "ERR_BUNDLE_PARSE")
    return "ENTRY";
  return "UNCLASSIFIED(" + reason + ")";
}

std::vector<unsigned char> unb64(const std::string &s) {
  std::vector<unsigned char> out(s.size());
  size_t n = 0;
  if (sodium_base642bin(out.data(), out.size(), s.data(), s.size(), nullptr, &n, nullptr,
                        sodium_base64_VARIANT_ORIGINAL) != 0)
    return {};
  out.resize(n);
  return out;
}

void writeBytes(const std::string &path, const std::string &content) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f << content;
}

std::string join(std::vector<std::string> v) {
  std::sort(v.begin(), v.end());
  std::string s;
  for (const auto &x : v) s += (s.empty() ? "" : ",") + x;
  return s;
}

std::string joinNode(const YAML::Node &n) {
  std::vector<std::string> v;
  for (const auto &x : n) v.push_back(x.as<std::string>());
  return join(v);
}

void runVector(const YAML::Node &vec) {
  const std::string name = vec["name"].as<std::string>();
  char tmpl[] = "/tmp/h02vec.XXXXXX";
  const char *d = mkdtemp(tmpl);
  const std::string dir = d ? d : "/tmp/h02vec.fallback";
  const std::string bundle = dir + "/keyring_bundle.json", state = dir + "/keyring_bundle.state.json",
                    root = dir + "/root_pub.b64";

  const auto raw = unb64(vec["bundle_b64"].as<std::string>());
  writeBytes(bundle, std::string(raw.begin(), raw.end()));
  writeBytes(root, vec["root_pub_b64"].as<std::string>() + "\n");
  const std::string st = vec["state"].as<std::string>();
  if (starts(st, "floor:")) writeBytes(state, "{\"last_version\": " + st.substr(6) + "}\n");
  else if (st == "garbled") writeBytes(state, "this is not json");
  // "absent": no file.

  setenv("PAIL_KEYRING_MODE", "bundle", 1);
  setenv("PAIL_KEYRING_BUNDLE", bundle.c_str(), 1);
  setenv("PAIL_ROOT_PUBKEY_FILE", root.c_str(), 1);
  setenv("PAIL_KEYRING_STATE", state.c_str(), 1);
  setenv("PAIL_PROFILE", vec["profile"].as<std::string>().c_str(), 1);
  const std::string ceiling = vec["max_lifetime_sec"].as<std::string>();
  if (ceiling.empty()) unsetenv("PAIL_KEYRING_MAX_LIFETIME_SEC");
  else setenv("PAIL_KEYRING_MAX_LIFETIME_SEC", ceiling.c_str(), 1);

  std::string mode, reason;
  const Keyring kr = LoadTrustedKeyring(dir + "/keyring.json", &mode, &reason);
  const bool loaded = reason.empty() && !kr.pubkeys.empty();
  std::vector<std::string> issuers, revoked;
  for (const auto &kv : kr.pubkeys) issuers.push_back(kv.first);
  for (const auto &kv : kr.revoked) revoked.push_back(kv.first);

  const YAML::Node want = vec["want"];
  const bool want_loaded = want["loaded"].as<bool>();
  const std::string want_class = want["class"].as<std::string>();
  const std::string got = std::string(loaded ? "LOADED" : "REFUSED") + " class=" + classOf(reason) +
                          " issuers=[" + join(issuers) + "] revoked=[" + join(revoked) + "] reason=" + reason;
  const std::string exp = std::string(want_loaded ? "LOADED" : "REFUSED") + " class=" + want_class +
                          " issuers=[" + joinNode(want["issuer_ids"]) + "] revoked=[" + joinNode(want["revoked_ids"]) + "]";
  const bool ok = loaded == want_loaded && classOf(reason) == want_class &&
                  join(issuers) == joinNode(want["issuer_ids"]) && join(revoked) == joinNode(want["revoked_ids"]);
  if (ok) {
    std::printf("PASS VEC_%s\n", name.c_str());
  } else {
    std::printf("FAIL VEC_%s — got %s ; want %s (%s)\n", name.c_str(), got.c_str(), exp.c_str(),
                vec["note"].as<std::string>().c_str());
    ++g_failures;
  }
}
}  // namespace

int main() {
  if (sodium_init() < 0) { std::printf("FAIL sodium_init\n"); return 2; }
  const char *root = std::getenv("PAIL_REPO_ROOT");
  if (!root || !*root) { std::printf("FAIL PAIL_REPO_ROOT is not set\n"); return 2; }
  // A delivered Core carries the file as spec/vectors/keyring_bundle/vectors.json; the
  // development tree keeps it under tests/golden (same rule as test_contract_golden).
  std::string path = std::string(root) + "/spec/vectors/keyring_bundle/vectors.json";
  if (!std::ifstream(path).good()) path = std::string(root) + "/tests/golden/keyring_bundle/vectors.json";
  YAML::Node doc;
  try {
    doc = YAML::LoadFile(path);
  } catch (const std::exception &e) {
    std::printf("FAIL cannot read %s: %s\n", path.c_str(), e.what());
    return 2;
  }
  const YAML::Node vectors = doc["vectors"];
  if (!vectors || vectors.size() < 14) {
    std::printf("FAIL %s holds %zu vectors (14 expected at least)\n", path.c_str(), vectors ? vectors.size() : 0);
    return 2;
  }
  for (const auto &vec : vectors) runVector(vec);
  if (g_failures > 0) {
    std::printf("TRUST VECTORS: %d of %zu differ\n", g_failures, vectors.size());
    return 1;
  }
  std::printf("ALL %zu TRUST VECTORS AGREE\n", vectors.size());
  return 0;
}
