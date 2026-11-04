// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#ifndef PAIL_DEPLOY_GUARD__KEY_FINGERPRINT_HPP_
#define PAIL_DEPLOY_GUARD__KEY_FINGERPRINT_HPP_

// S8 (PAIL-SD2-LLD-v1 §2.3, check 6): the trust anchors the gate actually
// loaded must not be keys that ship in this repository's source tree.
//
// The predicate takes fingerprints, not keys: hashing needs libsodium and this
// package is header-only by design (SD3), so the caller — which already links
// sodium to verify signatures — computes them. The judgement stays here, next
// to the other deployment rules, and stays testable without a crypto library.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "pail_deploy_guard/deploy_guard.hpp"
#include "pail_deploy_guard/known_dev_keys.hpp"

namespace pail_deploy_guard
{

// KeyMaterialItem is one loaded key. where is for the operator's message.
struct KeyMaterialItem
{
  std::string where;
  std::string fingerprint;  // lowercase sha256 hex
};

inline bool LookupDevKey(const std::string & fingerprint, std::string * label)
{
  std::size_t n = 0;
  const KnownDevKey * keys = KnownDevKeys(&n);
  for (std::size_t i = 0; i < n; ++i) {
    if (fingerprint == keys[i].fingerprint) {
      if (label) {
        *label = keys[i].label;
      }
      return true;
    }
  }
  return false;
}

// EvaluateKeyMaterial is pure: one S8 finding per item on the committed list.
inline std::vector<GuardFinding> EvaluateKeyMaterial(const std::vector<KeyMaterialItem> & items)
{
  std::vector<GuardFinding> out;
  for (const auto & it : items) {
    std::string label;
    if (!LookupDevKey(it.fingerprint, &label)) {
      continue;
    }
    out.push_back(GuardFinding{
      "S8",
      it.where + " is a key committed to this repository (sha256:" +
      it.fingerprint.substr(0, 16) + " = " + label +
      ") — anyone with the source can sign with it"});
  }
  return out;
}

// EnforceKeyMaterial applies the verdict. profile is the resolved profile
// ("production" when PAIL_PROFILE is unset), matching the Go side.
inline void EnforceKeyMaterial(
  const std::string & profile, const std::string & component,
  const std::vector<GuardFinding> & findings)
{
  if (findings.empty()) {
    return;
  }
  if (profile != "production") {
    std::fprintf(stderr, "PAIL PREFLIGHT: profile=%s INSECURE(S8) component=%s — NOT FOR PRODUCTION\n",
      profile.c_str(), component.c_str());
    for (const auto & f : findings) {
      std::fprintf(stderr, "PAIL PREFLIGHT:   %s %s\n", f.id.c_str(), f.detail.c_str());
    }
    std::fflush(stderr);
    return;
  }
  for (const auto & f : findings) {
    std::fprintf(stderr, "PAIL PREFLIGHT FAIL: %s %s [profile=%s component=%s]\n",
      f.id.c_str(), f.detail.c_str(), profile.c_str(), component.c_str());
  }
  std::fprintf(stderr,
    "PAIL PREFLIGHT FAIL: refusing to start. Set PAIL_PROFILE=dev to run without "
    "these protections (DEV ONLY).\n");
  std::fflush(stderr);
  std::exit(kExitConfig);
}

}  // namespace pail_deploy_guard

#endif  // PAIL_DEPLOY_GUARD__KEY_FINGERPRINT_HPP_
