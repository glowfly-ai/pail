// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// TB-11 (see spec/ARCHITECTURE.md): profile monotonicity.
// The existing test_deploy_profile.cpp pins rows; this file pins the RELATION
// between rows: dev may never be stricter than production .
//
//   for every x = (mode, use_token_service, grpc_built):
//     verdict(production, x) == Ok  ⟹  verdict(dev, x) == Ok
//
// The reverse direction (dev Ok, production Fail) is the design intent, not a
// violation. Today's implementation concentrates strictness in one variable
// (deny = dev ? Warn : Fail), so this test passes by construction — its job is
// to catch the day a third profile or a special case breaks the ordering
// (§6.3.1: RED evidence for this file comes from deliberate defect injection,
// not from a live bug. We do not hide that).
//
// No gtest (HLD TC-3): plain executable, literal expectations, PAIL-CASE
// markers for CG-B.

#include <cstdio>
#include <string>
#include <vector>

#include "pail_pep_gate/deploy_profile.hpp"

namespace {

using pail_pep_gate::EvaluateDeployMode;
using pail_pep_gate::ModeVerdict;

int g_failures = 0;

const char *VerdictName(ModeVerdict v) {
  switch (v) {
    case ModeVerdict::Ok:   return "Ok";
    case ModeVerdict::Warn: return "Warn";
    case ModeVerdict::Fail: return "Fail";
  }
  return "?";
}

// PAIL-CASE: ProfileMonotonic
// G-DEP-08 — weakening is monotonic. Exhaustive sweep: mode 5 × uts 2 ×
// built 2 = 20 combos (§6.3). One counterexample fails the case.
bool CaseProfileMonotonic() {
  const std::vector<std::string> modes = {"grpc", "static", "notoken", "bogus", ""};
  const bool bools[2] = {false, true};

  int checked = 0;
  bool ok = true;
  for (const auto &mode : modes) {
    for (bool uts : bools) {
      for (bool built : bools) {
        const auto prod = EvaluateDeployMode("production", mode, uts, built);
        const auto dev  = EvaluateDeployMode("dev", mode, uts, built);
        ++checked;
        if (prod.verdict == ModeVerdict::Ok && dev.verdict != ModeVerdict::Ok) {
          std::printf(
              "    counterexample: mode='%s' uts=%d built=%d -> production=Ok "
              "but dev=%s\n",
              mode.c_str(), uts ? 1 : 0, built ? 1 : 0, VerdictName(dev.verdict));
          ok = false;
        }
      }
    }
  }
  if (checked != 20) {  // the sweep itself must be exhaustive
    std::printf("    sweep covered %d combos, expected 20\n", checked);
    ok = false;
  }
  return ok;
}

void Run(const char *name, bool (*fn)()) {
  const bool ok = fn();
  std::printf("%-32s %s\n", name, ok ? "PASS" : "FAIL");
  if (!ok) ++g_failures;
}

}  // namespace

int main() {
  Run("ProfileMonotonic", CaseProfileMonotonic);
  if (g_failures != 0) {
    std::printf("FAILED: %d case(s)\n", g_failures);
    return 1;
  }
  std::printf("OK: all cases passed\n");
  return 0;
}
