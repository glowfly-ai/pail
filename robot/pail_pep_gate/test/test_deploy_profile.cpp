// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// SD1-1: exhaustive truth table for EvaluateDeployMode
// (see spec/ARCHITECTURE.md).
// Plain executable, no gtest: returns 0 only if every row matches.
// Expectations are written out literally — deriving them from the same rules
// the implementation uses would make the test tautological.

#include <cstdio>
#include <string>
#include <vector>

#include "pail_pep_gate/deploy_profile.hpp"

using pail_pep_gate::EvaluateDeployMode;
using pail_pep_gate::ModeVerdict;

namespace {

struct Row {
  const char *profile;
  const char *mode;
  bool use_token_service;
  bool grpc_built;
  ModeVerdict expect;
  const char *expect_id;
};

const char *VerdictName(ModeVerdict v) {
  switch (v) {
    case ModeVerdict::Ok: return "Ok";
    case ModeVerdict::Warn: return "Warn";
    case ModeVerdict::Fail: return "Fail";
  }
  return "?";
}

const Row kRows[] = {
  // ---- production, grpc build ------------------------------------------
  {"production", "grpc",    false, true,  ModeVerdict::Ok,   "S7"},
  {"production", "grpc",    true,  true,  ModeVerdict::Ok,   "S7"},
  {"production", "static",  false, true,  ModeVerdict::Fail, "S7"},
  {"production", "static",  true,  true,  ModeVerdict::Ok,   "S7"},  // use_token_service wins
  {"production", "notoken", false, true,  ModeVerdict::Warn, "S7"},
  {"production", "notoken", true,  true,  ModeVerdict::Ok,   "S7"},
  {"production", "bogus",   false, true,  ModeVerdict::Fail, "S7"},
  {"production", "bogus",   true,  true,  ModeVerdict::Ok,   "S7"},
  // ---- production, non-grpc build --------------------------------------
  {"production", "grpc",    false, false, ModeVerdict::Fail, "S7"},
  {"production", "grpc",    true,  false, ModeVerdict::Fail, "S7"},
  {"production", "static",  false, false, ModeVerdict::Fail, "S7"},
  {"production", "static",  true,  false, ModeVerdict::Fail, "S7"},
  {"production", "notoken", false, false, ModeVerdict::Warn, "S7"},
  {"production", "notoken", true,  false, ModeVerdict::Fail, "S7"},
  {"production", "bogus",   false, false, ModeVerdict::Fail, "S7"},
  {"production", "bogus",   true,  false, ModeVerdict::Fail, "S7"},
  // ---- empty profile == production (BG S0 convention) ------------------
  {"", "grpc",    false, true,  ModeVerdict::Ok,   "S7"},
  {"", "static",  false, true,  ModeVerdict::Fail, "S7"},
  {"", "static",  true,  true,  ModeVerdict::Ok,   "S7"},
  {"", "notoken", false, true,  ModeVerdict::Warn, "S7"},
  {"", "bogus",   false, true,  ModeVerdict::Fail, "S7"},
  {"", "grpc",    false, false, ModeVerdict::Fail, "S7"},
  {"", "static",  false, false, ModeVerdict::Fail, "S7"},
  {"", "notoken", false, false, ModeVerdict::Warn, "S7"},
  // ---- dev: every production Fail becomes Warn, nothing else changes ---
  {"dev", "grpc",    false, true,  ModeVerdict::Ok,   "S7"},
  {"dev", "grpc",    true,  true,  ModeVerdict::Ok,   "S7"},
  {"dev", "static",  false, true,  ModeVerdict::Warn, "S7"},
  {"dev", "static",  true,  true,  ModeVerdict::Ok,   "S7"},
  {"dev", "notoken", false, true,  ModeVerdict::Warn, "S7"},
  {"dev", "notoken", true,  true,  ModeVerdict::Ok,   "S7"},
  {"dev", "bogus",   false, true,  ModeVerdict::Warn, "S7"},
  {"dev", "bogus",   true,  true,  ModeVerdict::Ok,   "S7"},
  {"dev", "grpc",    false, false, ModeVerdict::Warn, "S7"},
  {"dev", "grpc",    true,  false, ModeVerdict::Warn, "S7"},
  {"dev", "static",  false, false, ModeVerdict::Warn, "S7"},
  {"dev", "static",  true,  false, ModeVerdict::Warn, "S7"},
  {"dev", "notoken", false, false, ModeVerdict::Warn, "S7"},
  {"dev", "notoken", true,  false, ModeVerdict::Warn, "S7"},
  {"dev", "bogus",   false, false, ModeVerdict::Warn, "S7"},
  {"dev", "bogus",   true,  false, ModeVerdict::Warn, "S7"},
  // ---- unknown profile is refused before the mode is even looked at ----
  {"prod",       "grpc",    false, true,  ModeVerdict::Fail, "S0"},
  {"Production", "grpc",    true,  true,  ModeVerdict::Fail, "S0"},
  {"development","static",  false, true,  ModeVerdict::Fail, "S0"},
  {"dev ",       "notoken", false, false, ModeVerdict::Fail, "S0"},
};

}  // namespace

// PAIL-CASE: DeployProfileTruthTable
int main() {
  int failures = 0;
  for (const Row &r : kRows) {
    const auto got = EvaluateDeployMode(r.profile, r.mode, r.use_token_service, r.grpc_built);
    if (got.verdict != r.expect || got.id != std::string(r.expect_id)) {
      std::fprintf(stderr,
                   "FAIL profile=%-11s mode=%-8s uts=%d built=%d -> %s/%s (want %s/%s)\n",
                   r.profile, r.mode, r.use_token_service ? 1 : 0, r.grpc_built ? 1 : 0,
                   VerdictName(got.verdict), got.id.c_str(),
                   VerdictName(r.expect), r.expect_id);
      ++failures;
    }
    if (got.detail.empty()) {
      std::fprintf(stderr, "FAIL profile=%s mode=%s: empty detail\n", r.profile, r.mode);
      ++failures;
    }
  }

  const size_t total = sizeof(kRows) / sizeof(kRows[0]);
  if (failures == 0) {
    std::printf("test_deploy_profile: %zu/%zu rows OK\n", total, total);
    return 0;
  }
  std::fprintf(stderr, "test_deploy_profile: %d failure(s) of %zu rows\n", failures, total);
  return 1;
}
