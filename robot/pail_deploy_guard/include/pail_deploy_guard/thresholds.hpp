// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#ifndef PAIL_DEPLOY_GUARD__THRESHOLDS_HPP_
#define PAIL_DEPLOY_GUARD__THRESHOLDS_HPP_

// S10 (PAIL-SD2-LLD-v1 §4): refuse threshold values that turn a check off while
// leaving it in place.
//
// Responsibility boundary (쉬운설명 §8.1): the operator picks the numbers for
// their site — a slow indoor cart and a fast outdoor one do not want the same
// freshness window. The deployer only decides which values are still a check at
// all. So this rejects the disabling end (confidence 0 accepts any perception
// result; a 60s staleness window is no freshness test) and lets every stricter
// value through, because stricter is fail-closed and is the operator's to choose.
//
// Negative values are rejected as typos, not as danger: the node used to clamp
// them silently to 0, which means running on a number nobody configured.

#include <string>
#include <vector>

#include "pail_deploy_guard/deploy_guard.hpp"

namespace pail_deploy_guard
{

struct ThresholdInput
{
  double evidence_conf_threshold = 0.90;
  int evidence_window_ms = 2000;
  int safety_stale_ms = 1000;
  int clock_skew_ms = 500;
  int permit_grace_n = 3;
  int permit_recheck_ms = 100;
};

// Upper bounds. Each is a multiple of the default large enough that no site
// tuning reaches it, so hitting one means the check was meant to be off.
constexpr int kMaxEvidenceWindowMs = 60000;  // 30x default
constexpr int kMaxSafetyStaleMs = 60000;     // 60x default
constexpr int kMaxClockSkewMs = 30000;       // = the token validity window
constexpr int kMaxPermitHoldMs = 5000;       // 16x default 3 x 100ms

inline std::string Num(double v)
{
  std::string s = std::to_string(v);
  const auto dot = s.find('.');
  if (dot != std::string::npos) {
    while (s.size() > dot + 2 && s.back() == '0') {
      s.pop_back();
    }
  }
  return s;
}

inline std::string Num(int v) { return std::to_string(v); }

inline std::vector<GuardFinding> EvaluateThresholds(const ThresholdInput & in)
{
  std::vector<GuardFinding> f;

  if (in.evidence_conf_threshold <= 0.0) {
    f.push_back({"S10", "evidence_conf_threshold=" + Num(in.evidence_conf_threshold) +
        " — any perception result passes, whatever its confidence"});
  } else if (in.evidence_conf_threshold > 1.0) {
    f.push_back({"S10", "evidence_conf_threshold=" + Num(in.evidence_conf_threshold) +
        " — confidence is 0..1, so no evidence can ever satisfy this"});
  }

  if (in.evidence_window_ms < 0) {
    f.push_back({"S10", "evidence_window_ms=" + Num(in.evidence_window_ms) + " — negative"});
  } else if (in.evidence_window_ms > kMaxEvidenceWindowMs) {
    f.push_back({"S10", "evidence_window_ms=" + Num(in.evidence_window_ms) + " > " +
        Num(kMaxEvidenceWindowMs) + " — the robot would keep moving on a perception "
        "result a minute old"});
  }

  if (in.safety_stale_ms < 0) {
    f.push_back({"S10", "safety_stale_ms=" + Num(in.safety_stale_ms) + " — negative"});
  } else if (in.safety_stale_ms > kMaxSafetyStaleMs) {
    f.push_back({"S10", "safety_stale_ms=" + Num(in.safety_stale_ms) + " > " +
        Num(kMaxSafetyStaleMs) + " — permits would still be granted a minute after the "
        "safety signal stopped, which is no freshness check"});
  }

  if (in.clock_skew_ms < 0) {
    f.push_back({"S10", "clock_skew_ms=" + Num(in.clock_skew_ms) + " — negative"});
  } else if (in.clock_skew_ms >= kMaxClockSkewMs) {
    f.push_back({"S10", "clock_skew_ms=" + Num(in.clock_skew_ms) + " >= " +
        Num(kMaxClockSkewMs) + " — the tolerance cancels the whole token validity "
        "window, so expired tokens are accepted"});
  }

  // The deadman's real length is the product, not the count: grace_n=50 with a
  // 10ms recheck is stricter than grace_n=3 with a 2s one.
  if (in.permit_grace_n < 0) {
    f.push_back({"S10", "permit_grace_n=" + Num(in.permit_grace_n) + " — negative"});
  } else if (in.permit_recheck_ms > 0 &&
    in.permit_grace_n > kMaxPermitHoldMs / in.permit_recheck_ms)
  {
    f.push_back({"S10", "permit_grace_n x permit_recheck_ms = " + Num(in.permit_grace_n) +
        " x " + Num(in.permit_recheck_ms) + " = " +
        Num(in.permit_grace_n * in.permit_recheck_ms) + "ms > " + Num(kMaxPermitHoldMs) +
        "ms — that is how long the robot may drive on with the issuer unreachable"});
  }

  return f;
}

// EnforceThresholds applies the verdict, with the same output contract as the
// other gates. Call it before any subscription or timer exists.
inline void EnforceThresholds(const std::string & profile, const std::string & component,
  const ThresholdInput & in)
{
  const auto fail = EvaluateThresholds(in);
  if (fail.empty()) {
    return;
  }
  if (profile != "production") {
    std::fprintf(stderr,
      "PAIL PREFLIGHT: profile=%s INSECURE(S10) component=%s — NOT FOR PRODUCTION\n",
      profile.c_str(), component.c_str());
    for (const auto & f : fail) {
      std::fprintf(stderr, "PAIL PREFLIGHT:   %s %s\n", f.id.c_str(), f.detail.c_str());
    }
    std::fflush(stderr);
    return;
  }
  for (const auto & f : fail) {
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

#endif  // PAIL_DEPLOY_GUARD__THRESHOLDS_HPP_
