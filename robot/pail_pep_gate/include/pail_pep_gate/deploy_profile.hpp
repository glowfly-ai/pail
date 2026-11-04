// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#ifndef PAIL_PEP_GATE__DEPLOY_PROFILE_HPP_
#define PAIL_PEP_GATE__DEPLOY_PROFILE_HPP_

// SD1 (see spec/ARCHITECTURE.md): token provider mode is refused in
// the production profile when it would skip authorization verification.
// Header-only and rclcpp-free so the truth table can be unit tested.

#include <string>

namespace pail_pep_gate {

enum class ModeVerdict { Ok, Warn, Fail };

struct ModePolicy {
  ModeVerdict verdict;
  std::string id;      // "S0" | "S7"
  std::string detail;
};

inline ModePolicy EvaluateDeployMode(const std::string & profile,
                                     const std::string & mode,
                                     bool use_token_service,
                                     bool grpc_built)
{
  const bool dev = (profile == "dev");
  if (!(profile.empty() || profile == "production" || dev)) {
    return {ModeVerdict::Fail, "S0",
            "unknown PAIL_PROFILE '" + profile + "' (expected production|dev)"};
  }

  const ModeVerdict deny = dev ? ModeVerdict::Warn : ModeVerdict::Fail;
  const bool grpc_mode = (mode == "grpc" || use_token_service);

  if (grpc_mode && !grpc_built) {
    return {deny, "S7",
            "token_provider_mode=grpc on a PAIL_ENABLE_GRPC=0 build: "
            "no token verification code is linked"};
  }
  if (grpc_mode) {
    return {ModeVerdict::Ok, "S7", "token_provider_mode=grpc"};
  }
  if (mode == "static") {
    return {deny, "S7",
            "token_provider_mode=static fabricates an unsigned token and skips "
            "signature, time window, single-use and action-type verification"};
  }
  if (mode == "notoken") {
    return {ModeVerdict::Warn, "S7",
            "token_provider_mode=notoken: no token is ever issued, so every "
            "motion is blocked (ERR_NO_TOKEN)"};
  }
  return {deny, "S7",
          "unknown token_provider_mode '" + mode + "' (expected grpc|static|notoken)"};
}

}  // namespace pail_pep_gate

#endif  // PAIL_PEP_GATE__DEPLOY_PROFILE_HPP_
