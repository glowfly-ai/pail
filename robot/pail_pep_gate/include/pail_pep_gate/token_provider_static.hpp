// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#pragma once

#include <string>

#include "pail_gate/token_provider.hpp"

namespace pail_pep_gate {

// StaticTokenProvider is a dev/testing provider to enable end-to-end gating
// without grpc++ and without token protobuf parsing.
//
// It returns a synthetic token view with a configured target_object_id.
class StaticTokenProvider final : public ITokenProvider {
public:
  StaticTokenProvider(std::string chain_id, std::string token_id, int seq_index, std::string target_object_id);

  ActiveTokenView GetActiveToken(const std::string &robot_id) override;

  bool ReportDecision(const std::string &robot_id,
                      const std::string &chain_id,
                      const std::string &token_id,
                      const std::string &decision,
                      const std::string &reason_code,
                      bool step_complete,
                      bool fatal,
                      const std::string &detail) override;

  std::string Attest(const std::string &robot_id,
                     const std::string &component,
                     const std::string &measurement_sha256,
                     const std::string &build_info) override;

  const std::string &TargetObjectId() const { return target_object_id_; }

private:
  std::string chain_id_;
  std::string token_id_;
  int seq_index_{1};
  std::string target_object_id_;
};

} // namespace pail_pep_gate
