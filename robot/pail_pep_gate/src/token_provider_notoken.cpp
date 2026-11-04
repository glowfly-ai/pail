// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_gate/token_provider.hpp"

namespace pail_pep_gate {

ActiveTokenView NoTokenProvider::GetActiveToken(const std::string &robot_id) {
  (void)robot_id;
  ActiveTokenView v;
  v.ok = false;
  v.status = "NO_TOKEN";
  v.expected_sequence_index = 1;
  return v;
}

bool NoTokenProvider::ReportDecision(const std::string &robot_id,
                                    const std::string &chain_id,
                                    const std::string &token_id,
                                    const std::string &decision,
                                    const std::string &reason_code,
                                    bool step_complete,
                                    bool fatal,
                                      const std::string &detail) {
  (void)detail;
  (void)robot_id;
  (void)chain_id;
  (void)token_id;
  (void)decision;
  (void)reason_code;
  (void)step_complete;
  (void)fatal;
  return true;  // no issuer: nothing to deliver, nothing left unconfirmed
}

std::string NoTokenProvider::Attest(const std::string &robot_id,
                                    const std::string &component,
                                    const std::string &measurement_sha256,
                                    const std::string &build_info) {
  (void)robot_id;
  (void)component;
  (void)measurement_sha256;
  (void)build_info;
  return "OK"; // no issuer to attest to
}

} // namespace pail_pep_gate
