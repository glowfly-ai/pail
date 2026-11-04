// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_pep_gate/token_provider_static.hpp"

#include <utility>

namespace pail_pep_gate {

StaticTokenProvider::StaticTokenProvider(std::string chain_id, std::string token_id, int seq_index,
                                         std::string target_object_id)
    : chain_id_(std::move(chain_id)), token_id_(std::move(token_id)), seq_index_(seq_index),
      target_object_id_(std::move(target_object_id)) {}

ActiveTokenView StaticTokenProvider::GetActiveToken(const std::string &robot_id) {
  (void)robot_id;
  ActiveTokenView v;
  v.ok = true;
  v.status = "OK";
  v.chain_id = chain_id_;
  v.token_id = token_id_;
  v.expected_sequence_index = seq_index_;
  // Not used in this provider.
  v.action_token_bytes = "";
  v.signature_bytes = "";
  v.key_id_bytes = "";
  v.signed_token_bytes = "";
  return v;
}

bool StaticTokenProvider::ReportDecision(const std::string &robot_id, const std::string &chain_id,
                                        const std::string &token_id, const std::string &decision,
                                        const std::string &reason_code, bool step_complete, bool fatal,
                                      const std::string &detail) {
  (void)detail;
  (void)robot_id;
  (void)chain_id;
  (void)token_id;
  (void)decision;
  (void)reason_code;
  (void)step_complete;
  (void)fatal;
  return true;  // dev provider, no issuer: nothing to deliver, nothing left unconfirmed
}

std::string StaticTokenProvider::Attest(const std::string &robot_id,
                                        const std::string &component,
                                        const std::string &measurement_sha256,
                                        const std::string &build_info) {
  (void)robot_id;
  (void)component;
  (void)measurement_sha256;
  (void)build_info;
  return "OK"; // static/dev mode has no issuer attestation surface
}

} // namespace pail_pep_gate
