// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_pep_gate/token_provider_grpc.hpp"

#include <utility>

namespace pail_pep_gate {

// One communication contract (0.2.0-preview.40): nothing selects it, so the stub build no longer refuses construction
// (the former CORE_COMM_CONTRACT_REQUIRES_GRPC). A stub provider is a non-reporting provider: every report answers
// "not delivered" and every token query answers NO_TOKEN (fail-closed, visible), exactly as below.
GrpcTokenProvider::GrpcTokenProvider(std::string addr, bool core_contract) : addr_(std::move(addr)), core_contract_(core_contract) {}

// The header declares the destructor so the grpc build can destroy the
// pimpl'd TokenServiceClient; the stub build must still define it or the
// vtable never gets emitted (undefined-reference at link).
GrpcTokenProvider::~GrpcTokenProvider() = default;

ActiveTokenView GrpcTokenProvider::GetActiveToken(const std::string &robot_id) {
  (void)robot_id;
  // TODO: implement gRPC call to TokenService.GetActiveToken (token_service.proto).
  // Safe fallback until implemented. Replace this file with src/grpc/token_provider_grpc.cpp and add grpc deps.
  ActiveTokenView v;
  v.ok = false;
  v.status = "NO_TOKEN";
  v.expected_sequence_index = 1;
  return v;
}

bool GrpcTokenProvider::ReportDecision(const std::string &robot_id,
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
  return false;  // no transport in stub build — nothing was delivered (fail-closed, visible)
}

bool GrpcTokenProvider::ReportDecisionIdentified(const std::string &robot_id,const std::string &chain_id,
    const std::string &token_id,const std::string &decision,const std::string &reason_code,
    bool step_complete,bool fatal,const std::string &detail,const std::string &report_id){
 (void)report_id;return ReportDecision(robot_id,chain_id,token_id,decision,reason_code,step_complete,fatal,detail);
}

ReportOutcome GrpcTokenProvider::ReportFatalOutcome(const std::string &robot,const std::string &chain,
 const std::string &token,const std::string &decision,const std::string &reason,
 const std::string &detail,const std::string &id){
 return ReportDecisionIdentified(robot,chain,token,decision,reason,false,true,detail,id)?ReportOutcome::Confirmed:ReportOutcome::Retry;
}

void GrpcTokenProvider::ShutdownAttestation(){}

std::string GrpcTokenProvider::Attest(const std::string &robot_id,
                                      const std::string &component,
                                      const std::string &measurement_sha256,
                                      const std::string &build_info) {
  (void)robot_id;
  (void)component;
  (void)measurement_sha256;
  (void)build_info;
  return "ERROR"; // no transport in stub build — fail-closed
}

} // namespace pail_pep_gate
