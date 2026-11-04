// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#pragma once

#include <memory>
#include <string>
#include <utility>

#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
#include <grpcpp/channel.h>
#else
namespace grpc {
class Channel;
} // namespace grpc
#endif

#include "pail_gate/token_provider.hpp"

namespace pail_pep_gate {

// GrpcTokenProvider is a placeholder implementation.
// Codex must replace this with a real gRPC client using proto/token_service.proto.
class GrpcTokenProvider final : public ITokenProvider {
public:
  // core_contract: stamp every decision report as C1 (report_id, contract version 1, digest). The node parses
  // PAIL_CORE_COMM_CONTRACT once and passes the result; the provider does not read the environment (RV11).
  explicit GrpcTokenProvider(std::string addr, bool core_contract = true);
  ~GrpcTokenProvider();

  ActiveTokenView GetActiveToken(const std::string &robot_id) override;

  // A fatal report runs under PAIL_FATAL_REPORT_DEADLINE_MS (default 2000), not the
  // 50 ms command-path deadline: it is sent off the callback thread by the node's
  // fatal_report_worker and retried until this returns true (P15-H1).
  bool ReportDecision(const std::string &robot_id,
                      const std::string &chain_id,
                      const std::string &token_id,
                      const std::string &decision,
                      const std::string &reason_code,
                      bool step_complete,
                      bool fatal,
                      const std::string &detail) override;

  bool ReportDecisionIdentified(const std::string &robot_id,const std::string &chain_id,
      const std::string &token_id,const std::string &decision,const std::string &reason_code,
      bool step_complete,bool fatal,const std::string &detail,const std::string &report_id) override;

  ReportOutcome ReportFatalOutcome(const std::string&,const std::string&,const std::string&,
    const std::string&,const std::string&,const std::string&,const std::string&) override;

  void ShutdownAttestation() override;

  std::string Attest(const std::string &robot_id,
                     const std::string &component,
                     const std::string &measurement_sha256,
                     const std::string &build_info) override;

  // [OSSB-D C-B12 O-3] Process-constant provenance of the evidence plane's
  // sender authentication, sent with every ReportDecision. "enforced" only
  // when SROS2 is on AND the strategy is Enforce — Permissive silently
  // permits unsecured participants, so enable alone is not enforcement.
  void SetEvidenceProvenance(std::string p) { evidence_provenance_ = std::move(p); }

  // [implementation contract D-S5] Process-constant mode stamp (D-S7: read once at
  // startup, no runtime switch), sent with every ReportDecision. Same
  // honest-record wiring as evidence_provenance: empty stays empty on the
  // wire and the journal omits the key (H-B2).
  void SetEffectiveMode(std::string m) { effective_mode_ = std::move(m); }

private:
  std::string addr_;
  const bool core_contract_;  // C1 stamp on every report; decided by the node, never read from the environment here
  std::string evidence_provenance_;
  std::string effective_mode_;

#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
  std::shared_ptr<grpc::Channel> channel_;
  class TokenServiceClient;
  std::unique_ptr<TokenServiceClient> client_;
#endif
};

} // namespace pail_pep_gate
