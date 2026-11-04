// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#pragma once

#include <string>

namespace pail_pep_gate {

// [OR3/X12②] Everything here is ENVELOPE-derived: it arrives beside the
// signature, not under it, so any field can be restated by whoever delivers
// the response. The verified counterparts live in VerifiedTokenInfo and are
// the only ones a decision may rest on.
struct ActiveTokenView {
  bool ok{false};
  std::string chain_id;
  std::string token_id;
  // Envelope-derived; do not decide on it. Nothing reads it today — and the
  // verified sequence_index in VerifiedTokenInfo is what a future reader wants.
  int expected_sequence_index{1};

  // Raw bytes for strict verification (Phase 2 Step 2).
  // These are the exact bytes received from TokenService.
  // - action_token_bytes = proto.Marshal(ActionToken)
  // - signature_bytes = SignedToken.signature
  // - key_id_bytes = SignedToken.key_id
  // - signed_token_bytes (optional) = proto.Marshal(SignedToken)
  std::string action_token_bytes;
  std::string signature_bytes;
  std::string key_id_bytes;
  std::string signed_token_bytes;

  // [AG-2/CR3] Issuer-side re-derivation of this step's authorization-subgraph
  // hash in the CURRENT world (GetActiveTokenResponse.current_subgraph_hash).
  // Empty when the issuer runs without a site model — comparison is skipped.
  std::string current_subgraph_hash;

  // [AV1] UNREACHABLE = the issuer never answered (transport failure or RPC
  // deadline). It is not a negative answer, and it is the only status eligible
  // for the permit grace window (AV LLD §1.2).
  std::string status; // OK|NO_TOKEN|REVOKED|ERROR|UNREACHABLE
};

enum class ReportOutcome { Confirmed, Retry, TerminalUnconfirmed };

class ITokenProvider {
public:
  virtual ~ITokenProvider() = default;
  virtual ActiveTokenView GetActiveToken(const std::string &robot_id) = 0;
  // [v2/M3] step_complete: PERMIT report that completes the step (consumes the
  // token / advances the issuer sequence). fatal: BLOCK/ESTOP that revokes the
  // whole chain. Both false = no issuer state transition (LLD-v2 §1.2).
  // Returns true only when the recipient confirmed the report (issuer answered
  // accepted=true). P15-H1: the result used to be discarded, so a fatal report
  // lost on its single RPC left the chain active at the issuer; the node now
  // retries a fatal until this returns true (fatal_report_worker.hpp). Providers
  // without an issuer (static, notoken) return true: there is no recipient whose
  // confirmation could be outstanding, and the session's own latch is the record.
  virtual bool ReportDecision(const std::string &robot_id,
                              const std::string &chain_id,
                              const std::string &token_id,
                              const std::string &decision,  // PERMIT|BLOCK|ESTOP
                              const std::string &reason_code,
                              bool step_complete,
                              bool fatal,
                              const std::string &detail) = 0;  // SK-3: completion signal / block detail

  // [AS-2] PEP self-attestation (HA/AT LLD §6). The gate streams its own
  // sha256(/proc/self/exe) so the issuer can verify the running binary before
  // trusting it. Returns the issuer verdict "OK|UNKNOWN_MEASUREMENT|ERROR"
  // (transport failure => "ERROR"). Non-issuer providers no-op with "OK".
  virtual std::string Attest(const std::string &robot_id,
                             const std::string &component,
                             const std::string &measurement_sha256,
                             const std::string &build_info) = 0;

  // Stable event identity is assigned by the owning worker, not by a retry.
  virtual bool ReportDecisionIdentified(const std::string &robot_id,const std::string &chain_id,
      const std::string &token_id,const std::string &decision,const std::string &reason_code,
      bool step_complete,bool fatal,const std::string &detail,const std::string &report_id) {
    (void)report_id;
    return ReportDecision(robot_id,chain_id,token_id,decision,reason_code,step_complete,fatal,detail);
  }

  virtual ReportOutcome ReportFatalOutcome(const std::string &robot_id,const std::string &chain_id,
      const std::string &token_id,const std::string &decision,const std::string &reason_code,
      const std::string &detail,const std::string &report_id) {
    return ReportDecisionIdentified(robot_id,chain_id,token_id,decision,reason_code,false,true,detail,report_id)
      ? ReportOutcome::Confirmed : ReportOutcome::Retry;
  }
  // Lifecycle cancellation only: never cancels command or fatal-report RPCs.
  virtual void ShutdownAttestation() {}


};

// Safe default provider used until TokenService client is implemented.
class NoTokenProvider final : public ITokenProvider {
public:
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
};

} // namespace pail_pep_gate
