#include "core_report.hpp"
#include <atomic>
#include <mutex>
#include "pail_gate/report_identity.hpp"
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_pep_gate/token_provider_grpc.hpp"

#include "pail_pep_gate/env_strict.hpp"
#include "pail_pep_gate/grpc_channel.hpp"

#include <grpcpp/grpcpp.h>

// Generated headers (when protoc is run per codex_spec/29_CPP_GRPC_STUBS.md)
#include "token_service.grpc.pb.h"
#include "token_service.pb.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <utility>
#include <random>
#include <iterator>

namespace pail_pep_gate {
namespace {

// [AV1] Without a deadline a single stalled issuer blocks this call for as long
// as the stall lasts (AV0-1 measured 1458ms on a 2s stall) — and it does so on
// the ROS callback thread, starving the 20Hz permit heartbeat whose deadman is
// 100ms. The deadline must stay below the recheck period so one slow answer
// cannot push out the next one.
//
// DC-13 : strict parse, measured bounds. hi=200 is derived,
// not invented: 2 x permit_deadline_ms(100) silence window
// (motion_bridge_node.cpp:27,:100) — one RPC may never outlive the window it
// is supposed to protect. The static caches the value validated at startup
// (GrpcTokenProvider ctor) so a mid-run env edit cannot re-parse.
std::chrono::milliseconds RpcDeadline() {
  static const int ms = EnvIntStrict("PAIL_RPC_DEADLINE_MS", 50, 5, 200);
  return std::chrono::milliseconds(ms);
}

// Attest is a one-shot at start-up and its failure keeps the robot down in
// required mode, so it gets a much longer budget than the steady-state RPCs.
// It runs off the callback thread, hence the independent 30000 ceiling.
std::chrono::milliseconds AttestDeadline() {
  static const int ms = EnvIntStrict("PAIL_ATTEST_DEADLINE_MS", 2000, 5, 30000);
  return std::chrono::milliseconds(ms);
}

// P15-H1 (TB3 judge2 scene 8, 2026-10-16): a fatal report revokes the chain at
// the issuer. It used to ride the 50 ms command-path deadline and its result was
// discarded; one lost RPC left the chain active, and the same token was granted
// again when safety returned to OK. A fatal report is sent off the callback
// thread (fatal_report_worker.hpp) and retried until confirmed, so it gets its
// own budget — the stop is already out before it is sent, nothing waits on it.
std::chrono::milliseconds FatalReportDeadline() {
  static const int ms = EnvIntStrict("PAIL_FATAL_REPORT_DEADLINE_MS", 2000, 50, 30000);
  return std::chrono::milliseconds(ms);
}

std::string ExecutionID() {
  std::random_device random;
  static const char hex[] = "0123456789abcdef";
  std::string id; id.reserve(32);
  for (int i=0;i<16;++i) { auto b=random() & 255u; id.push_back(hex[b>>4]); id.push_back(hex[b&15]); }
  return id;
}

void SetDeadline(grpc::ClientContext *ctx, std::chrono::milliseconds d) {
  ctx->set_deadline(std::chrono::system_clock::now() + d);
}

}  // namespace

// Minimal adapter for TokenService RPCs.
class GrpcTokenProvider::TokenServiceClient {
 public:
  TokenServiceClient(std::shared_ptr<grpc::Channel> ch, bool core_contract)
      : stub_(pail::token::v1::TokenService::NewStub(std::move(ch))), core_contract_(core_contract) {}

  ActiveTokenView GetActiveToken(const std::string &robot_id) {
    ActiveTokenView out;

    pail::token::v1::GetActiveTokenRequest req;
    req.set_robot_id(robot_id);

    pail::token::v1::GetActiveTokenResponse resp;
    grpc::ClientContext ctx;
    SetDeadline(&ctx, RpcDeadline());
    ctx.AddMetadata("pail-execution-instance", execution_id_);

    auto status = stub_->GetActiveToken(&ctx, req, &resp);
    if (!status.ok()) {
      out.ok = false;
      // [AV1] The issuer did not answer. Distinguished from a negative answer so
      // the node can apply the grace window (AV LLD §1.2).
      out.status = "UNREACHABLE";
      return out;
    }

    const auto &headers=ctx.GetServerInitialMetadata();
    auto range=headers.equal_range("pail-execution-instance");
    auto bound=range.first;
    if (bound==range.second || std::next(bound)!=range.second || std::string(bound->second.data(),bound->second.length())!=execution_id_) {
      out.ok=false; out.status="ERROR"; return out; // no capability downgrade to an older gateway
    }

    if (resp.status() != pail::token::v1::OK) {
      out.ok = false;
      switch (resp.status()) {
        case pail::token::v1::NO_TOKEN: out.status = "NO_TOKEN"; break;
        case pail::token::v1::REVOKED:  out.status = "REVOKED";  break;
        default:                        out.status = "ERROR";    break;
      }
      out.chain_id = resp.chain_id();
      out.expected_sequence_index = resp.expected_sequence_index();
      return out;
    }

    out.ok = true;
    out.status = "OK";
    out.chain_id = resp.chain_id();
    out.expected_sequence_index = resp.expected_sequence_index();
    out.current_subgraph_hash = resp.current_subgraph_hash();

    if (resp.has_token()) {
      const auto &st = resp.token();

      // v2 (LLD-v2 §1.1): use the exact issuer-signed bytes. Never re-serialize
      // (proto3 serialization is not canonical; re-serialization enables the
      // old-stub unknown-field bypass). Empty bytes => strict verify fails closed.
      out.action_token_bytes = st.action_token_bytes();
      out.signature_bytes = st.signature();
      out.key_id_bytes = st.key_id();
      out.signed_token_bytes = st.SerializeAsString();

      // [E-W2 / F-PR-12] token_id comes from the bytes the signature covers,
      // never from SignedToken.token — pail.proto:206 calls that copy
      // "informational only" and :210 tells verifiers to read decision-relevant
      // fields from Unmarshal(action_token_bytes). Parsing is not verifying;
      // what it buys is that the name carried here is the one strict verify
      // will bind, so whoever delivers the response can no longer restate it
      // beside the signature.
      pail::v1::ActionToken signed_token;
      if (out.action_token_bytes.empty() ||
          !signed_token.ParseFromString(out.action_token_bytes)) {
        // Fail-closed. Bytes that do not parse can never verify, so refusing
        // here changes no legitimate outcome — it only stops an empty token_id
        // from travelling on as if the issuer had answered.
        out.ok = false;
        out.status = "ERROR";
        out.token_id.clear();
        return out;
      }
      out.token_id = signed_token.token_id();
    }
    return out;
  }

  bool ReportDecision(const std::string &robot_id, const std::string &chain_id, const std::string &token_id,
                      const std::string &decision, const std::string &reason_code,
                      bool step_complete, bool fatal, const std::string &evidence_provenance,
                      const std::string &effective_mode, const std::string &detail, const std::string &report_id = {}, bool *terminal = nullptr) {
    if(terminal)*terminal=false;
    pail::token::v1::ReportDecisionRequest req;
    req.set_detail(detail);  // SK-3: completion signal / block detail
    req.set_robot_id(robot_id);
    req.set_chain_id(chain_id);
    req.set_token_id(token_id);
    req.set_reason_code(reason_code);
    req.set_step_complete(step_complete);
    req.set_fatal(fatal);
    // [C-B12 O-3] Empty (node never told us) stays empty on the wire — the
    // journal then omits the key rather than claiming a state it was not told.
    req.set_evidence_provenance(evidence_provenance);
    // [implementation contract D-S5] Same honest-record rule as above.
    req.set_effective_mode(effective_mode);

    if (decision == "PERMIT") {
      req.set_decision(pail::token::v1::PERMIT);
    } else if (decision == "ESTOP") {
      req.set_decision(pail::token::v1::ESTOP);
    } else {
      req.set_decision(pail::token::v1::BLOCK);
    }

    const bool core = core_contract_;
    if(core){
      req.set_report_id(report_id.empty()?execution_id_+"-"+std::to_string(++report_seq_):report_id);
      req.set_receipt_contract_version(1);
      try{req.set_report_digest(pail_core_comm::Digest(req));}catch(const std::exception&){return false;}
    }
    pail::token::v1::ReportDecisionResponse resp;
    grpc::ClientContext ctx;
    SetDeadline(&ctx, fatal ? FatalReportDeadline() : RpcDeadline());
    const auto status = stub_->ReportDecision(&ctx, req, &resp);
    // Confirmed only when the issuer answered and accepted. A transport failure, a
    // deadline, or accepted=false all read as "not confirmed" (H-B2: the caller must
    // not mistake an unanswered report for a delivered one).
    if(!status.ok())return false;
    if(!core)return resp.accepted();
    if(!resp.has_receipt())return false;
    const auto &r=resp.receipt();
    if(r.contract_version()!=1||r.report_id()!=req.report_id()||r.report_digest()!=req.report_digest()||r.robot_id()!=robot_id||r.receiver_instance_id().empty())return false;
    if(!resp.accepted()){
      if(terminal && r.storage()==pail::token::v1::ISSUER_DURABLE && !r.journal_record_ref().empty() &&
         r.disposition()==pail::token::v1::TERMINAL_REJECTED &&
         (r.effect()==pail::token::v1::REJECTED||r.effect()==pail::token::v1::UNKNOWN))*terminal=true;
      return false;
    }
    const bool disposition=r.disposition()==pail::token::v1::NEW||r.disposition()==pail::token::v1::DUPLICATE||
      (step_complete&&!fatal&&r.storage()==pail::token::v1::LOCAL_DURABLE&&r.effect_scope()==pail::token::v1::LOCAL_LEASE&&r.disposition()==pail::token::v1::RETRYABLE);
    if(!disposition)return false;
    if(fatal)return r.storage()==pail::token::v1::ISSUER_DURABLE && r.effect()==pail::token::v1::APPLIED && r.effect_scope()==pail::token::v1::ISSUER_CHAIN && !r.journal_record_ref().empty();
    if(step_complete)return (r.storage()==pail::token::v1::LOCAL_DURABLE||r.storage()==pail::token::v1::ISSUER_DURABLE)&&r.effect()==pail::token::v1::APPLIED;
    return (r.storage()==pail::token::v1::LOCAL_BUFFERED||r.storage()==pail::token::v1::LOCAL_DURABLE||r.storage()==pail::token::v1::ISSUER_DURABLE)&&(r.effect()==pail::token::v1::NOT_APPLICABLE||r.effect()==pail::token::v1::APPLIED);
  }

  std::string Attest(const std::string &robot_id, const std::string &component,
                     const std::string &measurement_sha256, const std::string &build_info) {
    pail::token::v1::AttestRequest req;
    req.set_robot_id(robot_id);
    req.set_component(component);
    req.set_measurement_sha256(measurement_sha256);
    req.set_build_info(build_info);

    pail::token::v1::AttestResponse resp;
    auto ctx=std::make_shared<grpc::ClientContext>();
    SetDeadline(ctx.get(), AttestDeadline());
    {std::lock_guard<std::mutex> lock(attest_mu_);if(attest_stopped_)return "ERROR";attest_context_=ctx;}
    auto status = stub_->Attest(ctx.get(), req, &resp);
    {std::lock_guard<std::mutex> lock(attest_mu_);if(attest_context_==ctx)attest_context_.reset();}
    if (!status.ok()) return "ERROR"; // transport failure => fail-closed
    return resp.status();
  }

  void ShutdownAttestation(){
    std::lock_guard<std::mutex> lock(attest_mu_);attest_stopped_=true;
    if(attest_context_)attest_context_->TryCancel();
  }
 private:
  std::mutex attest_mu_;bool attest_stopped_{false};
  std::shared_ptr<grpc::ClientContext> attest_context_;
  std::unique_ptr<pail::token::v1::TokenService::Stub> stub_;
  const std::string execution_id_{ExecutionID()};
  std::atomic<uint64_t> report_seq_{0};
  const bool core_contract_;  // decided by the node (core_contract.hpp), not read from the environment here
};

GrpcTokenProvider::GrpcTokenProvider(std::string addr, bool core_contract) : addr_(std::move(addr)), core_contract_(core_contract) {
  // DC-13: force both deadlines through the strict parser *now*, at node
  // startup, so a malformed env refuses to start (exit 78) instead of
  // surfacing on the first RPC minutes later with a robot already moving.
  RpcDeadline();
  AttestDeadline();
  FatalReportDeadline();
  channel_ = MakeControlChannel(addr_);
  // Start the TLS connection before the first command rather than charging its
  // handshake to the real-time 50ms RPC budget. Offline startup still fails
  // closed on commands; this bounded warmup grants no token and sends no motion.
  const bool connected = channel_->WaitForConnected(std::chrono::system_clock::now() + std::chrono::seconds(5));
  std::fprintf(stderr, "PAIL_TOKEN_TRANSPORT: startup connected=%s (command deadline unchanged)\n", connected ? "true" : "false");
  client_ = std::make_unique<TokenServiceClient>(channel_, core_contract_);
}

GrpcTokenProvider::~GrpcTokenProvider() = default;

ActiveTokenView GrpcTokenProvider::GetActiveToken(const std::string &robot_id) {
  return client_->GetActiveToken(robot_id);
}

bool GrpcTokenProvider::ReportDecision(const std::string &robot_id, const std::string &chain_id,
                                      const std::string &token_id, const std::string &decision,
                                      const std::string &reason_code, bool step_complete, bool fatal,
                                      const std::string &detail) {
  return client_->ReportDecision(robot_id, chain_id, token_id, decision, reason_code, step_complete, fatal,
                                 evidence_provenance_, effective_mode_, detail);
}

bool GrpcTokenProvider::ReportDecisionIdentified(const std::string &robot_id,const std::string &chain_id,
    const std::string &token_id,const std::string &decision,const std::string &reason_code,
    bool step_complete,bool fatal,const std::string &detail,const std::string &report_id){
  return client_->ReportDecision(robot_id,chain_id,token_id,decision,reason_code,step_complete,fatal,evidence_provenance_,effective_mode_,detail,report_id);
}

ReportOutcome GrpcTokenProvider::ReportFatalOutcome(const std::string &robot,const std::string &chain,
 const std::string &token,const std::string &decision,const std::string &reason,
 const std::string &detail,const std::string &id){
 bool terminal=false;
 bool ok=client_->ReportDecision(robot,chain,token,decision,reason,false,true,evidence_provenance_,effective_mode_,detail,id,&terminal);
 return ok?ReportOutcome::Confirmed:(terminal?ReportOutcome::TerminalUnconfirmed:ReportOutcome::Retry);
}

void GrpcTokenProvider::ShutdownAttestation(){client_->ShutdownAttestation();}

std::string GrpcTokenProvider::Attest(const std::string &robot_id, const std::string &component,
                                      const std::string &measurement_sha256,
                                      const std::string &build_info) {
  return client_->Attest(robot_id, component, measurement_sha256, build_info);
}

} // namespace pail_pep_gate
