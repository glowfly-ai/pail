// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_gate/pail_gate.h"

#include <cstdlib>
#include <cstring>
#include <string>

#include "pail.pb.h"
#include "pail_gate_abi.pb.h"
#include "token_service.pb.h"

#include "pail_gate/gate_session.hpp"
#include "pail_gate/keyring_bundle.hpp"
#include "pail_gate/policy_load.hpp"

namespace abi = pail::gate::abi::v1;
using pail_pep_gate::ActiveTokenView;
using pail_pep_gate::GateSession;

struct pail_gate {
  GateSession *session{nullptr};
  std::string keyring_mode;
  std::string keyring_error;
};

namespace {

char *DupString(const std::string &s) {
  char *p = static_cast<char *>(std::malloc(s.size() + 1));
  if (!p) return nullptr;
  std::memcpy(p, s.data(), s.size());
  p[s.size()] = '\0';
  return p;
}

int Emit(const google::protobuf::MessageLite &m, uint8_t **out, size_t *out_len) {
  if (!out || !out_len) return PAIL_GATE_EINTERNAL;
  std::string bytes;
  if (!m.SerializeToString(&bytes)) return PAIL_GATE_EINTERNAL;
  uint8_t *p = static_cast<uint8_t *>(std::malloc(bytes.size() ? bytes.size() : 1));
  if (!p) return PAIL_GATE_EINTERNAL;
  std::memcpy(p, bytes.data(), bytes.size());
  *out = p;
  *out_len = bytes.size();
  return PAIL_GATE_OK;
}

void Fill(abi::Outcome *o, const pail_pep_gate::SessionOutcome &s) {
  o->set_path(s.path);
  o->set_state(s.decision.state);
  o->set_reason(s.decision.reason);
  o->set_detail(s.decision.detail);  // SK-2
  o->set_forward(s.decision.forward);
  o->set_report(s.decision.report);
  o->set_report_chain_id(s.report_chain_id);
  o->set_report_token_id(s.report_token_id);
  o->set_step_complete(s.decision.step_complete);
  o->set_fatal(s.decision.fatal);
  o->set_permit_active(s.permit_active);
  o->set_step_active(s.step_active);
  o->set_estop_active(s.estop_active);
  o->set_unreachable_streak(s.unreachable_streak);
  o->set_effective_mode(s.effective_mode);
  o->set_hold_permit(s.decision.hold_permit);
  o->set_fired(s.fired);
  o->set_enter_permit(s.decision.enter_permit);
  o->set_stop_permit(s.decision.stop_permit);
  o->set_begin_step(s.decision.begin_step);
}

// GrpcTokenProvider::GetActiveToken's response → view translation (token_provider_grpc.cpp),
// restated for a caller that holds the response bytes instead of the channel. Same three
// outcomes: transport failure → UNREACHABLE; non-OK status → that status with the envelope's
// chain id; OK → the bytes, with token_id taken from the SIGNED bytes, never the envelope.
ActiveTokenView ViewFromResponse(bool reachable, const pail::token::v1::GetActiveTokenResponse &resp) {
  ActiveTokenView out;
  if (!reachable) {
    out.ok = false;
    out.status = "UNREACHABLE";
    return out;
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
    out.action_token_bytes = st.action_token_bytes();
    out.signature_bytes = st.signature();
    out.key_id_bytes = st.key_id();
    out.signed_token_bytes = st.SerializeAsString();
    pail::v1::ActionToken signed_token;
    if (out.action_token_bytes.empty() || !signed_token.ParseFromString(out.action_token_bytes)) {
      out.ok = false;
      out.status = "ERROR";
      out.token_id.clear();
      return out;
    }
    out.token_id = signed_token.token_id();
  }
  return out;
}

}  // namespace

extern "C" {

uint32_t pail_gate_abi_version(void) { return PAIL_GATE_ABI_VERSION; }

pail_gate_t *pail_gate_new(const uint8_t *in, size_t in_len, char **err) {
  if (err) *err = nullptr;
  abi::Config cfg;
  if (!in || !cfg.ParseFromArray(in, static_cast<int>(in_len))) {
    if (err) *err = DupString("EPARSE: Config did not parse");
    return nullptr;
  }
  if (cfg.robot_id().empty()) {
    if (err) *err = DupString("CONFIG_INCOMPLETE robot_id is empty");
    return nullptr;
  }
  pail_pep_gate::SessionPolicy policy;
  std::string perr;
  if (!pail_pep_gate::LoadSessionPolicy(cfg.policy_path(), &policy, &perr)) {
    if (err) *err = DupString(perr);
    return nullptr;
  }
  pail_pep_gate::SessionConfig sc;
  sc.robot_id = cfg.robot_id();
  if (!cfg.provider_mode().empty()) sc.provider_mode = cfg.provider_mode();
  sc.use_token_service = (sc.provider_mode == "grpc");
  sc.grpc_built = true;
  if (cfg.permit_grace_n() > 0) sc.permit_grace_n = cfg.permit_grace_n();
  if (cfg.clock_skew_ms() > 0) sc.clock_skew_ms = cfg.clock_skew_ms();
  sc.static_target_object_id = cfg.static_target_object_id();
  sc.config_digest = cfg.config_digest();
  sc.skills_file = cfg.skills_file();  // SK-3
  sc.robot_class = cfg.robot_class();

  // KM2-1 trust path exactly as the node loads it (pep_gate_node.cpp:185): the signed bundle
  // by default, unsigned keyring.json only under PAIL_KEYRING_MODE=unsigned-dev. A failed
  // load leaves the trust map empty — every token then fails verification (fail-closed).
  std::string kr_mode, kr_reason;
  const std::string legacy = cfg.keyring_path().empty() ? "/etc/pail/keys/keyring.json" : cfg.keyring_path();
  pail_pep_gate::Keyring keyring = pail_pep_gate::LoadTrustedKeyring(legacy, &kr_mode, &kr_reason);

  auto *h = new pail_gate;
  h->session = new GateSession(sc, policy, keyring);
  h->keyring_mode = kr_mode;
  h->keyring_error = kr_reason;
  return h;
}

void pail_gate_free(pail_gate_t *h) {
  if (!h) return;
  delete h->session;
  delete h;
}

int pail_gate_set_token(pail_gate_t *h, const uint8_t *in, size_t in_len) {
  if (!h || !h->session) return PAIL_GATE_EHANDLE;
  abi::TokenInput t;
  if (!in || !t.ParseFromArray(in, static_cast<int>(in_len))) return PAIL_GATE_EPARSE;
  h->session->SetTokenView(ViewFromResponse(t.reachable(), t.response()));
  return PAIL_GATE_OK;
}

int pail_gate_observe_safety(pail_gate_t *h, const uint8_t *in, size_t in_len,
                             uint8_t **out, size_t *out_len) {
  if (!h || !h->session) return PAIL_GATE_EHANDLE;
  abi::SafetyInput s;
  if (!in || !s.ParseFromArray(in, static_cast<int>(in_len))) return PAIL_GATE_EPARSE;
  pail_pep_gate::SafetyObservation obs;
  obs.level = s.level();
  obs.source = s.source();
  obs.detail = s.detail();
  obs.observed_ms = s.observed_ms();
  abi::Outcome o;
  Fill(&o, h->session->ObserveSafety(obs));
  return Emit(o, out, out_len);
}

int pail_gate_observe_evidence(pail_gate_t *h, const uint8_t *in, size_t in_len) {
  if (!h || !h->session) return PAIL_GATE_EHANDLE;
  abi::EvidenceInput e;
  if (!in || !e.ParseFromArray(in, static_cast<int>(in_len))) return PAIL_GATE_EPARSE;
  pail_pep_gate::EvidenceObservation obs;
  obs.object_id = e.object_id();
  obs.confidence = e.confidence();
  obs.source = e.source();
  obs.received_ms = e.received_ms();
  h->session->ObserveEvidence(obs);
  return PAIL_GATE_OK;
}

int pail_gate_command(pail_gate_t *h, const uint8_t *in, size_t in_len,
                      uint8_t **out, size_t *out_len) {
  if (!h || !h->session) return PAIL_GATE_EHANDLE;
  abi::CommandInput c;
  if (!in || !c.ParseFromArray(in, static_cast<int>(in_len))) return PAIL_GATE_EPARSE;
  pail_pep_gate::CommandRequest cmd;
  cmd.linear_norm = c.linear_norm();
  cmd.angular_norm = c.angular_norm();
  if (c.requested_class() != 0) cmd.requested_class = c.requested_class();
  cmd.skill = c.skill();  // SK-4: empty = the caller did not say (a v5 token refuses it)
  for (const auto &kv : c.measured()) cmd.measured[kv.first] = kv.second;  // SK-2
  abi::Outcome o;
  Fill(&o, h->session->OnCommand(cmd, c.now_ms()));
  return Emit(o, out, out_len);
}

int pail_gate_complete_step(pail_gate_t *h, const uint8_t *in, size_t in_len,
                            uint8_t **out, size_t *out_len) {
  if (!h || !h->session) return PAIL_GATE_EHANDLE;
  abi::CompleteInput c;
  if (!in || !c.ParseFromArray(in, static_cast<int>(in_len))) return PAIL_GATE_EPARSE;
  abi::Outcome o;
  Fill(&o, h->session->CompleteStep(c.now_ms(), c.skill()));
  return Emit(o, out, out_len);
}

int pail_gate_tick(pail_gate_t *h, const uint8_t *in, size_t in_len,
                   uint8_t **out, size_t *out_len) {
  if (!h || !h->session) return PAIL_GATE_EHANDLE;
  abi::TickInput t;
  if (!in || !t.ParseFromArray(in, static_cast<int>(in_len))) return PAIL_GATE_EPARSE;
  abi::TickOutcome o;
  // SEC-H02: take up a bundle placed beside the running gate before judging with the keys.
  // No new call and no new message: an adapter that ticks gets revocations and renewals.
  // The result shows in pail_gate_info (keys, revoked_keys) and in the decisions.
  const pail_pep_gate::TrustApplyResult trust = h->session->PollTrust();
  if (trust.outcome == pail_pep_gate::TrustApply::Applied) h->keyring_error = trust.reason;
  // GC-TIME-1: service an ordinary completion before rechecking its permit.
  // Otherwise every on-time tick would manufacture ERR_CONSTRAINT first.
  // OnRecheck still enforces duration independently if a timer is absent/late.
  Fill(o.mutable_step(), h->session->OnStepTimer(t.now_ms()));
  Fill(o.mutable_recheck(), h->session->OnRecheck(t.now_ms()));
  return Emit(o, out, out_len);
}

int pail_gate_info(pail_gate_t *h, uint8_t **out, size_t *out_len) {
  if (!h || !h->session) return PAIL_GATE_EHANDLE;
  const auto &p = h->session->policy();
  abi::Info i;
  i.set_abi_version(PAIL_GATE_ABI_VERSION);
  i.set_gate_mode(p.gate_mode);
  i.set_human_safety_enabled(p.human_safety_enabled);
  i.set_min_trust_rank(p.min_trust_rank);
  i.set_safety_stale_ms(p.safety_stale_ms);
  i.set_evidence_window_ms(p.evidence_window_ms);
  i.set_evidence_conf_threshold(p.evidence_conf_threshold);
  i.set_safety_exempt_in_progress_step(p.safety_exempt_in_progress_step);
  i.set_keys(static_cast<uint32_t>(h->session->keyring().pubkeys.size()));
  i.set_revoked_keys(static_cast<uint32_t>(h->session->keyring().revoked.size()));
  i.set_keyring_mode(h->keyring_mode);
  i.set_keyring_error(h->keyring_error);
  i.set_permit_active(h->session->permit_active());
  i.set_step_active(h->session->step_active());
  i.set_estop_active(h->session->estop_active());
  i.set_unreachable_streak(h->session->unreachable_streak());
  i.set_consumed_size(static_cast<uint32_t>(h->session->consumed_size()));
  return Emit(i, out, out_len);
}

void pail_gate_free_buf(void *p) { std::free(p); }

}  // extern "C"
