// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_gate/gate_session.hpp"

#include <sys/stat.h>

#include "pail_gate/safety_level.hpp"
#include "pail_gate/strict_verify.hpp"

namespace pail_pep_gate {

GateSession::GateSession(SessionConfig cfg, SessionPolicy policy, Keyring keyring)
    : cfg_(std::move(cfg)), policy_(std::move(policy)), keyring_(std::move(keyring)) {
  // SK-3: the registry is what the completion rules read. A file that fails to load
  // leaves the session with no rows (every step completes by its deadline) and the
  // reason kept — the caller's preflight (S33) decides whether that is a refusal.
  if (!cfg_.skills_file.empty()) {
    if (!LoadSkillRegistry(cfg_.skills_file, cfg_.robot_class, &skills_, &skills_error_)) {
      skills_ = SkillRegistryView{};
    }
  }
}

GateSession::GateSession(SessionConfig cfg, SessionPolicy policy, Keyring keyring, SkillRegistryView loaded_skills)
    : cfg_(std::move(cfg)), policy_(std::move(policy)), keyring_(std::move(keyring)), skills_(std::move(loaded_skills)) {}

void GateSession::SetTokenView(const ActiveTokenView &view) { token_view_ = view; }

bool GateSession::TrustExpired() const {
  // The wall clock the session reads itself (DC-8) — the clock token validity is judged
  // on. Not now_ms: that value is handed in by the caller.
  return keyring_.expires_at_unix > 0 && WallNowMs() / 1000 >= static_cast<int64_t>(keyring_.expires_at_unix);
}

TrustApplyResult GateSession::PollTrust() {
  TrustApplyResult unchanged;
  unchanged.version = keyring_.bundle_version;
  unchanged.expires_at_unix = keyring_.expires_at_unix;
  const std::string &path = keyring_.source.bundle_path;
  if (path.empty()) return unchanged;
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0) return unchanged;   // nothing placed (or not readable): keep judging as before
#if defined(__APPLE__)
  const int64_t mtime_ns = static_cast<int64_t>(st.st_mtimespec.tv_sec) * 1000000000LL + st.st_mtimespec.tv_nsec;
#else
  const int64_t mtime_ns = static_cast<int64_t>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
#endif
  const bool same = trust_seen_ && trust_seen_ino_ == static_cast<uint64_t>(st.st_ino) &&
                    trust_seen_size_ == static_cast<int64_t>(st.st_size) && trust_seen_mtime_ns_ == mtime_ns;
  if (same) return unchanged;
  const bool first_look = !trust_seen_;
  trust_seen_ = true;
  trust_seen_ino_ = static_cast<uint64_t>(st.st_ino);
  trust_seen_size_ = static_cast<int64_t>(st.st_size);
  trust_seen_mtime_ns_ = mtime_ns;
  TrustApplyResult r = ApplyPlacedBundle(&keyring_);
  // The first look sees the file the keyring was loaded from: same version, Unchanged.
  // Reported as such — a refusal can only be news once something was placed.
  (void)first_look;
  return r;
}

void GateSession::ObserveEvidence(const EvidenceObservation &obs) {
  // pep_gate_node.cpp on_evidence: the only place ever_received becomes true (D-L7 §6.4).
  last_evidence_ = obs;
  if (last_evidence_.received_ms <= 0) last_evidence_.received_ms = WallNowMs();
  evidence_ever_received_ = true;
}

void GateSession::Stamp(SessionOutcome *o) const {
  o->permit_active = permit_active_;
  o->step_active = step_active_;
  o->estop_active = estop_active_;
  o->unreachable_streak = unreachable_streak_;
  o->effective_mode = policy_.gate_mode;
}

SessionOutcome GateSession::ObserveSafety(const SafetyObservation &obs) {
  // pep_gate_node.cpp on_safety_state (DC-8: judgment input on the wall clock).
  last_safety_ms_ = obs.observed_ms > 0 ? obs.observed_ms : WallNowMs();
  safety_ever_received_ = true;
  const SafetyLevel level = ParseSafetyLevel(obs.level);
  safety_level_ = obs.level;
  SessionOutcome o;
  o.path = "safety";
  switch (EstopActionFor(level)) {
    case EstopAction::kTrigger:
      if (!estop_active_) {
        // pep_gate_node.cpp trigger_estop.
        estop_active_ = true;
        const bool had_permit = permit_active_;
        std::string chain_id = permit_chain_id_;
        std::string token_id = permit_token_id_;
        PermitStop();
        step_active_ = false;  // the revoked chain's step must not report completion later
        o.decision.state = "ESTOP";
        o.decision.reason = "ERR_SAFETY_UNSAFE";
        o.decision.stop_permit = true;
        o.decision.report = true;
        o.decision.fatal = true;
        if (!had_permit) {
          // The node fetches GetActiveToken here; the latest pushed view is the same answer
          // one poll later.
          chain_id = token_view_.chain_id;
          token_id = token_view_.token_id;
          // P18-H1: with the issuer unreachable the view is empty, but the chain whose step
          // this session was running is still alive at the issuer. Name it: the active (or
          // just-stopped) step first, then the last permit entered.
          if (chain_id.empty() && token_id.empty()) {
            chain_id = step_chain_id_;
            token_id = step_token_id_;
          }
          if (chain_id.empty() && token_id.empty()) {
            chain_id = last_permit_chain_id_;
            token_id = last_permit_token_id_;
          }
        }
        o.report_chain_id = chain_id;
        o.report_token_id = token_id;
        // P15-H1: the chain dies here, not when (or whether) the issuer hears about it.
        // P18-H1: every identity this session knows dies with it — a view, a step and a
        // permit can name different chains only when the older ones are already over.
        LatchFatal(chain_id, token_id);
        LatchFatal(token_view_.chain_id, token_view_.token_id);
        LatchFatal(step_chain_id_, step_token_id_);
        LatchFatal(last_permit_chain_id_, last_permit_token_id_);
      }
      break;
    case EstopAction::kRelease:
      estop_active_ = false;  // recovery still requires a new plan (chain was revoked)
      break;
    case EstopAction::kHold:
      break;
  }
  Stamp(&o);
  return o;
}

void GateSession::LatchFatal(const std::string &chain_id, const std::string &token_id) {
  auto add = [](std::deque<std::string> *list, const std::string &id) {
    if (id.empty()) return;
    for (const auto &x : *list) {
      if (x == id) return;
    }
    list->push_back(id);
    while (list->size() > kFatalLatchMax) list->pop_front();
  };
  add(&fatal_chains_, chain_id);
  add(&fatal_tokens_, token_id);
}

bool GateSession::fatal_latched(const std::string &chain_id, const std::string &token_id) const {
  auto has = [](const std::deque<std::string> &list, const std::string &id) {
    if (id.empty()) return false;
    for (const auto &x : list) {
      if (x == id) return true;
    }
    return false;
  };
  return has(fatal_chains_, chain_id) || has(fatal_tokens_, token_id);
}

void GateSession::MarkConsumed(const std::string &key) {
  // pep_gate_node.cpp mark_consumed — keyed by consumption_key (canon A §3.5).
  if (key.empty() || consumed_.count(key)) return;
  consumed_.insert(key);
  consumed_order_.push_back(key);
  while (consumed_order_.size() > kConsumedCacheMax) {
    consumed_.erase(consumed_order_.front());
    consumed_order_.pop_front();
  }
}

void GateSession::FlushConsumedIfChainChanged(const std::string &chain_id) {
  // pep_gate_node.cpp flush_consumed_if_chain_changed.
  if (chain_id == consumed_chain_id_) return;
  consumed_.clear();
  consumed_order_.clear();
  consumed_chain_id_ = chain_id;
  step_active_ = false;  // step state belongs to the old chain
}

void GateSession::BeginStepIfNeeded(const std::string &chain_id, const std::string &token_id,
                                    const std::string &key, const VerifiedTokenInfo &info,
                                    int64_t now_ms, int64_t elapsed_ms) {
  // pep_gate_node.cpp begin_step_if_needed — "same step?" is asked of the key, not the name.
  if (step_active_ && step_consumption_key_ == key) return;
  step_active_ = true;
  step_chain_id_ = chain_id;
  step_token_id_ = token_id;
  step_consumption_key_ = key;
  step_uses_elapsed_ = info.max_duration_sec > 0.0;
  step_deadline_elapsed_ms_ = -1;
  if (step_uses_elapsed_) {
    // decide() validated conversion/range before allowing this transition.
    DurationDeadlineMs(elapsed_ms, info.max_duration_sec, &step_deadline_elapsed_ms_);
    step_deadline_ms_ = 0;  // diagnostic projection only; overflow means unavailable
    DurationDeadlineMs(now_ms, info.max_duration_sec, &step_deadline_ms_);
  } else {
    step_deadline_ms_ = info.not_after_unix_ms;  // 0 = no deadline
  }
}

void GateSession::PermitEnter(const std::string &chain_id, const std::string &token_id,
                              const std::string &key, int64_t not_after_ms,
                              const std::string &issued_hash) {
  // pep_gate_node.cpp permit_enter.
  permit_active_ = true;
  permit_chain_id_ = chain_id;
  permit_token_id_ = token_id;
  permit_consumption_key_ = key;
  permit_not_after_ms_ = not_after_ms;
  permit_issued_hash_ = issued_hash;
  unreachable_streak_ = 0;
  last_permit_chain_id_ = chain_id;  // P18-H1: kept after PermitStop
  last_permit_token_id_ = token_id;
}

int64_t GateSession::ReadElapsedNow() {
  const int64_t now = ElapsedNowMs();
  if (!elapsed_clock_fault_ && (now < 0 || (last_elapsed_ms_ >= 0 && now < last_elapsed_ms_))) {
    elapsed_clock_fault_ = true;
    elapsed_clock_fault_reason_ = now < 0 ? "elapsed_unavailable" : "elapsed_reversed";
  }
  if (elapsed_clock_fault_) return -1;  // no recovery by resetting the baseline
  last_elapsed_ms_ = now;
  return now;
}

GateInputs GateSession::BuildInputs(GatePath path, const CommandRequest *cmd, int64_t now_ms) {
  // pep_gate_node.cpp build_inputs, line for line, minus the ROS message unpacking.
  GateInputs in;
  in.path = path;
  in.now_ms = now_ms;
  in.elapsed_now_ms = ReadElapsedNow();
  in.clock_drift_known = in.elapsed_now_ms >= 0;
  in.clock_drift_ms = DriftMs(clock_baseline_);
  in.clock_fault = elapsed_clock_fault_reason_;

  // SEC-H02 : the trust in force, measured here on the session's own wall clock.
  in.trust_expired = TrustExpired();
  in.trust_expires_at_unix = static_cast<int64_t>(keyring_.expires_at_unix);
  if (permit_active_ && !permit_key_id_.empty() && keyring_.pubkeys.count(permit_key_id_) == 0) {
    in.hold_key_state = keyring_.revoked.count(permit_key_id_) > 0 ? 1 : 2;
  }

  in.supplier.provider_mode = cfg_.provider_mode;
  in.supplier.use_token_service = cfg_.use_token_service;
  in.supplier.grpc_built = cfg_.grpc_built;
  in.supplier.permit_grace_n = cfg_.permit_grace_n;
  in.supplier.unreachable_streak = unreachable_streak_;

  in.limits.clock_skew_ms = cfg_.clock_skew_ms;
  in.limits.evidence_window_ms = policy_.evidence_window_ms;
  in.limits.evidence_conf_threshold = policy_.evidence_conf_threshold;
  in.limits.safety_stale_ms = policy_.safety_stale_ms;
  in.limits.min_trust_rank = policy_.min_trust_rank;
  in.limits.safety_exempt_in_progress_step = policy_.safety_exempt_in_progress_step;

  in.evidence.object_id = last_evidence_.object_id;
  in.evidence.confidence = last_evidence_.confidence;
  in.evidence.received_ms = last_evidence_.received_ms;
  in.evidence.source = last_evidence_.source;
  {
    const auto it = policy_.trust_rank_by_source.find(last_evidence_.source);
    in.evidence.trust_rank = (it == policy_.trust_rank_by_source.end()) ? 0 : it->second;
  }
  in.evidence.ever_received = evidence_ever_received_;

  in.safety.enabled = policy_.human_safety_enabled;
  in.safety.level = safety_level_;
  in.safety.ever_received = safety_ever_received_;
  in.safety.observed_ms = last_safety_ms_;
  in.safety.estop_active = estop_active_;

  if (cmd != nullptr) in.command = *cmd;

  in.hold.active = permit_active_;
  in.hold.chain_id = permit_chain_id_;
  in.hold.token_id = permit_token_id_;
  in.hold.consumption_key = permit_consumption_key_;
  in.hold.issued_hash = permit_issued_hash_;
  in.hold.not_after_ms = permit_not_after_ms_;
  in.hold.max_linear = held_max_linear_;
  in.hold.max_angular = held_max_angular_;
  in.hold.guardrails = held_guardrails_;
  if (!held_skill_.empty()) in.require_evidence_feed = SkillNeedsFeed(skills_, held_skill_, "evidence_claim");
  in.hold.target = held_target_;

  in.step_active = step_active_;
  in.step_consumption_key = step_consumption_key_;
  in.step_deadline_ms = step_deadline_ms_;
  in.step_uses_elapsed = step_uses_elapsed_;
  in.step_deadline_elapsed_ms = step_deadline_elapsed_ms_;
  in.static_target_object_id = cfg_.static_target_object_id;
  in.config_digest = cfg_.config_digest;
  // P15-H1: the local fatal latch rides on every input, both paths.
  in.fatal_chains.assign(fatal_chains_.begin(), fatal_chains_.end());
  in.fatal_tokens.assign(fatal_tokens_.begin(), fatal_tokens_.end());

  // Issuer round trips at the monolith's positions (IR-1): the rule is WantsTokenFetch —
  // one place, asked here and by the node before it pushes. Here "fetch" means "consult the
  // latest pushed view"; an unfetched view is the default (ok=false), as in the node.
  if (WantsTokenFetch(path, in.now_ms)) in.token_view = token_view_;

  // Strict verification stays caller-side of decide() (implementation contract invariant 3), at the
  // monolith's position: command path, grpc mode, token present.
  if (path == GatePath::Command && !estop_active_ &&
      (cfg_.provider_mode == "grpc" || cfg_.use_token_service) && in.token_view.ok) {
    std::string verify_reason;
    in.verify_ok = StrictVerifyActiveTokenView(in.token_view, cfg_.robot_id, keyring_,
                                               cfg_.clock_skew_ms, &in.token_info, &verify_reason);
    in.verify_reason = verify_reason;
    // SK-5 : a v5 token names its skill; the registry row's feeds say
    // whether fresh evidence is required while it holds a permit (evidence_claim).
    // v<=4 tokens name nothing — the target binding alone applies, as before.
    if (in.verify_ok && in.token_info.schema_version >= kTokenSchemaNamedEnvelope) {
      in.require_evidence_feed = SkillNeedsFeed(skills_, in.token_info.skill, "evidence_claim");
    }
    if (in.verify_ok &&
        world_match(in.token_info.subgraph_snapshot_hash, in.token_view.current_subgraph_hash) ==
            WorldMatch::kMatch) {
      FlushConsumedIfChainChanged(in.token_info.chain_id);
      in.token_consumed = consumed_.count(in.token_info.consumption_key) > 0;
    }
  }
  return in;
}

SessionOutcome GateSession::Apply(const GateDecision &d, const GateInputs &in, const char *path) {
  // pep_gate_node.cpp apply, minus publish/forward/report (returned instead).
  SessionOutcome o;
  o.path = path;
  o.decision = d;
  const auto &tv = in.token_view;
  const bool grpc_mode = (in.supplier.provider_mode == "grpc" || in.supplier.use_token_service);
  const bool verified = grpc_mode && in.verify_ok;
  const std::string &id_chain = verified ? in.token_info.chain_id : tv.chain_id;
  const std::string &id_token = verified ? in.token_info.token_id : tv.token_id;
  const std::string &id_key = verified ? in.token_info.consumption_key : tv.token_id;

  if (in.path == GatePath::Recheck && in.hold.active) {
    if (d.hold_permit || d.reason == "ERR_ISSUER_UNREACHABLE") {
      ++unreachable_streak_;
    } else if (d.reason != "ERR_EXPIRED") {
      unreachable_streak_ = 0;
    }
  }
  if (d.hold_permit) {
    Stamp(&o);
    return o;  // holding the last permit; nothing published, nothing reported
  }

  // publish_gate's invariant (M4): any non-PERMIT decision stops the heartbeat.
  if (!d.state.empty() && d.state != "PERMIT") PermitStop();

  o.report_chain_id = id_chain;
  o.report_token_id = id_token;
  // P15-H1: a fatal decision (ERR_WORLD_CHANGED and the like) kills the chain in this
  // session the moment it is decided, not when the issuer confirms the report.
  if (d.report && d.fatal) LatchFatal(id_chain, id_token);

  if (d.enter_permit) {
    held_max_linear_ = in.token_info.max_linear_speed_mps;
    held_skill_ = in.token_info.skill;  // SK-5: empty on v<=4
    held_max_angular_ = in.token_info.max_angular_speed_rps;
    held_guardrails_ = in.token_info.guardrails;
    if (grpc_mode) {
      held_target_ = in.token_info.target_object_id;
    } else if (in.supplier.provider_mode == "static") {
      held_target_ = in.static_target_object_id;
    } else {
      held_target_.clear();
    }
    PermitEnter(id_chain, id_token, id_key, in.token_info.not_after_unix_ms,
                in.token_info.subgraph_snapshot_hash);
    // SEC-H02: remember whose signature this permit rests on (grpc mode; empty otherwise).
    permit_key_id_ = grpc_mode ? tv.key_id_bytes : std::string();
  }
  if (d.begin_step) {
    BeginStepIfNeeded(id_chain, id_token, id_key, in.token_info, in.now_ms, in.elapsed_now_ms);
  }
  Stamp(&o);
  return o;
}

bool GateSession::WantsTokenFetch(GatePath path, int64_t now_ms) const {
  // pep_gate_node.cpp build_inputs, the fetch_token predicate (IR-1) — verbatim.
  return (path == GatePath::Command && !estop_active_) ||
         (path == GatePath::Recheck && permit_active_ &&
          !held_expired(now_ms, permit_not_after_ms_, cfg_.clock_skew_ms));
}

GateInputs GateSession::PrepareInputs(GatePath path, const CommandRequest *cmd, int64_t now_ms) {
  return BuildInputs(path, cmd, Now(now_ms));
}

SessionOutcome GateSession::ApplyDecision(const GateDecision &d, const GateInputs &in) {
  return Apply(d, in, in.path == GatePath::Recheck ? "recheck" : "command");
}

SessionOutcome GateSession::OnCommand(const CommandRequest &cmd, int64_t now_ms) {
  const int64_t now = Now(now_ms);
  const GateInputs in = BuildInputs(GatePath::Command, &cmd, now);
  const GateDecision d = decide(in);
  return Apply(d, in, "command");
}

SessionOutcome GateSession::OnRecheck(int64_t now_ms) {
  const int64_t now = Now(now_ms);
  const GateInputs in = BuildInputs(GatePath::Recheck, nullptr, now);
  const GateDecision d = decide(in);
  return Apply(d, in, "recheck");
}

// SK-3 : the robot's own "done", relayed by the adapter for a named skill.
SessionOutcome GateSession::CompleteStep(int64_t now_ms, const std::string &skill) {
  const int64_t now = Now(now_ms);
  SessionOutcome o;
  o.path = "complete";
  auto ignore = [&](const std::string &why) {
    o.decision.detail = "complete ignored: " + why;  // nothing published, nothing reported
    Stamp(&o);
    return o;
  };
  if (!step_active_) return ignore("no active step");
  if (skills_.rows == 0) return ignore("no skill registry loaded — steps complete by deadline only");
  const auto sig = skills_.complete_by_skill.find(skill);
  if (sig == skills_.complete_by_skill.end()) return ignore("skill " + skill + " is not in the registry");
  if (sig->second == "duration") return ignore("skill " + skill + " completes by duration, not by report");
  if (sig->second == "robot_report+evidence") {
    // at_complete: the target must be read NOW — absence, staleness and mismatch are each
    // their own refusal (D-L7 §6.4 shape), reported, the step kept for a later report.
    auto refuse = [&](const std::string &why) {
      o.decision = GateDecision{};
      o.decision.state = "BLOCK";
      o.decision.reason = "ERR_NO_EVIDENCE";
      o.decision.detail = "at_complete: " + why;
      o.decision.report = true;
      o.decision.stop_permit = true;
      PermitStop();
      o.report_chain_id = step_chain_id_;
      o.report_token_id = step_token_id_;
      Stamp(&o);
      return o;
    };
    if (!evidence_ever_received_) return refuse("no evidence ever received");
    if (now - last_evidence_.received_ms > policy_.evidence_window_ms) return refuse("evidence stale");
    if (!held_target_.empty() && last_evidence_.object_id != held_target_) {
      return refuse("evidence names " + last_evidence_.object_id + ", step targets " + held_target_);
    }
  }
  // Consume exactly as the deadline would, naming the signal that did it.
  step_active_ = false;
  PermitStop();
  MarkConsumed(step_consumption_key_);
  o.fired = true;
  o.decision.state = "PERMIT";
  o.decision.reason = "OK";
  o.decision.detail = "complete:" + sig->second;
  o.decision.report = true;
  o.decision.step_complete = true;
  o.decision.stop_permit = true;
  o.report_chain_id = step_chain_id_;
  o.report_token_id = step_token_id_;
  Stamp(&o);
  return o;
}

SessionOutcome GateSession::OnStepTimer(int64_t now_ms) {
  // pep_gate_node.cpp on_step_timer.
  const int64_t now = Now(now_ms);
  SessionOutcome o;
  o.path = "step";
  if (!step_active_) { Stamp(&o); return o; }
  const int64_t elapsed = ReadElapsedNow();
  const int64_t drift = DriftMs(clock_baseline_);
  if (elapsed < 0 || cfg_.clock_skew_ms < 0 || drift > cfg_.clock_skew_ms ||
      drift < -cfg_.clock_skew_ms || (step_uses_elapsed_ && step_deadline_elapsed_ms_ < 0)) {
    PermitStop();
    o.decision.state = "BLOCK"; o.decision.reason = "ERR_CLOCK_DRIFT";
    o.decision.stop_permit = true;
    GateInputs clock;
    clock.clock_drift_known = elapsed >= 0; clock.clock_drift_ms = drift;
    clock.elapsed_now_ms = elapsed; clock.clock_fault = elapsed_clock_fault_reason_;
    clock.limits.clock_skew_ms = cfg_.clock_skew_ms; clock.step_active = step_active_;
    clock.step_uses_elapsed = step_uses_elapsed_; clock.step_deadline_elapsed_ms = step_deadline_elapsed_ms_;
    o.decision.detail = ClockRefusalDetail(clock) + " path=step_timer";
    Stamp(&o);
    return o;  // a clock fault is NOT successful step completion
  }
  const bool due = step_uses_elapsed_ ? elapsed >= step_deadline_elapsed_ms_ :
                   (step_deadline_ms_ > 0 && now >= step_deadline_ms_);
  if (due) {
    step_active_ = false;
    PermitStop();  // the granting token is consumed; next step re-enters via a command
    MarkConsumed(step_consumption_key_);
    o.fired = true;
    o.decision.state = "PERMIT";
    o.decision.reason = "OK";
    o.decision.detail = "complete:timeout";  // SK-3: the deadline is the signal
    o.decision.report = true;
    o.decision.step_complete = true;
    o.decision.stop_permit = true;
    o.report_chain_id = step_chain_id_;
    o.report_token_id = step_token_id_;
  }
  Stamp(&o);
  return o;
}

}  // namespace pail_pep_gate
