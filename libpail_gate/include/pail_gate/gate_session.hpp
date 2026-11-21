// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#pragma once

// AD-1 (see spec/ARCHITECTURE.md): the permit state machine, extracted from the ROS
// node into a class with no I/O. Everything `pep_gate_node.cpp` keeps between two calls of
// `decide()` — held permit, held limits, consumed-key cache, step tracking, E-STOP latch,
// unreachable streak, the safety/evidence feeds' last values — lives here; everything the
// node DOES with a decision (publish, forward, report, stop) comes back as a SessionOutcome
// for the caller to do. `decide()` itself is untouched: this class only feeds it and applies
// its transitions, at the positions the node applies them (build_inputs / apply / step timer /
// on_safety_state, cited inline).
//
// AD-4 (2026-09-08): the node now uses this class. Its TB-7 surface (build_inputs / apply)
// is kept as a delegation so the wiring batteries keep driving the exact functions the
// product callbacks call; the state the node used to own lives here only. The two-doors
// battery still pins session == ABI; the node batteries pin node == session.

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_set>

#include "pail_gate/gate_core.hpp"
#include "pail_gate/keyring_bundle.hpp"
#include "pail_gate/skills_load.hpp"
#include "pail_gate/policy_load.hpp"
#include "pail_gate/wall_clock.hpp"

namespace pail_pep_gate {

struct SessionConfig {
  std::string robot_id;
  // Supplier contract as the adapter deploys it: a real token service over gRPC.
  std::string provider_mode{"grpc"};
  bool use_token_service{true};
  bool grpc_built{true};
  int permit_grace_n{3};
  int64_t clock_skew_ms{500};
  std::string static_target_object_id;
  std::string config_digest;
  // SK-3 : the skill registry this gate serves, for the completion
  // rules (complete.signal, evidence.when). Empty = no registry: every step
  // completes by its deadline only, and CompleteStep() is ignored with a detail.
  std::string skills_file;
  std::string robot_class;
};

struct SafetyObservation {
  std::string level;    // raw feed string; only "OK" passes (safety_level.hpp)
  std::string source;
  std::string detail;
  int64_t observed_ms{0};   // 0 = stamp with the wall clock now
};

struct EvidenceObservation {
  std::string object_id;
  double confidence{0.0};
  std::string source;       // raw source string; rank is resolved here from the policy
  int64_t received_ms{0};   // 0 = stamp with the wall clock now
};

struct SessionOutcome {
  std::string path;             // "command" | "recheck" | "step" | "safety"
  GateDecision decision;        // state/reason/forward/report/step_complete/fatal/hold_permit…
  // Identity the report (and the log) should carry — the verified ids on a verified command
  // path, the envelope ids otherwise, exactly as the node's apply() picks them.
  std::string report_chain_id;
  std::string report_token_id;
  bool permit_active{false};
  bool step_active{false};
  bool estop_active{false};
  int unreachable_streak{0};
  std::string effective_mode;   // policy gate_mode, stamped on every outcome (D-S5)
  bool fired{false};            // step path: true only when the deadline actually completed
};

class GateSession {
 public:
  GateSession(SessionConfig cfg, SessionPolicy policy, Keyring keyring);
  // Adapter preflight may pass the exact registry it validated, avoiding a second file read.
  GateSession(SessionConfig cfg, SessionPolicy policy, Keyring keyring, SkillRegistryView loaded_skills);

  // Latest answer from the token service (the adapter polls every permit_recheck_ms and
  // pushes; the node fetched synchronously inside build_inputs). `reachable=false` is the
  // UNREACHABLE status — never a stale body.
  void SetTokenView(const ActiveTokenView &view);

  // SEC-H02 : takes up a bundle placed beside the running gate. Cheap enough for every
  // tick: it reads the bundle file's identity (inode, size, mtime) and only when that
  // changed since the last look puts the file through the load checks
  // (ApplyPlacedBundle). A refused candidate is looked at once, not on every call.
  // Same thread as the decisions.
  TrustApplyResult PollTrust();
  // True once the wall clock has passed the expiry of the bundle in force.
  bool TrustExpired() const;

  // pep_gate_node.cpp on_safety_state / trigger_estop: may produce an ESTOP outcome.
  SessionOutcome ObserveSafety(const SafetyObservation &obs);
  // pep_gate_node.cpp on_evidence.
  void ObserveEvidence(const EvidenceObservation &obs);

  // P15-H1 (TB3, 2026-10-16): the local fatal latch. Every fatal this session
  // produces (ESTOP, fatal BLOCK) latches the chain and token it reported; the
  // caller may add the identity it learned after the fact (the E-STOP path fetches
  // the active token only once the stop is out). A latched chain or token is
  // refused on both gate paths until the latch rolls over (kFatalLatchMax most
  // recent entries), independently of whether the revoking report ever reached the
  // issuer. Empty ids are ignored.
  //
  // P18-H1 (preview.18 evaluation, 2026-10-18): an E-STOP that arrives while no permit is
  // live AND the issuer is unreachable used to latch nothing — the pushed view was empty,
  // so the report went out with empty ids and the chain whose step the gate had been
  // running was granted again the moment the issuer came back. ObserveSafety now latches
  // every identity this session knows — the pushed view, the active step and the last
  // permit it entered (kept across PermitStop for exactly this purpose) — and reports
  // against the first of them it can name. Only a session that never held a permit and
  // never saw a token reports without an identity; the issuer then revokes the robot's
  // current chain (GATE_FATAL_SUPERSEDED_CHAIN) and the agent never treats such a report
  // as a repeat of an earlier one.
  void LatchFatal(const std::string &chain_id, const std::string &token_id);
  bool fatal_latched(const std::string &chain_id, const std::string &token_id) const;
  size_t fatal_latch_size() const { return fatal_chains_.size() + fatal_tokens_.size(); }
  // The last permit this session entered, kept after the permit stopped (P18-H1).
  const std::string &last_permit_chain_id() const { return last_permit_chain_id_; }
  const std::string &last_permit_token_id() const { return last_permit_token_id_; }

  // pep_gate_node.cpp on_cmd_vel: build_inputs(Command) → decide → apply.
  SessionOutcome OnCommand(const CommandRequest &cmd, int64_t now_ms = 0);
  // pep_gate_node.cpp on_permit_recheck: build_inputs(Recheck) → decide → apply.
  SessionOutcome OnRecheck(int64_t now_ms = 0);
  // pep_gate_node.cpp on_step_timer: completes the step at its deadline.
  SessionOutcome OnStepTimer(int64_t now_ms = 0);
  // SK-3 : the adapter relays the robot's own "done" for the named skill.
  // Consumes the active step only when the registry row says the signal is
  // `robot_report` (or `robot_report+evidence`, which additionally requires fresh
  // evidence of the step's target at this moment — else BLOCK ERR_NO_EVIDENCE with
  // detail "at_complete", reported, the step kept). A `duration` row, an unknown
  // skill, no registry, or no active step → nothing published, detail says why.
  SessionOutcome CompleteStep(int64_t now_ms, const std::string &skill);
  // What the registry said about this session's rows (empty when none loaded).
  const std::string &skills_error() const { return skills_error_; }
  std::size_t skills_rows() const { return skills_.rows; }
  const std::string& loaded_skills_digest() const { return skills_.sha256_hex; }

  // ---- AD-4: the node's TB-7 surface, delegated ----
  // IR-1 in one place: the issuer round trip happens at the monolith's positions only —
  // none during ESTOP, none for an inactive or already-expired permit on recheck. The node
  // asks this BEFORE pushing a fresh view, so "consult the latest pushed view" inside
  // PrepareInputs is a fresh answer exactly where the node used to fetch synchronously.
  // Same `now_ms` must be passed to both calls; the expiry test is time-dependent.
  bool WantsTokenFetch(GatePath path, int64_t now_ms) const;
  // build_inputs / apply, split so the caller can run decide() in between (as the node's
  // wiring tests do) and perform its own I/O on the returned outcome.
  GateInputs PrepareInputs(GatePath path, const CommandRequest *cmd, int64_t now_ms = 0);
  SessionOutcome ApplyDecision(const GateDecision &d, const GateInputs &in);
  // The seal can be recomputed once at runtime (on_bridge_state re-seal, DC-12); the digest
  // rides on every input as a carried field, so it is refreshed here rather than copied once.
  void SetConfigDigest(const std::string &digest) { cfg_.config_digest = digest; }

  // ---- read-only observation (L-9/S3 accessors of the node, made first-class) ----
  bool permit_active() const { return permit_active_; }
  bool step_active() const { return step_active_; }
  bool estop_active() const { return estop_active_; }
  int unreachable_streak() const { return unreachable_streak_; }
  // Wall projection for observation; NOT the positive-duration authority.
  int64_t step_deadline_ms() const { return step_deadline_ms_; }
  int64_t step_deadline_elapsed_ms() const { return step_deadline_elapsed_ms_; }
  bool step_uses_elapsed() const { return step_uses_elapsed_; }
  const std::string &step_consumption_key() const { return step_consumption_key_; }
  const std::string &permit_token_id() const { return permit_token_id_; }
  const std::string &safety_level() const { return safety_level_; }
  bool consumed_contains(const std::string &key) const { return consumed_.count(key) > 0; }
  size_t consumed_size() const { return consumed_order_.size(); }
  const SessionPolicy &policy() const { return policy_; }
  const SessionConfig &config() const { return cfg_; }
  const Keyring &keyring() const { return keyring_; }

 private:
  GateInputs BuildInputs(GatePath path, const CommandRequest *cmd, int64_t now_ms);
  SessionOutcome Apply(const GateDecision &d, const GateInputs &in, const char *path);
  void MarkConsumed(const std::string &key);
  void FlushConsumedIfChainChanged(const std::string &chain_id);
  void BeginStepIfNeeded(const std::string &chain_id, const std::string &token_id,
                         const std::string &key, const VerifiedTokenInfo &info, int64_t now_ms, int64_t elapsed_ms);
  void PermitEnter(const std::string &chain_id, const std::string &token_id,
                   const std::string &key, int64_t not_after_ms, const std::string &issued_hash);
  void PermitStop() { permit_active_ = false; }
  void Stamp(SessionOutcome *o) const;
  int64_t Now(int64_t given) const { return given > 0 ? given : WallNowMs(); }

  int64_t ReadElapsedNow();

  SessionConfig cfg_;
  SessionPolicy policy_;
  Keyring keyring_;
  SkillRegistryView skills_;   // SK-3: empty when cfg_.skills_file is empty or failed to load
  std::string skills_error_;
  ClockBaseline clock_baseline_ = CaptureBaseline();

  // ---- feeds ----
  ActiveTokenView token_view_;
  std::string safety_level_;
  bool safety_ever_received_{false};
  int64_t last_safety_ms_{0};
  EvidenceObservation last_evidence_;
  bool evidence_ever_received_{false};

  // ---- permit hold (node: permit_* / held_*) ----
  bool permit_active_{false};
  std::string permit_chain_id_, permit_token_id_, permit_consumption_key_, permit_issued_hash_;
  std::string permit_key_id_;   // SEC-H02: the key the held token is signed with
  int64_t permit_not_after_ms_{0};
  double held_max_linear_{0.0}, held_max_angular_{0.0};
  std::vector<Guardrail> held_guardrails_;  // SK-2: the held envelope by name
  std::string held_skill_;  // SK-5: the held token's skill (v5) — its row's feeds bind the grace path
  std::string held_target_;
  int unreachable_streak_{0};
  // P18-H1: survives PermitStop — the identity an E-STOP with no live permit falls back to.
  std::string last_permit_chain_id_, last_permit_token_id_;

  // ---- single-use cache (node: consumed_token_ids_ / consumed_order_ / consumed_chain_id_) ----
  static constexpr size_t kConsumedCacheMax = 4096;
  std::unordered_set<std::string> consumed_;
  std::deque<std::string> consumed_order_;
  std::string consumed_chain_id_;

  // ---- step (node: step_*) ----
  bool step_active_{false};
  std::string step_chain_id_, step_token_id_, step_consumption_key_;
  int64_t step_deadline_ms_{0};
  bool step_uses_elapsed_{false};
  int64_t step_deadline_elapsed_ms_{-1};
  int64_t last_elapsed_ms_{-1};
  bool elapsed_clock_fault_{false};
  std::string elapsed_clock_fault_reason_;

  bool estop_active_{false};

  // ---- SEC-H02: the last bundle file looked at (identity, not content) ----
  bool trust_seen_{false};
  uint64_t trust_seen_ino_{0};
  int64_t trust_seen_size_{-1};
  int64_t trust_seen_mtime_ns_{0};

  // ---- P15-H1: local fatal latch (most recent first to roll over, oldest at the front) ----
  static constexpr size_t kFatalLatchMax = 64;
  std::deque<std::string> fatal_chains_;
  std::deque<std::string> fatal_tokens_;
};

// The provider's response → view translation (pep_gate_node's GrpcTokenProvider, restated
// for callers that hold a GetActiveTokenResponse instead of a channel). Declared here, defined
// in the ABI translation unit where the protobuf types are visible.
}  // namespace pail_pep_gate
