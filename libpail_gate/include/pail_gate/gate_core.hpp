// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#ifndef PAIL_PEP_GATE__GATE_CORE_HPP_
#define PAIL_PEP_GATE__GATE_CORE_HPP_

// Transport-independent decision core; public overview: spec/ARCHITECTURE.md.
// No rclcpp / grpc / sockets / clock — everything the decision needs arrives as
// an argument, everything it decides leaves as a return value, so a truth table
// can exercise it as an L1 unit.
//
// Invariants :
//   1. decide() is a pure function: same inputs, same outputs, no side effects.
//   2. Time, consumption history and verification results are injected.
//   3. decide() does NOT verify signatures (sodium stays behind the existing
//      strict_verify seam); it receives verify_ok / verify_reason.
//   4. decide() does not log.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "pail_gate/token_provider.hpp"
#include "pail_gate/strict_verify.hpp"

namespace pail_pep_gate {

// Which decision path . Three paths share predicates but
// differ in order; one function + a path argument keeps the shared predicate
// physically single (G-ENF-09 ownership point).
enum class GatePath { Command, Grace, Recheck };

// Supplier contract 3 modes + build shape. G-ENF-19 / G-ENF-10 live here.
struct SupplierMode {
  std::string provider_mode;      // "grpc" | "static" | "notoken"
  bool use_token_service{false};
  bool grpc_built{true};          // PAIL_ENABLE_GRPC
  int  permit_grace_n{0};
  int  unreachable_streak{0};
};

struct EvidenceSnapshot {
  std::string object_id;
  double      confidence{0.0};
  int64_t     received_ms{0};     // receipt time — upstream clocks are not trusted
  // implementation contract D-L5 §6.1: the raw pail_msgs/Evidence.source string, carried
  // for the record, and the rank the NODE resolved for it against the policy's
  // trust_classes table. The core does not know the string→rank mapping on
  // purpose (it stays a pure decision function); an unmapped source arrives as
  // rank 0. Confidence and trust class measure different things: a 0.99 VISION
  // read is a confident inference, not an identity response.
  std::string source;
  int         trust_rank{0};
  // D-L7 §6.4 (O-3): absence, staleness and freshness are THREE values. This
  // used to be two — the node stamped received_ms at construction, so a gate
  // that had never seen evidence read as "just received". Default false for the
  // same reason clock_drift_known does: not asked must not read as passed.
  bool        ever_received{false};
};

struct SafetyState {
  bool        enabled{true};
  std::string level;              // raw feed string — parsed via ParseSafetyLevel
                                  // (safety_level.hpp, D §4.1); only "OK" passes.
                                  // This comment once said `"" | "OK" | "WARN"`
                                  // while the code blocked on WARN alone — the
                                  // mismatch itself was the C-B7 defect (§1.3).
  bool        ever_received{false};
  int64_t     observed_ms{0};
  bool        estop_active{false};
};

struct CommandRequest {
  double linear_norm{0.0};        // sqrt(x²+y²+z²) — computed by the caller
  double angular_norm{0.0};
  // SK-2 : what the adapter measured, by GUARDRAILS.tsv name.
  // Empty means "only the two norms above" — the core derives sls.linear_mps /
  // sls.angular_rps from them, so the ROS node is unchanged. An adapter that
  // fills this must fill every name the token's envelope carries: a bound the
  // adapter did not measure blocks (ERR_BAD_TOKEN, detail "unmeasured:<name>").
  std::map<std::string, double> measured;
  // The action class requested by the command, as a
  // kClass* bit. The ROS node judges /cmd_vel only and never sets this, so the default is
  // MOVE and its verdicts are unchanged. An adapter whose ingress carries other intents
  // (Microduck robot.enable/init = ACTUATE, robot.head = NONE, …) names the class here and
  // the token's v4 mask must carry that bit; a legacy (schema < 4) token authorizes MOVE only.
  int    requested_class{kClassMove};
  // SK-4 (implementation contract, L15): the skill name the command asks for (registry `name`).
  // A v5 token is judged by name — `skill` must equal the token's skill; empty is
  // "the caller did not say" and a v5 token refuses it (fail-closed). v<=4 tokens
  // ignore this and keep the class-mask comparison above.
  std::string skill;
};

// Held-permit state. Only meaningful on the Grace / Recheck paths.
struct PermitHold {
  bool        active{false};
  std::string chain_id;
  std::string token_id;
  // [OR3/X12②, U-B3] Identity for MATCHING, kept apart from token_id, which is
  // a NAME. The two differ in what they survive: the name is what the issuer
  // and the recheck answer agree to call this authorization, while the key is
  // derived from the signed bytes and cannot be restated by an envelope.
  // Matching on the key means the same bytes are the same permit no matter
  // what the envelope calls them. Empty in static mode, which has no signature
  // to derive from and does not enforce single-use.
  std::string consumption_key;
  std::string issued_hash;
  int64_t     not_after_ms{0};
  double      max_linear{0.0};
  double      max_angular{0.0};
  // SK-2: the held envelope by name (copied from the token at permit entry).
  // Empty → derived from the two fields above, as for VerifiedTokenInfo.
  std::vector<Guardrail> guardrails;
  std::string target;
};

struct GateLimits {
  int64_t clock_skew_ms{0};
  int64_t evidence_window_ms{0};
  double  evidence_conf_threshold{0.0};
  int64_t safety_stale_ms{0};
  // D-L5 §6.2: the rank of policy `evidence.min_trust_class`, resolved by the
  // node. 0 means the policy named no floor; it does NOT mean "any source".
  int     min_trust_rank{0};
  // D-L3 preconditions[safety_feed].exempt_in_progress_step, consumed here
  // (PC-27). [OR3/X26] The default is the REFUSING value: a caller that never
  // states the policy gets no exemption, because an exemption nobody granted
  // is the one that must not be inherited from a struct default.
  bool    safety_exempt_in_progress_step{false};
};

struct GateInputs {
  GatePath          path{GatePath::Command};
  int64_t           now_ms{0};        // injected — the core never reads a clock
  // DC-10 : wall-vs-monotonic drift, measured by the caller
  // (wall_clock.hpp DriftMs). [OR3/X26, H-B2] known defaults to false because
  // an unmeasured clock is not a healthy clock — a caller that forgets to
  // measure must land in refusal, not in "no drift". A -1 sentinel in the int
  // was rejected: two meanings in one number is the bool-overload defect class.
  bool              clock_drift_known{false};
  std::string       clock_fault;  // measured fault cause, never inferred from a zero value
  int64_t           clock_drift_ms{0};
  ActiveTokenView   token_view;       // .ok == false means no authorization
  // [OR3/X26] Defaults are the REFUSING values, not the passing ones. Both
  // fields are answers the caller must supply; an unset answer means the
  // question was never asked, and "not asked" must not read as "passed".
  bool              verify_ok{false}; // StrictVerify result (caller performs it)
  std::string       verify_reason;    // ERR_* on failure
  VerifiedTokenInfo token_info;
  EvidenceSnapshot  evidence;
  SafetyState       safety;
  CommandRequest    command;
  PermitHold        hold;
  SupplierMode      supplier;
  GateLimits        limits;
  bool              token_consumed{true};    // consumed-cache lookup (caller queries)
  bool              step_active{false};
  // [OR3/X12②] Step identity is the consumption key for the same reason as
  // PermitHold::consumption_key — the in-progress-step exemption must not be
  // claimable by renaming a token in the envelope.
  std::string       step_consumption_key;
  // implementation contract (C-B5): the active step's deadline, injected by the
  // node (begin_step computed it; the timer merely consumes at it). The command
  // path asks the overrun question itself because the timer is an ACTIVE part —
  // enforcement that depends on a part stopping is fail-open when that part
  // wedges (macOS Docker Ticker defect class, measured). 0 = no active
  // deadline; only consulted while step_active.
  // With a positive duration this wall projection is diagnostic ONLY. With
  // duration=0 it remains the absolute not_after fallback (legacy contract).
  int64_t           step_deadline_ms{0};
  bool              step_uses_elapsed{false};
  int64_t           elapsed_now_ms{-1};          // local OS clock, never ABI now_ms
  int64_t           step_deadline_elapsed_ms{-1};
  std::string       static_target_object_id;
  // SK-5 : the skill's registry row lists `evidence_claim` among its
  // feeds — fresh evidence is required while it holds a permit even when the
  // token names no target (the target binding below is a separate question).
  // The session derives it from the registry; the core only asks.
  bool              require_evidence_feed{false};
  std::string       config_digest;           // sealed effective-config digest
  // P15-H1 (TB3, 2026-10-16): chains and tokens this session has already declared
  // fatal — an E-STOP, or a fatal BLOCK it reported (or is still trying to report).
  // The fatal report that revokes the chain at the issuer travelled on one 50 ms RPC
  // whose result was discarded; when it was lost, the issuer kept the chain active,
  // safety returned to OK, the same token was served again and the robot resumed
  // without an operator. The session fills these lists from its latch on every
  // path; the core refuses a view, a verified token or a held permit that names
  // any of them, whatever the issuer currently answers. Bounded (the session keeps
  // the most recent entries), oldest first.
  std::vector<std::string> fatal_chains;
  std::vector<std::string> fatal_tokens;
};

struct GateDecision {
  // ---- publication ----
  std::string state;          // "PERMIT" | "BLOCK" | "ESTOP" | "" (no publish)
  std::string reason;         // "OK" | "ERR_*"
  // SK-2: what the reason does not say — which name, which value, which bound.
  // Never a new reason code (the dictionary has five places per code); logged
  // and carried on the adapter ABI (Outcome.detail), not on the ROS reason
  // string (consumers compare that one for equality).
  std::string detail;
  bool        forward{false}; // forward the safe command

  // ---- issuer report ----
  bool report{false};
  bool step_complete{false};
  bool fatal{false};

  // ---- state transitions ----
  bool enter_permit{false};
  bool stop_permit{false};
  bool begin_step{false};
  bool hold_permit{false};    // Recheck grace hold (no publish)
};

std::string ClockRefusalDetail(const GateInputs &in);
GateDecision decide(const GateInputs &in);

// Exported for the node's build_inputs guards (input validation): the RPC-fetch and
// consumed-flush positions of the monolith depend on these two predicates, and
// duplicating them in the node would undo the physical-single-predicate point
// of TB-1 (G-ENF-09 / G-ENF-14). They decide no state/reason on their own.
//
// C-B8 : three values, not two. An empty side means the
// comparison NEVER HAPPENED; the old bool folded that into "match", so
// "cloud could not compute the world hash" was indistinguishable from
// "checked and equal". The bool is gone on purpose — returning an enum makes
// every caller a compile error until it says what indeterminate means there.
enum class WorldMatch { kMatch, kMismatch, kIndeterminate };
WorldMatch world_match(const std::string &issued, const std::string &current);
bool held_expired(int64_t now_ms, int64_t not_after_ms, int64_t clock_skew_ms);

}  // namespace pail_pep_gate

#endif  // PAIL_PEP_GATE__GATE_CORE_HPP_
