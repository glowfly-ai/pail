// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// TB-1 : truth table for the purified decision core.
// Plain executable, no gtest : returns 0 only if every row matches.
// Expectations are written out literally — deriving them from the same rules
// the implementation uses would make the test tautological.
//
// 14 guarantees = 14 cases; a case may hold several rows (boundaries, modes).
// Case registration convention : the `// PAIL-CASE: <name>` comment
// is canonical — CG-B greps it.

#include <cmath>
#include <cstdio>
#include <string>

#include "pail_gate/gate_core.hpp"

using pail_pep_gate::GateDecision;
using pail_pep_gate::GateInputs;
using pail_pep_gate::GatePath;
using pail_pep_gate::decide;

namespace {

// All four expect_* columns are mandatory : checking only `state`
// lets `report` drift silently, and then the issuer ledger silently empties.
struct Expect {
  const char *state;
  const char *reason;
  bool report;
  bool fatal;
  bool forward;
  bool enter_permit;
  bool stop_permit;
  bool begin_step;
  bool hold_permit;
};

constexpr int64_t kNow = 1000000;

// A clean grpc-mode command that reaches PERMIT — every case mutates from here
// so each row differs from a passing baseline in exactly the property it names.
GateInputs BaseGrpc() {
  GateInputs in;
  in.path = GatePath::Command;
  in.now_ms = kNow;
  in.clock_drift_known = true;  // DC-10: measured, zero drift (drift rows live in test_clock_drift)

  in.token_view.ok = true;
  in.token_view.chain_id = "chain-1";
  in.token_view.token_id = "tok-1";
  in.token_view.status = "OK";

  // [OR3/X26] Both answers stated outright. The baseline used to inherit
  // token_consumed from the struct default, which meant every row below was
  // resting on a default that pointed at "permit".
  in.verify_ok = true;
  in.token_consumed = false;

  in.token_info.target_object_id = "pallet-7";
  in.token_info.action_type = pail_pep_gate::kActionMove;
  in.token_info.max_linear_speed_mps = 1.0;
  in.token_info.max_angular_speed_rps = 1.0;
  in.token_info.not_after_unix_ms = kNow + 30000;
  // [OR3/X12②] Verified identity. Deliberately unlike token_view.token_id so a
  // row that matches on the envelope name cannot pass by coincidence.
  in.token_info.token_id = "tok-1";
  in.token_info.chain_id = "chain-1";
  in.token_info.consumption_key = "ck-tok-1";
  // C-B8 : the world comparison is now three-valued and an
  // empty side BLOCKS (ERR_WORLD_INDETERMINATE). The baseline used to leave
  // both hashes empty and pass — that pass was riding the very fold this
  // battery must not depend on. A passing baseline states both sides.
  in.token_info.subgraph_snapshot_hash = "wh-1";
  in.token_view.current_subgraph_hash = "wh-1";

  in.evidence.object_id = "pallet-7";
  in.evidence.confidence = 0.97;
  in.evidence.received_ms = kNow - 500;
  // D-L7 §6.4 (O-3): stated, not inherited. The default is false because a
  // gate that was never asked must not read as one that answered — so a
  // baseline carrying evidence has to say it carries evidence.
  in.evidence.ever_received = true;

  in.safety.enabled = true;
  in.safety.level = "OK";
  in.safety.ever_received = true;
  in.safety.observed_ms = kNow - 200;
  in.safety.estop_active = false;

  in.command.linear_norm = 0.5;
  in.command.angular_norm = 0.2;

  in.supplier.provider_mode = "grpc";
  in.supplier.use_token_service = false;
  in.supplier.grpc_built = true;
  in.supplier.permit_grace_n = 3;
  in.supplier.unreachable_streak = 0;

  in.limits.clock_skew_ms = 500;
  in.limits.evidence_window_ms = 2000;
  in.limits.evidence_conf_threshold = 0.90;
  in.limits.safety_stale_ms = 1000;

  return in;
}

const Expect kPermit      = {"PERMIT", "OK", true,  false, true,  true,  false, true,  false};
const Expect kPermitStat  = {"PERMIT", "OK", true,  false, true,  true,  false, false, false};

Expect Block(const char *reason, bool report) {
  return {"BLOCK", reason, report, false, false, false, true, false, false};
}
// BlockFatal / kHold live in test_gate_failclosed.cpp — the fatal (world-hash)
// and recheck-hold cases are TB-6's subject, not TB-1's.
const Expect kNoPublish   = {"", "", false, false, false, false, false, false, false};
// Grace-path PERMIT: forwarded but never reported (issuer unreachable), and the
// permit is neither re-entered nor a step begun.
const Expect kGracePermit = {"PERMIT", "OK", false, false, true, false, false, false, false};

int g_failures = 0;

void CheckRow(const char *gid, const char *note, const GateInputs &in, const Expect &e) {
  const GateDecision d = decide(in);
  const bool ok = d.state == e.state && d.reason == e.reason && d.report == e.report &&
                  d.fatal == e.fatal && d.forward == e.forward &&
                  d.enter_permit == e.enter_permit && d.stop_permit == e.stop_permit &&
                  d.begin_step == e.begin_step && d.hold_permit == e.hold_permit;
  if (!ok) {
    std::fprintf(stderr,
                 "  FAIL [%s] %s\n"
                 "       got  state=%s reason=%s report=%d fatal=%d fwd=%d enter=%d stop=%d step=%d hold=%d\n"
                 "       want state=%s reason=%s report=%d fatal=%d fwd=%d enter=%d stop=%d step=%d hold=%d\n",
                 gid, note,
                 d.state.c_str(), d.reason.c_str(), d.report, d.fatal, d.forward,
                 d.enter_permit, d.stop_permit, d.begin_step, d.hold_permit,
                 e.state, e.reason, e.report, e.fatal, e.forward,
                 e.enter_permit, e.stop_permit, e.begin_step, e.hold_permit);
    ++g_failures;
  }
}

// ---------------------------------------------------------------------------

// PAIL-CASE: Baseline
static int CaseBaseline() {
  const int before = g_failures;
  CheckRow("BASE", "clean grpc command permits", BaseGrpc(), kPermit);
  return g_failures - before;
}

// PAIL-CASE: NoToken
static int CaseNoToken() {  // G-ENF-01
  const int before = g_failures;
  GateInputs in = BaseGrpc();
  in.token_view.ok = false;
  in.token_view.status = "NO_TOKEN";
  CheckRow("G-ENF-01", "no active token", in, Block("ERR_NO_TOKEN", true));
  return g_failures - before;
}

// PAIL-CASE: TargetMismatch
static int CaseTargetMismatch() {  // G-ENF-02
  const int before = g_failures;
  GateInputs in = BaseGrpc();
  in.evidence.object_id = "pallet-8";
  CheckRow("G-ENF-02", "evidence names another object", in, Block("ERR_TARGET_MISMATCH", true));

  in = BaseGrpc();
  in.evidence.confidence = 0.89;  // below threshold 0.90
  CheckRow("G-ENF-02", "confidence below threshold", in, Block("ERR_TARGET_MISMATCH", true));
  return g_failures - before;
}

// PAIL-CASE: NoEvidence
static int CaseNoEvidence() {  // G-ENF-03
  const int before = g_failures;
  GateInputs in = BaseGrpc();
  in.evidence.received_ms = kNow - 2001;  // window 2000, strict >
  CheckRow("G-ENF-03", "evidence older than window", in, Block("ERR_NO_EVIDENCE", true));

  in = BaseGrpc();
  in.evidence.received_ms = kNow - 2000;  // exactly at window: not stale
  CheckRow("G-ENF-03", "evidence exactly at window boundary", in, kPermit);

  // D-L7 §6.4 (O-3): absence carrying a FRESH timestamp. This is the shape of
  // P-8 exactly — the node used to stamp the clock in its constructor, so a
  // gate that had never received evidence presented a brand-new reading.
  //
  // This row exists because the obvious one does not measure anything. With an
  // unset received_ms of 0 the window arithmetic refuses anyway, so deleting
  // the absence check left every battery green (measured: variant V3,
  // RED_TRUSTCLASS_STEP5 §6). A rule whose only witness is a coincidence has
  // no witness. Here the timestamp is fresh, so the window CANNOT refuse and
  // the absence check is the only thing standing.
  in = BaseGrpc();
  in.evidence.ever_received = false;
  in.evidence.received_ms = kNow;  // fresh — absence must not be inferred from time
  CheckRow("G-ENF-03", "never received, yet timestamped fresh", in,
           Block("ERR_NO_EVIDENCE", true));
  return g_failures - before;
}

// PAIL-CASE: ActionMismatch
static int CaseActionMismatch() {  // G-ENF-04
  const int before = g_failures;
  GateInputs in = BaseGrpc();
  in.token_info.action_type = pail_pep_gate::kActionTypeUnspecified;
  CheckRow("G-ENF-04", "non-MOVE token gating /cmd_vel", in, Block("ERR_ACTION_MISMATCH", true));
  // AL-3 (implementation contract D3): from schema_version 4 the field is a class mask. The
  // same numeric value 3 is PLACE (enum) under v3 and MOVE|MANIPULATE under
  // v4 — the version decides, and an unversioned value is read as legacy.
  in = BaseGrpc();
  in.token_info.schema_version = 4;
  in.token_info.action_type = pail_pep_gate::kClassMove | pail_pep_gate::kClassManipulate;
  CheckRow("G-LED-06", "v4 mask with MOVE bit authorizes /cmd_vel", in, kPermit);
  in = BaseGrpc();
  in.token_info.schema_version = 4;
  in.token_info.action_type = pail_pep_gate::kClassManipulate;
  CheckRow("G-LED-06", "v4 mask without MOVE bit blocks /cmd_vel", in, Block("ERR_ACTION_MISMATCH", true));
  in = BaseGrpc();
  in.token_info.schema_version = 4;
  in.token_info.action_type = pail_pep_gate::kClassNone;
  CheckRow("G-LED-06", "v4 NONE(8) is a real class, not MOVE", in, Block("ERR_ACTION_MISMATCH", true));
  in = BaseGrpc();
  in.token_info.schema_version = 3;
  in.token_info.action_type = 3;  // v3: PLACE (enum), not a mask
  CheckRow("G-LED-06", "v3 value 3 is PLACE, not MOVE|MANIPULATE (mixed deployment)", in, Block("ERR_ACTION_MISMATCH", true));
  in = BaseGrpc();
  in.token_info.schema_version = 0;  // unparsed version: legacy reading
  in.token_info.action_type = 3;
  CheckRow("G-LED-06", "unversioned value 3 is judged as legacy enum", in, Block("ERR_ACTION_MISMATCH", true));
  return g_failures - before;
}

// PAIL-CASE: FeedEvidenceClaim
static int CaseFeedEvidenceClaim() {  // G-ENF-33 (SK-5, implementation contract)
  const int before = g_failures;
  // A registry row that feeds on evidence_claim needs fresh evidence with no target.
  GateInputs in = BaseGrpc();
  in.token_info.target_object_id = "";
  in.hold.target = "";
  in.require_evidence_feed = true;
  in.evidence.ever_received = false;
  in.evidence.received_ms = kNow;
  CheckRow("G-ENF-33", "evidence_claim feed, never received — blocks", in, Block("ERR_NO_EVIDENCE", true));
  in.evidence.ever_received = true;
  in.evidence.received_ms = kNow - in.limits.evidence_window_ms - 1;
  CheckRow("G-ENF-33", "evidence_claim feed, stale — blocks", in, Block("ERR_NO_EVIDENCE", true));
  in.evidence.received_ms = kNow;
  in.evidence.object_id = "anything";  // no target: identity is not asked
  CheckRow("G-ENF-33", "evidence_claim feed, fresh — permits without a target binding", in, kPermit);
  in.require_evidence_feed = false;
  in.evidence.ever_received = false;
  CheckRow("G-ENF-33", "no feed, no target — evidence is not asked (unchanged)", in, kPermit);
  return g_failures - before;
}

// PAIL-CASE: SkillNameV5
static int CaseSkillNameV5() {  // G-ENF-32
  const int before = g_failures;
  // SK-4 (implementation contract, L15·L16): a v5 token is judged by skill NAME, not by the mask.
  GateInputs in = BaseGrpc();
  in.token_info.schema_version = pail_pep_gate::kTokenSchemaNamedEnvelope;
  in.token_info.action_type = 0;  // mask deliberately empty — v5 does not read it
  in.token_info.skill = "twist";
  in.token_info.slot = "main";
  in.command.skill = "twist";
  CheckRow("G-ENF-32", "v5 name match permits with an empty mask", in, kPermit);
  in.command.skill = "pick";
  CheckRow("G-ENF-32", "v5 skill name mismatch blocks", in, Block("ERR_ACTION_MISMATCH", true));
  in.command.skill = "";
  CheckRow("G-ENF-32", "v5 command naming no skill blocks (no mask fallback)", in, Block("ERR_ACTION_MISMATCH", true));
  in.command.skill = "twist";
  in.token_info.slot = "left_hand";
  CheckRow("G-ENF-32", "v5 slot this gate does not hold blocks", in, Block("ERR_BAD_TOKEN", true));
  return g_failures - before;
}

// PAIL-CASE: Constraint
static int CaseConstraint() {  // G-ENF-05 (rows per implementation contract, pins_current_behavior)
  const int before = g_failures;
  GateInputs in = BaseGrpc();
  in.command.linear_norm = 1.5;  // limit 1.0
  CheckRow("G-ENF-05", "row a: linear over limit — block, not clamp", in,
           Block("ERR_CONSTRAINT", true));

  in = BaseGrpc();
  in.command.angular_norm = 1.2;  // limit 1.0
  CheckRow("G-ENF-05", "angular over limit", in, Block("ERR_CONSTRAINT", true));

  // Row b FLIPPED by implementation contract (C-B5): it used to freeze "0 = unlimited"
  // and promise to go RED first when that convention died — this is that flip,
  // recorded. A 0 limit now blocks: the issuer refuses to mint 0 speeds and
  // strict_verify refuses them at the seam, so a 0 reaching decide() is an
  // erased field, and erasure must not widen authority.
  in = BaseGrpc();
  in.token_info.max_linear_speed_mps = 0.0;
  in.command.linear_norm = 99.0;
  CheckRow("G-ENF-05", "row b: 0 limit blocks (C-B5 — was 'unlimited')", in,
           Block("ERR_CONSTRAINT", true));
  return g_failures - before;
}

// PAIL-CASE: EnvelopeGeneric
// G-ADP-13 (SK-2, implementation contract): the envelope compares by NAME over the whole
// list. A name the token bounds but the adapter did not measure blocks as
// unmeasured (ERR_BAD_TOKEN) — "did not look" is not "within limits". A lower
// bound (min) blocks from below. The v4 two-speed spelling is one instance.
static int CaseEnvelopeGeneric() {
  const int before = g_failures;
  using pail_pep_gate::Guardrail;
  auto rail = [](const char *name, bool has_max, double mx, bool has_min, double mn) {
    Guardrail g; g.name = name; g.has_max = has_max; g.max = mx; g.has_min = has_min; g.min = mn; return g;
  };
  auto check_detail = [&](const GateInputs &in, const char *needle, const char *note) {
    const GateDecision d = decide(in);
    if (d.detail.find(needle) == std::string::npos) {
      std::fprintf(stderr, "  FAIL [G-ADP-13] %s: detail=%s lacks %s\n", note, d.detail.c_str(), needle);
      ++g_failures;
    }
  };

  // measured map that names both speeds within bounds — same verdict as the norms
  GateInputs in = BaseGrpc();
  in.command.measured = {{"sls.linear_mps", 0.5}, {"sls.angular_rps", 0.5}};
  CheckRow("G-ADP-13", "measured map within the v4 envelope", in, kPermit);

  // unmeasured: the map names only the linear speed; the token bounds both
  in = BaseGrpc();
  in.command.measured = {{"sls.linear_mps", 0.5}};
  CheckRow("G-ADP-13", "unmeasured name blocks as ERR_BAD_TOKEN", in, Block("ERR_BAD_TOKEN", true));
  check_detail(in, "unmeasured:sls.angular_rps", "unmeasured detail names the name");

  // a third name on the token (contact force) — over → block, with the name in the detail
  in = BaseGrpc();
  in.token_info.guardrails = {rail("sls.linear_mps", true, 1.0, false, 0), rail("sls.angular_rps", true, 1.0, false, 0),
                              rail("sfc.contact_n", true, 5.0, false, 0)};
  in.command.measured = {{"sls.linear_mps", 0.5}, {"sls.angular_rps", 0.5}, {"sfc.contact_n", 7.0}};
  CheckRow("G-ADP-13", "third name over its max blocks", in, Block("ERR_CONSTRAINT", true));
  check_detail(in, "sfc.contact_n=7", "detail names the third name");
  in.command.measured["sfc.contact_n"] = 4.0;
  CheckRow("G-ADP-13", "third name within its max permits", in, kPermit);

  // a lower bound (separation distance) — under → block
  in = BaseGrpc();
  in.token_info.guardrails = {rail("sls.linear_mps", true, 1.0, false, 0), rail("sls.angular_rps", true, 1.0, false, 0),
                              rail("ssm.separation_m", false, 0, true, 1.0)};
  in.command.measured = {{"sls.linear_mps", 0.5}, {"sls.angular_rps", 0.5}, {"ssm.separation_m", 0.4}};
  CheckRow("G-ADP-13", "lower bound violated blocks", in, Block("ERR_CONSTRAINT", true));
  in.command.measured["ssm.separation_m"] = 1.5;
  CheckRow("G-ADP-13", "lower bound satisfied permits", in, kPermit);

  // NaN measurement blocks (C-B7 twin) even when the bound is fine
  in = BaseGrpc();
  in.command.measured = {{"sls.linear_mps", std::nan("")}, {"sls.angular_rps", 0.5}};
  CheckRow("G-ADP-13", "NaN measurement blocks", in, Block("ERR_CONSTRAINT", true));

  // grace twin: the HELD envelope compares by name too, unreported
  in = BaseGrpc();
  in.path = GatePath::Grace;
  in.token_view.ok = false;
  in.token_view.status = "UNREACHABLE";
  in.hold.active = true;
  in.hold.token_id = "tok-1";
  in.hold.not_after_ms = kNow + 10000;
  in.hold.max_linear = 1.0;
  in.hold.max_angular = 1.0;
  in.hold.guardrails = {rail("sls.linear_mps", true, 1.0, false, 0), rail("sfc.contact_n", true, 5.0, false, 0)};
  in.command.measured = {{"sls.linear_mps", 0.5}, {"sfc.contact_n", 9.0}};
  CheckRow("G-ADP-13", "grace: held third name over blocks, unreported", in, Block("ERR_CONSTRAINT", false));
  return g_failures - before;
}

// PAIL-CASE: StepOverrun
static int CaseStepOverrun() {  // D §3.2 (C-B5): command path asks the overrun question
  const int before = g_failures;

  // Overrun: the step timer should have consumed at the deadline and did not
  // (wedged/late). The command path blocks on its own — enforcement must not
  // depend on an active part stopping.
  GateInputs in = BaseGrpc();
  in.step_active = true;
  in.step_deadline_ms = kNow - 1;
  CheckRow("C-B5", "step overrun: command blocks without the timer", in,
           Block("ERR_CONSTRAINT", true));
  // rc12 4-4: the refusal names what ran out and by how much — the issuer's refusal carries
  // name/requested/max, and a gate refusal that says nothing made a real overrun (Linux,
  // 2026-09-16) indistinguishable from a speed-limit refusal in the record.
  auto check_overrun_detail = [&](const GateInputs &i, const char *note) {
    const GateDecision d = decide(i);
    const std::string want_deadline = "deadline=" + std::to_string(i.step_deadline_ms);
    const std::string want_now = "now=" + std::to_string(i.now_ms);
    const std::string want_over = "overrun_ms=" + std::to_string(i.now_ms - i.step_deadline_ms);
    if (d.detail.find("step.max_duration_s") == std::string::npos || d.detail.find(want_deadline) == std::string::npos ||
        d.detail.find(want_now) == std::string::npos || d.detail.find(want_over) == std::string::npos) {
      std::fprintf(stderr, "  FAIL [C-B5] %s: detail=%s lacks %s / %s / %s\n", note, d.detail.c_str(),
                   want_deadline.c_str(), want_now.c_str(), want_over.c_str());
      ++g_failures;
    }
  };
  check_overrun_detail(in, "overrun detail names the bound, now, deadline and the overrun");
  in.step_deadline_ms = kNow - 2500;
  check_overrun_detail(in, "overrun detail carries the actual gap");
  in.step_deadline_ms = kNow - 1;

  // Boundary: AT the deadline the timer's own consumption is the intended
  // actor (strict >) — decide() does not preempt it.
  in.step_deadline_ms = kNow;
  CheckRow("C-B5", "at deadline: not yet overrun (timer's turn)", in, kPermit);

  // No deadline (step from a durationless token, not_after fallback 0): the
  // question is not asked.
  in.step_deadline_ms = 0;
  CheckRow("C-B5", "deadline 0 while step active: no overrun question", in, kPermit);

  // Inactive step: a stale deadline left behind must not block.
  in = BaseGrpc();
  in.step_active = false;
  in.step_deadline_ms = kNow - 5000;
  CheckRow("C-B5", "stale deadline, no active step: ignored", in, kPermit);

  // Grace never outlives the step (D §3.2): overrun blocks under grace too,
  // unreported (issuer unreachable).
  in = BaseGrpc();
  in.path = GatePath::Grace;
  in.token_view.ok = false;
  in.token_view.status = "UNREACHABLE";
  in.hold.active = true;
  in.hold.token_id = "tok-1";
  in.hold.not_after_ms = kNow + 30000;
  in.hold.max_linear = 1.0;
  in.hold.max_angular = 1.0;
  in.step_active = true;
  in.step_deadline_ms = kNow - 1;
  CheckRow("C-B5", "step overrun under grace: blocked, unreported", in,
           Block("ERR_CONSTRAINT", false));
  check_overrun_detail(in, "grace overrun detail is filled the same way");
  return g_failures - before;
}

// PAIL-CASE: ExpiryBoundary
static int CaseExpiryBoundary() {  // G-ENF-06
  const int before = g_failures;
  // The core-owned expiry boundary lives on the Recheck/Grace paths
  // (`now > not_after + skew`, strict >). The Command-path window check lives
  // inside strict_verify (its own seam) and is not re-proven here.
  GateInputs in = BaseGrpc();
  in.path = GatePath::Recheck;
  in.hold.active = true;
  in.hold.token_id = "tok-1";
  in.hold.issued_hash = "wh-1";  // C-B8: recheck step 5 compares — state the side
  in.hold.not_after_ms = kNow;  // skew 500

  in.now_ms = kNow + 499;
  CheckRow("G-ENF-06", "not_after+skew-1: alive", in, kNoPublish);

  in.now_ms = kNow + 500;
  CheckRow("G-ENF-06", "not_after+skew exactly: alive (strict >)", in, kNoPublish);

  in.now_ms = kNow + 501;
  Expect e = Block("ERR_EXPIRED", false);
  CheckRow("G-ENF-06", "not_after+skew+1: expired", in, e);
  return g_failures - before;
}

// PAIL-CASE: TokenConsumed
static int CaseTokenConsumed() {  // G-ENF-07
  const int before = g_failures;
  GateInputs in = BaseGrpc();
  in.token_consumed = true;
  CheckRow("G-ENF-07", "consumed token replayed", in, Block("ERR_TOKEN_CONSUMED", true));
  return g_failures - before;
}

// PAIL-CASE: SafetyUnsafe
static int CaseSafetyUnsafe() {  // G-ENF-08
  const int before = g_failures;
  GateInputs in = BaseGrpc();  // valid token, fresh evidence — and still:
  in.safety.estop_active = true;
  Expect e = {"ESTOP", "ERR_SAFETY_UNSAFE", false, false, false, false, true, false, false};
  CheckRow("G-ENF-08", "estop outranks a valid token", in, e);
  return g_failures - before;
}

// PAIL-CASE: SafetyStale
static int CaseSafetyStale() {  // G-ENF-09
  const int before = g_failures;
  GateInputs in = BaseGrpc();
  in.safety.level = "WARN";
  CheckRow("G-ENF-09", "explicit WARN", in, Block("ERR_SAFETY_STALE", true));

  in = BaseGrpc();
  in.safety.ever_received = false;
  in.safety.level = "";
  CheckRow("G-ENF-09", "no safety feed ever", in, Block("ERR_SAFETY_STALE", true));

  in = BaseGrpc();
  in.safety.observed_ms = kNow - 1001;  // stale_ms 1000, strict >
  CheckRow("G-ENF-09", "safety feed stale", in, Block("ERR_SAFETY_STALE", true));

  // Exemption: the in-progress step may finish — WHEN THE POLICY GRANTS IT.
  // D-L3 : the grant is stated on every row below, because the
  // struct default is the refusing value ([OR3/X26]). Leaving it unstated would
  // make the two rows below pass on the policy gate rather than on the key
  // comparison they exist to measure — adjacent guards covering for each other.
  in = BaseGrpc();
  in.limits.safety_exempt_in_progress_step = true;
  in.safety.level = "WARN";
  in.step_active = true;
  in.step_consumption_key = "ck-tok-1";
  CheckRow("G-ENF-09", "in-progress step exempt", in, kPermit);

  // [OR3/X12②] The exemption belongs to the step's own bytes. A token that
  // merely carries the same envelope name does not inherit it. Differs from the
  // row above in the KEY alone.
  in = BaseGrpc();
  in.limits.safety_exempt_in_progress_step = true;
  in.safety.level = "WARN";
  in.step_active = true;
  in.step_consumption_key = "ck-other";
  CheckRow("G-ENF-09", "step exemption not claimable by another token", in,
           Block("ERR_SAFETY_STALE", true));

  // D-L3 (§9.2 PC-27) at L1: same matching key, policy withdrawn. Differs from
  // the exempt row in the POLICY alone, so the two together say the exemption is
  // granted by the file and not by the code.
  in = BaseGrpc();
  in.limits.safety_exempt_in_progress_step = false;
  in.safety.level = "WARN";
  in.step_active = true;
  in.step_consumption_key = "ck-tok-1";
  CheckRow("G-ENF-09", "step exemption withdrawn by policy", in,
           Block("ERR_SAFETY_STALE", true));
  return g_failures - before;
}

// PAIL-CASE: GrpcDisabled
static int CaseGrpcDisabled() {  // G-ENF-10
  const int before = g_failures;
  GateInputs in = BaseGrpc();
  in.supplier.grpc_built = false;
  CheckRow("G-ENF-10", "grpc mode on a PAIL_ENABLE_GRPC=0 build", in,
           Block("ERR_GRPC_DISABLED", true));
  return g_failures - before;
}

// PAIL-CASE: GraceNeverExtendsExpiry
static int CaseGraceNeverExtendsExpiry() {  // G-ENF-14
  const int before = g_failures;
  GateInputs in = BaseGrpc();
  in.path = GatePath::Grace;
  in.token_view.ok = false;
  in.token_view.status = "UNREACHABLE";
  in.hold.active = true;
  in.hold.token_id = "tok-1";
  in.hold.not_after_ms = kNow;
  // C-B5: hold limits must be real now (0 blocks). BaseGrpc's command is
  // 0.5/0.2, so the held permit carries the verified token's 1.0 limits.
  in.hold.max_linear = 1.0;
  in.hold.max_angular = 1.0;
  in.now_ms = kNow + 501;  // past not_after + skew
  // If this were PERMIT the guarantee is false: grace covers an unanswered
  // question, not a token that has run out.
  CheckRow("G-ENF-14", "expired under grace: refused", in,
           Block("ERR_ISSUER_UNREACHABLE", false));

  // Control row: within expiry, grace forwards under the held constraints.
  in.now_ms = kNow + 400;
  CheckRow("G-ENF-14", "alive under grace: forwarded, unreported", in, kGracePermit);
  return g_failures - before;
}

// PAIL-CASE: ConsumedCacheAtCapacity
static int CaseConsumedCacheAtCapacity() {  // G-ENF-15
  const int before = g_failures;
  // Honest limit : the 4096-entry cache is a NODE data structure;
  // the core receives only the boolean. This proves the blocking branch stays
  // alive when the cache reports a hit at capacity — the eviction policy itself
  // is TB-7's (node component) subject, not proven here.
  GateInputs in = BaseGrpc();
  in.token_consumed = true;
  CheckRow("G-ENF-15", "consumed verdict at cache capacity still blocks", in,
           Block("ERR_TOKEN_CONSUMED", true));
  return g_failures - before;
}

// PAIL-CASE: VerifyFailurePropagates
static int CaseVerifyFailurePropagates() {  // G-ENF-16
  const int before = g_failures;
  GateInputs in = BaseGrpc();
  in.verify_ok = false;
  in.verify_reason = "ERR_TAMPERED";
  CheckRow("G-ENF-16", "verify reason propagates verbatim", in, Block("ERR_TAMPERED", true));

  in.verify_reason = "ERR_SCHEMA";
  CheckRow("G-ENF-16", "core never rewrites the reason", in, Block("ERR_SCHEMA", true));
  return g_failures - before;
}

// PAIL-CASE: SupplierModeContract
static int CaseSupplierModeContract() {  // G-ENF-19 — 3 modes x {token, no token}
  const int before = g_failures;

  // grpc: full verification path (baseline is exactly this).
  CheckRow("G-ENF-19", "grpc + valid token", BaseGrpc(), kPermit);
  GateInputs in = BaseGrpc();
  in.token_view.ok = false;
  in.token_view.status = "NO_TOKEN";
  CheckRow("G-ENF-19", "grpc + no token", in, Block("ERR_NO_TOKEN", true));

  // static: signature verification is never consulted — only required_target.
  // deploy_profile refuses this mode in production; the pair of facts is the
  // substance of G-ENF-19 (implementation contract O-4).
  in = BaseGrpc();
  in.supplier.provider_mode = "static";
  in.verify_ok = false;              // would block in grpc mode — ignored here
  in.verify_reason = "ERR_TAMPERED";
  in.static_target_object_id = "pallet-7";
  CheckRow("G-ENF-19", "static skips signature verification", in, kPermitStat);
  in.token_view.ok = false;
  in.token_view.status = "NO_TOKEN";
  CheckRow("G-ENF-19", "static + no token", in, Block("ERR_NO_TOKEN", true));

  // notoken: the gate itself has NO notoken branch — the always-block rests on
  // NoTokenProvider returning ok=false (provider contract). Row 6 pins that
  // gate-side fact honestly: were a token view ever handed in, the core would
  // permit with no checks. deploy_profile flags the mode Warn for this reason.
  in = BaseGrpc();
  in.supplier.provider_mode = "notoken";
  in.token_view.ok = false;
  in.token_view.status = "NO_TOKEN";
  CheckRow("G-ENF-19", "notoken + no token (provider contract)", in,
           Block("ERR_NO_TOKEN", true));
  in.token_view.ok = true;
  in.token_view.status = "OK";
  CheckRow("G-ENF-19", "notoken + fabricated ok view (pins current behavior)", in,
           kPermitStat);
  return g_failures - before;
}

}  // namespace

int main() {
  struct { const char *name; int (*fn)(); } cases[] = {
    {"Baseline", CaseBaseline},
    {"NoToken", CaseNoToken},
    {"TargetMismatch", CaseTargetMismatch},
    {"NoEvidence", CaseNoEvidence},
    {"ActionMismatch", CaseActionMismatch},
    {"SkillNameV5", CaseSkillNameV5},
    {"FeedEvidenceClaim", CaseFeedEvidenceClaim},
    {"Constraint", CaseConstraint},
    {"EnvelopeGeneric", CaseEnvelopeGeneric},
    {"StepOverrun", CaseStepOverrun},
    {"ExpiryBoundary", CaseExpiryBoundary},
    {"TokenConsumed", CaseTokenConsumed},
    {"SafetyUnsafe", CaseSafetyUnsafe},
    {"SafetyStale", CaseSafetyStale},
    {"GrpcDisabled", CaseGrpcDisabled},
    {"GraceNeverExtendsExpiry", CaseGraceNeverExtendsExpiry},
    {"ConsumedCacheAtCapacity", CaseConsumedCacheAtCapacity},
    {"VerifyFailurePropagates", CaseVerifyFailurePropagates},
    {"SupplierModeContract", CaseSupplierModeContract},
  };
  int failed = 0;
  for (const auto &c : cases) {
    const int rc = c.fn();
    std::printf("%-32s %s\n", c.name, rc == 0 ? "PASS" : "FAIL");
    if (rc != 0) ++failed;
  }
  std::printf("---- %d case(s), %d failed\n", (int)(sizeof(cases) / sizeof(cases[0])), failed);
  return failed == 0 ? 0 : 1;
}
