// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// TB-1: pure transposition of the three decision paths measured in
// pep_gate_node.cpp @ e7f0899 . Behaviour change is forbidden
// in this file's introduction commit (HLD IR-1): order, reason strings and
// report flags are copied, not redesigned.

#include "pail_gate/gate_core.hpp"

#include <cmath>
#include <cstdio>

#include "pail_gate/safety_level.hpp"
#include "pail_gate/wall_clock.hpp"

namespace pail_pep_gate {

// C-B8 : "could not compare" is not "compared and equal".
// The old bool skipped empty sides as an "intended fail-open exception for
// CG1 mode and pre-v3 tokens" — but that discriminated old versions by
// EMPTINESS, not by schema_version, so an issuer that failed to compute the
// world hash produced the same value as a clean match (R-D3: v1 tokens
// already die at ERR_SCHEMA in strict verification; a site-model-less
// issuance now blocks, observably, instead of silently ungating).
WorldMatch world_match(const std::string &issued, const std::string &current) {
  if (issued.empty() || current.empty()) return WorldMatch::kIndeterminate;
  return issued == current ? WorldMatch::kMatch : WorldMatch::kMismatch;
}

// DC-14 : subtraction, not addition. `not_after_ms +
// clock_skew_ms` overflows (UB) at INT64_MAX-adjacent values and a
// deployer-set negative skew silently *advances* expiry; `now_ms - skew`
// cannot leave int64 range because now_ms is a real clock reading. Saturating
// add was rejected — saturation pins the sum at INT64_MAX and expiry never
// arrives (fail-open). Negative skew is neutralized exactly as
// strict_verify.cpp:126 does; the two sites differing was itself the defect.
bool held_expired(int64_t now_ms, int64_t not_after_ms, int64_t clock_skew_ms) {
  if (not_after_ms == 0) return false;  // "no expiry" — the 0 verdict is C-B5, D's to judge
  const int64_t skew = clock_skew_ms > 0 ? clock_skew_ms : 0;
  return now_ms - skew > not_after_ms;
}

namespace {

// SK-2 : the envelope compare, one shape for both paths.
//
// The token's bounds and the adapter's measurements meet by NAME. A token that
// carries no list (v<=4 filled by strict_verify, or a test that set only the
// two fixed fields) reads as the two speed names; a command that carries no map
// reads as the two norms. So every pre-SK-2 caller is judged exactly as before,
// and an adapter that measures more is judged on all of it.
std::vector<Guardrail> effective_guardrails(const std::vector<Guardrail> &list,
                                            double max_linear, double max_angular) {
  if (!list.empty()) return list;
  Guardrail lin; lin.name = kGuardrailLinear; lin.max = max_linear; lin.has_max = true;
  Guardrail ang; ang.name = kGuardrailAngular; ang.max = max_angular; ang.has_max = true;
  return {lin, ang};
}

std::map<std::string, double> effective_measured(const CommandRequest &c) {
  if (!c.measured.empty()) return c.measured;
  return {{kGuardrailLinear, c.linear_norm}, {kGuardrailAngular, c.angular_norm}};
}

std::string fmt_num(double v) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%.4g", v);
  return buf;
}

GateDecision publish(const char *state, const std::string &reason);

// Returns true (and fills *d) when the envelope refuses. Block, never clamp.
// D §4.3 (C-B7): NaN blocks before the comparison, on either operand. A name
// the token bounds but the command did not measure is refused as unmeasured —
// "did not look" must not read as "within limits" (H-B2).
bool envelope_refuses(const std::map<std::string, double> &measured,
                      const std::vector<Guardrail> &rails, GateDecision *d) {
  for (const auto &g : rails) {
    const auto it = measured.find(g.name);
    if (it == measured.end()) {
      // SK-5 (revealed by the v5 list): step.max_duration_s is a permit-LIFETIME
      // bound — the session's step deadline enforces it, so a command that does
      // not measure it is not silent about it. An adapter that does measure it
      // (Microduck: the skill's own duration) is still compared below.
      if (g.name == kGuardrailDuration) continue;
      *d = publish("BLOCK", "ERR_BAD_TOKEN");
      d->detail = "unmeasured:" + g.name;
      return true;
    }
    const double v = it->second;
    const bool over = g.has_max && (!std::isfinite(g.max) || v > g.max);
    const bool under = g.has_min && (!std::isfinite(g.min) || v < g.min);
    if (!std::isfinite(v) || over || under) {
      *d = publish("BLOCK", "ERR_CONSTRAINT");
      d->detail = g.name + "=" + fmt_num(v) + " outside [" +
                  (g.has_min ? fmt_num(g.min) : std::string("-")) + "," +
                  (g.has_max ? fmt_num(g.max) : std::string("-")) + "]";
      return true;
    }
  }
  return false;
}

// publish_gate() in the node stops the permit heartbeat on every non-PERMIT
// publication (M4 fail-closed invariant). The core mirrors that coupling in
// one place so no branch can forget it.
GateDecision publish(const char *state, const std::string &reason) {
  GateDecision d;
  d.state = state;
  d.reason = reason;
  d.stop_permit = (d.state != "PERMIT");
  return d;
}

// implementation contract D-L5 §6.2. Confidence and trust class measure different things:
// the first asks how sure this reading is, the second asks whether a reading of
// this KIND can carry this authority. A 0.99 VISION read is a confident
// inference, not an identity response.
//
// Physically single, called from both evidence blocks. The design named only
// the P-GRACE site (§6.2 quotes gate_core.cpp:115-120); the observation points
// it specifies (PC-21/PC-23, §9.2) run on P-CMD, so naming one site would have
// left the measured path unguarded. Recorded as a divergence rather than
// silently widened — see EVIDENCE §5.
//
// An unmapped source arrives as rank 0 and is refused whenever the policy named
// a floor. That does NOT duplicate S16g: S16g catches a POLICY that omitted one
// of the five sources, this catches a MESSAGE carrying a string outside the
// vocabulary. Different things, so both stay.
bool evidence_trust_below_floor(const GateInputs &in) {
  return in.limits.min_trust_rank > 0 &&
         in.evidence.trust_rank < in.limits.min_trust_rank;
}

// Shared predicate of P-CMD and P-GRACE (node: safety_blocks_new_permit).
bool safety_blocks_new_permit(const GateInputs &in, const std::string &identity) {
  if (!in.safety.enabled) return false;
  // [OR3/X12②] Matched on consumption keys, not envelope names: the exemption
  // that lets an in-progress step continue through a degraded safety feed is
  // exactly the kind of thing worth claiming by renaming a token.
  // D-L3 (implementation contract, PC-27): and only when the POLICY granted it. This
  // exemption used to be unconditional, so `preconditions[safety_feed].
  // exempt_in_progress_step: false` was a sentence the operator could write and
  // the gate would not read — the P-19 shape, one level up.
  if (in.limits.safety_exempt_in_progress_step && in.step_active &&
      identity == in.step_consumption_key) {
    return false;
  }
  // D §4.1 (C-B7): only a parsed kOk passes. "WARN" used to be the single
  // blocking value, so "UNSAFE", a typo and an empty string all slid through —
  // kUnknown blocks exactly like kUnsafe but stays a distinct value (H-B2).
  if (ParseSafetyLevel(in.safety.level) != SafetyLevel::kOk) return true;
  if (!in.safety.ever_received) return true;
  return (in.now_ms - in.safety.observed_ms) > in.limits.safety_stale_ms;
}

bool held_expired(const GateInputs &in) {
  return pail_pep_gate::held_expired(in.now_ms, in.hold.not_after_ms,
                                     in.limits.clock_skew_ms);
}

// GC-TIME-1 / C-B5: duration is local elapsed time, NOT an adjustable
// wall deadline. Check independently of the active timer, including grace.
bool step_overrun(const GateInputs &in) {
  if (!in.step_active) return false;
  if (in.step_uses_elapsed) return in.elapsed_now_ms >= in.step_deadline_elapsed_ms;
  return in.step_deadline_ms > 0 && in.now_ms > in.step_deadline_ms;
}

GateDecision block_step_overrun(const GateInputs &in) {
  GateDecision d = publish("BLOCK", "ERR_CONSTRAINT");
  const int64_t now = in.step_uses_elapsed ? in.elapsed_now_ms : in.now_ms;
  const int64_t deadline = in.step_uses_elapsed ? in.step_deadline_elapsed_ms : in.step_deadline_ms;
  d.detail = std::string(kGuardrailDuration) + ": clock=" +
             (in.step_uses_elapsed ? "elapsed" : "wall") + " now=" + std::to_string(now) +
             " deadline=" + std::to_string(deadline) +
             " overrun_ms=" + std::to_string(now - deadline) +
             " path=" + (in.path == GatePath::Command ? "command" : in.path == GatePath::Recheck ? "recheck" : "grace");
  return d;
}

// P-GRACE (node: forward_under_held_permit). Every check that does not need
// the issuer still runs; only the issuer round trip is skipped. Expiry is
// never graced (G-ENF-14) — on expiry the composed path falls through to
// BLOCK/ERR_ISSUER_UNREACHABLE, mirrored here because Grace is only ever
// entered from an UNREACHABLE read.
GateDecision decide_grace(const GateInputs &in) {
  if (held_expired(in)) {
    return publish("BLOCK", "ERR_ISSUER_UNREACHABLE");  // no report: unreachable
  }
  if (step_overrun(in)) {
    return block_step_overrun(in);  // D §3.2 — grace never outlives the step
  }
  // D §3.3 (C-B5): the `> 0.0` guards are gone — 0 is a real limit that blocks
  // all motion, not "unlimited". Legitimate v2+ tokens can no longer carry 0
  // here (issuer refuses at mint, strict_verify refuses at the seam), and v1
  // tokens never reach this path (ERR_SCHEMA at 3b).
  // D §4.3 (C-B7): NaN is false in every comparison — an unmeasurable norm or
  // limit must block BEFORE it is compared, or it slides through `>` as
  // "within limits". Both operands are checked: a NaN limit is as unmeasured
  // as a NaN command.
  // SK-2: the same named compare as 3f, against the HELD envelope.
  {
    GateDecision refused;
    if (envelope_refuses(effective_measured(in.command),
                         effective_guardrails(in.hold.guardrails, in.hold.max_linear, in.hold.max_angular),
                         &refused)) {
      return refused;  // unreported: the issuer is unreachable on this path
    }
  }
  // SK-5: a row that feeds on evidence_claim needs it fresh with or without a
  // target; the target binding is the separate question that follows.
  if (!in.hold.target.empty() || in.require_evidence_feed) {
    // D-L7 §6.4 (O-3): absence is asked as its OWN question, before staleness.
    // Leaving it to the window arithmetic meant absence passed for staleness
    // only because an unset received_ms happens to be 0 — the coincidence shape
    // that hid P-19 for months. A gate that never saw evidence must refuse
    // because it never saw evidence, not because zero is a long time ago.
    if (!in.evidence.ever_received) {
      return publish("BLOCK", "ERR_NO_EVIDENCE");
    }
    if (in.now_ms - in.evidence.received_ms > in.limits.evidence_window_ms) {
      return publish("BLOCK", "ERR_NO_EVIDENCE");
    }
  }
  if (!in.hold.target.empty()) {
    // D §4.3: NaN confidence would read as "confident enough" through `<`.
    if (!std::isfinite(in.evidence.confidence) ||
        !std::isfinite(in.limits.evidence_conf_threshold) ||
        in.evidence.object_id != in.hold.target ||
        in.evidence.confidence < in.limits.evidence_conf_threshold) {
      return publish("BLOCK", "ERR_TARGET_MISMATCH");
    }
    if (evidence_trust_below_floor(in)) {
      return publish("BLOCK", "ERR_EVIDENCE_TRUST_CLASS");
    }
  }
  if (safety_blocks_new_permit(in, in.hold.consumption_key)) {
    return publish("BLOCK", "ERR_SAFETY_STALE");
  }
  GateDecision d = publish("PERMIT", "OK");  // no report: the issuer is unreachable
  d.forward = true;
  return d;
}

// P15-H1: the session's local fatal latch. True when the view the issuer served,
// the verified token, or the permit being held names a chain or token this
// session already declared fatal. `which` names the match for the detail string.
bool fatal_latched(const GateInputs &in, std::string *which) {
  auto hit = [](const std::vector<std::string> &list, const std::string &id) {
    if (id.empty()) return false;
    for (const auto &x : list) {
      if (x == id) return true;
    }
    return false;
  };
  // The hold's ids are only an identity while the permit is active: after a stop the
  // session keeps them for the report and the log, and they name the chain just latched.
  static const std::string kNone;
  const std::string &hold_chain = in.hold.active ? in.hold.chain_id : kNone;
  const std::string &hold_token = in.hold.active ? in.hold.token_id : kNone;
  struct Probe { const char *what; const std::vector<std::string> *list; const std::string *id; };
  const Probe probes[] = {
      {"chain", &in.fatal_chains, &in.token_view.chain_id},
      {"chain", &in.fatal_chains, &in.token_info.chain_id},
      {"chain", &in.fatal_chains, &hold_chain},
      {"token", &in.fatal_tokens, &in.token_view.token_id},
      {"token", &in.fatal_tokens, &in.token_info.token_id},
      {"token", &in.fatal_tokens, &hold_token},
  };
  for (const auto &p : probes) {
    if (hit(*p.list, *p.id)) {
      *which = std::string(p.what) + ":" + *p.id;
      return true;
    }
  }
  return false;
}

GateDecision block_fatal_latched(const std::string &which) {
  GateDecision d = publish("BLOCK", "ERR_REVOKED");
  d.detail = "fatal_latched " + which;
  return d;  // no report: the fatal that latched it was reported (and is retried) already
}

// P-CMD (node: on_cmd_vel), order per implementation contract
GateDecision decide_command(const GateInputs &in) {
  // 1. M8: safety interlock outranks everything else (G-ENF-17 order fact).
  if (in.safety.estop_active) {
    return publish("ESTOP", "ERR_SAFETY_UNSAFE");  // no report: trigger_estop already did
  }

  // 1.2. P15-H1: a chain this session declared fatal stays dead here, whatever the
  // issuer answers — the report that revokes it may still be in flight, or lost.
  // Only an answer that offers authority is tested; a missing answer blocks below
  // under its own name (ERR_NO_TOKEN / ERR_ISSUER_UNREACHABLE).
  if (in.token_view.ok) {
    std::string which;
    if (fatal_latched(in, &which)) return block_fatal_latched(which);
  }

  // 1.5. D §3.2 (C-B5): an overrun step blocks commands until its consumption
  // resolves. Normally the step timer consumes AT the deadline and step_active
  // drops before this ever fires; if this fires, the timer is late or wedged
  // and the robot may still be moving under an authorization that has run out.
  if (step_overrun(in)) {
    GateDecision d = block_step_overrun(in);
    d.report = true;
    return d;
  }

  // 2. authorization absent
  if (!in.token_view.ok) {
    if (in.token_view.status == "UNREACHABLE" && in.hold.active &&
        in.supplier.permit_grace_n > 0 && !held_expired(in)) {
      return decide_grace(in);  // P-GRACE delegation
    }
    if (in.token_view.status == "UNREACHABLE") {
      return publish("BLOCK", "ERR_ISSUER_UNREACHABLE");  // no report (AV1)
    }
    GateDecision d = publish("BLOCK", "ERR_NO_TOKEN");
    d.report = true;
    return d;
  }

  std::string required_target;
  const bool grpc_mode =
      (in.supplier.provider_mode == "grpc" || in.supplier.use_token_service);

  if (grpc_mode) {
    // 3a. build without verification code linked
    if (!in.supplier.grpc_built) {
      GateDecision d = publish("BLOCK", "ERR_GRPC_DISABLED");
      d.report = true;
      return d;
    }
    // 3b. strict verification (performed by the caller; result injected).
    //     The core forwards the reason verbatim (G-ENF-16).
    if (!in.verify_ok) {
      // [OR3/X26] An empty reason means the caller never ran verification and
      // left the defaults standing. Publishing "" would put a value outside the
      // reason dictionary on the wire, so the refusal names itself instead.
      // Real verification results still travel verbatim.
      GateDecision d = publish(
          "BLOCK", in.verify_reason.empty() ? std::string("ERR_TAMPERED") : in.verify_reason);
      d.report = true;
      return d;
    }
    required_target = in.token_info.target_object_id;

    // 3c. world moved out from under this token after issuance — before the
    //     consumption question is even asked (order fact, implementation contract).
    switch (world_match(in.token_info.subgraph_snapshot_hash,
                        in.token_view.current_subgraph_hash)) {
      case WorldMatch::kMatch:
        break;
      case WorldMatch::kMismatch: {
        GateDecision d = publish("BLOCK", "ERR_WORLD_CHANGED");
        d.report = true;
        d.fatal = true;
        return d;
      }
      case WorldMatch::kIndeterminate: {
        // Blocked but NOT fatal: an empty hash is an infrastructure-failure
        // signal, not world-change evidence. Fatal would revoke the chain and
        // turn an issuer glitch into a self-inflicted DoS; the block already
        // fails closed and the reason names the comparison that never ran.
        GateDecision d = publish("BLOCK", "ERR_WORLD_INDETERMINATE");
        d.report = true;
        return d;
      }
    }
    // 3d. single-use (replay defense)
    if (in.token_consumed) {
      GateDecision d = publish("BLOCK", "ERR_TOKEN_CONSUMED");
      d.report = true;
      return d;
    }
    // 3e. /cmd_vel is only authorized by a token whose action carries MOVE.
    //     AL-3 (implementation contract D3): schema_version >= 4 → action_type is a class mask
    //     and the MOVE bit is what authorizes motion; older tokens keep the
    //     single-enum comparison (F8). The version comes from the verified
    //     bytes; an unversioned value (0) is judged as legacy — the narrow
    //     reading — never as a mask.
    //     AD-1: the caller may ask for a class other than MOVE (CommandRequest::
    //     requested_class); a v4 mask must carry every requested bit, and a legacy
    //     token can only ever answer for MOVE. A requested_class of 0 asks for
    //     nothing, and "nothing" is not authorized (fail-closed, same as UNSPECIFIED).
    //     SK-4 (implementation contract, L15·L16): a v5 token authorizes a skill by NAME. The
    //     command must name the same skill; a command that names nothing cannot
    //     be matched and is refused (fail-closed — an adapter that did not learn
    //     v5 does not get the mask fallback). The class mask on a v5 token is
    //     minted for journals and v<=4 tools; it is not read here. The permit
    //     slot must be one this session holds — "main" in this edition.
    if (in.token_info.schema_version >= kTokenSchemaNamedEnvelope) {
      if (in.command.skill.empty() || in.command.skill != in.token_info.skill) {
        GateDecision d = publish("BLOCK", "ERR_ACTION_MISMATCH");
        d.report = true;
        d.detail = in.command.skill.empty()
            ? "command names no skill; token authorizes " + in.token_info.skill
            : "skill:" + in.command.skill + " token:" + in.token_info.skill;
        return d;
      }
      if (in.token_info.slot != kSlotMain) {
        GateDecision d = publish("BLOCK", "ERR_BAD_TOKEN");
        d.report = true;
        d.detail = "slot:" + in.token_info.slot + " not held by this gate (single-slot edition)";
        return d;
      }
    } else {
      const bool mask_semantics = in.token_info.schema_version >= kTokenSchemaMask;
      const int  wanted = in.command.requested_class;
      const bool move_ok = wanted != 0 && (mask_semantics
          ? (in.token_info.action_type & wanted) == wanted
          : (wanted == kClassMove && in.token_info.action_type == kActionMove));
      if (!move_ok) {
        GateDecision d = publish("BLOCK", "ERR_ACTION_MISMATCH");
        d.report = true;
        return d;
      }
    }
    // 3f. per-token constraint — block, do not clamp. D §3.3 (C-B5): the
    //     `> 0.0` guards are gone — a 0 limit is a real limit (blocks all
    //     motion), not "unlimited". proto3 omits defaults on the wire, so a
    //     deleted field used to arrive as "unlimited"; now the issuer refuses
    //     to mint 0 speeds, strict_verify refuses them at the seam (3b, before
    //     this line), and v1 tokens are already ERR_SCHEMA at 3b — so a 0 seen
    //     here is an erased field, and erasure must not widen authority.
    //     D §4.3 (C-B7): NaN blocks before the comparison — see the grace-path
    //     twin. Post-C-B5 there is no `> 0.0` guard left to accidentally catch
    //     a NaN limit, so the comparison itself is the penetration point.
    //     SK-2 : the compare is by name over the whole envelope —
    //     the two speeds are the v4 spelling of it, not the shape of it.
    {
      GateDecision refused;
      if (envelope_refuses(effective_measured(in.command),
                           effective_guardrails(in.token_info.guardrails,
                                                in.token_info.max_linear_speed_mps,
                                                in.token_info.max_angular_speed_rps),
                           &refused)) {
        refused.report = true;
        return refused;
      }
    }
  } else if (in.supplier.provider_mode == "static") {
    // 4. static mode: no signature / window / single-use / action checks —
    //    deploy_profile refuses this in production (G-ENF-19).
    required_target = in.static_target_object_id;
  }

  // 5. cognitive evidence binding. SK-5: a row feeding on evidence_claim needs
  //    fresh evidence with or without a target (the session asks via
  //    require_evidence_feed); the target binding stays its own question.
  if (!required_target.empty() || in.require_evidence_feed) {
    // D-L7 §6.4 (O-3) — twin of the P-GRACE site. Absence before staleness:
    // before this line existed, a gate that had never received evidence read as
    // "received just now" (the node stamped the clock in its constructor) and
    // fell through to ERR_TARGET_MISMATCH, sending the operator to re-align a
    // robot that had seen nothing. Measured, then fixed — RED_TRUSTCLASS_STEP5 §4.
    if (!in.evidence.ever_received) {
      GateDecision d = publish("BLOCK", "ERR_NO_EVIDENCE");
      d.report = true;
      return d;
    }
    if (in.now_ms - in.evidence.received_ms > in.limits.evidence_window_ms) {
      GateDecision d = publish("BLOCK", "ERR_NO_EVIDENCE");
      d.report = true;
      return d;
    }
  }
  if (!required_target.empty()) {
    if (in.evidence.object_id != required_target) {
      GateDecision d = publish("BLOCK", "ERR_TARGET_MISMATCH");
      d.report = true;
      return d;
    }
    // D §4.3 (C-B7): NaN confidence reads as "confident" through `<` — block
    // before comparing (F-CPP-5 site; the fourth of four).
    if (!std::isfinite(in.evidence.confidence) ||
        !std::isfinite(in.limits.evidence_conf_threshold) ||
        in.evidence.confidence < in.limits.evidence_conf_threshold) {
      GateDecision d = publish("BLOCK", "ERR_TARGET_MISMATCH");
      d.report = true;
      return d;
    }
    // D-L5 §6.2 — after confidence, so the two refusals stay separable: a
    // low-confidence RFID read is still ERR_TARGET_MISMATCH (PC-22), and only a
    // read of the wrong KIND lands here (PC-21/PC-23).
    if (evidence_trust_below_floor(in)) {
      GateDecision d = publish("BLOCK", "ERR_EVIDENCE_TRUST_CLASS");
      d.report = true;
      return d;
    }
  }

  // 6. stale/absent/WARN safety feed forbids NEW permits
  // [OR3/X12②] In grpc mode we are past 3b, so token_info comes from verified
  // bytes. Static mode has no signature, so the envelope name is the only
  // identity there is — and single-use is not enforced on that path anyway.
  if (safety_blocks_new_permit(
          in, grpc_mode ? in.token_info.consumption_key : in.token_view.token_id)) {
    GateDecision d = publish("BLOCK", "ERR_SAFETY_STALE");
    d.report = true;
    return d;
  }

  // GC-TIME-1: reject unusable budgets before any forwarding/state mutation.
  // duration=0 retains the signed absolute-expiry fallback.
  if (grpc_mode) {
    const double duration = in.token_info.max_duration_sec;
    int64_t deadline = 0;
    if (!std::isfinite(duration) || duration < 0.0) {
      GateDecision d = publish("BLOCK", "ERR_CONSTRAINT");
      d.detail = "step.max_duration_s: invalid duration"; d.report = true;
      return d;
    }
    if (duration > 0.0) {
      if (in.elapsed_now_ms < 0) {
        auto d = publish("BLOCK", "ERR_CLOCK_DRIFT");
        d.detail = ClockRefusalDetail(in) + " path=" +
        (in.path == GatePath::Command ? "command" : in.path == GatePath::Recheck ? "recheck" : "grace");
        return d;
      }
      if (!DurationDeadlineMs(in.elapsed_now_ms, duration, &deadline)) {
        GateDecision d = publish("BLOCK", "ERR_CONSTRAINT");
        d.detail = "step.max_duration_s: deadline not representable"; d.report = true;
        return d;
      }
      if (deadline <= in.elapsed_now_ms) {
        GateDecision d = publish("BLOCK", "ERR_CONSTRAINT");
        d.detail = "step.max_duration_s: below clock resolution"; d.report = true;
        return d;
      }
    }
  }

  // 7. PERMIT
  GateDecision d = publish("PERMIT", "OK");
  d.forward = true;
  d.report = true;
  d.enter_permit = true;
  d.begin_step = grpc_mode;
  return d;
}

// P-RECHECK (node: on_permit_recheck), order per implementation contract
GateDecision decide_recheck(const GateInputs &in) {
  if (!in.hold.active) return GateDecision{};

  // 1.2. P15-H1: the held permit (or the answer that would renew it) names a chain
  // this session declared fatal — stop the heartbeat, whatever the issuer answers.
  {
    std::string which;
    if (fatal_latched(in, &which)) return block_fatal_latched(which);
  }

  // 2. expiry — grace never outlives not_after
  if (held_expired(in)) {
    return publish("BLOCK", "ERR_EXPIRED");
  }

  // GC-TIME-1: heartbeat/grace must not outlive the duration if the step
  // timer is late. Expiry retains its existing ERR_EXPIRED priority above.
  if (step_overrun(in)) return block_step_overrun(in);

  // 3. AV1 grace: only an unanswered issuer is graced
  if (in.supplier.permit_grace_n > 0 && !in.token_view.ok &&
      in.token_view.status == "UNREACHABLE") {
    if (in.supplier.unreachable_streak + 1 < in.supplier.permit_grace_n) {
      GateDecision d;
      d.hold_permit = true;  // keep the permit, publish nothing
      return d;
    }
    return publish("BLOCK", "ERR_ISSUER_UNREACHABLE");
  }

  // 4. negative answer or token changed
  // This one stays a NAME comparison on purpose: the recheck path performs no
  // signature verification, so no verified key exists for the incoming answer.
  // Failing the comparison stops the permit, so an envelope that lies here
  // buys a denial, never a grant.
  if (!in.token_view.ok || in.token_view.token_id != in.hold.token_id) {
    return publish("BLOCK", (!in.token_view.ok && in.token_view.status == "REVOKED")
                                ? "ERR_REVOKED"
                                : "ERR_NO_TOKEN");
  }

  // 5. AG-2: world moved while the issuer still serves the same token.
  //    crypto360 F-PR-1 measured the old bool here: emptying
  //    current_subgraph_hash tipped this step toward GRANT — the one step of
  //    the recheck where a lying envelope bought a grant, not a denial.
  switch (world_match(in.hold.issued_hash, in.token_view.current_subgraph_hash)) {
    case WorldMatch::kMatch:
      break;
    case WorldMatch::kMismatch: {
      GateDecision d = publish("BLOCK", "ERR_WORLD_CHANGED");
      d.report = true;
      d.fatal = true;
      return d;
    }
    case WorldMatch::kIndeterminate: {
      GateDecision d = publish("BLOCK", "ERR_WORLD_INDETERMINATE");
      d.report = true;
      return d;
    }
  }

  return GateDecision{};  // permit stands; nothing to publish
}

}  // namespace

std::string ClockRefusalDetail(const GateInputs &in) {
  std::string cause = in.clock_fault;
  if (cause.empty()) {
    if (!in.clock_drift_known) cause = "unmeasured";
    else if (in.limits.clock_skew_ms < 0) cause = "invalid_skew_limit";
    else if (in.elapsed_now_ms < 0) cause = "elapsed_unavailable";
    else if (in.step_active && in.step_uses_elapsed && in.step_deadline_elapsed_ms < 0) cause = "invalid_elapsed_deadline";
    else cause = "wall_drift";
  }
  return "clock=wall-minus-steady drift_ms=" + std::to_string(in.clock_drift_ms) +
      " limit_ms=" + std::to_string(in.limits.clock_skew_ms) +
      " known=" + (in.clock_drift_known ? "true" : "false") +
      " elapsed_now_ms=" + std::to_string(in.elapsed_now_ms) + " cause=" + cause;
}

GateDecision decide(const GateInputs &in) {
  // DC-10 : drift outranks every path, including the ESTOP
  // ordering inside P-CMD — every check below reads now_ms, so a settable
  // clock that has jumped contaminates expiry, evidence windows and safety
  // staleness at once. BLOCK is still fail-closed here (a physical estop
  // happened outside this decision and trigger_estop already acted).
  // Tolerance is the existing clock_skew_ms: a clock trusted to disagree with
  // the issuer by at most N ms cannot be allowed to disagree with itself by
  // more. Unknown drift refuses too (H-B2): unmeasured is not "no drift".
  // Compare without abs(INT64_MIN) overflow. Unknown elapsed timestamps
  // may never become a passing deadline comparison.
  if (!in.clock_drift_known || in.limits.clock_skew_ms < 0 ||
      in.clock_drift_ms > in.limits.clock_skew_ms ||
      in.clock_drift_ms < -in.limits.clock_skew_ms ||
      (in.step_active && in.step_uses_elapsed &&
       (in.elapsed_now_ms < 0 || in.step_deadline_elapsed_ms < 0))) {
    auto d = publish("BLOCK", "ERR_CLOCK_DRIFT");
    d.detail = ClockRefusalDetail(in) + " path=" +
        (in.path == GatePath::Command ? "command" : in.path == GatePath::Recheck ? "recheck" : "grace");
    return d;
  }

  switch (in.path) {
    case GatePath::Command: return decide_command(in);
    case GatePath::Grace:   return decide_grace(in);
    case GatePath::Recheck: return decide_recheck(in);
  }
  // Unreachable; fail closed if it ever isn't.
  return publish("BLOCK", "ERR_NO_TOKEN");
}

}  // namespace pail_pep_gate
