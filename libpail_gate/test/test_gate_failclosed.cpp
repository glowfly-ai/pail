// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// TB-6 : fail-closed boundary. The substance of this block is that
// "not knowing" — an unanswered issuer, an unknown world hash, a lost feed —
// must be expressible as an input, and that the grace configuration never
// flips a fail-closed verdict (§4.4: every case runs grace_n=0 AND grace_n>0).
//
// Plain executable, no gtest. `// PAIL-CASE:` comments are canonical (CG-B).

#include <cstdio>
#include <string>

#include "pail_gate/gate_core.hpp"

using pail_pep_gate::GateDecision;
using pail_pep_gate::GateInputs;
using pail_pep_gate::GatePath;
using pail_pep_gate::decide;

namespace {

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

GateInputs BaseGrpc() {
  GateInputs in;
  in.path = GatePath::Command;
  in.now_ms = kNow;
  in.clock_drift_known = true;  // DC-10: measured, zero drift (drift rows live in test_clock_drift)
  in.token_view.ok = true;
  in.token_view.chain_id = "chain-1";
  in.token_view.token_id = "tok-1";
  in.token_view.status = "OK";
  in.verify_ok = true;
  in.token_consumed = false;  // [OR3/X26] stated, not inherited from a default
  in.token_info.target_object_id = "pallet-7";
  in.token_info.action_type = pail_pep_gate::kActionMove;
  in.token_info.max_linear_speed_mps = 1.0;
  in.token_info.max_angular_speed_rps = 1.0;
  in.token_info.not_after_unix_ms = kNow + 30000;
  // C-B8 : the world comparison is three-valued and an empty
  // side BLOCKS. A passing baseline states both sides; WorldChanged rows
  // override these explicitly.
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
  in.command.linear_norm = 0.5;
  in.command.angular_norm = 0.2;
  in.supplier.provider_mode = "grpc";
  in.supplier.grpc_built = true;
  in.supplier.permit_grace_n = 0;  // TB-6 default: no grace unless the row says so
  in.limits.clock_skew_ms = 500;
  in.limits.evidence_window_ms = 2000;
  in.limits.evidence_conf_threshold = 0.90;
  in.limits.safety_stale_ms = 1000;
  return in;
}

const Expect kPermit      = {"PERMIT", "OK", true,  false, true,  true,  false, true,  false};
const Expect kHold        = {"", "", false, false, false, false, false, false, true};
const Expect kGracePermit = {"PERMIT", "OK", false, false, true, false, false, false, false};

Expect Block(const char *reason, bool report) {
  return {"BLOCK", reason, report, false, false, false, true, false, false};
}
Expect BlockFatal(const char *reason) {
  return {"BLOCK", reason, true, true, false, false, true, false, false};
}

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

// PAIL-CASE: IssuerUnreachable
static int CaseIssuerUnreachable() {  // G-ENF-11
  const int before = g_failures;

  // UNREACHABLE is not a negative answer — and it is NOT reported (reporting to
  // an issuer that just failed to answer cannot arrive, implementation contract O-3).
  GateInputs in = BaseGrpc();
  in.token_view.ok = false;
  in.token_view.status = "UNREACHABLE";
  in.supplier.permit_grace_n = 0;
  CheckRow("G-ENF-11", "grace_n=0: block, unreported", in,
           Block("ERR_ISSUER_UNREACHABLE", false));

  // grace_n>0 but no held permit: nothing to grace — still fail-closed.
  in.supplier.permit_grace_n = 3;
  in.hold.active = false;
  CheckRow("G-ENF-11", "grace_n=3, no held permit: block", in,
           Block("ERR_ISSUER_UNREACHABLE", false));

  // grace_n>0 WITH a live permit: the held token's own checks still run and
  // the forward is unreported — grace does not weaken fail-closed, it narrows
  // it to the already-granted step.
  in.hold.active = true;
  in.hold.token_id = "tok-1";
  in.hold.not_after_ms = kNow + 30000;
  // C-B5: 0 hold limits now block (D §3.3) — the held permit carries the
  // verified token's real limits.
  in.hold.max_linear = 1.0;
  in.hold.max_angular = 1.0;
  CheckRow("G-ENF-11", "grace_n=3, held permit: forwarded unreported", in, kGracePermit);

  // ...and an ERROR status is never eligible for grace (UNREACHABLE only).
  in.token_view.status = "ERROR";
  CheckRow("G-ENF-11", "ERROR is not UNREACHABLE: no grace", in,
           Block("ERR_NO_TOKEN", true));
  return g_failures - before;
}

// PAIL-CASE: Revoked
static int CaseRevoked() {  // G-ENF-12
  const int before = g_failures;

  GateInputs in = BaseGrpc();
  in.path = GatePath::Recheck;
  in.hold.active = true;
  in.hold.token_id = "tok-1";
  in.hold.not_after_ms = kNow + 30000;
  in.token_view.ok = false;
  in.token_view.status = "REVOKED";
  in.supplier.permit_grace_n = 0;
  CheckRow("G-ENF-12", "recheck, grace_n=0: revoked stops the permit", in,
           Block("ERR_REVOKED", false));

  // A negative answer is never graced — grace covers only UNREACHABLE.
  in.supplier.permit_grace_n = 3;
  in.supplier.unreachable_streak = 0;
  CheckRow("G-ENF-12", "recheck, grace_n=3: revocation still immediate", in,
           Block("ERR_REVOKED", false));

  // Command-path REVOKED pins current behavior: the cmd path flattens every
  // non-UNREACHABLE failure to ERR_NO_TOKEN (only the recheck path names
  // ERR_REVOKED). Recorded, not endorsed — implementation contract discipline.
  in = BaseGrpc();
  in.token_view.ok = false;
  in.token_view.status = "REVOKED";
  CheckRow("G-ENF-12", "command path flattens to ERR_NO_TOKEN (pins current behavior)",
           in, Block("ERR_NO_TOKEN", true));
  return g_failures - before;
}

// PAIL-CASE: WorldChanged
static int CaseWorldChanged() {  // G-ENF-13 — rows per implementation contract
  const int before = g_failures;

  // Command path. fatal=true is the point: the report revokes the chain.
  GateInputs in = BaseGrpc();
  in.token_info.subgraph_snapshot_hash = "A";
  in.token_view.current_subgraph_hash = "B";
  CheckRow("G-ENF-13", "issued=A current=B: block, fatal", in,
           BlockFatal("ERR_WORLD_CHANGED"));

  // Rows 2-3 flipped by C-B8 . These rows used to PIN the
  // fail-open exception ("either side empty skips the comparison") — the
  // fixture held the defect as its expectation. An empty side now means the
  // comparison never happened, and "could not compare" blocks with its own
  // reason (non-fatal: infrastructure failure is not world-change evidence,
  // so the chain is not revoked — the block alone fails closed).
  in = BaseGrpc();
  in.token_info.subgraph_snapshot_hash = "A";
  in.token_view.current_subgraph_hash = "";
  CheckRow("G-ENF-13", "issued=A current=empty: indeterminate blocks", in,
           Block("ERR_WORLD_INDETERMINATE", true));

  in = BaseGrpc();
  in.token_info.subgraph_snapshot_hash = "";
  in.token_view.current_subgraph_hash = "B";
  CheckRow("G-ENF-13", "issued=empty current=B: indeterminate blocks", in,
           Block("ERR_WORLD_INDETERMINATE", true));

  in = BaseGrpc();
  in.token_info.subgraph_snapshot_hash = "A";
  in.token_view.current_subgraph_hash = "A";
  CheckRow("G-ENF-13", "issued=A current=A: match", in, kPermit);

  // Recheck path: divergence while the issuer still serves the same token.
  // Grace configuration must not defer this (grace_n=3 here).
  in = BaseGrpc();
  in.path = GatePath::Recheck;
  in.hold.active = true;
  in.hold.token_id = "tok-1";
  in.hold.not_after_ms = kNow + 30000;
  in.hold.issued_hash = "A";
  in.token_view.current_subgraph_hash = "B";
  in.supplier.permit_grace_n = 3;
  CheckRow("G-ENF-13", "recheck divergence: block, fatal, permit stops", in,
           BlockFatal("ERR_WORLD_CHANGED"));
  return g_failures - before;
}

// PAIL-CASE: StepDeadlinePassed
static int CaseStepDeadlinePassed() {  // G-ENF-18
  const int before = g_failures;
  // When the step deadline passes, the node's step timer marks the granting
  // token consumed; a re-request of the SAME token then arrives at the core
  // with token_consumed=true. The timer mechanics are node-side (TB-7); the
  // core-side guarantee is that the consumed verdict blocks regardless of the
  // grace configuration.
  GateInputs in = BaseGrpc();
  in.token_consumed = true;
  in.supplier.permit_grace_n = 0;
  CheckRow("G-ENF-18", "grace_n=0: consumed token re-request blocked", in,
           Block("ERR_TOKEN_CONSUMED", true));

  in.supplier.permit_grace_n = 3;
  in.hold.active = true;  // even with a live permit hold
  in.hold.token_id = "tok-1";
  CheckRow("G-ENF-18", "grace_n=3: grace does not resurrect a consumed token", in,
           Block("ERR_TOKEN_CONSUMED", true));
  return g_failures - before;
}

// PAIL-CASE: RecheckGraceLadder
static int CaseRecheckGraceLadder() {  // supporting rows for G-ENF-11/12 boundary
  const int before = g_failures;
  // The recheck grace ladder: streak+1 < n holds silently; streak+1 >= n stops.
  GateInputs in = BaseGrpc();
  in.path = GatePath::Recheck;
  in.hold.active = true;
  in.hold.token_id = "tok-1";
  in.hold.not_after_ms = kNow + 30000;
  in.token_view.ok = false;
  in.token_view.status = "UNREACHABLE";
  in.supplier.permit_grace_n = 3;

  in.supplier.unreachable_streak = 0;  // 1st miss
  CheckRow("G-ENF-11", "recheck miss 1/3: hold, publish nothing", in, kHold);
  in.supplier.unreachable_streak = 1;  // 2nd miss
  CheckRow("G-ENF-11", "recheck miss 2/3: hold", in, kHold);
  in.supplier.unreachable_streak = 2;  // 3rd miss: exhausted
  CheckRow("G-ENF-11", "recheck miss 3/3: stop", in,
           Block("ERR_ISSUER_UNREACHABLE", false));

  // grace_n=0 at recheck: falls through to the generic failure branch — the
  // current code names it ERR_NO_TOKEN, not ERR_ISSUER_UNREACHABLE (pins
  // current behavior; the AV2 honesty fix covered the command path only).
  in.supplier.permit_grace_n = 0;
  in.supplier.unreachable_streak = 0;
  CheckRow("G-ENF-11", "recheck grace_n=0: ERR_NO_TOKEN (pins current behavior)", in,
           Block("ERR_NO_TOKEN", false));
  return g_failures - before;
}

}  // namespace

int main() {
  struct { const char *name; int (*fn)(); } cases[] = {
    {"IssuerUnreachable", CaseIssuerUnreachable},
    {"Revoked", CaseRevoked},
    {"WorldChanged", CaseWorldChanged},
    {"StepDeadlinePassed", CaseStepDeadlinePassed},
    {"RecheckGraceLadder", CaseRecheckGraceLadder},
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
