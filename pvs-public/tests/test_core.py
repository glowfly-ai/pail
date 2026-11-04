# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Core orchestrator tests (host-runnable, no ROS2/docker).

Exercises the v1/v2 loader branch, the timeline scheduler on a virtual clock, and
the full dispatch→verdict path with a scripted FakeBackend.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner.core import model, report  # noqa: E402
from runner.core.backend import Backend, GateObs, BridgeObs, TwistObs, PermitObs  # noqa: E402
from runner.core.orchestrator import Orchestrator  # noqa: E402
from runner.core.timeline import Timeline  # noqa: E402

SCEN_ROOT = Path(__file__).resolve().parents[1] / "scenarios"


# ---------------- virtual clock ----------------

class VClock:
    def __init__(self):
        self.t = 0.0

    def clock(self):
        return self.t

    def sleep(self, dt):
        self.t += dt


class FakeBackend(Backend):
    """Scripts observations; virtual clock so tests are instant/deterministic."""

    def __init__(self, enforcement=False, **obs):
        self._vc = VClock()
        self.clock = self._vc.clock
        self.sleep = self._vc.sleep
        self.wall = self._vc.clock                       # one virtual time base for everything
        self._fault_takes = obs.get("fault_takes", 0.0)  # how long injecting a fault blocks
        self._bridge_hist = obs.get("bridge_history", [])
        self._enf = enforcement
        self._gate = obs.get("gate", GateObs())
        self._bridge = obs.get("bridge", BridgeObs())
        self._drive = obs.get("drive", TwistObs())
        self._drive_hist = obs.get("drive_history", [])
        self._permit = obs.get("permits", PermitObs())
        self._stop = obs.get("stop", False)
        self._burst = obs.get("burst")
        self._audit = obs.get("audit")
        self._anchor = obs.get("anchor")
        self._rogue = obs.get("rogue_outcome", "denied")
        self.calls = []

    def enforcement_supported(self): return self._enf
    def north_cmd(self, sub, args): self.calls.append(("north_cmd", sub))
    def inject_evidence(self, args): self.calls.append(("inject_evidence", args))
    def inject_cmd_vel(self, args): self.calls.append(("inject_cmd_vel", args))
    def inject_safety(self, args): self.calls.append(("inject_safety", args))
    def fault(self, args):
        self.calls.append(("fault", args))
        self._vc.sleep(self._fault_takes)

    def bridge_history(self): return self._bridge_hist
    def rogue_publish(self, args): return self._rogue
    def gate(self): return self._gate
    def bridge(self): return self._bridge
    def drive(self): return self._drive
    def drive_history(self): return self._drive_hist
    def permits(self, window_ms): return self._permit
    def stop_request_asserted(self): return self._stop
    def burst_result(self): return self._burst
    def audit_result(self): return self._audit
    def anchor_result(self): return self._anchor


# ---------------- loader ----------------

def test_loader_v1_branch():
    sc = model.load_scenario(SCEN_ROOT.parent / "scenarios" / "02_target_match_permit.yaml")
    assert not sc.is_v2
    assert sc.raw["northbound"]["mode"] == "plan"
    assert sc.steps == []  # v1 steps handled by legacy runner


def test_loader_v2_parses_inline_verbs(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(
        "version: 2.0\nname: t\nrobot_id: robot-1\nprofile: insecure\n"
        "steps:\n"
        "  - {t: 0.0, north_cmd: replay_token, step_id: s1}\n"
        "  - {t: 1.0, expect_gate: {state: BLOCK, reason: ERR_TOKEN_CONSUMED}}\n"
        "expectations_global:\n  - {audit_chain: PASS}\n"
    )
    sc = model.load_scenario(p)
    assert sc.is_v2 and sc.profile == "insecure"
    s0, s1 = sc.steps
    assert s0.verb == "north_cmd" and s0.args()["sub"] == "replay_token"
    assert s0.args()["step_id"] == "s1"
    assert s1.verb == "expect_gate" and s1.is_observe
    assert sc.expectations_global == [{"audit_chain": "PASS"}]


# ---------------- timeline ----------------

def test_timeline_orders_and_skips_nightly():
    vc = VClock()
    steps = [
        model.Step(2.0, "expect_gate", {}, {}, None, 0),
        model.Step(1.0, "inject_evidence", {}, {}, None, 1),
        model.Step(1.5, "expect_bridge", {}, {}, "nightly", 2),
    ]
    fired = []
    Timeline(steps, clock=vc.clock, sleep=vc.sleep).play(lambda s: fired.append((s.t, s.verb)))
    assert fired == [(1.0, "inject_evidence"), (2.0, "expect_gate")]  # nightly skipped, sorted


# ---------------- orchestrator verdict ----------------

def _scn(steps, name="t", **kw):
    return model.Scenario("2.0", name, "robot-1", kw.get("profile", "insecure"),
                          steps, kw.get("globals", []), {})


def test_expect_gate_pass():
    b = FakeBackend(gate=GateObs(state="PERMIT", reason="OK"))
    sc = _scn([model.Step(0.0, "expect_gate", {"state": "PERMIT", "reason": "OK"}, {}, None, 0)])
    v = Orchestrator(b).run(sc)
    assert v.passed, v.evidence_dump()


def test_expect_gate_fail_records_evidence():
    b = FakeBackend(gate=GateObs(state="PERMIT", reason="OK"))
    sc = _scn([model.Step(0.0, "expect_gate", {"state": "BLOCK", "reason": "ERR_TARGET_MISMATCH",
                                               "timeout": 0.1}, {}, None, 0)])
    v = Orchestrator(b).run(sc)
    assert not v.passed
    assert "expect_gate" in v.evidence_dump()


def test_expect_drive_never_detects_leak():
    leaked = [TwistObs(linear_x=9.9)]
    b = FakeBackend(drive_history=leaked)
    sc = _scn([model.Step(0.0, "expect_drive_never", {"linear_x": 9.9, "within_ms": 10}, {}, None, 0)])
    v = Orchestrator(b).run(sc)
    assert not v.passed  # rogue value reached the driver


def test_enforcement_skipped_on_insecure():
    b = FakeBackend(enforcement=False)
    sc = _scn([model.Step(0.0, "rogue_publish", {"topic": "/safe_cmd_vel"}, {}, None, 0)])
    v = Orchestrator(b).run(sc)
    assert v.skipped_axis == "Enforcement"
    assert v.passed  # skipped, not failed


def test_enforcement_pass_on_sros2():
    b = FakeBackend(enforcement=True, rogue_outcome="denied")
    sc = _scn([model.Step(0.0, "rogue_publish", {"topic": "/safe_cmd_vel"}, {}, None, 0)],
              profile="sros2")
    v = Orchestrator(b).run(sc)
    assert v.passed and v.skipped_axis is None


def test_expect_permit_absence():
    b = FakeBackend(permits=PermitObs(seqs=[], window_ms=300))
    sc = _scn([model.Step(0.0, "expect_permit", {"present": False, "observe_window_ms": 50},
                          {}, None, 0)])
    v = Orchestrator(b).run(sc)
    assert v.passed


def test_global_audit_chain():
    from runner.verifiers.segment_chain import Result
    b = FakeBackend(audit=Result(ok=True, records=5))
    sc = _scn([], globals=[{"audit_chain": "PASS"}])
    v = Orchestrator(b).run(sc)
    assert v.passed


def test_report_junit_and_html(tmp_path):
    b = FakeBackend(gate=GateObs(state="PERMIT", reason="OK"))
    sc = _scn([model.Step(0.0, "expect_gate", {"state": "PERMIT", "reason": "OK"}, {}, None, 0)],
              name="demo")
    v = Orchestrator(b).run(sc)
    report.write_junit([v], tmp_path / "j.xml", {"demo": "functional"})
    report.write_html([v], tmp_path / "r.html", {"demo": "functional"})
    assert (tmp_path / "j.xml").read_text().startswith("<?xml")
    assert "PASS" in (tmp_path / "r.html").read_text()


def test_discover_returns_only_files_that_load_as_scenarios():
    """Every discovered file must load, and the registry files must not be discovered."""
    from runner.core.model import discover, load_scenario
    root = Path(__file__).resolve().parents[1] / "scenarios"
    found = discover(str(root))
    assert len(found) >= 24, "discovery found too few scenarios to mean anything: %d" % len(found)
    for p in found:
        load_scenario(p)                                   # raises if it is not a scenario
    names = {p.name for p in found}
    assert "OWNERSHIP.yaml" not in names and "CA_MAP.yaml" not in names
    assert (root / "token" / "OWNERSHIP.yaml").is_file(), "the registry file this test guards against is gone"


def test_step_selector_inside_verb_arguments_is_refused():
    """`only: nightly` inside the verb's arguments used to be ignored without a word."""
    good = model._parse_v2_step({"t": 3.0, "expect_bridge": {"state": "HOLD"}, "only": "nightly"}, 0)
    assert good.only == "nightly" and "only" not in good.args()
    with pytest.raises(ValueError, match="belongs to the step"):
        model._parse_v2_step({"t": 3.0, "expect_bridge": {"state": "HOLD", "only": "nightly"}}, 0)


# ---------------- reaction time after a fault ----------------
#
# The dead-man scenarios bound how long after a fault the bridge enters HOLD. The bound used to
# be compared with the time the check spent polling: a check scheduled a second after the fault
# found HOLD already there, measured ~0 ms and could not fail. These tests fix the measurement
# to the transition itself and keep its three outcomes apart.

def _reaction(hold_at, fault_takes=0.03, history=None, bound=200, with_fault=True):
    hist = history if history is not None else [BridgeObs(state="FORWARDING", t=0.5),
                                                BridgeObs(state="HOLD", t=hold_at, t_received=hold_at + 0.01)]
    b = FakeBackend(bridge=BridgeObs(state="HOLD"), bridge_history=hist, fault_takes=fault_takes)
    steps = [model.Step(2.0, "fault", {"kill": "pep_gate"}, {}, None, 0)] if with_fault else []
    steps.append(model.Step(3.0, "expect_bridge", {"state": "HOLD", "within_ms_of_fault": bound}, {}, None, 1))
    return Orchestrator(b).run(_scn(steps))


def test_reaction_within_bound_passes_and_reports_the_interval():
    v = _reaction(hold_at=2.13)                          # fault issued 2.00, call returned 2.03
    assert v.passed and not v.inconclusive, v.evidence_dump()
    got = v.checks[-1].actual
    assert got["after_fault_ms"] == {"at_least": 100.0, "at_most": 130.0}
    assert got["fault_injection_took_ms"] == 30.0 and got["report_received_after_ms"] == 140.0


def test_late_reaction_fails_even_though_the_state_is_already_there_when_checked():
    """The regression this measurement exists for: HOLD arrives 500 ms after the fault, the check
    runs at t=3.0 and finds HOLD at once. The old comparison passed this."""
    v = _reaction(hold_at=2.5)
    assert not v.passed and not v.inconclusive
    assert "at least 470 ms" in v.checks[-1].detail


def test_bound_inside_the_injection_uncertainty_is_inconclusive_not_a_pass():
    v = _reaction(hold_at=2.25, fault_takes=0.15)        # at least 100 ms, at most 250 ms; bound 200
    assert v.passed, "an undecidable check must not fail the scenario"
    assert [c.step_index for c in v.inconclusive] == [1]
    rec = v.to_record()["checks"][-1]
    assert rec["passed"] is None and rec["inconclusive"] is True
    assert "lies between" in rec["detail"]


def test_no_transition_to_time_fails():
    hist = [BridgeObs(state="HOLD", t=0.5), BridgeObs(state="HOLD", t=2.1)]   # never left HOLD
    v = _reaction(hold_at=None, history=hist)
    assert not v.passed and "no transition to time" in v.checks[-1].detail


def test_backend_without_timestamped_history_is_inconclusive():
    v = _reaction(hold_at=None, history=[])
    assert v.passed and len(v.inconclusive) == 1 and "no timestamped" in v.checks[-1].detail


def test_reaction_bound_without_a_fault_fails():
    v = _reaction(hold_at=2.1, with_fault=False)
    assert not v.passed and "no fault step" in v.checks[-1].detail


def test_the_old_polling_time_bound_is_refused():
    b = FakeBackend(bridge=BridgeObs(state="HOLD"))
    sc = _scn([model.Step(3.0, "expect_bridge", {"state": "HOLD", "max_latency_ms": 200}, {}, None, 0)])
    with pytest.raises(ValueError, match="within_ms_of_fault"):
        Orchestrator(b).run(sc)


def test_deadman_scenarios_bound_the_reaction_to_the_fault():
    """The two scenarios must carry the bound in the form that is measured, on a nightly step."""
    for name in ("dm01_pep_kill_bridge_hold", "dm03_pep_pause_hang_hold"):
        sc = model.load_scenario(SCEN_ROOT / "deadman" / (name + ".yaml"))
        timed = [s for s in sc.steps if s.verb == "expect_bridge" and "within_ms_of_fault" in s.args()]
        assert len(timed) == 1 and timed[0].only == "nightly", name
        faults = [s for s in sc.steps if s.verb == "fault"]
        assert faults and faults[0].t < timed[0].t, name



# ---------------- a plan the issuer refuses ----------------
#
# rc02 measures that issuance stays frozen after a replayed unlock, so its second submission is
# meant to be refused. The harness used to treat every refusal as its own failure and the
# scenario could not run; before that it swallowed refusals and the run failed downstream as
# ERR_NO_TOKEN. The step now declares the outcome it expects and the refusal is judged against it.

def test_a_refusal_the_step_declared_is_not_an_error():
    args = {"submit_status": "REJECTED", "submit_reason": "SAFE_STOP"}
    assert model.submit_declaration_error(args, "REJECTED", "issuer state SAFE_STOP") is None


def test_an_undeclared_refusal_is_still_an_error():
    """The 2026-09-06 guard: a plan nobody served must not read as a plan nobody asked for."""
    err = model.submit_declaration_error({}, "REJECTED", "requester unknown")
    assert err and "requester unknown" in err


def test_a_declared_refusal_that_did_not_happen_is_an_error():
    """If the issuer serves the plan, the freeze rc02 exists to measure did not hold."""
    err = model.submit_declaration_error({"submit_status": "REJECTED"}, "ACCEPTED", "")
    assert err and "ACCEPTED" in err


def test_a_refusal_for_another_reason_than_declared_is_an_error():
    err = model.submit_declaration_error(
        {"submit_status": "REJECTED", "submit_reason": "SAFE_STOP"}, "REJECTED", "target not declared in the site model")
    assert err and "another reason" in err


def test_an_unknown_declaration_is_refused_rather_than_read_as_permissive():
    err = model.submit_declaration_error({"submit_status": "refused"}, "REJECTED", "whatever")
    assert err and "submit_status" in err


def test_rc02_declares_the_refusal_it_measures():
    """The scenario file must carry the declaration; without it the step cannot run at all."""
    sc = model.load_scenario(SCEN_ROOT / "recovery" / "rc02_unlock_nonce_replay_denied.yaml")
    declared = [s for s in sc.steps if s.verb == "north_cmd" and "submit_status" in s.args()]
    assert len(declared) == 1 and declared[0].args()["submit_status"] == "REJECTED"
    assert declared[0].args()["submit_reason"] == "SAFE_STOP"
