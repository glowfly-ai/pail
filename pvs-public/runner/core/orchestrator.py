# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Orchestrator .

Wires the scenario timeline to a Backend and evaluates every `expect_*` against
observed state, producing a Verdict. All comparison/deadline logic lives here so
it can be unit-tested with a FakeBackend; live I/O is delegated to the backend.
"""

from __future__ import annotations

import math
import time as _time
from typing import Any, Dict, Optional

from .backend import Backend
from .model import Scenario, Step
from .timeline import Timeline
from .verdict import VerdictEngine, Verdict

DEFAULT_EXPECT_TIMEOUT_S = 3.0
DEFAULT_PERMIT_DEADLINE_MS = 100  # matches PAIL_PERMIT_DEADLINE_MS


class Orchestrator:
    def __init__(self, backend: Backend, skip_nightly: bool = True):
        self.b = backend
        self.skip_nightly = skip_nightly
        self._fault = None          # (issued, returned) wall instants of the most recent fault

    # ---------- deadline polling helper ----------
    def _poll(self, predicate, timeout_s: float):
        """Poll predicate() -> (done, value) until done or timeout. Returns
        (done, value, t_observed_offset)."""
        t0 = self.b.clock()
        deadline = t0 + timeout_s
        last = None
        while True:
            done, value = predicate()
            last = value
            if done:
                return True, value, self.b.clock() - t0
            if self.b.clock() >= deadline:
                return False, last, None
            self.b.sleep(0.02)

    # ---------- run ----------
    def run(self, scenario: Scenario) -> Verdict:
        eng = VerdictEngine(scenario.name)
        self._fault = None
        # Enforcement axis honesty: SKIP on profiles that cannot enforce (§5.3)
        needs_enf = any(s.verb in ("rogue_publish", "rogue_subscribe") for s in scenario.steps)
        if needs_enf and not self.b.enforcement_supported():
            eng.skip_axis("Enforcement", "insecure/uds profile cannot prove bypass "
                          "prevention; boundary guaranteed only under sros2")

        tl = Timeline(scenario.steps, clock=self.b.clock, sleep=self.b.sleep,
                      skip_nightly=self.skip_nightly)
        tl.play(lambda st: self._dispatch(st, eng))
        self._eval_globals(scenario, eng)
        return eng.finalize()

    def _dispatch(self, st: Step, eng: VerdictEngine) -> None:
        a = st.args()
        if st.verb == "north_cmd":
            self.b.north_cmd(a.get("sub"), a)
        elif st.verb == "inject_evidence":
            self.b.inject_evidence(a)
        elif st.verb == "inject_cmd_vel":
            self.b.inject_cmd_vel(a)
        elif st.verb == "inject_skill":
            self.b.inject_skill(a)
        elif st.verb == "inject_safety":
            self.b.inject_safety(a)
        elif st.verb == "rogue_publish":
            self._h_rogue_publish(st, a, eng)
        elif st.verb == "rogue_subscribe":
            self._h_rogue_subscribe(st, a, eng)
        elif st.verb == "fault":
            # Bracket the injection. The call itself takes time (a container kill is not
            # instantaneous), so the fault happened somewhere between these two instants and a
            # reaction time measured against them is an interval, not a number.
            issued = self.b.wall()
            self.b.fault(a)
            self._fault = (issued, self.b.wall())
        elif st.verb == "operator_unlock":
            self.b.operator_unlock(a)
        elif st.verb == "expect_gate":
            self._h_expect_gate(st, a, eng)
        elif st.verb == "expect_bridge":
            self._h_expect_bridge(st, a, eng)
        elif st.verb == "expect_permit":
            self._h_expect_permit(st, a, eng)
        elif st.verb == "expect_drive":
            self._h_expect_drive(st, a, eng)
        elif st.verb == "expect_drive_never":
            self._h_expect_drive_never(st, a, eng)
        elif st.verb == "expect_stop_request":
            self._h_expect_stop_request(st, a, eng)
        elif st.verb == "expect_burst":
            self._h_expect_burst(st, a, eng)
        elif st.verb == "expect_audit":
            self._h_expect_audit(st, a, eng)
        elif st.verb == "expect_anchor":
            self._h_expect_anchor(st, a, eng)
        else:
            eng.check(st.verb, st.index, "known verb", "unknown", st.t, False)

    # ---------- expect handlers ----------
    def _h_expect_gate(self, st, a, eng):
        want_state = a.get("state")
        want_reason = a.get("reason")
        timeout = float(a.get("timeout", DEFAULT_EXPECT_TIMEOUT_S))

        def pred():
            g = self.b.gate()
            ok = (g.state == want_state) and (want_reason is None or g.reason == want_reason)
            return ok, g

        ok, g, tobs = self._poll(pred, timeout)
        if ok:
            eng.check("expect_gate", st.index, {"state": want_state, "reason": want_reason},
                      {"state": g.state, "reason": g.reason}, st.t, True, tobs)
            return
        # Not met. Was the gate observed at all? No record since the scenario started, or no record
        # during this whole poll while the far side shows the harness's commands flowing, means the
        # observation channel delivered nothing — that cannot be read as the adapter judging wrongly.
        h = self.b.observation_health() or {}
        unobserved = g.state is None and h.get("lines_since_clear", 0) == 0
        # Silence is only evidence while the harness's own command STREAM is running (a record is due every
        # 100 ms then). After a one-shot command (a skill call) one record and then silence is normal, and the
        # record that was observed — right or wrong — is the judgement.
        stale = (h.get("publisher_active") and h.get("last_line_age_s") is not None and h["last_line_age_s"] > min(timeout, 1.0))
        if h and (unobserved or stale or not h.get("tail_alive", True)):
            # Whose silence? The FILE decides (sixth evaluator report, adversarial D1/D2): a gate log that GREW while the
            # tail delivered nothing is the observation channel failing — INCONCLUSIVE, rerun on a quiet host. A gate log
            # that did NOT grow while the tail was alive is an adapter that does not write the gate log the contract
            # requires (ADAPTER_CONTRACT §5a) — a judgement that is not recorded cannot be verified, so that is FAIL.
            tail_alive = h.get("tail_alive", True)
            grew = h.get("file_grew_since_clear") if unobserved else h.get("file_grew_since_last_line")
            if tail_alive and grew is False:
                code = "ADAPTER_GATE_LOG_MISSING" if unobserved else "ADAPTER_GATE_LOG_STOPPED"
                why = ("no gate record was written since the scenario started (the tail is running and the log did not grow)"
                       if unobserved else
                       f"the gate log stopped growing although the harness's command stream was running ({timeout:.1f} s poll)")
                eng.check("expect_gate", st.index, {"state": want_state, "reason": want_reason},
                          {"state": g.state, "reason": g.reason, "observation": h}, st.t, False, tobs,
                          code + ": " + why + " — the adapter does not write the gate log the contract requires (ADAPTER_CONTRACT §5a); not a host problem")
                return
            why = ("the gate log grew but the tail delivered no record since the scenario started" if unobserved and tail_alive else
                   "the gate-log tail is not running" if not tail_alive else
                   f"the gate log grew but no record arrived during the {timeout:.1f} s poll although the harness's command stream was running")
            eng.check("expect_gate", st.index, {"state": want_state, "reason": want_reason},
                      {"state": g.state, "reason": g.reason, "observation": h}, st.t, False, tobs,
                      "gate not observed: " + why + " — observation channel, not judgement; run the case again on a quiet host",
                      inconclusive=True)
            return
        eng.check("expect_gate", st.index, {"state": want_state, "reason": want_reason},
                  {"state": g.state, "reason": g.reason}, st.t, False, tobs)

    def _h_expect_bridge(self, st, a, eng):
        want = a.get("state")
        timeout = float(a.get("timeout", DEFAULT_EXPECT_TIMEOUT_S))

        def pred():
            br = self.b.bridge()
            return br.state == want, br

        if "max_latency_ms" in a:
            # Until 2026-09-19 this bound was compared with the time this check spent polling.
            # A check scheduled after the state was already reached always measured ~0 ms, so
            # the bound could not fail and said nothing about the reaction to the fault.
            raise ValueError("expect_bridge: max_latency_ms measured the check's own polling time, "
                             "not the reaction to a fault — use within_ms_of_fault")
        ok, br, tobs = self._poll(pred, timeout)
        if a.get("within_ms_of_fault") is None or not ok:
            eng.check("expect_bridge", st.index, {"state": want}, {"state": br.state}, st.t, ok, tobs)
            return
        self._check_reaction(st, eng, want, float(a["within_ms_of_fault"]), br, tobs)

    def _check_reaction(self, st, eng, want, bound_ms, br, tobs):
        """How long after the most recent fault did the bridge first report `want`?

        The answer is an interval: at most (first report − fault issued), at least
        (first report − fault call returned). Within the bound only if the upper end is; over
        it only if the lower end is; otherwise the bound lies inside the uncertainty of the
        injection and the check is inconclusive — reported as such, never as a pass."""
        expected = {"state": want, "within_ms_of_fault": bound_ms}
        if self._fault is None:
            eng.check("expect_bridge", st.index, expected, {"state": br.state}, st.t, False, tobs,
                      "within_ms_of_fault used with no fault step before it")
            return
        issued, returned = self._fault
        hist = [h for h in self.b.bridge_history() if h.t is not None]
        if not hist:
            eng.check("expect_bridge", st.index, expected, {"state": br.state}, st.t, False, tobs,
                      "the backend keeps no timestamped bridge state history — reaction time cannot be measured",
                      inconclusive=True)
            return
        before = [h for h in hist if h.t < issued]
        if not before or before[-1].state == want:
            eng.check("expect_bridge", st.index, expected,
                      {"state": br.state, "state_before_fault": before[-1].state if before else None}, st.t, False, tobs,
                      f"the bridge was not observed outside {want} before the fault, so there is no transition to time")
            return
        first = next((h for h in hist if h.t >= issued and h.state == want), None)
        if first is None:
            eng.check("expect_bridge", st.index, expected, {"state": br.state}, st.t, False, tobs,
                      f"no {want} report is timestamped after the fault")
            return
        at_most = (first.t - issued) * 1000.0
        at_least = max(0.0, (first.t - returned) * 1000.0)
        actual = {"state": want, "after_fault_ms": {"at_least": round(at_least, 1), "at_most": round(at_most, 1)},
                  "fault_injection_took_ms": round((returned - issued) * 1000.0, 1)}
        if first.t_received is not None:
            actual["report_received_after_ms"] = round((first.t_received - issued) * 1000.0, 1)
        if at_most <= bound_ms:
            eng.check("expect_bridge", st.index, expected, actual, st.t, True, tobs)
        elif at_least > bound_ms:
            eng.check("expect_bridge", st.index, expected, actual, st.t, False, tobs,
                      f"{want} came at least {at_least:.0f} ms after the fault (bound {bound_ms:.0f} ms)")
        else:
            eng.check("expect_bridge", st.index, expected, actual, st.t, False, tobs,
                      f"bound {bound_ms:.0f} ms lies between at-least {at_least:.0f} ms and at-most {at_most:.0f} ms: "
                      f"injecting the fault took {(returned - issued) * 1000.0:.0f} ms", inconclusive=True)

    def _h_expect_permit(self, st, a, eng):
        present = bool(a.get("present", True))
        window_ms = int(a.get("observe_window_ms", 2 * DEFAULT_PERMIT_DEADLINE_MS))
        if present:
            timeout = max(window_ms / 1000.0, 0.5)

            def pred():
                p = self.b.permits(window_ms)
                return len(p.seqs) > 0, p

            ok, p, tobs = self._poll(pred, timeout)
            detail = ""
            inconclusive = False
            want_rate = a.get("rate_hz")
            if ok and want_rate is not None and window_ms > 0:
                # The poll returns at the FIRST permit it sees, when the window may hold that one
                # record only — a rate computed then said "5 Hz" of a 20 Hz adapter (2026-10-10).
                # Let a whole window pass after that first sighting, then count. The window is at
                # least one second: the Microduck rig drives at 10 Hz against a 20 Hz/2 floor, and a
                # 200 ms window holds 1 or 2 of its records depending on phase alone — the same
                # "5 Hz" red on a healthy adapter, once per ~50 runs (2026-10-11, custom-backend step).
                # One record of tolerance for the window's edges: 9 of the expected 10 is not "slow".
                rate_window_ms = max(window_ms, 1000)
                self.b.sleep(rate_window_ms / 1000.0)
                p = self.b.permits(rate_window_ms)
                observed_hz = len(p.seqs) / (rate_window_ms / 1000.0)
                need = max(1, math.ceil(float(want_rate) * 0.5 * rate_window_ms / 1000.0) - 1)
                # tolerate half the nominal rate on a busy CI host
                if len(p.seqs) < need:
                    ok = False
                    detail = f"rate {observed_hz:.1f}Hz < {want_rate}Hz/2 ({len(p.seqs)} permits in {rate_window_ms} ms, need {need})"
                    # A starved observer reads like a slow adapter: if the far side received the
                    # harness's own command stream below half its rate in the same second, the
                    # measurement is of the host, not of the adapter.
                    h = self.b.observation_health() or {}
                    reports = h.get("requested_reports_last_1s")
                    if reports is not None and reports < 10:   # the far side reports at 20 Hz
                        inconclusive = True
                        detail += (f"; the far side delivered only {reports} state reports in the last second "
                                   f"(observer or host starved) — not a judgement of the adapter; run again on a quiet host")
            eng.check("expect_permit", st.index, {"present": True, "rate_hz": want_rate},
                      {"count": len(p.seqs)}, st.t, ok, tobs, detail, inconclusive=inconclusive)
        else:
            # true absence: observe the full window and assert nothing arrives
            self.b.sleep(window_ms / 1000.0)
            p = self.b.permits(window_ms)
            ok = len(p.seqs) == 0
            eng.check("expect_permit", st.index, {"present": False},
                      {"count": len(p.seqs)}, st.t, ok)

    def _h_expect_drive(self, st, a, eng):
        want_lx = a.get("linear_x")
        want_az = a.get("angular_z")
        tol = float(a.get("tol", 0.01))
        timeout = float(a.get("timeout", DEFAULT_EXPECT_TIMEOUT_S))

        def pred():
            d = self.b.drive()
            ok = True
            if want_lx is not None:
                ok = ok and abs(d.linear_x - float(want_lx)) <= tol
            if want_az is not None:
                ok = ok and abs(d.angular_z - float(want_az)) <= tol
            return ok, d

        ok, d, tobs = self._poll(pred, timeout)
        eng.check("expect_drive", st.index, {"linear_x": want_lx, "angular_z": want_az, "tol": tol},
                  {"linear_x": d.linear_x, "angular_z": d.angular_z}, st.t, ok, tobs)

    def _h_expect_drive_never(self, st, a, eng):
        forbidden_lx = a.get("linear_x")
        tol = float(a.get("tol", 0.01))
        within_ms = int(a.get("within_ms", 500))
        # Samples received before this step are the scenario's legitimate
        # pre-stop forwarding phase (dm02/sf01 drive first, then must stop) —
        # only what arrives from this check onward can be a leak. Live TwistObs
        # carries a receipt epoch t; t=None (FakeBackend) is always counted.
        t0 = _time.time()
        self.b.sleep(within_ms / 1000.0)
        hit = None
        for d in self.b.drive_history():
            if d.t is not None and d.t < t0:
                continue
            if forbidden_lx is not None and abs(d.linear_x - float(forbidden_lx)) <= tol:
                hit = d
                break
        ok = hit is None
        eng.check("expect_drive_never", st.index, {"linear_x_absent": forbidden_lx},
                  {"hit": None if hit is None else hit.linear_x}, st.t, ok)

    def _h_expect_stop_request(self, st, a, eng):
        want = bool(a.get("asserted", True))
        timeout = float(a.get("timeout", DEFAULT_EXPECT_TIMEOUT_S))

        def pred():
            v = self.b.stop_request_asserted()
            return v == want, v

        ok, v, tobs = self._poll(pred, timeout)
        eng.check("expect_stop_request", st.index, {"asserted": want}, {"asserted": v},
                  st.t, ok, tobs)

    def _h_expect_burst(self, st, a, eng):
        want_event = a.get("event")
        want_reason = a.get("reason")
        want_valid = a.get("signature", "valid") == "valid"
        res = self.b.burst_result()
        if res is None:
            eng.check("expect_burst", st.index, {"event": want_event}, "no burst receiver",
                      st.t, False)
            return
        has = res.has_event(want_event, want_reason) if want_valid else False
        # signature:valid means the surviving event must have passed verification
        ok = has if want_valid else (not res.events)
        eng.check("expect_burst", st.index,
                  {"event": want_event, "reason": want_reason, "signature": a.get("signature", "valid")},
                  {"events": [e.event_name for e in res.events], "rejected": len(res.rejected)},
                  st.t, ok)

    def _h_expect_audit(self, st, a, eng):
        want_chain = a.get("chain", "PASS")
        contains = a.get("contains")
        res = self.b.audit_result()
        if res is None:
            eng.check("expect_audit", st.index, {"chain": want_chain}, "no audit result",
                      st.t, False)
            return
        ok = (res.ok and want_chain == "PASS") or ((not res.ok) and want_chain == "FAIL")
        detail = "; ".join(res.errors[:2])
        if ok and contains is not None:
            found = any(str(contains).encode() in r.payload for r in res.all_records)
            ok = found
            if not found:
                detail = f"record containing {contains!r} not found"
        eng.check("expect_audit", st.index, {"chain": want_chain, "contains": contains},
                  {"ok": res.ok, "records": res.records}, st.t, ok, detail=detail)

    def _h_expect_anchor(self, st, a, eng):
        want = bool(a.get("head_matches", True))
        res = self.b.anchor_result()
        if res is None:
            eng.check("expect_anchor", st.index, {"head_matches": want}, "no anchor result",
                      st.t, False)
            return
        ok = res.ok and (res.head_matches == want)
        eng.check("expect_anchor", st.index, {"head_matches": want},
                  {"head_matches": res.head_matches, "count": res.count}, st.t, ok,
                  detail="; ".join(res.errors[:2]))

    # ---------- rogue (Enforcement) ----------
    def _h_rogue_publish(self, st, a, eng):
        if not self.b.enforcement_supported():
            return  # already SKIP-noted in run()
        outcome = self.b.rogue_publish(a)
        # denied at participant creation is the honest PASS on sros2 (§5.3)
        eng.check("rogue_publish", st.index, {"outcome": "denied"}, {"outcome": outcome},
                  st.t, outcome == "denied")

    def _h_rogue_subscribe(self, st, a, eng):
        if not self.b.enforcement_supported():
            return
        outcome = self.b.rogue_subscribe(a)
        eng.check("rogue_subscribe", st.index, {"outcome": "denied"}, {"outcome": outcome},
                  st.t, outcome == "denied")

    # ---------- globals ----------
    def _eval_globals(self, scenario: Scenario, eng: VerdictEngine) -> None:
        for g in scenario.expectations_global:
            if "audit_chain" in g:
                res = self.b.audit_result()
                want = g["audit_chain"]
                ok = res is not None and ((res.ok and want == "PASS") or (not res.ok and want == "FAIL"))
                eng.check("audit_chain", -1, {"audit_chain": want},
                          None if res is None else {"ok": res.ok}, 0.0, ok)
            if "drive_never" in g:
                forbidden = g["drive_never"]
                hit = any(abs(d.linear_x - float(forbidden)) <= 0.01 for d in self.b.drive_history())
                eng.check("drive_never", -1, {"linear_x_absent": forbidden}, {"hit": hit},
                          0.0, not hit)
