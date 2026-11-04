# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Verdict engine .

Each `expect_*` observation yields a Check with (expected, actual, t_obs). A
scenario passes iff every check passes and every global expectation passes.
Failures carry an evidence dump (expected/actual + timeline) per §10.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Check:
    verb: str
    step_index: int
    passed: bool
    expected: Any
    actual: Any
    t_scheduled: float
    t_observed: Optional[float] = None
    detail: str = ""
    # The check ran but its outcome cannot be decided from what was observed (for example a
    # time bound that falls inside the uncertainty of the measurement). Neither a pass nor a
    # failure: "we could not tell" must not reach a reader looking like either.
    inconclusive: bool = False


@dataclass
class Verdict:
    scenario: str
    passed: bool = True
    checks: List[Check] = field(default_factory=list)
    skipped_axis: Optional[str] = None   # e.g. Enforcement SKIP on insecure
    notes: List[str] = field(default_factory=list)

    def record(self, check: Check) -> None:
        self.checks.append(check)
        if check.inconclusive:
            return
        if not check.passed:
            self.passed = False

    @property
    def inconclusive(self) -> List[Check]:
        return [c for c in self.checks if c.inconclusive]

    @property
    def status(self) -> str:
        """PASS, FAIL, or INCONCLUSIVE — the third when nothing failed but at least one check could not
        be decided from what was observed. Before 2026-10-10 such a scenario read as PASS: `record()`
        skips inconclusive checks when it computes `passed`, and the runner only knew two words."""
        if not self.passed:
            return "FAIL"
        return "INCONCLUSIVE" if self.inconclusive else "PASS"

    def note(self, msg: str) -> None:
        self.notes.append(msg)

    def to_record(self) -> Dict[str, Any]:
        """The verdict as plain JSON data, for result files that other tools read.

        `observed_after_s` is the time from the moment the check started polling until the
        expected state was observed; it is null when the check timed out. Values that JSON
        cannot carry are written as their string form rather than dropped.
        """
        return {
            "scenario": self.scenario,
            "passed": self.passed,
            "skipped_axis": self.skipped_axis,
            "notes": list(self.notes),
            "checks": [
                {
                    "verb": c.verb,
                    "step_index": c.step_index,
                    "passed": None if c.inconclusive else c.passed,
                    "inconclusive": c.inconclusive,
                    "expected": _jsonable(c.expected),
                    "actual": _jsonable(c.actual),
                    "scheduled_at_s": c.t_scheduled,
                    "observed_after_s": c.t_observed,
                    "detail": c.detail,
                }
                for c in self.checks
            ],
        }

    def evidence_dump(self) -> str:
        lines = [f"SCENARIO {self.scenario}: {'PASS' if self.passed else 'FAIL'}"]
        if self.skipped_axis:
            lines.append(f"  [SKIP] {self.skipped_axis}")
        for n in self.notes:
            lines.append(f"  note: {n}")
        for c in self.checks:
            status = "??  " if c.inconclusive else "ok " if c.passed else "FAIL"
            lines.append(
                f"  [{status}] t={c.t_scheduled} {c.verb} #{c.step_index} "
                f"expected={_short(c.expected)} actual={_short(c.actual)}"
                + (f" t_obs={c.t_observed}" if c.t_observed is not None else "")
                + (f" -- {c.detail}" if c.detail else "")
            )
        return "\n".join(lines)


def _jsonable(v: Any) -> Any:
    return json.loads(json.dumps(v, default=str))


def _short(v: Any) -> str:
    try:
        s = json.dumps(v, default=str)
    except TypeError:
        s = str(v)
    return s if len(s) <= 200 else s[:197] + "..."


class VerdictEngine:
    """Accumulates checks for one scenario run."""

    def __init__(self, scenario_name: str):
        self.verdict = Verdict(scenario=scenario_name)

    def check(self, verb: str, step_index: int, expected: Any, actual: Any,
              t_scheduled: float, passed: bool, t_observed: Optional[float] = None,
              detail: str = "", inconclusive: bool = False) -> None:
        self.verdict.record(Check(verb, step_index, passed, expected, actual,
                                  t_scheduled, t_observed, detail, inconclusive))

    def skip_axis(self, axis: str, reason: str) -> None:
        self.verdict.skipped_axis = axis
        self.verdict.note(reason)

    def finalize(self) -> Verdict:
        return self.verdict
