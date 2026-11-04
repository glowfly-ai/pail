# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Scenario data model + v1/v2 loader .

"버전 분기 공존": v1 scenarios keep the top-level `northbound:` mapping block and
are loaded by the v1 path unchanged; v2 scenarios use `version: 2.x`, a `profile`,
and inline step verbs (`north_cmd`, `expect_*`, ...). The loader branches on the
`version` field — this is NOT a backward-compatible superset.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# v2 step verbs (dispatch table, implementation contract). Exactly one appears per step.
V2_VERBS = {
    "north_cmd", "inject_evidence", "inject_cmd_vel", "inject_safety", "inject_skill",
    "rogue_publish", "rogue_subscribe", "fault", "operator_unlock",
    "expect_gate", "expect_bridge", "expect_permit", "expect_drive",
    "expect_drive_never", "expect_stop_request", "expect_burst",
    "expect_audit", "expect_anchor",
}
OBSERVE_VERBS = {v for v in V2_VERBS if v.startswith("expect_")}
_STEP_META = {"t", "only"}


@dataclass
class Step:
    t: float
    verb: str
    arg: Any                       # verb value: dict of args OR scalar sub-verb name
    extra: Dict[str, Any]          # sibling keys (e.g. step_id alongside north_cmd)
    only: Optional[str]            # e.g. "nightly" — skipped on the PR axis
    index: int
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_observe(self) -> bool:
        return self.verb in OBSERVE_VERBS

    def args(self) -> Dict[str, Any]:
        """Merged argument dict for handlers: verb-dict + sibling keys.
        For a scalar verb value it is exposed under the key 'sub'."""
        out: Dict[str, Any] = {}
        if isinstance(self.arg, dict):
            out.update(self.arg)
        else:
            out["sub"] = self.arg
        out.update(self.extra)
        return out


@dataclass
class Scenario:
    version: str
    name: str
    robot_id: str
    profile: str                   # sros2 | uds | insecure
    steps: List[Step]
    expectations_global: List[Dict[str, Any]]
    raw: Dict[str, Any]
    path: Optional[Path] = None

    @property
    def is_v2(self) -> bool:
        return str(self.version).split(".")[0] == "2"


def _parse_v2_step(raw: Dict[str, Any], index: int) -> Step:
    if "t" not in raw:
        raise ValueError(f"v2 step #{index} missing 't': {raw}")
    verb = None
    for k in raw:
        if k in V2_VERBS:
            if verb is not None:
                raise ValueError(f"v2 step #{index} has multiple verbs ({verb}, {k})")
            verb = k
    if verb is None:
        raise ValueError(f"v2 step #{index} has no known verb: {list(raw)}")
    # `only` selects when a step runs, so it belongs beside the verb, not inside its arguments.
    # Written inside, it was silently ignored: the step ran on every run while the file said
    # "nightly only" (dm01 and dm03 carried it that way until 2026-09-19).
    if isinstance(raw[verb], dict) and any(k in raw[verb] for k in _STEP_META):
        raise ValueError(f"v2 step #{index}: {sorted(set(raw[verb]) & _STEP_META)} belongs to the step, "
                         f"not to the arguments of {verb}")
    extra = {k: v for k, v in raw.items() if k not in _STEP_META and k != verb}
    return Step(t=float(raw["t"]), verb=verb, arg=raw[verb], extra=extra,
                only=raw.get("only"), index=index, raw=raw)


SUBMIT_STATUS_DECLARATIONS = ("ACCEPTED", "REJECTED")


def submit_declaration_error(args: Dict[str, Any], status_name: str, rejected_reason: str) -> Optional[str]:
    """Judge a plan submission against what the step declared, or None when they agree.

    A refused plan is not always a rig failure: rc02 asserts that issuance stays frozen while
    the operator guard is in SAFE_STOP, so the refusal *is* the observation. Two earlier
    shapes were both wrong. Silence (before 2026-09-06) made "the issuer refused" read the
    same as "nobody asked", and the scenario then failed downstream as ERR_NO_TOKEN (H-B2).
    An unconditional error (2026-09-06 .. 2026-09-19) called that expected refusal a harness
    failure and rc02 could not run at all. So the step says which outcome it expects, and an
    outcome that differs from the declaration — in either direction — is the error.
    """
    want = str(args.get("submit_status", "ACCEPTED")).upper()
    if want not in SUBMIT_STATUS_DECLARATIONS:
        return "submit_status must be one of %s, not %r" % (", ".join(SUBMIT_STATUS_DECLARATIONS), want)
    want_reason = str(args.get("submit_reason", "") or "")
    if want == "ACCEPTED":
        if status_name == "ACCEPTED":
            return None
        return "submit_plan rejected: %s %s" % (status_name, rejected_reason)
    if status_name == "ACCEPTED":
        # The declared refusal did not happen. Passing here would prove nothing about the
        # freeze the scenario exists to measure.
        return "submit_plan was declared to be refused but the issuer ACCEPTED it"
    if want_reason and want_reason.lower() not in str(rejected_reason or "").lower():
        return "submit_plan was refused for another reason than declared: declared %r, got %r" % (
            want_reason, rejected_reason)
    return None


def load_scenario(path) -> Scenario:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        raise ValueError(f"empty scenario {path}")
    version = str(data.get("version", ""))

    if version.split(".")[0] == "2":
        steps = [_parse_v2_step(s, i) for i, s in enumerate(data.get("steps", []))]
        return Scenario(
            version=version,
            name=data["name"],
            robot_id=data["robot_id"],
            profile=data.get("profile", "insecure"),
            steps=steps,
            expectations_global=list(data.get("expectations_global", [])),
            raw=data,
            path=path,
        )

    # ---- v1 path (unchanged): top-level northbound block required ----
    _validate_v1(data)
    return Scenario(
        version=version or "0.1",
        name=data["name"],
        robot_id=data["robot_id"],
        profile="insecure",
        steps=[],  # v1 steps are consumed by the legacy runner, not the v2 timeline
        expectations_global=[],
        raw=data,
        path=path,
    )


def _validate_v1(data: Dict[str, Any]) -> None:
    # mirrors the legacy validate_scenario contract
    assert data.get("version") is not None, "v1 scenario missing version"
    assert data.get("northbound") is not None, "v1 scenario missing top-level northbound"
    assert data.get("steps") is not None, "v1 scenario missing steps"


def is_registry_file(path) -> bool:
    """Registry files live beside the scenarios and are named in capitals
    (OWNERSHIP.yaml, CA_MAP.yaml). They describe scenarios; they are not scenarios."""
    stem = Path(path).stem
    return stem.isupper()


def discover(scen_root) -> List[Path]:
    """All *.yaml scenarios under a root, sorted (pytest parametrize source).

    Registry files are left out: parametrizing them made a full live run report nine
    failures that were not verdicts about anything (each failed to load as a scenario)."""
    return sorted(p for p in Path(scen_root).rglob("*.yaml") if not is_registry_file(p))
