# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""PAIL Verification Suite (PVS) — minimal runner skeleton.

No external deps: uses JSON for now.
If you prefer YAML, add PyYAML and update loader.

This runner validates a scenario and provides stubs for:
- submitting an ActionPlan
- injecting evidence to /pail/evidence
- observing /pail/gate_state
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class Scenario:
    name: str
    robot_id: str
    raw: Dict[str, Any]


def load_scenario(path: Path) -> Scenario:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "name" in data
    assert "robot_id" in data
    return Scenario(name=data["name"], robot_id=data["robot_id"], raw=data)


def validate_scenario(data: Dict[str, Any]) -> None:
    assert data.get("version") is not None
    assert data.get("northbound") is not None
    assert data.get("steps") is not None


def run_scenario(path: Path) -> int:
    scenario = load_scenario(path)
    validate_scenario(scenario.raw)

    steps: List[Dict[str, Any]] = scenario.raw["steps"]
    t0 = time.time()

    for st in steps:
        tgt = float(st["t"])
        while (time.time() - t0) < tgt:
            time.sleep(0.01)

        if "inject_evidence" in st:
            ev = st["inject_evidence"]
            print(f"[t={tgt}] inject evidence: {ev}")

        if "set_context" in st:
            ctx = st["set_context"]
            print(f"[t={tgt}] set context: {ctx}")

        if "expect_gate" in st:
            exp = st["expect_gate"]
            print(f"[t={tgt}] expect gate: {exp}")

    print("DONE")
    return 0


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", type=str)
    args = ap.parse_args()
    raise SystemExit(run_scenario(Path(args.scenario)))
