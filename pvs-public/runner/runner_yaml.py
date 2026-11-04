# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""PVS runner (YAML-enabled) — optional.

Requires:
  python3 -m pip install pyyaml

This file mirrors runner.py but loads YAML.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml


@dataclass
class Scenario:
    name: str
    robot_id: str
    raw: Dict[str, Any]


def load_scenario(path: Path) -> Scenario:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
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
            print(f"[t={tgt}] inject evidence: {st['inject_evidence']}")
        if "expect_gate" in st:
            print(f"[t={tgt}] expect gate: {st['expect_gate']}")

    print("DONE")
    return 0


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", type=str)
    args = ap.parse_args()
    raise SystemExit(run_scenario(Path(args.scenario)))
