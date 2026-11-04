# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Report generation : JUnit XML (CI gate) + HTML matrix.

Each case carries expected-vs-actual, the observation timeline and any attached
evidence (segment parse, received bursts, anchor log). Enforcement SKIP raises a
banner ("insecure profile — bypass prevention not verified").
"""

from __future__ import annotations

import html
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, List, Optional

from .verdict import Verdict

# axis inferred from scenario path segment, for the coverage matrix
AXES = ["functional", "enforcement", "deadman", "token",
        "audit", "survivability", "safety", "recovery"]


def axis_of(scenario_path: Optional[str]) -> str:
    if not scenario_path:
        return "unknown"
    parts = Path(scenario_path).parts
    for a in AXES:
        if a in parts:
            return a
    return "unknown"


def write_junit(verdicts: Iterable[Verdict], out_path, axis_by_name=None) -> None:
    axis_by_name = axis_by_name or {}
    ts = ET.Element("testsuite", name="PVS-v2")
    total = failures = skipped = 0
    for v in verdicts:
        total += 1
        tc = ET.SubElement(ts, "testcase",
                           classname=f"pvs.{axis_by_name.get(v.scenario, 'unknown')}",
                           name=v.scenario)
        if v.skipped_axis:
            skipped += 1
            ET.SubElement(tc, "skipped", message=f"{v.skipped_axis}: " + "; ".join(v.notes))
        elif not v.passed:
            failures += 1
            fail = ET.SubElement(tc, "failure", message="verdict FAIL")
            fail.text = v.evidence_dump()
    ts.set("tests", str(total))
    ts.set("failures", str(failures))
    ts.set("skipped", str(skipped))
    ET.ElementTree(ts).write(str(out_path), encoding="utf-8", xml_declaration=True)


def write_html(verdicts: List[Verdict], out_path, axis_by_name=None) -> None:
    axis_by_name = axis_by_name or {}
    rows = []
    any_skip = False
    for v in verdicts:
        axis = axis_by_name.get(v.scenario, "unknown")
        if v.skipped_axis:
            any_skip = True
            status, color = "SKIP", "#999"
        elif v.passed:
            status, color = "PASS", "#2a7"
        else:
            status, color = "FAIL", "#c33"
        rows.append(
            f"<tr><td>{html.escape(axis)}</td><td>{html.escape(v.scenario)}</td>"
            f"<td style='color:{color};font-weight:bold'>{status}</td>"
            f"<td><pre>{html.escape(v.evidence_dump())}</pre></td></tr>"
        )
    banner = ("<div style='background:#fdd;padding:8px;border:1px solid #c33'>"
              "⚠ insecure profile — bypass prevention (Enforcement) not verified</div>") if any_skip else ""
    Path(out_path).write_text(
        "<html><head><meta charset='utf-8'><title>PVS v2 report</title></head><body>"
        "<h1>PAIL Verification Suite v2</h1>" + banner +
        "<table border='1' cellpadding='6' cellspacing='0'>"
        "<tr><th>axis</th><th>scenario</th><th>result</th><th>evidence</th></tr>"
        + "".join(rows) + "</table></body></html>",
        encoding="utf-8",
    )
