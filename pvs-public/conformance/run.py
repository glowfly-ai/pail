#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Adapter conformance runner (spec/ADAPTER_CONTRACT.md §4).

    run.py --backend microduck_uds [--map pvs/scenarios/adapter/CA_MAP.yaml] [--report out.json]
           [--only CA-01,CA-08] [--append] [--note "..."]

Reads CA_MAP, and for the chosen backend runs every `run` row: a `scenario` row through the
PVS Orchestrator (the same verdict engine the ROS gate node is judged with), a `tool` row as a
subprocess whose exit code is the verdict. `skip:` rows are reported as SKIP with their reason;
`cite:` rows as CITED. The exit code is 0 only when every executed row PASSed — a SKIP never
becomes a PASS, and a backend with zero executed rows exits 1 (an empty run is not a run).

Runs from the repository root inside the harness container; PYTHONPATH must include `pvs/`
and `pvs/runner/live` (for the generated gRPC stubs).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PVS = Path(__file__).resolve().parents[1] if Path(__file__).resolve().parents[1].name in ("pvs", "pvs-public") else ROOT / "pvs"
sys.path.insert(0, str(PVS))
sys.path.insert(0, str(PVS / "runner" / "live"))

from runner.core.model import load_scenario  # noqa: E402
from runner.core.orchestrator import Orchestrator  # noqa: E402


BUILTIN_BACKENDS = ("microduck_uds", "ros2_pep_gate")


def make_backend(name: str):
    if name == "microduck_uds":
        from runner.adapters.microduck_backend import MicroduckBackend
        return MicroduckBackend()
    if name == "ros2_pep_gate":
        from runner.live.backend_live import LiveBackend  # needs rclpy + the SUT compose
        return LiveBackend()
    if ":" in name:
        # A custom transport: MODULE:CLASS, the module a file under runner/adapters/ of this tree (the
        # harness runs the tree baked into the image it was built from, so a working-copy build is the
        # way to add one). The class must implement runner.core.backend.Backend.
        import importlib
        import re
        module, cls = name.split(":", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", module) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", cls):
            raise SystemExit(f"custom backend must be MODULE:CLASS with a lowercase module name, got {name!r}")
        try:
            mod = importlib.import_module("runner.adapters." + module)
        except ImportError as exc:
            raise SystemExit(f"custom backend module runner/adapters/{module}.py is not importable: {exc}") from exc
        from runner.core.backend import Backend
        obj = getattr(mod, cls, None)
        if not isinstance(obj, type) or not issubclass(obj, Backend):
            raise SystemExit(f"{name!r} is not a runner.core.backend.Backend subclass")
        return obj()
    raise SystemExit(f"unknown backend {name!r}; built in: {', '.join(BUILTIN_BACKENDS)}; custom: MODULE:CLASS under runner/adapters/")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", required=True)
    ap.add_argument("--map", default=str(PVS / "scenarios" / "adapter" / "CA_MAP.yaml"))
    ap.add_argument("--report", default=None)
    ap.add_argument("--only", default=None, help="comma-separated CA ids")
    ap.add_argument("--append", action="store_true",
                    help="merge into an existing --report: rows run now replace rows of the same id, "
                         "the rest are kept (a rig that needs two passes — e.g. the ROS gate pointed at "
                         "the real issuer for most rows and at the rogue seam for the negative-token "
                         "rows — writes one report)")
    ap.add_argument("--note", default=None, help="free text recorded on every row run in this pass")
    ap.add_argument("--rows-of", default=None, choices=BUILTIN_BACKENDS,
                    help="for a custom MODULE:CLASS backend: which built-in backend's column of CA_MAP (run/skip/cite per "
                         "case, env overrides) to execute. Until the map has a column for the custom transport, its rows "
                         "are those of the transport it stands in for; every row is reported under the custom name.")
    ap.add_argument("--reviewed-skip", action="append", default=[], metavar="CA-ID:REASON",
                    help="accept, with a written reason, one case the backend reports as Unsupported. The row stays SKIP "
                         "(never PASS) and the reason is recorded in the report; the run's result is then PASS_WITH_LIMITATIONS "
                         "instead of BLOCKED. Only a SKIP the backend raised itself can be reviewed — a map-declared skip row "
                         "and a FAIL cannot. Repeatable.")
    ap.add_argument("--observation-fault", default=None, choices=["tail_stall"],
                    help="demo only: stall the gate-log tail after the first record of each case so the INCONCLUSIVE path "
                         "(retry, exit 4, DIAGNOSIS) can be seen on purpose; never for a judged run")
    args = ap.parse_args()
    if args.observation_fault:
        os.environ["PAIL_DUCK_OBSERVATION_FAULT"] = args.observation_fault
    if args.rows_of and ":" not in args.backend:
        raise SystemExit("--rows-of is for a custom MODULE:CLASS backend")
    rows_of = args.rows_of or args.backend
    if ":" in args.backend and not args.rows_of:
        raise SystemExit("a custom backend needs --rows-of (which CA_MAP column to execute)")
    reviewed = {}
    for item in args.reviewed_skip:
        case_id, sep, reason = item.partition(":")
        if not sep or not reason.strip() or not case_id.startswith("CA-"):
            raise SystemExit(f"--reviewed-skip wants CA-ID:REASON with a non-empty reason, got {item!r}")
        reviewed[case_id] = reason.strip()

    cases = yaml.safe_load(open(args.map, encoding="utf-8"))["cases"]
    only = set(args.only.split(",")) if args.only else None
    prior_rows = {}
    prior = {}
    if args.append and args.report and Path(args.report).exists():
        prior = json.loads(Path(args.report).read_text(encoding="utf-8"))
        if prior.get("backend") != args.backend:
            raise SystemExit(f"--append: existing report is for backend {prior.get('backend')!r}")
        prior_rows = {r["id"]: r for r in prior["rows"]}
    # The backend is built on the first row that executes. A pass that only records SKIP/CITED
    # rows (e.g. appending a transport's "no ingress" rows) must not bring a live rig up — and
    # the ROS 2 live rig shares its compose project with the demo SUT.
    be = None
    def base_backend():
        nonlocal be
        if be is None:
            be = make_backend(args.backend)
            be.setup()
        return be
    rows = []
    executed = 0
    failed = 0
    alt_backends = {}

    def backend_for(c):
        """A row may name environment overrides (e.g. a second adapter instance on an observe
        policy). Such rows get their own backend instance, built under those variables."""
        env = (c.get("env") or {}).get(rows_of)
        if not env:
            return base_backend()
        key = json.dumps(env, sort_keys=True)
        if key not in alt_backends:
            saved = {k: os.environ.get(k) for k in env}
            os.environ.update({k: str(v) for k, v in env.items()})
            try:
                b2 = make_backend(args.backend)
                b2.setup()
            finally:
                for k, v in saved.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            alt_backends[key] = b2
        return alt_backends[key]

    try:
        for c in cases:
            if only and c["id"] not in only:
                continue
            plan = str(c["backends"].get(rows_of, "skip: NO_ROW_FOR_BACKEND"))
            row = {"id": c["id"], "title": c["title"], "backend": args.backend, "plan": plan}
            if rows_of != args.backend:
                row["rows_of"] = rows_of
            if args.note:
                row["note"] = args.note
            # `run: <scenario>` — this backend executes a transport-specific scenario file in
            # place of the row's default one (same case, same expectation; e.g. the ROS gate's
            # CA-09 kills the issuer container it actually dials, the socket adapter its seam).
            scenario_override = plan[4:].strip() if plan.startswith("run:") else None
            if plan.startswith("skip:"):
                row["status"] = "SKIP"
                row["reason"] = plan[5:].strip()
            elif plan.startswith("cite:"):
                row["status"] = "CITED"
                row["reason"] = plan[5:].strip()
            elif plan == "run" or scenario_override:
                executed += 1
                t0 = time.time()
                try:
                    if "scenario" in c or scenario_override:
                        b = backend_for(c)
                        sc = load_scenario(str(PVS / "scenarios" / (scenario_override or c["scenario"])))
                        attempts = []
                        for attempt in (1, 2):
                            b.reset_state()
                            v = Orchestrator(b).run(sc)
                            attempts.append(v)
                            # INCONCLUSIVE = nothing failed, but a check could not be decided from what was
                            # observed (observation channel silent, observer starved). That is the harness's
                            # prerequisite, not the adapter's verdict: one fresh attempt, then the word stays.
                            if v.status != "INCONCLUSIVE":
                                break
                            print(f"{c['id']:6} INCONCLUSIVE on attempt {attempt}: "
                                  + "; ".join(ch.detail for ch in v.inconclusive)[:300] + " — running the case once more", flush=True)
                        row["status"] = v.status
                        # Structured, so a report can show expected against observed per check.
                        row["observations"] = v.to_record()
                        if len(attempts) > 1:
                            row["attempts"] = len(attempts)
                            row["first_attempt"] = attempts[0].to_record()
                        if getattr(v, "skipped_axis", None):
                            row["skipped_axis"] = v.skipped_axis
                    elif "tool" in c:
                        if c.get("reset_before"):backend_for(c).reset_state()
                        tool = Path(__file__).resolve().parent / c["tool"]
                        p = subprocess.run(([sys.executable, str(tool)] if tool.suffix == ".py" else ["sh", str(tool)] if tool.suffix == ".sh" else [str(tool)]), capture_output=True, text=True, timeout=300,
                                           cwd=str(ROOT), env=dict(os.environ, PAIL_CA_ID=c["id"]))
                        row["status"] = "PASS" if p.returncode == 0 else "FAIL"
                        if c.get("structured_result"):
                            lines=[line for line in p.stdout.splitlines() if line.startswith('{')]
                            result=json.loads(lines[-1]) if lines else {}
                            if result.get('id')!=c['id'] or result.get('status') not in ('PASS','FAIL','INCONCLUSIVE'):
                                raise ValueError('structured tool result missing or mismatched')
                            if (result['status']=='PASS')!=(p.returncode==0):raise ValueError('structured tool verdict disagrees with exit code')
                            row['status']=result['status'];row['observations']=result
                        row["stdout"] = p.stdout[-4000:]
                        row["stderr"] = p.stderr[-2000:]
                        row["rc"] = p.returncode
                    else:
                        row["status"] = "FAIL"
                        row["reason"] = "row has neither scenario nor tool"
                except Exception as e:  # Unsupported and rig errors both land here, as FAIL-with-reason
                    row["status"] = "SKIP" if e.__class__.__name__ == "Unsupported" else "FAIL"
                    row["reason"] = f"{e.__class__.__name__}: {e}"
                    if row["status"] == "SKIP":
                        executed -= 1
                        if c["id"] in reviewed:
                            # The backend said Unsupported and its maintainer wrote down why: a reviewed limitation,
                            # still a SKIP. The classifier turns an unreviewed SKIP into BLOCKED, a reviewed one into
                            # PASS_WITH_LIMITATIONS with the reason in the limitations list.
                            row["reviewed_skip"] = reviewed[c["id"]]
                row["seconds"] = round(time.time() - t0, 2)
                if row["status"] == "FAIL":
                    failed += 1
            else:
                row["status"] = "FAIL"
                row["reason"] = f"unknown plan {plan!r}"
                failed += 1
            rows.append(row)
            print(f"{row['id']:6} {row['status']:6} {row['title']}" + (f"  — {row['reason']}" if row.get("reason") else ""))
    finally:
        if be is not None:
            be.teardown()
        for b2 in alt_backends.values():
            b2.teardown()

    # This pass's exit code is this pass's — an earlier pass's FAIL is already in its own rc.
    # The report, when appending, is the union: rows run now replace prior rows of the same
    # id, untouched prior rows stay, order is the map's, and the counts are recomputed over
    # the union so the file never says "executed=3" for a 13-row map.
    this_pass = {r["id"]: r for r in rows}
    merged = {**prior_rows, **this_pass}
    order = {c["id"]: i for i, c in enumerate(cases)}
    all_rows = sorted(merged.values(), key=lambda r: order.get(r["id"], 1 << 30))
    n_exec = sum(1 for r in all_rows if r["status"] in ("PASS", "FAIL", "INCONCLUSIVE"))
    n_fail = sum(1 for r in all_rows if r["status"] == "FAIL")
    report = {"backend": args.backend, "map": os.path.relpath(args.map, ROOT), "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
              "executed": n_exec, "failed": n_fail,
              "inconclusive": sum(1 for r in all_rows if r["status"] == "INCONCLUSIVE"),
              "skipped": sum(1 for r in all_rows if r["status"] == "SKIP"),
              "cited": sum(1 for r in all_rows if r["status"] == "CITED"), "rows": all_rows}
    if reviewed:
        # Every accepted reason is recorded, used or not; an unused one is visible as such (the case did not skip).
        report["reviewed_skips"] = {cid: {"reason": why, "used": any(r.get("id") == cid and r.get("reviewed_skip") for r in all_rows)}
                                    for cid, why in reviewed.items()}
    if prior_rows:
        report["passes"] = (prior.get("passes") or [prior.get("at")]) + [report["at"]]
    if args.report:
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    n_inc = sum(1 for r in rows if r["status"] == "INCONCLUSIVE")
    print(f"executed={executed} passed={executed - failed - n_inc} failed={failed} inconclusive={n_inc} "
          f"skipped={sum(1 for r in rows if r['status'] == 'SKIP')} cited={sum(1 for r in rows if r['status'] == 'CITED')}"
          + (f"  (report union: executed={n_exec} failed={n_fail} rows={len(all_rows)})" if prior_rows else ""))
    if executed == 0:
        print("no case was executed on this backend — an empty run is not a run")
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
