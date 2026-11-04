# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Shared pytest fixtures/markers for the PVS suite .

Two tiers of tests coexist:
  * host tier  — verifiers, core engine, mocks, injectors (no ROS2/docker).
  * live tier  — scenario integration against the running compose stack.

The live tier SKIPs (never fake-passes) when the stack, ROS2, or an sros2
keystore is unavailable, so `pytest` is green on a bare host and only the
host-tier assertions actually execute.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

PVS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PVS_ROOT))

AXES = ["functional", "enforcement", "deadman", "token",
        "audit", "survivability", "safety", "recovery"]


def pytest_configure(config):
    for axis in AXES:
        config.addinivalue_line("markers", f"{axis}: PVS {axis} axis scenario")
    config.addinivalue_line("markers", "nightly: precision timing / chaos — nightly only")
    config.addinivalue_line("markers", "unit: host-runnable unit test (no live stack)")
    config.addinivalue_line("markers", "live: requires the running compose/ROS2 stack")


# ---------------- structured result file (PVS_RESULT_JSON) ----------------
#
# A scenario run used to leave nothing behind when it passed: the Verdict was asserted on
# and dropped. Set PVS_RESULT_JSON=<path> and the session writes one row per scenario —
# its axis, its status, the reason it was skipped, how long it took and, for a scenario
# that ran, what each check expected and observed (Verdict.to_record()).
#
# The rows are collected from pytest's own reports rather than from the test body, so a
# scenario that never got as far as its body (the live fixture skipped it) is still a row.
# A run that selected only part of the suite says so: `selection` carries -m and -k, and a
# reader can compare `scenarios` against the scenario files on disk.
PVS_RESULT_SCHEMA = 1
_PVS_ROWS = {}
_PVS_STARTED = datetime.datetime.now(datetime.timezone.utc)


def _utc(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _skip_reason(rep):
    lr = rep.longrepr
    text = lr[2] if isinstance(lr, tuple) and len(lr) == 3 else str(lr)
    return text[len("Skipped: "):] if text.startswith("Skipped: ") else text


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    params = getattr(getattr(item, "callspec", None), "params", {})
    path = params.get("scenario_path")
    if path is None:
        return
    rel = str(Path(path).resolve().relative_to(PVS_ROOT / "scenarios"))
    from runner.core.report import axis_of   # one definition of "which axis is this file on"
    row = _PVS_ROWS.setdefault(rel, {"id": rel, "axis": axis_of(rel), "status": None,
                                     "reason": "", "seconds": 0.0})
    row["seconds"] = round(row["seconds"] + rep.duration, 2)
    if rep.skipped:
        row["status"], row["reason"] = "SKIP", _skip_reason(rep)
    elif rep.failed:
        # A failure while setting up or tearing down is not a verdict about the scenario.
        row["status"] = "FAIL" if rep.when == "call" else "ERROR"
        row["reason"] = "" if rep.when == "call" else "%s: %s" % (rep.when, str(rep.longrepr)[-400:])
    elif rep.when == "call" and row["status"] is None:
        row["status"] = "PASS"
    if rep.when == "call":
        for key in ("name", "observations"):
            value = getattr(item, "_pvs_" + key, None)
            if value is not None:
                row[key] = value


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get("PVS_RESULT_JSON")
    if not out:
        return
    rows = [_PVS_ROWS[k] for k in sorted(_PVS_ROWS)]
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    doc = {"schema_version": PVS_RESULT_SCHEMA, "suite": "pvs",
           "started_at_utc": _utc(_PVS_STARTED),
           "ended_at_utc": _utc(datetime.datetime.now(datetime.timezone.utc)),
           "selection": {"markexpr": session.config.getoption("markexpr") or "",
                         "keyword": session.config.getoption("keyword") or ""},
           "live": live_available(),          # the stack was reachable, not merely asked for
           "sros2_keystore": sros2_available(),
           "hardware_tested": os.environ.get("PVS_HARDWARE_TESTED") == "1",
           "pytest_exit_status": int(exitstatus),
           "counts": counts, "scenarios": rows}
    with open(out, "w", encoding="utf-8") as f:
        f.write(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


# ---------------- capability probes (honest SKIP gates) ----------------

def ros_available() -> bool:
    try:
        import rclpy  # noqa: F401
        return True
    except Exception:
        return False


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        import docker  # noqa: F401
        docker.from_env().ping()
        return True
    except Exception:
        return False


def live_available() -> bool:
    """The scenario integration tier needs ROS2 + docker + the compose stack.
    An explicit PVS_LIVE=1 opt-in avoids accidentally poking a real robot."""
    return os.environ.get("PVS_LIVE") == "1" and ros_available() and docker_available()


def sros2_available() -> bool:
    """sros2 keystore tooling (Enforcement axis). Requires ros2 security CLI and
    a provisioned keystore path."""
    if not ros_available():
        return False
    if shutil.which("ros2") is None:
        return False
    return bool(os.environ.get("ROS_SECURITY_KEYSTORE"))


@pytest.fixture(scope="session")
def live_backend():
    """Live Backend wired to the running stack. SKIPs the whole live tier when
    the stack is absent, so host CI stays green without faking a PASS."""
    if not live_available():
        # The reason starts with a token of the closed skip vocabulary so that a reader of the
        # result file can tell what would make this SKIP go away. The vocabulary has no word for
        # "not opted in"; that case keeps a plain sentence and a report shows it as unexplained.
        if os.environ.get("PVS_LIVE") == "1" and not ros_available():
            pytest.skip("NEEDS_ROS_RUNTIME: live stack unavailable — rclpy cannot be imported here")
        pytest.skip("live stack unavailable (set PVS_LIVE=1 with ROS2 + docker + compose up)")
    from runner.live.backend_live import LiveBackend  # imported lazily (needs rclpy)
    be = LiveBackend()
    be.setup()
    yield be
    be.teardown()
