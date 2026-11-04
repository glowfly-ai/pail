# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Validate the existing real gate/bridge synthetic reference report."""
EXPECTED = {"registry_loaded", "v5_signed_metadata", "base_forward", "no_authority_blocks",
            "completion_stops", "speed_limit", "bridge_deadman", "journal_verifies"}

def verify_reference(report, returncode):
    if not isinstance(report, dict):
        report = {}
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        checks = []
    ids = [c.get("id") for c in checks if isinstance(c, dict)]
    passed = (returncode == 0 and report.get("passed") is True and report.get("prerequisites_ok") is True
              and len(checks) == len(EXPECTED) and set(ids) == EXPECTED and len(set(ids)) == len(ids)
              and all(c.get("passed") is True for c in checks))
    return {"id": "real_gate_bridge_reference", "status": "PASS" if passed else "FAIL",
            "expected": sorted(EXPECTED), "observed": ids, "returncode": returncode}
