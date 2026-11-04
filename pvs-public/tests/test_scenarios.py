# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Scenario integration .

Parametrizes every scenario file, branches the v1/v2 loader on `version`, applies
the axis pytest marker, and runs it through the Orchestrator against the live
Backend. sros2-only scenarios SKIP when no keystore is provisioned; the entire
tier SKIPs on a bare host (see conftest `live_backend`).

State isolation is the LLD §9 correctness invariant: PEP `consumed_token_ids_`,
issuer chain state, and blackbox segments must not bleed between scenarios, so we
reset (or recreate) the stack before each run.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.conftest import PVS_ROOT, sros2_available
from runner.core.model import discover, load_scenario
from runner.core.orchestrator import Orchestrator
from runner.core.report import axis_of

SCEN_ROOT = PVS_ROOT / "scenarios"
_SCENARIOS = sorted(discover(str(SCEN_ROOT)))


def _ids(p):
    return str(Path(p).relative_to(SCEN_ROOT))


@pytest.mark.live
@pytest.mark.parametrize("scenario_path", _SCENARIOS, ids=[_ids(p) for p in _SCENARIOS])
def test_scenario(scenario_path, live_backend, request):
    sc = load_scenario(scenario_path)  # v1/v2 branch on `version`

    # tag the node with its axis marker so `-m token`, `-m safety`, ... select it
    axis = axis_of(scenario_path)
    if axis != "unknown":
        request.node.add_marker(getattr(pytest.mark, axis))

    if getattr(sc, "profile", None) == "sros2" and not sros2_available():
        pytest.skip("NEEDS_SROS2_KEYSTORE: sros2 keystore tooling unavailable — Enforcement boundary not provable")

    # fn05-style scenarios are only meaningful against a special SUT build; on
    # the normal build they turn into false tests (a grpc-enabled gate PERMITs).
    if sc.raw.get("requires_build") == "no_grpc" and os.environ.get("PVS_SUT_NO_GRPC") != "1":
        pytest.skip("NEEDS_NO_GRPC_BUILD: requires a PAIL_ENABLE_GRPC=0 gate build — set PVS_SUT_NO_GRPC=1 "
                    "after deploying that build to run this scenario")

    if sc.raw.get("live_pending") == "udp_proxy" and os.environ.get("PVS_UDP_PROXY") != "1":
        pytest.skip("NEEDS_UDP_PROXY: live UDP loss shaping needs a forwarding proxy in front of the "
                    "BurstListener (k-of-n reassembly proven host-side in test_mocks)")

    live_backend.reset_state()          # §9 isolation: fresh consumed-set / chain / segments
    live_backend.load_scenario(sc)      # wire mock AI/HAL/cloud + fault targets for this run

    # nightly precision steps run only when the nightly marker is explicitly selected
    markexpr = request.config.getoption("markexpr") or ""
    skip_nightly = "nightly" not in markexpr

    orch = Orchestrator(live_backend, skip_nightly=skip_nightly)
    verdict = orch.run(sc)
    # Picked up by conftest's report hook for the structured result file.
    request.node._pvs_name = sc.name
    request.node._pvs_observations = verdict.to_record()
    if verdict.skipped_axis:
        # The orchestrator declined to judge this axis on this profile. That is a SKIP, not a
        # PASS: no check failed only because the checks that matter were not made.
        pytest.skip("NEEDS_SROS2_KEYSTORE: %s axis not judged — %s" % (verdict.skipped_axis, "; ".join(verdict.notes)))
    assert verdict.passed, verdict.evidence_dump()
    if verdict.inconclusive:
        # Every decidable check passed, but at least one could not be decided. The observation
        # that would decide it (the exact instant of the fault) is not available to the rig.
        pytest.skip("NEEDS_SUT_SEAM: " + "; ".join(c.detail for c in verdict.inconclusive))
