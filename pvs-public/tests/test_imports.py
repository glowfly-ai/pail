# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Build-check imports.

Two kinds of module get exercised here:
  * Always: the generated gRPC/proto stubs and the pure-python runner packages
    must import on a bare host (catches syntax/packaging regressions in CI).
  * ROS-gated: the rclpy live nodes (mock_hal, safety_adapter, backend_live) are
    imported only when rclpy is present, so a build break in the live path is
    caught on a ROS2 machine without needing the full stack up.
"""

from __future__ import annotations

import importlib

import pytest

from tests.conftest import ros_available

# host-importable (no ROS2 / docker daemon required)
HOST_MODULES = [
    "runner.core.model",
    "runner.core.timeline",
    "runner.core.verdict",
    "runner.core.orchestrator",
    "runner.core.report",
    "runner.core.backend",
    "runner.verifiers.burst_verify",
    "runner.verifiers.segment_chain",
    "runner.verifiers.anchor_check",
    "runner.verifiers.keys",
    "runner.mocks.mock_ai",
    "runner.mocks.mock_cloud",
    "runner.mocks.rogue_actor",
    "runner.injectors.chaos_monkey",
    "runner.live.pail_pb2",
    "runner.live.pail_pb2_grpc",
    "runner.live.token_service_pb2",
    "runner.live.operator_service_pb2",
    "keystore_tools.provision",
]

# only importable where rclpy exists (build-check the live ROS2 path)
ROS_MODULES = [
    "runner.mocks._ros",
    "runner.mocks.mock_hal",
    "runner.mocks.safety_adapter",
    "runner.live.backend_live",
]


@pytest.mark.unit
@pytest.mark.parametrize("mod", HOST_MODULES)
def test_host_module_imports(mod):
    importlib.import_module(mod)


@pytest.mark.parametrize("mod", ROS_MODULES)
def test_ros_module_imports(mod):
    if not ros_available():
        pytest.skip("NEEDS_ROS_RUNTIME: rclpy unavailable — live ROS2 module build-check skipped")
    importlib.import_module(mod)
