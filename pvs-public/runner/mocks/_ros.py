# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Guarded ROS2 imports shared by the rclpy mock nodes.

rclpy + pail_msgs are provided by the ROS2 image, not pip. On the host these
imports fail; modules stay importable (ROS_AVAILABLE=False) so they can be
build/syntax-checked, but node construction requires the live ROS2 environment.
"""

from __future__ import annotations

try:
    import rclpy
    from rclpy.node import Node
    from geometry_msgs.msg import Twist
    from pail_msgs.msg import (Evidence, GateState, BridgeState, Permit,
                               SafetyState, StopRequest)
    ROS_AVAILABLE = True
    _IMPORT_ERROR = None
except Exception as e:  # pragma: no cover - host has no ROS2
    rclpy = None
    Node = object
    Twist = Evidence = GateState = BridgeState = Permit = SafetyState = StopRequest = object
    ROS_AVAILABLE = False
    _IMPORT_ERROR = e


def require_ros():
    if not ROS_AVAILABLE:
        raise RuntimeError(f"ROS2 not available: {_IMPORT_ERROR}")
