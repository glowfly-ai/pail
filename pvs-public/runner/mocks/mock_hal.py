# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Mock Robot HAL  — rclpy node.

Pub: /pail/evidence (Evidence), /cmd_vel (Twist).
Sub: /pail/gate_state, /pail/bridge_state, /pail/permit, and the v2 verdict
     정본 /drive_cmd_vel (bridge output = what actually reaches the driver).
     /safe_cmd_vel is also recorded but is NOT used for Enforcement verdicts.
"""

from __future__ import annotations

import os
from typing import List, Optional

from ._ros import (ROS_AVAILABLE, Node, Twist, Evidence, GateState, BridgeState,
                   Permit, require_ros)


class MockHAL(Node):
    def __init__(self):
        require_ros()
        super().__init__("pvs_mock_hal")
        self.pub_ev = self.create_publisher(Evidence, "/pail/evidence", 10)
        self.pub_cmd = self.create_publisher(Twist, "/cmd_vel", 10)

        self.last_gate: Optional[GateState] = None
        self.last_bridge: Optional[BridgeState] = None
        # (state, stamp the bridge put on the message, receipt time) — the bridge publishes on
        # every transition, so its own stamp is the time of the transition.
        self.bridge_history: List[tuple] = []
        self.permits: List[tuple] = []         # (permit_seq, t) — t needed for window queries
        self.drive_history: List[tuple] = []   # (linear_x, angular_z, t)
        self.safe_history: List[tuple] = []

        # The gate publishes /pail/permit BEST_EFFORT (deadman: RELIABLE
        # retransmits must not delay loss detection — pep_gate_node.cpp). A
        # RELIABLE subscription is QoS-incompatible and receives nothing.
        from rclpy.qos import QoSProfile, ReliabilityPolicy
        permit_qos = QoSProfile(depth=10,
                                reliability=ReliabilityPolicy.BEST_EFFORT)

        self.create_subscription(GateState, "/pail/gate_state", self._on_gate, 10)
        self.create_subscription(BridgeState, "/pail/bridge_state", self._on_bridge, 10)
        self.create_subscription(Permit, "/pail/permit", self._on_permit, permit_qos)
        self.create_subscription(Twist, "/drive_cmd_vel", self._on_drive, 10)
        # /safe_cmd_vel is a debugging-only observation, never a verdict input.
        # pvs_policy.xml deliberately DENIES the rig this subscription (§5.3:
        # the boundary monitor must be blind to /safe_cmd_vel so "rogue payload
        # never reached the wheels" is proven at /drive_cmd_vel). Under SROS2
        # Enforce, creating the denied endpoint would reject the whole node.
        if os.environ.get("ROS_SECURITY_ENABLE", "").lower() != "true":
            self.create_subscription(Twist, "/safe_cmd_vel", self._on_safe, 10)

    # ---- callbacks ----
    def _on_gate(self, m): self.last_gate = m
    def _on_bridge(self, m):
        self.last_bridge = m
        stamp = m.stamp.sec + m.stamp.nanosec / 1e9
        self.bridge_history.append((m.state, stamp if stamp > 0 else None, self._now()))
    def _on_permit(self, m): self.permits.append((int(m.permit_seq), self._now()))

    def _now(self):
        return self.get_clock().now().nanoseconds / 1e9

    def _on_drive(self, m): self.drive_history.append((m.linear.x, m.angular.z, self._now()))
    def _on_safe(self, m): self.safe_history.append((m.linear.x, m.angular.z, self._now()))

    # ---- actuation ----
    def publish_evidence(self, source: str, object_id: str, confidence: float):
        ev = Evidence()
        ev.stamp = self.get_clock().now().to_msg()
        ev.source = source
        ev.object_id = object_id
        ev.confidence = float(confidence)
        self.pub_ev.publish(ev)

    def publish_cmd_vel(self, linear_x: float, angular_z: float = 0.0):
        t = Twist()
        t.linear.x = float(linear_x)
        t.angular.z = float(angular_z)
        self.pub_cmd.publish(t)
