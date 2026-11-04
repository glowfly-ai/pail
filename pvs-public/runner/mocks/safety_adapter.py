# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Safety Adapter  — rclpy node, Safety axis.

Pub: /pail/safety_state (OK/WARN/UNSAFE — D §4.1 domain; "SAFE" was the old
defect-era value and now parses kUnknown = new permits blocked). Sub:
/pail/stop_request.
Stale연출: stop publishing and let the safety freshness window elapse so the gate
must demote to WARN (no new PERMIT) purely from staleness. That window is
`preconditions[id=safety_feed].freshness_ms` in the policy file — it was
`PAIL_SAFETY_STALE_MS` until 2026-08-23 (implementation contract 단계 6), and the env is
now refused at startup rather than silently ignored.
"""

from __future__ import annotations

from typing import Optional

from ._ros import ROS_AVAILABLE, Node, SafetyState, StopRequest, require_ros


class SafetyAdapter(Node):
    def __init__(self):
        require_ros()
        super().__init__("pvs_safety_adapter")
        self.pub = self.create_publisher(SafetyState, "/pail/safety_state", 10)
        self.last_stop: Optional[StopRequest] = None
        self.stop_count = 0
        self.create_subscription(StopRequest, "/pail/stop_request", self._on_stop, 10)
        # Heartbeat OK by default like a real OEM adapter: the gate demotes on
        # staleness (safety_stale_ms), so without a periodic feed NO scenario
        # could ever reach PERMIT. go_stale() silences the timer for Safety-axis
        # staleness runs; set_level() changes the level it carries.
        # C-B7 (2026-08-14 live 실측): "SAFE" is NOT in ParseSafetyLevel's
        # domain — the gate logs `safety level UNKNOWN (raw="SAFE")` and blocks
        # every new permit. Only "OK" passes.
        self._publishing = True
        self._level = "OK"
        self._source = "PVS_SAFETY"
        self._timer = self.create_timer(0.1, self._tick)

    def _tick(self):
        if self._publishing:
            self.publish_once()

    def _on_stop(self, m):
        self.last_stop = m
        self.stop_count += 1

    def set_level(self, level: str, source: str = "PVS_SAFETY"):
        """Set the level published on the timer (OK|WARN|UNSAFE)."""
        self._level = level
        self._source = source
        self._publishing = True
        self.publish_once()

    def go_stale(self):
        """Stop publishing → gate must demote to WARN after the safety freshness window."""
        self._publishing = False

    def publish_once(self):
        m = SafetyState()
        m.stamp = self.get_clock().now().to_msg()
        m.level = self._level
        m.source = self._source
        self.pub.publish(m)

    def stop_asserted(self) -> bool:
        return self.stop_count > 0
