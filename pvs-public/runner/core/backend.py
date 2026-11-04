# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Observation/actuation backend interface .

The Orchestrator keeps all verdict *logic* (comparisons, deadlines) and delegates
raw I/O to a Backend. This keeps the decision engine unit-testable on the host
(FakeBackend) while the LiveBackend performs the real docker/ROS2/gRPC work.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GateObs:
    state: Optional[str] = None      # PERMIT|BLOCK|ESTOP
    reason: Optional[str] = None
    t: Optional[float] = None


@dataclass
class BridgeObs:
    state: Optional[str] = None      # FORWARDING|HOLD
    t: Optional[float] = None        # when the bridge says it entered/reported this state (wall time)
    t_received: Optional[float] = None   # when the observer received that message


@dataclass
class TwistObs:
    linear_x: float = 0.0
    angular_z: float = 0.0
    t: Optional[float] = None


@dataclass
class PermitObs:
    seqs: List[int] = field(default_factory=list)  # permit_seq seen in window
    window_ms: int = 0


class Backend:
    """Raw primitives. Live implementation wires docker/rclpy/gRPC; the Fake
    implementation returns scripted values for host-only verdict tests."""

    clock = staticmethod(time.monotonic)
    sleep = staticmethod(time.sleep)
    # Wall time, the base shared with timestamps the system under test puts on its own
    # messages. `clock` is monotonic and cannot be compared with those.
    wall = staticmethod(time.time)

    # ---- actuation (control verbs) ----
    def north_cmd(self, sub: Optional[str], args: Dict[str, Any]) -> None: ...
    def inject_evidence(self, args: Dict[str, Any]) -> None: ...
    def inject_cmd_vel(self, args: Dict[str, Any]) -> None: ...
    # SK-2 : call a named skill on the robot's own skill ingress (Microduck
    # `robot.do`). A transport with no skill ingress raises NotImplementedError — the row is
    # a SKIP with a reason, never a PASS (H-B2).
    def inject_skill(self, args: Dict[str, Any]) -> None:
        raise NotImplementedError("inject_skill: this transport has no skill ingress")
    def inject_safety(self, args: Dict[str, Any]) -> None: ...
    def rogue_publish(self, args: Dict[str, Any]) -> str: return "unsupported"
    def rogue_subscribe(self, args: Dict[str, Any]) -> str: return "unsupported"
    def fault(self, args: Dict[str, Any]) -> None: ...
    def operator_unlock(self, args: Dict[str, Any]) -> str: return "unsupported"

    # ---- observation (expect verbs, non-blocking snapshots) ----
    def gate(self) -> GateObs: return GateObs()
    def bridge(self) -> BridgeObs: return BridgeObs()
    def bridge_history(self) -> List[BridgeObs]: return []   # every bridge state message, oldest first
    def drive(self) -> TwistObs: return TwistObs()
    def drive_history(self) -> List[TwistObs]: return []
    def permits(self, window_ms: int) -> PermitObs: return PermitObs(window_ms=window_ms)
    def stop_request_asserted(self) -> bool: return False
    def burst_result(self): return None       # runner.verifiers.burst_verify.BurstResult
    def audit_result(self):  return None       # runner.verifiers.segment_chain.Result
    def anchor_result(self): return None       # runner.verifiers.anchor_check.AnchorResult

    # ---- observation health ----
    def observation_health(self) -> Dict[str, Any]:
        """What the observation channels themselves can say about their own state (the gate-log tail
        alive and delivering, how recently, whether the far side shows the command stream flowing).
        The orchestrator reads this when an expectation is NOT met, to tell "the system under test
        judged wrongly" (FAIL) from "nothing was observed" (INCONCLUSIVE). Empty means "no such
        signal on this transport"; every expectation then stays a plain pass/fail."""
        return {}

    # ---- profile capability ----
    def enforcement_supported(self) -> bool:
        """False on the insecure profile → Enforcement axis is SKIPPED honestly."""
        return False
