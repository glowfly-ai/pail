# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""PVS runner (live) — gRPC + ROS 2 integration skeleton.

This file is intended to run on a ROS 2 Humble dev machine.

Capabilities:
- Load YAML scenario
- Submit ActionPlan via gRPC to pail-services
- Publish Evidence to /pail/evidence
- Subscribe GateState from /pail/gate_state
- Assert expected decisions

NOTE: Requires ROS 2 environment sourced so `rclpy` is available.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:
    import rclpy
    from rclpy.node import Node
    from pail_msgs.msg import Evidence, GateState
except Exception as e:  # pragma: no cover
    rclpy = None
    Node = object
    Evidence = object
    GateState = object
    _ros_import_error = e

try:
    import grpc
except Exception as e:  # pragma: no cover
    grpc = None
    _grpc_import_error = e


@dataclass
class Scenario:
    name: str
    robot_id: str
    raw: Dict[str, Any]


def load_yaml(path: Path) -> Scenario:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Scenario(name=data["name"], robot_id=data["robot_id"], raw=data)


class PVSNode(Node):
    def __init__(self):
        super().__init__("pvs_runner")
        self.pub = self.create_publisher(Evidence, "/pail/evidence", 10)
        self.sub = self.create_subscription(GateState, "/pail/gate_state", self._on_gate, 10)
        self.last_gate: Optional[GateState] = None

    def _on_gate(self, msg: GateState):
        self.last_gate = msg

    def publish_evidence(self, source: str, object_id: str, confidence: float):
        ev = Evidence()
        ev.stamp = self.get_clock().now().to_msg()
        ev.source = source
        ev.object_id = object_id
        ev.confidence = float(confidence)
        ev.frame_id = ""
        # pose left default
        self.pub.publish(ev)


def run_live(scenario_path: Path, grpc_addr: str = "127.0.0.1:50051", strict: bool = False) -> int:
    if rclpy is None:
        raise RuntimeError(f"ROS imports failed: {_ros_import_error}")
    if grpc is None:
        raise RuntimeError(f"grpc imports failed: {_grpc_import_error}")

    sc = load_yaml(scenario_path)

    # gRPC stubs
    # Generate python stubs first (see pvs/runner/gen_grpc_stubs.md)
    # Then import here:
    #   from pvs.runner.live import pail_pb2, pail_pb2_grpc
    #   from pvs.runner.live import token_service_pb2, token_service_pb2_grpc
    #
    # NOTE: if imports fail, ensure `pvs/runner/live/__init__.py` exists (it does in this repo)
    # and run python from repo root `PAIL/`.
    #
    # gRPC stubs (generated into pvs/runner/live)
    # See pvs/runner/gen_grpc_stubs.md
    from pvs.runner.live import pail_pb2, pail_pb2_grpc

    channel = grpc.insecure_channel(grpc_addr)
    nb = pail_pb2_grpc.PailNorthboundStub(channel)

    # Translate scenario -> ActionPlan (minimal phase-1 mapping)
    nb_cfg = sc.raw["northbound"]
    if nb_cfg.get("mode") != "plan":
        raise ValueError("runner_live supports northbound.mode=plan only")

    ap = pail_pb2.ActionPlan(plan_id=nb_cfg["action_plan"].get("plan_id", "pvs-plan"))
    for st in nb_cfg["action_plan"]["steps"]:
        step = pail_pb2.PlanStep(
            step_id=st["step_id"],
            target_object_id=st.get("target_object_id", ""),
        )
        t = st.get("type", "TWIST")
        if t == "TWIST":
            step.type = pail_pb2.STEP_TWIST
            tw = st.get("twist", {})
            step.twist.linear_x = float(tw.get("linear_x", 0.0))
            step.twist.angular_z = float(tw.get("angular_z", 0.0))
            step.twist.duration_sec = float(tw.get("duration_sec", 1.0))
        else:
            step.type = pail_pb2.STEP_CUSTOM
            step.task_goal_json = "{}"

        ap.steps.append(step)

    submit_req = pail_pb2.SubmitActionPlanRequest(session_id="pvs", robot_id=sc.robot_id, plan=ap)
    submit_resp = nb.SubmitActionPlan(submit_req, timeout=5.0)
    print(f"SubmitActionPlan: status={submit_resp.status} chain_id={submit_resp.chain_id} tokens={len(submit_resp.tokens)}")

    rclpy.init()
    node = PVSNode()

    steps: List[Dict[str, Any]] = sc.raw["steps"]
    t0 = time.time()

    try:
        for st in steps:
            tgt = float(st["t"])
            while (time.time() - t0) < tgt:
                rclpy.spin_once(node, timeout_sec=0.05)

            if "inject_evidence" in st:
                ev = st["inject_evidence"]
                node.publish_evidence(ev["source"], ev["object_id"], ev["confidence"])

            if "expect_gate" in st:
                exp = st["expect_gate"]
                # Wait briefly for a gate state update and (optionally) assert.
                deadline = time.time() + 3.0
                got = None
                while time.time() < deadline:
                    rclpy.spin_once(node, timeout_sec=0.05)
                    if node.last_gate is not None:
                        got = node.last_gate
                        break
                node.get_logger().info(f"EXPECT gate: {exp} GOT: {None if got is None else {'state': got.state, 'reason': got.reason}}")

                # Soft-assert by default; strict mode returns non-zero.
                if got is not None:
                    if got.state != exp.get('state'):
                        node.get_logger().error(f"state mismatch expected={exp.get('state')} actual={got.state}")
                        if strict:
                            return 2
                    if got.reason != exp.get('reason'):
                        node.get_logger().error(f"reason mismatch expected={exp.get('reason')} actual={got.reason}")
                        if strict:
                            return 3

        return 0
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", type=str)
    ap.add_argument("--grpc", type=str, default="127.0.0.1:50051")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--rogue-fake-ack", action="store_true",
                    help="negative fixture: the rogue seam answers ReportDecision accepted=True without forwarding "
                         "(a fabricated confirmation the consumer must detect); never for a positive run")
    args = ap.parse_args()
    if args.rogue_fake_ack:
        import os
        os.environ["PVS_ROGUE_FAKE_ACK"] = "1"
    raise SystemExit(run_live(Path(args.scenario), grpc_addr=args.grpc, strict=args.strict))
