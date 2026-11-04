#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""World feeders for the e2e enforcement demo: safety state + target evidence.

The gate needs two live inputs before it will permit motion under a token —
a safety level and an evidence claim naming the target object. Both are judged
by FRESHNESS (policy: safety 1000 ms, evidence 2000 ms), so each message is
stamped with the current time and republished continuously.

Why this is a node and not `ros2 topic pub`: that CLI leaves the header stamp
at zero, which the gate reads — correctly — as a claim from 1970. The run then
sits at BLOCK/ERR_WORLD_INDETERMINATE, and that looks like the policy rejecting
the target rather than a feeder that never dated its claim.

Run it inside the gate container under the /safety_adapter enclave; see
e2e/run_e2e.sh.
"""
import argparse

import rclpy
from rclpy.node import Node

from pail_msgs.msg import Evidence, SafetyState


class Feeders(Node):
    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__("e2e_feeders")
        self.args = args
        self.safety = self.create_publisher(SafetyState, "/pail/safety_state", 10)
        self.evidence = self.create_publisher(Evidence, "/pail/evidence", 10)
        self.create_timer(1.0 / args.rate, self.tick)

    def tick(self) -> None:
        now = self.get_clock().now().to_msg()

        s = SafetyState()
        s.stamp = now
        # OK — not "SAFE". The gate grades OK|WARN|UNSAFE and treats every other
        # spelling as unknown, which blocks new permits exactly like UNSAFE.
        s.level = "OK"
        s.source = self.args.safety_source
        self.safety.publish(s)

        e = Evidence()
        e.stamp = now
        e.source = self.args.evidence_source
        e.object_id = self.args.object_id
        e.confidence = self.args.confidence
        self.evidence.publish(e)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rate", type=float, default=5.0, help="Hz for both feeds")
    p.add_argument("--object-id", default="880123", help="target the evidence claims")
    # RFID is identity-bearing; VISION is inferential and the default policy
    # refuses it at any confidence.
    p.add_argument("--evidence-source", default="RFID")
    p.add_argument("--safety-source", default="E2E")
    p.add_argument("--confidence", type=float, default=0.99)
    args = p.parse_args()

    rclpy.init()
    node = Feeders(args)
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
