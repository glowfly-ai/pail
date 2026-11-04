# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Rogue Actor  — Enforcement axis core.

profile==sros2: boot an rclpy node WITHOUT a keystore (or with a keystore whose
    permissions.xml omits the target topic). DDS-Security must reject participant
    creation → the exception IS the honest PASS (publish is not merely ignored;
    the node cannot come up). Caught → outcome="denied".
profile==uds: write to the bridge input socket as an unauthorized process → EACCES.
profile==insecure: bypass succeeds → Enforcement axis SKIPPED (never faked PASS).

Verdict observation point = /drive_cmd_vel (bridge output). A rogue payload
(e.g. linear_x=9.9) must NOT appear there. /safe_cmd_vel is never directly
watched: the monitor lacks permission to subscribe it, so '미관측=거짓 PASS'.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from typing import Dict

from ._ros import ROS_AVAILABLE

# The rogue MUST live in its own process (ENF-D1, evidence_d5/
# enf_fail_first_vacuous_denied.txt): in-process it re-ran rclpy.init() while
# the harness context was already initialized, so the RuntimeError from
# double-init — not DDS-Security — produced a vacuous "denied" even with
# security fully off. A child process also keeps the attacker's security env
# (keystore popped, Enforce forced) from poisoning the harness's own nodes.
_ROGUE_CHILD = r"""
import sys
topic, lin = sys.argv[1], float(sys.argv[2])
try:
    import rclpy
    from rclpy.node import Node
    from geometry_msgs.msg import Twist
except Exception:
    print("unsupported"); raise SystemExit(0)
try:
    rclpy.init()
    node = Node("pvs_rogue")            # DDS-Security should reject here
    pub = node.create_publisher(Twist, topic, 10)
    t = Twist()
    t.linear.x = lin
    pub.publish(t)
    import time; time.sleep(0.5)        # let DDS actually ship it if it can
    node.destroy_node()
    rclpy.shutdown()
    print("published")                 # only reachable when enforcement is off
except Exception:
    print("denied")
"""


def rogue_publish_sros2(topic: str, payload: Dict, key: str = "none",
                        keystore: str = "") -> str:
    """Attempt an unauthorized publish from a fresh process.
    Returns 'denied' | 'published' | 'unsupported' | 'error:...'.

    key=="none": no credentials at all — ROS_SECURITY_KEYSTORE/-ENCLAVE are
    stripped while Enforce stays on, so participant creation must be rejected.
    Only the child's explicit verdict is trusted; any other outcome surfaces
    as error:* and FAILS the expect (never faked as denied)."""
    if not ROS_AVAILABLE:
        return "unsupported"
    env = dict(os.environ)
    if key == "none":
        env.pop("ROS_SECURITY_KEYSTORE", None)
        env.pop("ROS_SECURITY_ENCLAVE_OVERRIDE", None)
        env["ROS_SECURITY_ENABLE"] = "true"
        env["ROS_SECURITY_STRATEGY"] = "Enforce"
        if keystore:  # optional empty (enclave-less) keystore variant (§5.3)
            env["ROS_SECURITY_KEYSTORE"] = keystore
    try:
        r = subprocess.run(
            [sys.executable, "-c", _ROGUE_CHILD,
             topic, str(float(payload.get("linear_x", 9.9)))],
            env=env, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return "error:timeout"
    out = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    if out in ("denied", "published", "unsupported"):
        return out
    return f"error:rc={r.returncode} out={out[:80]!r} err={r.stderr.strip()[-120:]!r}"


def rogue_write_uds(sock_path: str, payload: bytes = b"\x00" * 32) -> str:
    """profile==uds: unauthorized write to the bridge input socket → EACCES."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        s.sendall(payload)
        s.close()
        return "published"
    except PermissionError:
        return "denied"
    except OSError:
        return "denied"
