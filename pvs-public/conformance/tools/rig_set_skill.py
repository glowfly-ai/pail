#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Rig step (SK-2, CA-13): give the fake robot a skill whose declared twist exceeds the
policy's speed limit, BEFORE the adapters connect and learn envelopes from `robot.skills`.

Adds a new skill `pail_dash` (path = the built-in roulade's network) with command
[1.5, 0.0, 0.3] for 4 s. The built-ins themselves are upstream's zero-command family and
keep [0,0,0] whatever a setSkill says (measured on the rig, 2026-09-09). The token's limit
is the policy's 1.0 m/s, so a `robot.do {skill: pail_dash}` must BLOCK with ERR_CONSTRAINT on
sls.linear_mps = 1.5.

Talks to robotd's raw socket directly (this is rig setup, not a requester path).
Exit 0 = the daemon acknowledged; 2 = it did not (the case cannot be run — say so).
"""
import json
import os
import socket
import sys
import time

RAW = os.environ.get("PAIL_DUCK_RAW", "/run/duck/robotd.sock")
SKILL = os.environ.get("PAIL_DUCK_FAST_SKILL", "pail_dash")
LIN = float(os.environ.get("PAIL_DUCK_FAST_LIN", "1.5"))
YAW = float(os.environ.get("PAIL_DUCK_FAST_YAW", "0.3"))
DUR = float(os.environ.get("PAIL_DUCK_FAST_DUR", "4.0"))


def line(obj):
    return (json.dumps(obj) + "\n").encode()


def read_answers(s, want_ids, timeout=3.0):
    buf = b""
    deadline = time.monotonic() + timeout
    answers = {}
    while time.monotonic() < deadline and not want_ids <= set(answers):
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if "id" in msg:
                answers[msg["id"]] = msg
    return answers


def skill_row(answer, name):
    res = (answer or {}).get("result", {})
    if not isinstance(res, dict):
        return None
    for p in res.get("skills", []):
        if p.get("name") == name:
            return p
    return None


def main():
    for _ in range(50):
        if os.path.exists(RAW):
            break
        time.sleep(0.1)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3.0)
    s.connect(RAW)
    s.sendall(line({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"api_version": 44}}))
    # Check first: the rig's params file (rig_microduck.sh) normally supplies the skill.
    s.sendall(line({"jsonrpc": "2.0", "id": 3, "method": "robot.skills"}))
    pre = read_answers(s, {3})
    p0 = skill_row(pre.get(3), SKILL)
    if p0 and p0.get("command", [0, 0, 0])[0] == LIN:
        print("rig_set_skill: %s present from the params file: command=%s duration=%s" % (SKILL, p0.get("command"), p0.get("duration")))
        s.close()
        return 0
    # Fallback: a NEW name with an explicit path: the built-ins are upstream's zero-command family and a
    # `command` on them is not what they are (2026-09-09 rig: setSkill on roulade left it at
    # [0,0,0]). The path names the built-in's own network so nothing has to exist that does not.
    s.sendall(line({"jsonrpc": "2.0", "id": 2, "method": "robot.setSkill",
                    "params": {"name": SKILL, "path": "roulade.onnx", "duration": DUR, "command": [LIN, 0.0, YAW]}}))
    s.sendall(line({"jsonrpc": "2.0", "id": 4, "method": "robot.skills"}))
    answers = read_answers(s, {2, 4})
    s.close()
    set_ans = answers.get(2)
    if set_ans is None or "error" in set_ans:
        print("rig_set_skill: robot.setSkill not acknowledged: %s" % (set_ans,))
        return 2
    p = skill_row(answers.get(4), SKILL)
    if not p or p.get("command", [0, 0, 0])[0] != LIN:
        print("rig_set_skill: robot.skills does not show %s at %.2f m/s: %s" % (SKILL, LIN, p))
        return 2
    print("rig_set_skill: %s now command=%s duration=%s (robot.skills confirms)" % (SKILL, p.get("command"), p.get("duration")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
