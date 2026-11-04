#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Live demo actors for the TB3 reference stack (no hardware).

  planner   executes the console's instruction on /cmd_vel (it plays the AI planner:
            PAIL does not trust it — the gate decides what reaches the base)
  base      simulated differential-drive base: integrates ONLY /drive_cmd_vel, the
            command that passed the gate and the motion bridge, and reports the pose
  evidence  synthetic identity reading (the tag the console selects)
  safety    synthetic safety feed (the level the console selects)

The instruction is /control/demo.json, written atomically by the console:
  {"seq": n, "instruction": k, "mode": "idle" | "plan" | "raw",
   "steps": [{"linear": v, "angular": w, "duration": s, "token": id}, ...],
   "override_linear": null | v,      # plan mode: publish v instead of the step's speed
   "raw": {"linear": v, "angular": w, "duration": s},
   "tag": "sample-box", "safety": "OK"}
seq changes on every write; instruction changes only when the planner's task changes, so
switching the synthetic tag or safety level never restarts a running plan.
Every observation is a JSON line under /evidence/runtime/demo-<role>.jsonl.
Positions from the base role are a simulation, labelled source=simulation. They show
what the gate let through; they are not a measurement of a real robot.
"""
import argparse
import json
import math
import os
import sys
import time
from pathlib import Path

import rclpy
from rclpy.node import Node
from geometry_msgs.msg import Twist
from pail_msgs.msg import Evidence, GateState, SafetyState

P = argparse.ArgumentParser()
P.add_argument('--role', choices=['planner', 'base', 'evidence', 'safety'], required=True)
A = P.parse_args()
OUT = Path('/evidence/runtime') / ('demo-' + A.role + '.jsonl')
CONTROL = Path('/control/demo.json')
sys.path.insert(0,str(Path(__file__).resolve().parent))
from raw_retention import ObservationWriter,RotationManager
RAW_WRITER=ObservationWriter(OUT)
RAW_MANAGER=RotationManager(OUT.parent).start() if A.role=='base' else None
if RAW_MANAGER is not None:
    import atexit
    atexit.register(RAW_MANAGER.close)
# The gate starts a step's clock when it permits the token; this planner only sees that
# permit a moment later. Publishing to its own clock's end would put a few commands past
# the gate's deadline (each refused as a step overrun, ERR_CONSTRAINT). A planner that
# respects its permit ends a little early instead. One command period (10 Hz) is enough:
# the step ends at the first tick where elapsed >= duration - 0.1 s, so the tick before it
# published strictly before the gate's deadline (the gate's clock started no later).
STOP_EARLY_S = 0.1
STOP_CMD_S = 0.5  # after a stop or completion, command zero velocity this long: a stop is a command, not silence


def clock_identity():
    # Namespace inode numbers may differ even when CLOCK_MONOTONIC has the same
    # kernel origin and offset. Compare the boot and the actual monotonic offset.
    try:
        with open('/proc/sys/kernel/random/boot_id') as f:
            boot = f.read().strip()
        with open('/proc/self/timens_offsets') as f:
            rows = [line.split() for line in f if line.split() and line.split()[0] == 'monotonic']
        if not boot or len(rows) != 1 or len(rows[0]) != 3:
            return 'unavailable'
        seconds, nanos = int(rows[0][1]), int(rows[0][2])
        return boot + ':monotonic-offset-ns=' + str(seconds * 1000000000 + nanos)
    except (OSError, ValueError):
        return 'unavailable'


CLOCK_ID = clock_identity()


def record(event, **kw):
    RAW_WRITER.append(dict(t=time.time(),mono=time.monotonic(),clock_id=CLOCK_ID,event=event,**kw))


def read_control():
    return json.loads(CONTROL.read_text())


class Actor(Node):
    def __init__(self):
        super().__init__('tb3_reference_' + A.role, start_parameter_services=False)
        self.ctl = {'seq': -1, 'mode': 'idle'}
        self.unreadable = False
        if A.role == 'planner':
            self.pub = self.create_publisher(Twist, '/cmd_vel', 10)
            self.create_subscription(GateState, '/pail/gate_state', self.on_gate, 10)
            self.started = None     # monotonic start of the current instruction
            self.step = 0           # index of the step being executed
            self.step_since = None  # monotonic time the gate first permitted this step's token
            self.last_gate = ('', '', '')
            self.permits = {}       # token -> monotonic time of the FIRST PERMIT seen for it (may precede the plan instruction)
            self.create_timer(0.1, self.plan_tick)
        elif A.role == 'base':
            self.x = self.y = self.th = 0.0
            self.v = self.w = 0.0
            self.cmd_at = None
            self.tick_at = time.monotonic()
            self.create_subscription(Twist, '/drive_cmd_vel', self.on_drive, 10)
            self.create_timer(0.05, self.base_tick)
            self.pose_every = 0
        elif A.role == 'evidence':
            self.pub = self.create_publisher(Evidence, '/pail/evidence', 10)
            self.create_timer(0.2, self.evidence_tick)
        else:
            self.pub = self.create_publisher(SafetyState, '/pail/safety_state', 10)
            self.create_timer(0.2, self.safety_tick)
        record('ready', role=A.role)

    def refresh(self):
        try:
            c = read_control()
        except (OSError, ValueError) as ex:
            if not self.unreadable:
                record('control_unreadable', detail=str(ex))
            self.unreadable = True
            return False
        self.unreadable = False
        if c.get('seq') != self.ctl.get('seq'):
            self.ctl = c
            return True
        return False

    # ---- planner: the untrusted executor -------------------------------------------
    def on_gate(self, m):
        now = (m.state, m.reason, m.active_token_id)
        if now != self.last_gate:  # transitions only; the full stream is the gate's own log
            record('gate', state=m.state, reason=m.reason, token=m.active_token_id)
            self.last_gate = now
        if m.state == 'PERMIT' and m.active_token_id and m.active_token_id not in self.permits:
            self.permits[m.active_token_id] = time.monotonic()
            for old in list(self.permits)[:-16]:
                del self.permits[old]
        self.adopt_permit()

    def adopt_permit(self):
        """Start this step's clock at the FIRST PERMIT the gate reported for its token — even one
        seen before this planner had read the plan. The gate's deadline counts from the first
        command it permitted, and that can be a zero-velocity command of the stop window that
        precedes the plan (real TurtleBot3, 2026-09-16: the token reached the gate 0.2 s before
        the plan instruction reached this planner; a clock started at the plan's own first
        permit then ran 0.2 s late and the step's last commands were refused as an overrun)."""
        steps = self.ctl.get('steps') or []
        if self.ctl.get('mode') == 'plan' and self.step < len(steps) and self.step_since is None:
            token = steps[self.step].get('token')
            if token in self.permits:
                self.step_since = self.permits[token]
                record('step_permitted', seq=self.ctl.get('seq'), step=self.step, token=token, permit_lead_s=round(time.monotonic() - self.step_since, 3))

    def publish(self, linear, angular):
        m = Twist()
        m.linear.x = float(linear)
        m.angular.z = float(angular)
        self.pub.publish(m)
        if linear == 0 and angular == 0:
            record('planner_zero', stop_id=self.ctl.get('stop_id'))

    def plan_tick(self):
        before, before_mode = self.ctl.get('instruction'), self.ctl.get('mode')
        if self.refresh() and self.ctl.get('instruction') != before:
            self.started, self.step, self.step_since = time.monotonic(), 0, None
            record('instruction', seq=self.ctl.get('seq'), instruction=self.ctl.get('instruction'), mode=self.ctl.get('mode'), stop_id=self.ctl.get('stop_id'))
            if before_mode in ('plan', 'raw') and self.ctl.get('mode') == 'idle':
                # TB3 floor 2026-09-15: a planner that merely goes silent leaves the base at its last
                # velocity (the OpenCR keeps it) — the robot ran 7.7 s after 'stop'. Say zero.
                self.stop_until = time.monotonic() + STOP_CMD_S
        mode = self.ctl.get('mode')
        now = time.monotonic()
        self.adopt_permit()
        if mode == 'raw':
            r = self.ctl.get('raw') or {}
            if now - self.started < float(r.get('duration', 0)):
                self.publish(r.get('linear', 0), r.get('angular', 0))
                return
            self.finish('raw_done')
            return
        if mode != 'plan':
            if now < getattr(self, 'stop_until', 0.0):
                self.publish(0.0, 0.0)
            return
        steps = self.ctl['steps']
        if self.step >= len(steps):
            return
        s = steps[self.step]
        if self.step_since is not None and now - self.step_since >= max(0.0, float(s['duration']) - STOP_EARLY_S):
            record('step_done', seq=self.ctl.get('seq'), step=self.step)
            self.window_end = self.step_since + float(s['duration'])  # the permit's deadline for this step
            self.step, self.step_since = self.step + 1, None
            if self.step >= len(steps):
                self.finish('plan_done')
                return
            s = steps[self.step]
        budget = sum(float(x['duration']) for x in steps) * 2 + 15
        if now - self.started > budget:  # never publish forever on a plan the gate keeps refusing
            self.finish('plan_timeout')
            return
        if self.step > 0 and self.step_since is None:
            self.publish(0.0, 0.0)  # hold still until the gate permits THIS step's token
            return
        linear = self.ctl.get('override_linear')
        self.publish(s['linear'] if linear is None else linear, s['angular'])

    def finish(self, why):
        record(why, seq=self.ctl.get('seq'), plan_id=self.ctl.get('plan_id'))
        self.ctl = dict(self.ctl, mode='idle')
        self.stop_until = time.monotonic() + STOP_CMD_S
        if why == 'plan_done' and getattr(self, 'window_end', None) is not None:
            # after a normal completion the zero commands stay inside the permit: past its
            # deadline the gate refuses them anyway (token consumed) and the bridge already
            # holds zero — sending more only paints a refusal after every successful move
            self.stop_until = min(self.stop_until, self.window_end - STOP_EARLY_S)

    # ---- base: simulated differential drive ------------------------------------------
    def on_drive(self, m):
        self.last_drive = dict(x=m.linear.x, z=m.angular.z, sample_mono=time.monotonic())
        self.v, self.w, self.cmd_at = m.linear.x, m.angular.z, time.monotonic()
        record('drive_state', x=m.linear.x, z=m.angular.z)
        if abs(m.linear.x) > 1e-8 or abs(m.angular.z) > 1e-8:
            record('drive', x=m.linear.x, z=m.angular.z)

    def base_tick(self):
        if getattr(self, 'last_drive', None) is not None:
            record('drive_observer', **self.last_drive)
        now = time.monotonic()
        dt, self.tick_at = now - self.tick_at, now
        if self.cmd_at is None or now - self.cmd_at > 0.3:  # a base with no fresh command stops
            self.v = self.w = 0.0
        self.th = math.atan2(math.sin(self.th + self.w * dt), math.cos(self.th + self.w * dt))
        self.x += self.v * math.cos(self.th) * dt
        self.y += self.v * math.sin(self.th) * dt
        self.pose_every = (self.pose_every + 1) % 2
        if self.pose_every == 0:
            record('pose', x=round(self.x, 4), y=round(self.y, 4), th=round(self.th, 4),
                   v=round(self.v, 4), w=round(self.w, 4), source='simulation')

    # ---- synthetic feeds ---------------------------------------------------------------
    def evidence_tick(self):
        self.refresh()
        m = Evidence()
        m.stamp = self.get_clock().now().to_msg()
        m.source = 'RFID'
        m.object_id = str(self.ctl.get('tag', 'sample-box'))
        m.confidence = .99
        self.pub.publish(m)

    def safety_tick(self):
        before = self.ctl.get('safety', 'OK')
        if self.refresh() and self.ctl.get('safety', 'OK') != before:
            record('safety', level=self.ctl.get('safety', 'OK'))
        m = SafetyState()
        m.stamp = self.get_clock().now().to_msg()
        m.level = str(self.ctl.get('safety', 'OK'))
        m.source = 'SYNTHETIC_REFERENCE'
        self.pub.publish(m)


rclpy.init()
n = Actor()
try:
    rclpy.spin(n)
finally:
    n.destroy_node()
    rclpy.shutdown()
