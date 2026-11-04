#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""TB3 live demo — robot-side participants on a real TurtleBot3 base.

Same instruction file and event vocabulary as examples/tb3/demo_io.py, but the base is the
vendor driver on the OpenCR and the position comes from the wheel encoders. Started by
start_demo_rig.sh, one container per role, on the robot's computer.

One DDS participant per enclave (SROS2 Enforce discovery cost grows with the square of the
participant count; an RPi3 must stay small). Roles, env DEMO_ROLE:

  planner   /oem_planner            executes /control/demo.json on /cmd_vel and watches
                                    /pail/gate_state (untrusted planner — the gate decides)
  base      /robot_state_publisher  /joint_states → wheel odometry pose (source=encoders)
  drive     /driver                 observes /drive_cmd_vel (what reached the driver)
  safety    /safety_adapter         synthetic safety feed (level from the instruction)
  evidence  /perception             synthetic RFID reading (tag from the instruction)

Each event is one JSON line on stdout; the console mirrors `docker logs -f`.
With raised wheels the encoder pose is how far the wheels turned, not how far a robot on the
floor would travel.
"""
import json
import math
import os
import sys
import time
import tempfile

import rclpy
from rclpy.node import Node
from rclpy.qos import qos_profile_sensor_data
from geometry_msgs.msg import Twist
from sensor_msgs.msg import JointState
from pail_msgs.msg import Evidence, GateState, SafetyState

ROLE = os.environ.get('DEMO_ROLE', '')
CONTROL = '/control/demo.json'
CLOCK_ABORT_STATE = '/state/demo_planner_clock_abort.json'
WHEEL_RADIUS = float(os.environ.get('DEMO_WHEEL_RADIUS', '0.033'))       # waffle_pi.yaml
WHEEL_SEPARATION = float(os.environ.get('DEMO_WHEEL_SEPARATION', '0.287'))
# Explicit local execution budget, not an extension of signed authority.
COMMAND_PERIOD_S = 0.1
DELIVERY_BUDGET_S = 0.1
SCHEDULER_BUDGET_S = 0.05
STOP_BUDGET_MS = round(1000 * (COMMAND_PERIOD_S + DELIVERY_BUDGET_S + SCHEDULER_BUDGET_S))
STOP_CMD_S = 0.5  # after a stop or completion, command zero velocity this long: a stop is a command, not silence
MAX_STEP_S = float(os.environ.get('DEMO_MAX_STEP_S', '30'))  # the issuer policy's step.max_duration_s; the planner never runs a step longer
TARGET = os.environ.get('DEMO_TARGET', 'sample-box')          # tag reported before the first instruction arrives


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


def elapsed_identity():
    try:
        with open('/proc/sys/kernel/random/boot_id') as f:
            boot = f.read().strip()
        with open('/proc/self/timens_offsets') as f:
            rows = [r.split() for r in f if r.split() and r.split()[0] == 'boottime']
        if not boot or len(rows) != 1 or len(rows[0]) != 3:
            return 'unavailable'
        return 'linux-boottime:%s:%d:%d' % (boot, int(rows[0][1]), int(rows[0][2]))
    except (OSError, ValueError):
        return 'unavailable'


def elapsed_ms():
    try:
        return int(time.clock_gettime(time.CLOCK_BOOTTIME) * 1000)
    except (OSError, AttributeError, ValueError):
        return -1


STEP_CLOCK_ID = elapsed_identity()
CLOCK_ID = clock_identity()


def record(event, **kw):
    sys.stdout.write(json.dumps(dict(t=time.time(), mono=time.monotonic(), clock_id=CLOCK_ID, event=event, **kw)) + '\n')
    sys.stdout.flush()


class Actor(Node):
    def __init__(self):
        super().__init__('demo_' + ROLE, start_parameter_services=False)
        self.ctl = {'seq': -1, 'mode': 'idle'}
        self.unreadable = False
        if ROLE == 'planner':
            self.pub = self.create_publisher(Twist, '/cmd_vel', 10)
            self.create_subscription(GateState, '/pail/gate_state', self.on_gate, 10)
            self.started, self.step, self.step_since = time.monotonic(), 0, None
            self.last_gate = ('', '', '')
            self.deadlines = {}
            self.completed_tokens = set()
            self.current_grant = ''
            self.motion_started = {}
            self.clock_abort = None
            self.clock_abort_io_failed = False
            self.load_clock_abort()
            self.permits = {}       # token -> monotonic time of the FIRST PERMIT seen for it (may precede the plan instruction)
            self.create_timer(COMMAND_PERIOD_S, self.plan_tick)
        elif ROLE == 'base':
            self.last = None            # (left, right) wheel positions, rad
            self.x = self.y = self.th = 0.0
            self.seen = None
            self.stale_reported = False
            self.pose_at = 0.0
            self.create_subscription(JointState, '/joint_states', self.on_joints, qos_profile_sensor_data)
            self.create_timer(0.5, self.watch_joints)
        elif ROLE == 'drive':
            self.last_drive = None
            self.create_subscription(Twist, '/drive_cmd_vel', self.on_drive, 10)
            self.create_timer(0.2, self.drive_heartbeat)
        elif ROLE == 'safety':
            self.pub = self.create_publisher(SafetyState, '/pail/safety_state', 10)
            self.create_timer(0.2, self.safety_tick)
        elif ROLE == 'evidence':
            self.pub = self.create_publisher(Evidence, '/pail/evidence', 10)
            self.create_timer(0.2, self.evidence_tick)
        else:
            raise SystemExit('DEMO_ROLE must be planner|base|drive|safety|evidence')
        record('ready', role=ROLE)

    def refresh(self):
        try:
            with open(CONTROL, encoding='utf-8') as f:
                c = json.load(f)
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

    # ---- planner -------------------------------------------------------------------
    def load_clock_abort(self):
        try:
            with open(CLOCK_ABORT_STATE) as f:
                marker = json.load(f)
            if (not isinstance(marker, dict) or marker.get('schema') != 1 or
                not isinstance(marker.get('instruction'), int) or
                not isinstance(marker.get('tokens'), list) or
                not all(isinstance(t, str) and t for t in marker['tokens'])):
                raise ValueError('invalid clock-abort marker')
            self.clock_abort = marker
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as ex:
            self.clock_abort_io_failed = True
            record('clock_abort_state_error', operation='load', detail=str(ex))

    def save_clock_abort(self, marker):
        name = None
        try:
            directory = os.path.dirname(CLOCK_ABORT_STATE)
            if marker is None:
                os.unlink(CLOCK_ABORT_STATE)
            else:
                fd, name = tempfile.mkstemp(prefix='.demo-clock-abort-', dir=directory)
                with os.fdopen(fd, 'w') as f:
                    json.dump(marker, f); f.flush(); os.fsync(f.fileno())
                os.replace(name, CLOCK_ABORT_STATE)
            fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            return True
        except OSError as ex:
            self.clock_abort_io_failed = True
            record('clock_abort_state_error', operation='save', detail=str(ex))
            return False
        finally:
            if name is not None and os.path.exists(name):
                os.unlink(name)

    def enforce_clock_abort(self):
        marker = self.clock_abort
        if not self.clock_abort_io_failed and marker is None:
            return True
        tokens = [s.get('token') for s in self.ctl.get('steps', [])]
        fresh_plan = (not self.clock_abort_io_failed and marker is not None and
                      self.ctl.get('mode') == 'plan' and tokens and all(tokens) and
                      set(tokens).isdisjoint(marker['tokens']))
        if fresh_plan:
            # Console counters can restart. Candidate IDs alone are not authority:
            # probe only with zero until the gate actually grants a fresh token.
            if self.current_grant not in tokens or self.current_grant not in self.deadlines:
                self.publish(0.0, 0.0)
                return False
            if self.save_clock_abort(None):
                self.clock_abort = None
                self.started, self.step, self.step_since = time.monotonic(), 0, None
                self.motion_started = {}
                record('clock_abort_cleared', instruction=self.ctl.get('instruction'),
                       basis='fresh_gate_permit', token=self.current_grant)
                return True
        self.ctl = dict(self.ctl, mode='idle')
        return True

    def on_gate(self, m):
        completed = getattr(m, 'completed_token_id', '')
        if completed and m.state == 'BLOCK' and m.reason == 'ERR_TOKEN_CONSUMED':
            self.completed_tokens.add(completed)
        self.current_grant = m.active_token_id if m.state == 'PERMIT' else ''
        deadline = getattr(m, 'step_deadline_elapsed_ms', 0)
        if (self.current_grant and deadline > 0 and STEP_CLOCK_ID != 'unavailable' and
            getattr(m, 'step_clock_id', '') == STEP_CLOCK_ID):
            old = self.deadlines.get(self.current_grant, deadline)
            self.deadlines[self.current_grant] = min(old, deadline)
        elif self.current_grant:
            self.deadlines.pop(self.current_grant, None)
            self.current_grant = ''
        now = (m.state, m.reason, m.active_token_id, self.ctl.get('instruction'))
        if now != self.last_gate:
            record('gate', state=m.state, reason=m.reason, token=m.active_token_id, detail=m.detail, instruction=self.ctl.get('instruction'), step_deadline_elapsed_ms=deadline, step_clock_id=getattr(m, 'step_clock_id', ''), completed_token_id=completed)
            self.last_gate = now
            if m.state == 'PERMIT' and not self.current_grant:
                record('timing_unavailable', token=m.active_token_id, expected_clock=STEP_CLOCK_ID,
                       observed_clock=getattr(m, 'step_clock_id', ''), deadline_elapsed_ms=deadline)
        if m.state == 'PERMIT' and m.active_token_id and m.active_token_id not in self.permits:
            self.permits[m.active_token_id] = time.monotonic()
            for old in list(self.permits)[:-16]:
                del self.permits[old]
                self.deadlines.pop(old, None)
                self.completed_tokens.discard(old)
        if m.reason == 'ERR_CLOCK_DRIFT' and m.state != 'PERMIT' and self.ctl.get('mode') in ('plan', 'raw'):
            self.clock_abort = dict(schema=1, instruction=self.ctl.get('instruction', -1),
                                    tokens=[s['token'] for s in self.ctl.get('steps', []) if s.get('token')])
            self.save_clock_abort(self.clock_abort)
            record('clock_abort', instruction=self.ctl.get('instruction'),
                   tokens=self.clock_abort['tokens'], reason=m.reason, detail=m.detail,
                   requires_new_plan=True, persisted=not self.clock_abort_io_failed)
            self.finish('plan_clock_aborted')
        self.adopt_permit()

    def adopt_permit(self):
        """Record first PERMIT receipt for UI telemetry only. Authorization timing
        uses the gate's explicit BOOTTIME deadline, never this receipt estimate.
        A zero command can have started the gate budget before the plan was read.
        """
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

    def finish(self, why):
        record(why, seq=self.ctl.get('seq'), plan_id=self.ctl.get('plan_id'),
               completion_scope='planner_command_budget', physical_execution='NOT_VERIFIED')
        self.ctl = dict(self.ctl, mode='idle')
        self.stop_until = time.monotonic() + STOP_CMD_S
        if why == 'plan_done':
            # A zero was already sent inside the actual budget (if time allowed).
            # Never let an estimate based on PERMIT receipt create a late tail.
            self.stop_until = 0

    def plan_tick(self):
        before, before_mode = self.ctl.get('instruction'), self.ctl.get('mode')
        if self.refresh() and self.ctl.get('instruction') != before:
            self.started, self.step, self.step_since = time.monotonic(), 0, None
            self.motion_started = {}
            record('instruction', seq=self.ctl.get('seq'), instruction=self.ctl.get('instruction'), mode=self.ctl.get('mode'), stop_id=self.ctl.get('stop_id'))
            if before_mode in ('plan', 'raw') and self.ctl.get('mode') == 'idle':
                # TB3 floor 2026-09-15: a planner that merely goes silent leaves the base at its last
                # velocity (the OpenCR keeps it) — the robot ran 7.7 s after 'stop'. Say zero.
                self.stop_until = time.monotonic() + STOP_CMD_S
        if not self.enforce_clock_abort():
            return
        mode, now = self.ctl.get('mode'), time.monotonic()
        self.adopt_permit()
        if mode == 'raw':
            r = self.ctl.get('raw') or {}
            if now - self.started < min(float(r.get('duration', 0)), MAX_STEP_S):
                self.publish(r.get('linear', 0), r.get('angular', 0))
            else:
                self.finish('raw_done')
            return
        if mode != 'plan':
            if now < getattr(self, 'stop_until', 0.0):
                self.publish(0.0, 0.0)
            return
        steps = self.ctl.get('steps') or []
        if self.step >= len(steps):
            return
        s = steps[self.step]
        token = s.get('token')
        # Do not probe the next step with zero commands until the gate has
        # actually consumed the previous token. A planner's step_done is not that fact.
        if self.step > 0 and steps[self.step-1].get('token') not in self.completed_tokens:
            return
        deadline = self.deadlines.get(token)
        grant_deadline = self.deadlines.get(self.current_grant)
        if deadline is not None and grant_deadline is not None:
            deadline = min(deadline, grant_deadline)
        clock_now = elapsed_ms()
        if clock_now < 0:
            return  # no clock, no command; the gate/bridge remain independent
        motion_start = self.motion_started.get(self.step)
        motion_duration = s.get('motion_duration')
        motion_due = (motion_start is not None and motion_duration is not None and
                      clock_now >= motion_start + round(float(motion_duration) * 1000))
        if motion_due or (deadline is not None and clock_now + STOP_BUDGET_MS >= deadline):
            if deadline is not None and clock_now + round(1000 * DELIVERY_BUDGET_S) < deadline:
                self.publish(0.0, 0.0)
            record('step_done', seq=self.ctl.get('seq'), step=self.step,
                   completion_scope='planner_command_budget', physical_execution='NOT_VERIFIED',
                   gate_deadline_elapsed_ms=deadline, observed_elapsed_ms=clock_now,
                   stop_budget_ms=STOP_BUDGET_MS, grant_token=self.current_grant,
                   termination='motion_intent_elapsed' if motion_due else 'gate_budget_exhausted')
            self.step, self.step_since = self.step + 1, None
            if self.step >= len(steps):
                self.finish('plan_done')
            return
        if now - self.started > sum(min(float(x['duration']), MAX_STEP_S) for x in steps) * 2 + 15:
            self.finish('plan_timeout')
            return
        if deadline is None or not self.current_grant:
            self.publish(0.0, 0.0)  # bootstrap a measured permit; never guess a deadline
            return
        self.motion_started.setdefault(self.step, clock_now)
        linear = self.ctl.get('override_linear')
        self.publish(s['linear'] if linear is None else linear, s['angular'])

    # ---- base: wheel odometry from the encoders ---------------------------------------
    def on_joints(self, m):
        names = list(m.name)
        if 'wheel_left_joint' not in names or 'wheel_right_joint' not in names:
            return
        left, right = m.position[names.index('wheel_left_joint')], m.position[names.index('wheel_right_joint')]
        if not (math.isfinite(left) and math.isfinite(right)):
            record('encoder_invalid')
            return
        self.seen = time.monotonic()
        if self.stale_reported:
            record('encoders_fresh')
            self.stale_reported = False
        if self.last is not None:
            dl = WHEEL_RADIUS * math.remainder(left - self.last[0], 2 * math.pi)
            dr = WHEEL_RADIUS * math.remainder(right - self.last[1], 2 * math.pi)
            ds, dth = (dl + dr) / 2.0, (dr - dl) / WHEEL_SEPARATION
            mid = self.th + dth / 2.0
            self.x += ds * math.cos(mid)
            self.y += ds * math.sin(mid)
            self.th = math.atan2(math.sin(self.th + dth), math.cos(self.th + dth))
        self.last = (left, right)
        if self.seen - self.pose_at >= 0.1:
            self.pose_at = self.seen
            record('pose', x=round(self.x, 4), y=round(self.y, 4), th=round(self.th, 4),
                   left_rad=round(left, 4), right_rad=round(right, 4), source='encoders')

    def watch_joints(self):
        if self.seen is None or time.monotonic() - self.seen > 1.0:
            if not self.stale_reported:
                record('encoders_stale')
                self.stale_reported = True

    # ---- drive observer -------------------------------------------------------------
    def drive_heartbeat(self):
        if self.last_drive is not None:
            record('drive_observer', **self.last_drive)

    def on_drive(self, m):
        self.last_drive = dict(x=m.linear.x, z=m.angular.z, sample_mono=time.monotonic())
        record('drive_state', x=m.linear.x, z=m.angular.z)
        if abs(m.linear.x) > 1e-8 or abs(m.angular.z) > 1e-8:
            record('drive', x=m.linear.x, z=m.angular.z)

    # ---- synthetic feeds --------------------------------------------------------------
    def safety_tick(self):
        before = self.ctl.get('safety', 'OK')
        if self.refresh() and self.ctl.get('safety', 'OK') != before:
            record('safety', level=self.ctl.get('safety', 'OK'))
        m = SafetyState()
        m.stamp = self.get_clock().now().to_msg()
        m.level = str(self.ctl.get('safety', 'OK'))
        m.source = 'SAFETY_PLC'
        m.detail = 'tb3-live-demo: synthetic safety input'
        self.pub.publish(m)

    def evidence_tick(self):
        self.refresh()
        m = Evidence()
        m.stamp = self.get_clock().now().to_msg()
        m.source = 'RFID'
        m.object_id = str(self.ctl.get('tag', TARGET))
        m.confidence = 0.95
        self.pub.publish(m)


def main():
    rclpy.init()
    n = Actor()
    try:
        rclpy.spin(n)
    finally:
        n.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
