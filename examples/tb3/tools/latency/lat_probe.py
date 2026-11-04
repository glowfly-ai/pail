#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""cmd_vel -> safe_cmd_vel -> drive_cmd_vel latency probe (measurement tool, not product code).

Runs INSIDE one container that shares the rig's network+IPC namespace so every process reads
the same CLOCK_MONOTONIC. Twist carries no header, so the sequence number is encoded in
linear.x (BASE + seq*SCALE); the gate and the bridge republish the message verbatim.

  pub  --rate HZ --seconds S --out FILE       publisher (enclave /oem_planner)
  tap  --topic /cmd_vel --out FILE            subscriber (enclave with subscribe permission)

Every record: {"mono_ns": CLOCK_MONOTONIC ns, "real": time.time(), "seq": n, "x": linear.x}
"""
import argparse, json, os, signal, sys, time
import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy, HistoryPolicy
from geometry_msgs.msg import Twist

BASE, SCALE = 0.02, 1e-7


def encode(seq):
    return BASE + seq * SCALE


def decode(x):
    return int(round((x - BASE) / SCALE))


class Out:
    """--buffer keeps every record in memory and writes once at exit (no per-message I/O on a small
    board); the driver stops taps with SIGTERM so the flush runs."""
    def __init__(self, path, buffer=False):
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        os.fchmod(fd, 0o644)
        self.f = os.fdopen(fd, 'a', buffering=1)
        self.buf = [] if buffer else None

    def rec(self, **kw):
        line = json.dumps(kw, separators=(',', ':')) + '\n'
        if self.buf is None:
            self.f.write(line)
        else:
            self.buf.append(line)

    def flush(self):
        if self.buf:
            self.f.write(''.join(self.buf))
            self.buf = []
        self.f.flush()


class Pub(Node):
    def __init__(self, a, out):
        super().__init__('lat_probe_pub', start_parameter_services=False)
        self.a, self.out = a, out
        self.pub = self.create_publisher(Twist, '/cmd_vel', 10)
        self.seq, self.n = a.seq0, int(a.rate * a.seconds)
        self.period = 1.0 / a.rate
        self.t0 = None
        self.timer = self.create_timer(self.period, self.tick)
        out.rec(event='start', rate=a.rate, seconds=a.seconds, n=self.n, seq0=a.seq0,
                mono_ns=time.monotonic_ns(), real=time.time(), pid=os.getpid())

    def tick(self):
        if self.seq - self.a.seq0 >= self.n:
            self.out.rec(event='done', mono_ns=time.monotonic_ns(), real=time.time(), last_seq=self.seq - 1)
            self.timer.cancel()
            raise SystemExit(0)
        m = Twist()
        m.linear.x = encode(self.seq)
        t = time.monotonic_ns()
        self.pub.publish(m)
        self.out.rec(mono_ns=t, real=time.time(), seq=self.seq, x=m.linear.x)
        self.seq += 1


class Tap(Node):
    def __init__(self, a, out):
        super().__init__('lat_probe_tap_' + a.topic.strip('/').replace('/', '_'), start_parameter_services=False)
        self.out = out
        qos = QoSProfile(depth=200, reliability=ReliabilityPolicy.RELIABLE, history=HistoryPolicy.KEEP_LAST)
        self.create_subscription(Twist, a.topic, self.on_msg, qos)
        out.rec(event='ready', topic=a.topic, mono_ns=time.monotonic_ns(), real=time.time(), pid=os.getpid())

    def on_msg(self, m):
        t = time.monotonic_ns()
        x = m.linear.x
        seq = decode(x) if BASE - SCALE / 2 <= x <= BASE + 1e6 * SCALE else -1
        self.out.rec(mono_ns=t, real=time.time(), seq=seq, x=x, z=m.angular.z)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=['pub', 'tap'])
    ap.add_argument('--rate', type=float, default=10.0)
    ap.add_argument('--seconds', type=float, default=14.0)
    ap.add_argument('--seq0', type=int, default=0)
    ap.add_argument('--topic', default='/cmd_vel')
    ap.add_argument('--out', required=True)
    ap.add_argument('--buffer', action='store_true', help='keep records in memory; write once at exit')
    a = ap.parse_args()
    out = Out(a.out, buffer=a.buffer)

    def on_term(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, on_term)
    rclpy.init()
    n = Pub(a, out) if a.mode == 'pub' else Tap(a, out)
    try:
        rclpy.spin(n)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        out.rec(event='exit', mono_ns=time.monotonic_ns(), real=time.time())
        out.flush()
        n.destroy_node()
        rclpy.try_shutdown()


if __name__ == '__main__':
    main()
