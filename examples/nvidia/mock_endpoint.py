# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Test-only command sink. Not an authorization gate or a physical watchdog."""
import math
import time

class MockEndpoint:
    def __init__(self, timeout_ms=250, clock=None):
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
            raise ValueError("invalid timeout")
        self.timeout_ms = timeout_ms
        self.clock = clock or (lambda: time.monotonic_ns() // 1000000)
        self.last_clock = None
        self.last_receive = None
        self.velocity = (0.0, 0.0)
        self.fault = False

    def now(self):
        value = self.clock()
        if type(value) is not int or value < 0 or (self.last_clock is not None and value < self.last_clock):
            self.fault = True
        if not self.fault:
            self.last_clock = value
        return value

    def receive(self, linear, angular):
        now = self.now()
        if self.fault:
            self.velocity = (0.0, 0.0)
            return False
        if any(type(x) not in (int, float) or not math.isfinite(x) for x in (linear, angular)):
            self.velocity = (0.0, 0.0); self.last_receive = None
            return False
        self.last_receive = now
        self.velocity = (float(linear), float(angular))
        return True

    def sample(self):
        now = self.now()
        if self.fault or self.last_receive is None or now - self.last_receive >= self.timeout_ms:
            self.velocity = (0.0, 0.0)
        return self.velocity

    def stop(self):
        self.velocity = (0.0, 0.0); self.last_receive = None
