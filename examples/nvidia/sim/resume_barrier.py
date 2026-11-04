# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Preparation contract for a trusted future SDK coordinator, NOT an authorization API.

No ROS/SDK binding or public RPC is provided. Callers must obtain all attestations
through trusted independent ports; booleans from arbitrary publishers are not evidence.
Existing MOCK Lifecycle remains unchanged. This does not claim real Sim support.
"""
import math
import threading
import uuid


class ResumeBarrier:
    def __init__(self,port,clock,observation_age_ms=250):
        if type(observation_age_ms) is not int or observation_age_ms<=0:raise ValueError('positive age required')
        self.port=port;self.clock=clock;self.max_age=observation_age_ms
        self.state='LOCKED';self.generation=uuid.uuid4().hex;self.last=None
        self.zero_at=None;self.current=None;self.old=set();self.fault=False
        self.mutex=threading.RLock()

    def _now(self):
        now=self.clock()
        if type(now) not in (int,float) or not math.isfinite(now) or (self.last is not None and now<self.last):
            self.abort();self.fault=True;raise ValueError('elapsed clock invalid')
        self.last=now;return now

    def abort(self):
        with self.mutex:
            # Close the software barrier before any fallible external action.
            self.state='LOCKED';self.zero_at=None
            if self.current:self.old.update(self.current)
            self.current=None;self.generation=uuid.uuid4().hex
            try:self.port.stop_inputs();self.port.clear_targets()
            except Exception:
                self.fault=True;raise
            return self.generation  # NOT a stop-confirmed receipt

    def prepare(self,generation,cancelled,path_recreated,zero_observed_at):
        with self.mutex:
            now=self._now()
            if self.fault or self.state!='LOCKED' or generation!=self.generation:return False
            if cancelled is not True or path_recreated is not True:return False
            if type(zero_observed_at) not in (int,float) or not math.isfinite(zero_observed_at) or not 0<=now-zero_observed_at<=self.max_age:return False
            self.zero_at=zero_observed_at;self.state='WAIT_NEW_PLAN';return True

    def activate(self,generation,issued,robot_ready):
        with self.mutex:
            now=self._now()
            if self.fault or self.state!='WAIT_NEW_PLAN' or generation!=self.generation:return False
            if self.zero_at is None or now-self.zero_at>self.max_age:
                self.abort();return False
            if not isinstance(issued,tuple) or len(issued)!=2 or issued!=robot_ready or any(not isinstance(v,str) or not v or v in self.old for v in issued):return False
            self.current=issued
            try:self.port.play()
            except Exception:
                self.abort();self.fault=True;raise
            self.state='ACTIVE';return True

    def forward(self,value,generation):
        with self.mutex:
            try:
                self._now()
                if type(value) not in (int,float) or not math.isfinite(value):raise ValueError('nonfinite command')
                if self.fault or self.state!='ACTIVE' or generation!=self.generation:
                    self.abort();return False
                self.port.apply(value);return True
            except Exception:
                self.abort();self.fault=True;raise
