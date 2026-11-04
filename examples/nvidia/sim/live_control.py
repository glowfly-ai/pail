# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""One-exercise SDK endpoint latch. Gate/bridge remain the command authority.

Control file is a trusted coordinator mount, never a public ROS input. No hot
resume: expiry, pause/reset and faults require a fresh full run. Not a PEP.
"""
import math
import re
import uuid


class LiveControl:
    def __init__(self,run_id,generation,boot_id,clock,timeout_ms=250):
        self.run_id=run_id;self.generation=generation;self.boot_id=boot_id
        self.clock=clock;self.timeout=timeout_ms;self.epoch=uuid.uuid4().hex
        self.state='READY_LOCKED';self.reason='initial';self.last_clock=None
        self.grant=None;self.heartbeat=-1;self.beat_at=None;self.command_at=None
        self.command_value=(0.,0.);self.used=False;self.started_at=None

    def lock(self,reason):
        # The first cause is the evidence; later causes while locked (e.g. NOT_PLAYING every
        # cycle after a timeline pause) must not overwrite it. A lock never reopens.
        if self.state!='FAULT_LOCKED':self.reason=reason
        self.state='FAULT_LOCKED';self.command_value=(0.,0.)
        self.command_at=None

    def now(self):
        now=self.clock()
        if type(now) not in (int,float) or not math.isfinite(now) or (self.last_clock is not None and now<self.last_clock):
            self.lock('CLOCK_INVALID');raise ValueError('invalid elapsed clock')
        self.last_clock=now;return now

    def control(self,row):
        now=self.now()
        if self.state=='FAULT_LOCKED':return
        if not isinstance(row,dict) or row.get('run_id')!=self.run_id or row.get('generation')!=self.generation or row.get('boot_id')!=self.boot_id:
            self.lock('CONTROL_IDENTITY');return
        hb=row.get('heartbeat');sent=row.get('elapsed_ms')
        if type(hb) is not int or type(sent) not in (int,float) or not math.isfinite(sent):
            self.lock('CONTROL_STALE');return
        if row.get('on') is False and not self.used:return  # initial locked hold during slow SDK startup
        if not 0<=now-sent<=500:self.lock('CONTROL_STALE');return
        if hb<self.heartbeat:self.lock('CONTROL_REPLAY');return
        if hb>self.heartbeat:self.heartbeat=hb;self.beat_at=now
        if row.get('on') is not True:
            if self.used:self.lock('EXERCISE_ENDED')
            return
        grant=row.get('grant')
        if not isinstance(grant,dict) or grant.get('epoch')!=self.epoch or any(not isinstance(grant.get(k),str) or not grant[k] for k in ('plan','chain','token','token_hash')) or not re.fullmatch('[0-9a-f]{64}',grant['token_hash']):
            self.lock('GRANT_INVALID');return
        if self.grant is not None and grant!=self.grant:self.lock('NEW_RUN_REQUIRED');return
        if self.grant is None:
            self.grant=dict(grant);self.used=True;self.started_at=now
            self.command_at=None;self.command_value=(0.,0.);self.state='ACTIVE'

    def receive(self,values):
        now=self.now()
        if len(values)!=6 or any(type(v) not in (int,float) or not math.isfinite(v) for v in values) or any(values[i]!=0 for i in (1,2,3,4)):
            self.lock('INVALID_TWIST');return
        # Bounded reference envelope is defensive, never a replacement for gate policy.
        if abs(values[0])>.1 or abs(values[5])>1.:
            self.lock('REFERENCE_ENVELOPE');return
        if self.state=='ACTIVE':self.command_value=(values[0],values[5]);self.command_at=now

    def output(self):
        now=self.now()
        if self.state!='ACTIVE':return (0.,0.)
        if self.beat_at is None or now-self.beat_at>=500:
            self.lock('HEARTBEAT_LOST');return (0.,0.)
        if now-self.started_at>=8000:
            self.lock('EXERCISE_DEADLINE');return (0.,0.)
        if self.command_at is None:return (0.,0.)
        if now-self.command_at>=self.timeout:
            self.lock('COMMAND_TIMEOUT');return (0.,0.)
        return self.command_value


def require_security(env,keystore):
    from pathlib import Path
    expected={'ROS_SECURITY_ENABLE':'true','ROS_SECURITY_STRATEGY':'Enforce',
              'ROS_SECURITY_ENCLAVE_OVERRIDE':'/nv_endpoint','RMW_IMPLEMENTATION':'rmw_fastrtps_cpp','ROS_DISTRO':'humble'}
    if any(env.get(k)!=v for k,v in expected.items()):raise ValueError('SROS2_REQUIRED_NO_FALLBACK')
    if env.get('ROS_SECURITY_KEYSTORE')!=str(keystore):raise ValueError('KEYSTORE_MISMATCH')
    enclaves=Path(keystore)/'enclaves'
    if {p.name for p in enclaves.iterdir()}!={'nv_endpoint'}:raise ValueError('FOREIGN_ENCLAVE_MATERIAL')
    for name in ('cert.pem','key.pem','permissions.p7s','governance.p7s'):
        p=enclaves/'nv_endpoint'/name
        if p.is_symlink() or not p.is_file():raise ValueError('MISSING_SECURITY_MATERIAL')
