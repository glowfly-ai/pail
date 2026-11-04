# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Mock-verifiable lifecycle barrier; no NVIDIA/Issuer runtime port is implemented."""
from pathlib import Path
import uuid
import threading
from functools import wraps

def serialized(fn):
    @wraps(fn)
    def invoke(self,*args,**kwargs):
        with self._mutex: return fn(self,*args,**kwargs)
    return invoke
from state_store import atomic, read

REQUIRED={'ENDPOINT_ZERO','OLD_PLAN_CANCELLED','PATH_RECREATED','NEW_PLAN_ACCEPTED','ROBOT_PLAN_READY'}
ABORT={'PAUSE','STOP','RESET','BRIDGE_LOST','HEARTBEAT_LOST','TIME_FAULT','PORT_ERROR'}

class Lifecycle:
    def __init__(self, path, clock, generation=None):
        self._mutex=threading.RLock()
        self.path=Path(path); self.clock=clock; self.generation=generation or uuid.uuid4().hex
        self.state='LOCKED'; self.seen=set(); self.ready=set(); self.old_ids=set(); self.current=None
        self.last_time=None; self.since=clock(); self.persistence_fault=False
        if self.path.exists():
            try:
                previous=read(self.path); self.old_ids.update(previous.get('old_ids',[]))
                self.old_ids.update(previous.get('current') or [])
            except (ValueError,OSError): self.persistence_fault=True
        self.save()
    def save(self):
        if self.persistence_fault: return
        try: atomic(self.path,{'state':self.state,'generation':self.generation,'old_ids':sorted(self.old_ids),'current':self.current})
        except OSError: self.persistence_fault=True; self.state='LOCKED'
    def lock(self):
        self.old_ids.update(self.current or []); self.current=None; self.state='LOCKED'; self.ready.clear(); self.save()
    @serialized
    def event(self, kind, event_id, generation, source='MOCK', chain=None, token=None):
        now=self.clock()
        if self.last_time is not None and now<self.last_time:
            self.lock(); self.persistence_fault=True; return False
        self.last_time=now
        if source!='MOCK': raise ValueError('only MOCK ports are implemented')
        if generation!=self.generation or event_id in self.seen or self.persistence_fault: return False
        self.seen.add(event_id)
        if kind in ABORT:
            self.lock(); return True
        if self.state in ('PREPARING','WAIT_NEW_PLAN') and now-self.since>=5000:
            self.lock(); return False
        if kind=='PREPARE_OK' and self.state=='LOCKED':
            self.ready.clear(); self.state='PREPARING'; self.since=now
        elif kind in ('ENDPOINT_ZERO','OLD_PLAN_CANCELLED','PATH_RECREATED') and self.state=='PREPARING':
            self.ready.add(kind)
            if len(self.ready)==3: self.state='WAIT_NEW_PLAN'
        elif kind=='NEW_PLAN_ACCEPTED' and self.state=='WAIT_NEW_PLAN':
            if not isinstance(chain,str) or not isinstance(token,str) or not chain or not token or chain in self.old_ids or token in self.old_ids: return False
            self.current=[chain,token]; self.ready.discard('ROBOT_PLAN_READY'); self.ready.add(kind)
        elif kind=='ROBOT_PLAN_READY' and self.state=='WAIT_NEW_PLAN':
            if self.current != [chain,token]: return False
            self.ready.add(kind)
        elif kind=='PLAY_REQUEST' and self.state=='WAIT_NEW_PLAN' and self.ready==REQUIRED:
            self.state='ACTIVE'
        else: return False
        self.save(); return not self.persistence_fault
    @serialized
    def output(self, value):
        now=self.clock()
        if self.last_time is not None and now<self.last_time: self.lock(); self.persistence_fault=True
        self.last_time=now
        if self.state in ('PREPARING','WAIT_NEW_PLAN') and now-self.since>=5000: self.lock()
        return value if self.state=='ACTIVE' and not self.persistence_fault else 0.0
