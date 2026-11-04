# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Bounded clock/transport observations. Never infer issuer clock skew or CPU load."""
import math
import re
import time

CATEGORIES={'TRANSPORT_REFUSED','TIMEOUT','TLS_VERIFY_FAILED','DNS','REMOTE_UNAVAILABLE',
            'REMOTE_RESTART','RESOURCE_PRESSURE','UNKNOWN'}


def transport(code='',detail='',basis=None):
    code=str(code).rsplit('.',1)[-1].upper();text=str(detail).lower()
    category='UNKNOWN'
    if code=='DEADLINE_EXCEEDED' or basis=='timeout':category='TIMEOUT'
    elif any(x in text for x in ('certificate verify failed','certificate_verify_failed','certificate verification failed','tls handshake','ssl handshake','x509:','peer name','hostname verification check failed')):category='TLS_VERIFY_FAILED'
    elif any(x in text for x in ('dns resolution','name resolution','getaddrinfo','name or service not known','hostname lookup error','domain name not found')):category='DNS'
    elif 'connection refused' in text or basis=='connection_refused':category='TRANSPORT_REFUSED'
    elif code=='RESOURCE_EXHAUSTED' or basis=='oom_killed':category='RESOURCE_PRESSURE'
    elif code=='UNAVAILABLE' or basis=='service_not_running':category='REMOTE_UNAVAILABLE'
    elif basis=='instance_changed':category='REMOTE_RESTART'
    return {'category':category,'grpc_code':code if code in {'DEADLINE_EXCEEDED','UNAVAILABLE','RESOURCE_EXHAUSTED','PERMISSION_DENIED','UNAUTHENTICATED','CANCELLED','UNKNOWN','INTERNAL'} else None,
            'basis':basis or ('rpc_status_and_transport_detail' if code else 'unclassified')}


class ProbeError(RuntimeError):
    def __init__(self,diagnostic):
        self.diagnostic=diagnostic
        super().__init__(diagnostic['category'])


class ClockWatch:
    """Compare only advancing samples in the same reported clock realm."""
    def __init__(self,threshold=.25,steady=time.monotonic,wall=time.time):
        self.threshold=threshold;self.steady=steady;self.wall=wall;self.samples={}

    def observe(self,role,record):
        if record.get('replayed'):return None
        clock=record.get('clock_id');t=record.get('t');mono=record.get('mono')
        if (not isinstance(clock,str) or clock=='unavailable' or not re.fullmatch(r'[A-Za-z0-9:._+=-]{1,200}',clock)
                or any(type(v) not in (int,float) or not math.isfinite(v) for v in (t,mono))):return None
        previous=self.samples.get(clock)
        if previous is not None and mono<=previous['mono']:return None
        now=self.steady()
        if len(self.samples)>=64 and clock not in self.samples:
            del self.samples[min(self.samples,key=lambda k:self.samples[k]['received'])]
        delta=None if previous is None else (t-previous['wall'])-(mono-previous['mono'])
        stepped=delta is not None and abs(delta)>self.threshold
        sample={'wall':t,'mono':mono,'received':now,'stable_since':now if previous is None or stepped else previous['stable_since'],
                'count':1 if previous is None or stepped else previous['count']+1,
                'baseline_created_at_ms':int(self.wall()*1000) if previous is None else previous['baseline_created_at_ms']}
        self.samples[clock]=sample
        if not stepped:return None
        return {'event':'clock_step','role':role,'jump_s':round(delta,6),'wall_delta_s':t-previous['wall'],
                'monotonic_delta_s':mono-previous['mono'],'clock_id':clock,
                'producer_instance_id':record.get('producer_instance_id'),
                'baseline_created_at_ms':sample['baseline_created_at_ms'],'detected_at_ms':int(self.wall()*1000),
                'basis':'local_wall_vs_monotonic','issuer_clock_difference_measured':False}

    def stable(self,clock,seconds=5):
        s=self.samples.get(clock)
        return bool(s and s['count']>=3 and self.steady()-s['received']<=2.5 and self.steady()-s['stable_since']>=seconds)
