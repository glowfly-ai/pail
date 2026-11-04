#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Read-only signed trust metadata; never a replacement for runtime admission.

Configuration is supplied by the local operator, not by browser parameters.
The existing offline signer performs signature verification. No root key is
read by this module and no Docker/process/motion operation is performed.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time
import threading
import copy

class TrustError(RuntimeError):pass

def regular_owned(path,max_bytes=None):
    p=Path(path)
    if not p.is_absolute():raise TrustError('ABSOLUTE_PATH_REQUIRED')
    for part in (p,*p.parents):
        if part.is_symlink():raise TrustError('SYMLINK_TARGET')
    st=p.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0,os.geteuid()) or st.st_mode&0o022:
        raise TrustError('UNTRUSTED_FILE_OWNER_OR_MODE')
    if max_bytes is not None and st.st_size>max_bytes:raise TrustError('INPUT_TOO_LARGE')
    return p

def checked_helper(profile):
    p=regular_owned(profile['helper_path'])
    if hashlib.sha256(p.read_bytes()).hexdigest()!=profile['helper_sha256']:
        raise TrustError('HELPER_CHANGED')
    return p

def helper(profile,args,stop=None):
    # Trust metadata inputs are <=32 KiB; this offline, pinned program has no
    # network access of its own. Bound elapsed time and refuse oversized output.
    p=checked_helper(profile)
    process=subprocess.Popen([str(p),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,start_new_session=True)
    streams=selectors.DefaultSelector();out=bytearray();err=bytearray();deadline=time.monotonic()+10
    try:
        for pipe,label in ((process.stdout,'out'),(process.stderr,'err')):
            os.set_blocking(pipe.fileno(),False);streams.register(pipe,selectors.EVENT_READ,label)
        while streams.get_map():
            if stop is not None and stop.is_set():raise TrustError('INSPECTION_CANCELLED')
            if time.monotonic()>=deadline:raise TrustError('HELPER_DEADLINE_EXCEEDED')
            for key,_ in streams.select(min(.1,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fd,4096)
                if not chunk:streams.unregister(key.fileobj);continue
                target=out if key.data=='out' else err;target.extend(chunk)
                if len(target)>65536:raise TrustError('HELPER_OUTPUT_LIMIT')
        returncode=process.wait(timeout=max(.01,deadline-time.monotonic()))
    finally:
        streams.close()
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=1)
        process.stdout.close();process.stderr.close()
    try:value=json.loads(out)
    except (ValueError,TypeError):raise TrustError('HELPER_RESPONSE_INVALID') from None
    if not isinstance(value,dict):raise TrustError('HELPER_RESPONSE_INVALID')
    if returncode!=0:
        # A failed inspection is display data, never successful preparation or
        # candidate validation. Keep the negative state and the CLI's refusal.
        if not (args[0]=='inspect-json' and value.get('schema_version')==1 and
                value.get('file',{}).get('state') in ('INVALID_SIGNATURE','INVALID_METADATA')):
            raise TrustError('TRUST_HELPER_REJECTED')
    return value

def inspect(profile,stop=None):
    target=profile.get('target_id')
    if not isinstance(target,str) or not 1<=len(target)<=128:raise TrustError('TARGET_ID_INVALID')
    mode=profile.get('configured_mode')
    result=dict(schema_version=1,target_id=target,deployment_id=profile.get('deployment_id'),
                configured_mode=mode,configuration_basis='OPERATOR_MANIFEST',clock_basis='UNVERIFIED',remaining_s=None,
                runtime=dict(state='NOT_OBSERVED',components=[]),renewal=dict(allowed=False,reasons=['APPROVED_PLAN_AND_EXECUTION_FENCE_REQUIRED']))
    if mode=='unsigned-dev':
        result['file']=dict(state='UNSIGNED_DEVELOPMENT',expiry_applicability='NOT_APPLICABLE')
        result['renewal']=dict(allowed=False,reasons=['SIGNED_BUNDLE_REQUIRED']);return result
    if mode!='bundle':
        result['file']=dict(state='UNSUPPORTED');return result
    try:
        bundle=regular_owned(profile['bundle_path'],32768);root=regular_owned(profile['root_public_path'],4096)
        observed=helper(profile,['inspect-json','--root-pub',str(root),'--bundle',str(bundle)],stop)
        if observed.get('schema_version')!=1:raise TrustError('TRUST_SCHEMA_UNSUPPORTED')
        f=observed['file']
        if f['root_fingerprint_sha256']!=profile['root_fingerprint_sha256']:raise TrustError('ROOT_FINGERPRINT_MISMATCH')
        # JSON numbers lose uint64 precision in a browser. Keep the numeric
        # helper contract and add exact decimal display metadata.
        version=f.get('bundle_version')
        if type(version) is int and 0<version<2**64:
            f=dict(f,bundle_version_decimal=str(version))
        result['file']=f
    except FileNotFoundError:result['file']=dict(state='MISSING')
    except (OSError,TrustError,KeyError,subprocess.TimeoutExpired):
        result['file']=dict(state='UNOBSERVED',reason='TRUST_INSPECTION_FAILED')
    return result


def unconfigured_observation(reason='NO_APPROVED_TARGET_PROFILE'):
    return dict(schema_version=1,configured_mode='UNOBSERVED',file=dict(state='UNOBSERVED'),
                runtime=dict(state='NOT_OBSERVED',components=[]),clock_basis='UNVERIFIED',remaining_s=None,
                renewal=dict(allowed=False,reasons=[reason]))


def launcher_observation(mode,bundle_path=None,root_pub_path=None,now=time.time):
    """What the launcher itself knows about this run's trust, served when no operator profile is configured
    (preview.40 review item 11). It is declared, not verified: this console checks no signature — the gate and the
    Issuer do, at load — and an operator profile (configuration_basis OPERATOR_MANIFEST) replaces it when configured."""
    result=dict(schema_version=1,configuration_basis='LAUNCHER',configured_mode=mode,clock_basis='HOST_UNVERIFIED',remaining_s=None,
                runtime=dict(state='NOT_OBSERVED',components=[]),renewal=dict(allowed=False,reasons=['APPROVED_PLAN_AND_EXECUTION_FENCE_REQUIRED']),
                scope='read-only metadata declared by the launcher; not authorization, not signature verification, not runtime-load proof')
    if mode=='unsigned-dev':
        result['file']=dict(state='UNSIGNED_DEVELOPMENT',expiry_applicability='NOT_APPLICABLE')
        result['meaning']='development trust: not judged as signature trust; bundle expiry does not apply'
        result['renewal']=dict(allowed=False,reasons=['SIGNED_BUNDLE_REQUIRED']);return result
    if mode!='bundle':
        result['file']=dict(state='UNSUPPORTED');return result
    try:
        raw=Path(bundle_path).read_bytes();env=json.loads(raw)
        payload=json.loads(base64.b64decode(env['payload_b64']))
        root=base64.b64decode(Path(root_pub_path).read_text().strip())
        keys=[dict(key_id=k['key_id'],roles=[k['role']],public_key_fingerprint=hashlib.sha256(base64.b64decode(k['ed25519_public_key_base64'])).hexdigest())
              for k in payload.get('keys',[])]
        version=payload['bundle_version']
        result['file']=dict(state='DECLARED_SIGNATURE_UNVERIFIED',root_key_id=env.get('root_key_id'),root_fingerprint_sha256=hashlib.sha256(root).hexdigest(),
                            bundle_sha256=hashlib.sha256(raw).hexdigest(),bundle_version=version,bundle_version_decimal=str(version),
                            issued_at_unix=payload['issued_at_unix'],expires_at_unix=payload['expires_at_unix'],keys=keys)
        result['remaining_s']=int(payload['expires_at_unix']-now())
        result['meaning']='signed bundle declared by the launcher; signature not verified by this console (the gate and the Issuer verify it at load)'
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        result['file']=dict(state='UNOBSERVED',reason='BUNDLE_UNREADABLE')
    return result


class TrustObservationCache:
    """Read-only worker; UI reads a snapshot and never waits for signer/IO."""
    def __init__(self,profile_path,interval=5):
        from ops_state import load_private
        self.path=Path(profile_path).absolute()
        self.profile=load_private(self.path)
        self.profile_hash=hashlib.sha256(self.path.read_bytes()).hexdigest()
        if not isinstance(self.profile,dict):raise TrustError('PROFILE_INVALID')
        if type(interval) not in (int,float) or not .1<=interval<=60:raise TrustError('OBSERVATION_INTERVAL')
        self.interval=interval;self._lock=threading.Lock();self._stop=threading.Event()
        self._value=unconfigured_observation('INSPECTION_PENDING')
        self._thread=threading.Thread(target=self._run,name='pail-trust-observer',daemon=True)
        self._thread.start()
    def _run(self):
        from ops_state import load_private
        while not self._stop.is_set():
            try:
                load_private(self.path)
                if hashlib.sha256(self.path.read_bytes()).hexdigest()!=self.profile_hash:
                    value=unconfigured_observation('PROFILE_CHANGED_RECONFIGURATION_REQUIRED')
                else:value=inspect(self.profile,self._stop)
            except Exception:value=unconfigured_observation('TRUST_INSPECTION_FAILED')
            value['observed_at_unix']=time.time()
            value['scope']='read-only metadata; not authorization or runtime-load proof'
            with self._lock:self._value=value
            self._stop.wait(self.interval)
    def snapshot(self):
        with self._lock:return copy.deepcopy(self._value)
    def close(self):
        self._stop.set();self._thread.join(2)
        return not self._thread.is_alive()
