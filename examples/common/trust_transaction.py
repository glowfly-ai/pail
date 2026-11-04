#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Renewal file transaction under an existing, operator-provisioned window.

The ordinary demo installs NO window provider and cannot call this as an HTTP
operation. A provider is a trusted management integration, not a boolean
checkbox or a user-supplied callback from a request. It must hold an exclusive
management execution window, keep every consumer stopped with auto-start
inhibited OR preserve verified local execution fences, and serialize release /
adopt / restart throughout the context. All writers of this bundle (including
gateway pulls and other renewals) must also be fenced. Exiting the context MUST
NOT release robot holds.
Unsupported deployments may plan and stage; they must not replace the bundle.
"""
from abc import ABC,abstractmethod
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from ops_state import load_private,location,write_state,fsync_dir
from trust_observation import TrustError,regular_owned,helper
from trust_admin import digest,profile_at

class RenewalWindowProvider(ABC):
    """Installed management code; implementations own authenticating all probes.

    open(plan, deadline_mono) returns a context manager. Its window.revalidate()
    returns fresh observations bound to the operation, target and plan digest,
    plus a stable execution_id/fence/hold_seq. No provider is bundled by default.
    This interface never exposes a release, start, restart or submit operation.
    """
    @abstractmethod
    def open(self,plan,deadline_mono):raise NotImplementedError


def _hash(path):return hashlib.sha256(regular_owned(path,32768).read_bytes()).hexdigest()


def _window_receipt(window,state):
    r=window.revalidate()
    plan=state['plan']
    for key,want in [('operation_id',plan['operation_id']),('target_id',plan['target_id']),
                     ('deployment_id',plan['deployment_id']),('plan_digest',state['plan_digest'])]:
        if r.get(key)!=want:raise TrustError('WINDOW_SCOPE_MISMATCH')
    if r.get('exclusive') is not True or r.get('authority_blocked') is not True:
        raise TrustError('EXECUTION_WINDOW_NOT_VERIFIED')
    if r.get('bundle_writers_fenced') is not True:raise TrustError('BUNDLE_WRITERS_NOT_FENCED')
    if r.get('release_policy')!='KEEP_HOLD' or r.get('automatic_start_inhibited') is not True:
        raise TrustError('RESUME_NOT_FENCED')
    for key in ('execution_id','fence'):
        if not isinstance(r.get(key),str) or not 1<=len(r[key])<=128:raise TrustError('WINDOW_IDENTITY_MISSING')
    if type(r.get('hold_seq')) is not int or r['hold_seq']<1:raise TrustError('WINDOW_SEQUENCE_MISSING')
    consumers=r.get('consumers')
    if not isinstance(consumers,list) or not consumers or len(consumers)>128:raise TrustError('CONSUMER_OBSERVATION_REQUIRED')
    expected={c['id']:c['loaded_generation'] for c in plan['proposal']['consumers']}
    observed={c.get('id'):c.get('loaded_generation') for c in consumers if isinstance(c,dict)}
    if len(observed)!=len(consumers) or observed!=expected:raise TrustError('CONSUMER_GENERATION_CHANGED')
    return r


def _validate_candidate(profile,state,consumers,root):
    fd,name=tempfile.mkstemp(prefix='.renewal-consumers-',dir=root)
    try:
        with os.fdopen(fd,'w') as f:json.dump(consumers,f,allow_nan=False);f.flush();os.fsync(f.fileno())
        result=helper(profile,['validate-renewal','--root-pub',profile['root_public_path'],
            '--bundle',profile['bundle_path'],'--consumers',name,'--candidate',state['staged_path']])
        if result.get('base_sha256')!=state['plan']['proposal']['base_sha256'] or result.get('candidate_sha256')!=state['candidate_sha256']:
            raise TrustError('RENEWAL_BYTES_CHANGED')
    finally:
        if os.path.exists(name):os.unlink(name)


def apply(root,operation,profile_path,approval,provider=None,budget=30):
    """Apply only under a verified management window; no service/motion command.

    approval is supplied by the local authorized management caller. Remote
    callers must use that manager's existing signed approval/authentication,
    never feed browser JSON directly to this function.
    """
    if not isinstance(provider,RenewalWindowProvider):raise TrustError('MANAGEMENT_EXECUTION_WINDOW_NOT_INSTALLED')
    if type(budget) is not int or not 1<=budget<=120:raise TrustError('INVALID_APPLY_BUDGET')
    path=location(root,operation);state=load_private(path);plan=state['plan']
    if digest(plan)!=state['plan_digest']:raise TrustError('PLAN_CONTENT_CHANGED')
    profile=load_private(profile_path)
    if digest(profile)!=plan['profile_digest']:raise TrustError('PROFILE_CHANGED')
    target=regular_owned(profile['bundle_path'],32768)
    lock_path=Path(root)/(hashlib.sha256(str(target).encode()).hexdigest()+'.apply.lock')
    lock=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    changed=False;temp=None;deadline=time.monotonic()+budget
    try:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise TrustError('RENEWAL_BUSY')
        state=load_private(path)
        if state.get('state') not in ('STAGED_NOT_APPLIED','APPLYING','OUTCOME_UNKNOWN','FILE_UPDATED'):
            raise TrustError('CANDIDATE_NOT_STAGED')
        current=_hash(target)
        if current==state['candidate_sha256']:
            # Reconciliation observes existing bytes only. It does not claim
            # which consumers loaded them or repeat a signed operation.
            if state['state']!='FILE_UPDATED':
                state.update(state='FILE_UPDATED',reconciled=True,runtime_state='NOT_OBSERVED',motion_action='NONE',hold_release='NOT_PERFORMED')
                write_state(path,state)
            return state
        if current!=plan['proposal']['base_sha256']:raise TrustError('BASE_CAS_CONFLICT')
        if state['state']=='FILE_UPDATED':raise TrustError('APPLIED_FILE_CHANGED')
        def check_approval():
            if time.monotonic()>=deadline:raise TrustError('APPLY_DEADLINE_EXCEEDED')
            if (approval.get('plan_digest')!=state['plan_digest'] or approval.get('operation_id')!=operation
                    or approval.get('target_id')!=plan['target_id'] or approval.get('revoked') is not False):
                raise TrustError('APPROVAL_SCOPE_OR_REVOCATION')
            expiry=approval.get('expires_at_unix')
            if type(expiry) not in (int,float) or not time.time()<expiry<=time.time()+3600:
                raise TrustError('APPROVAL_EXPIRED_OR_UNBOUNDED')
        check_approval()
        profile_at(profile_path)
        if _hash(state['staged_path'])!=state['candidate_sha256']:raise TrustError('CANDIDATE_CHANGED')
        with provider.open(state,deadline) as window:
            initial=_window_receipt(window,state)
            _validate_candidate(profile,state,initial['consumers'],root)
            raw=regular_owned(state['staged_path'],32768).read_bytes()
            if hashlib.sha256(raw).hexdigest()!=state['candidate_sha256']:raise TrustError('CANDIDATE_CHANGED')
            # Preserve the actual baseline before an effect, not a stale copy.
            backup=Path(root)/(operation+'-baseline-'+current+'.json')
            if not backup.exists():
                old=target.read_bytes()
                if hashlib.sha256(old).hexdigest()!=current:raise TrustError('BASE_CAS_CONFLICT')
                fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as f:f.write(old);f.flush();os.fsync(f.fileno())
                fsync_dir(root)
            elif _hash(backup)!=current:raise TrustError('BACKUP_CONFLICT')
            fd,temp=tempfile.mkstemp(prefix='.trust-renewal-',dir=target.parent)
            st=target.stat()
            with os.fdopen(fd,'wb') as f:
                os.fchmod(f.fileno(),st.st_mode&0o777)
                os.fchown(f.fileno(),st.st_uid,st.st_gid)
                f.write(raw);f.flush();os.fsync(f.fileno())
            latest=_window_receipt(window,state)
            if any(latest[k]!=initial[k] for k in ('execution_id','fence','hold_seq')):raise TrustError('WINDOW_CHANGED')
            _validate_candidate(profile,state,latest['consumers'],root)
            check_approval()
            if _hash(target)!=current:raise TrustError('BASE_CAS_CONFLICT')
            state.update(state='APPLYING',backup_sha256=current,window_execution_id=initial['execution_id'],
                         hold_seq=initial['hold_seq'],hold_release='NOT_PERFORMED',motion_action='NONE')
            write_state(path,state)
            os.replace(temp,target);temp=None;changed=True
            fsync_dir(target.parent)
            state.update(state='FILE_UPDATED',runtime_state='NOT_OBSERVED',reload='RELOAD_REQUIRED_OR_PROBE_NEEDED',motion_action='NONE')
            write_state(path,state)
            return state
    except Exception:
        if changed:
            state.update(state='OUTCOME_UNKNOWN',runtime_state='NOT_OBSERVED',motion_action='NONE',hold_release='NOT_PERFORMED')
            write_state(path,state)
        raise
    finally:
        if temp and os.path.exists(temp):os.unlink(temp)
        os.close(lock)
