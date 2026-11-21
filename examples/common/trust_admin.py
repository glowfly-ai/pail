#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Operator-owned trust renewal preparation and externally signed staging.

No HTTP handler imports this CLI. No root private key is read here. Candidate
signing uses the existing offline signer, outside the observation process.
Application requires an installed management execution window; without one,
staging is supported but applying is explicitly unsupported, not a fake hold.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from ops_state import load_private,location,write_state,OpsStateError as RestartError
from trust_observation import inspect,helper,regular_owned,TrustError


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def profile_at(path):
    profile=load_private(path,field='--profile')
    if profile.get('schema_version')!=1 or profile.get('configured_mode')!='bundle':
        raise TrustError('RENEWAL_PROFILE_UNSUPPORTED')
    for field in ('target_id','deployment_id','root_fingerprint_sha256','helper_sha256'):
        if not isinstance(profile.get(field),str) or not profile[field]:raise TrustError('PROFILE_IDENTITY_REQUIRED')
    observation=inspect(profile)
    f=observation['file']
    # P024-M2: the reason the base was not confirmed travels with the refusal (a helper path behind a symlink used to
    # disappear behind this one word).
    if f['state']!='SIGNATURE_VALID_TIME_UNASSESSED':raise TrustError('BASE_SIGNATURE_NOT_CONFIRMED',f.get('field'),f.get('reason') or f['state'])
    return profile,observation


def prepare(root,operation,profile_path,consumers_path,issued,expires):
    profile,observed=profile_at(profile_path)
    consumers=regular_owned(consumers_path,32768,'--consumers')
    # Observations are supplied by the operator. These are planning inputs,
    # never substituted for fresh execution-window/runtime probes at apply.
    proposal=helper(profile,['prepare-renewal','--root-pub',profile['root_public_path'],
        '--bundle',profile['bundle_path'],'--consumers',str(consumers),
        '--issued-at',str(issued),'--expires-at',str(expires)])
    if proposal.get('base_sha256')!=observed['file']['bundle_sha256'] or proposal.get('root_fingerprint_sha256')!=profile['root_fingerprint_sha256']:
        raise TrustError('BASE_CHANGED_DURING_PLAN')
    plan=dict(schema_version=1,operation_id=operation,target_id=profile['target_id'],
        deployment_id=profile['deployment_id'],profile_digest=digest(profile),proposal=proposal,
        consumers_sha256=hashlib.sha256(consumers.read_bytes()).hexdigest(),
        # what is loaded-as-file today, so the operator sees current → requested before anything is signed (review item 11)
        current=dict(bundle_version=observed['file'].get('bundle_version'),expires_at_unix=observed['file'].get('expires_at_unix')),
        execution_window='NOT_OBSERVED',motion_action='NONE')
    state=dict(plan=plan,plan_digest=digest(plan),state='PLANNED',created_at=time.time(),
               runtime_state='NOT_OBSERVED',motion_action='NONE')
    path=location(root,operation,'--state')
    try:write_state(path,state,exclusive=True)
    except FileExistsError:
        old=load_private(path)
        if old.get('plan_digest')!=state['plan_digest']:raise TrustError('OPERATION_CONFLICT')
        return old
    return state


def stage(root,operation,profile_path,consumers_path,candidate_path,approved_digest):
    path=location(root,operation,'--state')
    fd=os.open(path.with_suffix('.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise TrustError('OPERATION_BUSY')
        return _stage(root,operation,profile_path,consumers_path,candidate_path,approved_digest)
    finally:os.close(fd)


def _stage(root,operation,profile_path,consumers_path,candidate_path,approved_digest):
    path=location(root,operation,'--state');state=load_private(path)
    if state['plan_digest']!=approved_digest:raise TrustError('APPROVAL_DIGEST_MISMATCH')
    if digest(state['plan'])!=approved_digest:raise TrustError('PLAN_CONTENT_CHANGED')
    profile,observed=profile_at(profile_path)
    plan=state['plan']
    if digest(profile)!=plan['profile_digest']:raise TrustError('PROFILE_CHANGED')
    if observed['file']['bundle_sha256']!=plan['proposal']['base_sha256']:raise TrustError('BASE_CHANGED')
    consumers=regular_owned(consumers_path,32768,'--consumers')
    if hashlib.sha256(consumers.read_bytes()).hexdigest()!=plan['consumers_sha256']:raise TrustError('CONSUMER_OBSERVATION_CHANGED')
    candidate=regular_owned(candidate_path,32768,'--candidate');raw=candidate.read_bytes();sha=hashlib.sha256(raw).hexdigest()
    # Validate the exact staged bytes, not a path another process may replace
    # between verification and copying. Immutable staging file is operation-bound.
    staged=path.with_name(operation+'-candidate-'+sha+'.json')
    fd=None
    try:
        fd=os.open(staged,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:fd=None;f.write(raw);f.flush();os.fsync(f.fileno())
    except FileExistsError:
        if regular_owned(staged,32768).read_bytes()!=raw:raise TrustError('STAGING_CONFLICT')
    finally:
        if fd is not None:os.close(fd)
    checked=helper(profile,['validate-renewal','--root-pub',profile['root_public_path'],
        '--bundle',profile['bundle_path'],'--consumers',str(consumers),'--candidate',str(staged)])
    if checked.get('candidate_sha256')!=sha or checked.get('base_sha256')!=plan['proposal']['base_sha256']:
        raise TrustError('STAGED_VALIDATION_MISMATCH')
    # A different, otherwise valid duration must not reuse the original approval.
    observed_candidate=helper(profile,['inspect-json','--root-pub',profile['root_public_path'],'--bundle',str(staged)])['file']
    payload=plan['proposal']['payload']
    for field in ('bundle_version','issued_at_unix','expires_at_unix'):
        if observed_candidate[field]!=payload[field]:raise TrustError('CANDIDATE_DIFFERS_FROM_APPROVED_PLAN')
    if state.get('candidate_sha256') not in (None,sha):raise TrustError('OPERATION_CONFLICT')
    state.update(state='STAGED_NOT_APPLIED',candidate_sha256=sha,staged_path=str(staged),
                 apply_supported=False,apply_reason='MANAGEMENT_EXECUTION_WINDOW_NOT_INSTALLED',motion_action='NONE')
    write_state(path,state);return state


def payload_target(path):
    """P024T-L3: where `plan-renewal --payload-out` writes. Stage 2 signs "the planned payload", which used to live
    only inside the operation's state file. Checked before anything is planned: absolute, no symlink, and new — an
    existing file is never replaced, it may be the payload of another plan."""
    p=Path(path)
    if not p.is_absolute():raise TrustError('ABSOLUTE_PATH_REQUIRED','--payload-out')
    for part in (p,*p.parents):
        if part.is_symlink():raise TrustError('SYMLINK_TARGET','--payload-out')
    if p.exists():raise TrustError('PAYLOAD_OUT_EXISTS','--payload-out')
    return p


def write_payload(path,payload):
    raw=(json.dumps(payload,sort_keys=True,indent=1)+'\n').encode()
    try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:raise TrustError('PAYLOAD_OUT_EXISTS','--payload-out') from None
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())


def plan_summary(state):
    """One line the operator reads before signing anything: target, current → requested version and validity, and
    how a renewal is applied (by the gate itself once the bundle is placed — a restart is the fallback — and by the
    Issuer at its next start; never by this tool). It never speaks of readiness to operate."""
    plan=state['plan'];req=plan['proposal']['payload'];cur=plan.get('current') or {}
    def iso(t):
        return datetime.datetime.fromtimestamp(int(t),datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') if t is not None else '?'
    current=('v%s expires %s'%(cur.get('bundle_version'),iso(cur.get('expires_at_unix')))) if cur.get('bundle_version') is not None else '(not in plan)'
    delta=''
    if cur.get('expires_at_unix') is not None:
        d=int(req['expires_at_unix'])-int(cur['expires_at_unix'])
        delta=' (%s%dh%dm)'%('+' if d>=0 else '-',abs(d)//3600,abs(d)%3600//60)
    return ('RENEWAL PLAN target=%s current %s → requested v%s expires %s%s; a gate applies a placed bundle by itself (a gate restart is the fallback) and the Issuer loads it at its next start; '
            'this tool does not apply; a loaded bundle does not mean ready to operate'
            %(plan.get('target_id'),current,req['bundle_version'],iso(req['expires_at_unix']),delta))


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action',choices=['inspect','plan-renewal','stage-renewal','apply-renewal','operation-status'])
    ap.add_argument('--profile');ap.add_argument('--state');ap.add_argument('--operation-id');ap.add_argument('--consumers')
    ap.add_argument('--candidate');ap.add_argument('--approved-plan-digest')
    ap.add_argument('--payload-out',help='plan-renewal: write the planned payload (the JSON the root signs in stage 2) to this NEW file')
    ap.add_argument('--issued-at',type=int);ap.add_argument('--expires-at',type=int)
    a=ap.parse_args()
    try:
        if a.action=='inspect':
            if not a.profile:raise TrustError('PROFILE_REQUIRED')
            result=inspect(load_private(a.profile,field='--profile'))
        else:
            if not a.state or not a.operation_id:raise TrustError('STATE_AND_OPERATION_REQUIRED')
            if a.payload_out and a.action!='plan-renewal':raise TrustError('PAYLOAD_OUT_ONLY_FOR_PLAN','--payload-out')
            if a.action=='operation-status':result=load_private(location(a.state,a.operation_id,'--state'))
            elif a.action=='apply-renewal':raise TrustError('MANAGEMENT_EXECUTION_WINDOW_NOT_INSTALLED; candidate remains staged')
            elif a.action=='plan-renewal':
                if not all((a.profile,a.consumers,a.issued_at,a.expires_at)):raise TrustError('PLAN_ARGUMENTS_REQUIRED')
                target=payload_target(a.payload_out) if a.payload_out else None
                result=prepare(a.state,a.operation_id,a.profile,a.consumers,a.issued_at,a.expires_at)
                if target is not None:write_payload(target,result['plan']['proposal']['payload'])
                print(plan_summary(result),file=sys.stderr)
            else:
                if not all((a.profile,a.consumers,a.candidate,a.approved_plan_digest)):raise TrustError('STAGE_ARGUMENTS_REQUIRED')
                result=stage(a.state,a.operation_id,a.profile,a.consumers,a.candidate,a.approved_plan_digest)
        print(json.dumps(result,sort_keys=True));return 0
    except (OSError,ValueError,KeyError,TypeError,TrustError,RestartError) as e:
        # Operational private paths are not emitted as diagnostic text. P024-M2: the item the refusal is about (a
        # profile field or a command argument) and, where one refusal follows from another, its cause, are.
        out=dict(state='REFUSED',reason=str(e) if isinstance(e,(TrustError,RestartError)) else type(e).__name__,motion_action='NONE')
        for key in ('field','cause'):
            if isinstance(getattr(e,key,None),str):out[key]=getattr(e,key)
        print(json.dumps(out));return 2

if __name__=='__main__':raise SystemExit(main())
