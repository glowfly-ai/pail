# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Observation-only bounded raw segments; never blackbox storage or robot control.

Rotation is performed by the existing trusted observation process. Pre-created
replacement slots preserve a less-privileged planner's ownership without a new
privileged service. Existing states are not silently converted or deleted.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
import time
import uuid

SEGMENT_BYTES=64*1024*1024
TOTAL_BYTES=1024*1024*1024
MAX_RECORD_BYTES=65536
ROLE=re.compile(r'[a-z][a-z0-9_-]{0,47}\Z')
class RetentionError(RuntimeError):pass


def _lock(fd, deadline=None):
    # Advisory locks are not scheduling deadlines. Refuse instead of waiting
    # indefinitely behind a stopped writer/manager; caller records unavailability.
    deadline=time.monotonic()+.2 if deadline is None else deadline
    while True:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return
        except BlockingIOError:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise RetentionError('RAW_LOCK_TIMEOUT')
            time.sleep(min(.001,remaining))


def _manifest(path, policy):
    state=_read(path)
    if not isinstance(state,dict) or state.get('schema_version')!=1 or state.get('policy_id')!=policy['policy_id']:
        raise RetentionError('RAW_MANIFEST_INVALID')
    archives=state.get('archives');slots=state.get('next_slot')
    if (not isinstance(archives,list) or len(archives)>128 or not isinstance(slots,dict)
        or set(slots)!=set(policy['roles']) or any(type(v) is not int or not 0<=v<=128 for v in slots.values())
        or state.get('status') not in ('READY','LIMIT_REACHED') or 'pending' not in state):
        raise RetentionError('RAW_MANIFEST_INVALID')
    pending=state['pending']
    if pending is not None and not isinstance(pending,dict):raise RetentionError('RAW_MANIFEST_INVALID')
    generations=set()
    for entry in archives+([pending] if pending is not None else []):
        if not isinstance(entry,dict):raise RetentionError('RAW_MANIFEST_INVALID')
        role=entry.get('role');gen=entry.get('generation');size=entry.get('bytes')
        if (not isinstance(role,str) or role not in policy['roles'] or not isinstance(gen,str) or not re.fullmatch('[0-9a-f]{32}',gen)
            or gen in generations or entry.get('name')!=role+'.'+gen+'.jsonl'
            or type(size) is not int or not 0<size<=policy['segment_bytes']):raise RetentionError('RAW_MANIFEST_INVALID')
        generations.add(gen)
        digest=entry.get('sha256')
        if digest is not None and (not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest)):
            raise RetentionError('RAW_MANIFEST_INVALID')
        if entry is pending:
            if entry.get('slot')!=role+'-'+str(slots[role])+'.empty':raise RetentionError('RAW_MANIFEST_INVALID')
            for key in ('old_identity','new_identity'):
                identity=entry.get(key)
                if not isinstance(identity,list) or len(identity)!=2 or any(type(v) is not int or v<0 for v in identity):
                    raise RetentionError('RAW_MANIFEST_INVALID')
    if sum(e['bytes'] for e in archives)>policy['archive_budget_bytes']:raise RetentionError('RAW_MANIFEST_INVALID')
    return state


def _read(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):raise RetentionError('RAW_METADATA_TYPE')
        raw=f.read(262145)
    if len(raw)>262144:raise RetentionError('RAW_METADATA_LIMIT')
    return json.loads(raw)


def _sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def _write(path,value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(raw)>262144:raise RetentionError('RAW_METADATA_LIMIT')
    fd,name=tempfile.mkstemp(prefix='.raw-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o644);f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(name,path);_sync_dir(path.parent)
    finally:
        if os.path.exists(name):os.unlink(name)


def policy(root):
    path=Path(root)/'raw-policy.json'
    if not path.exists():return None
    p=_read(path)
    if not isinstance(p,dict) or p.get('schema_version')!=1 or p.get('automatic_delete') is not False:raise RetentionError('RAW_POLICY_UNSUPPORTED')
    roles=p.get('roles');segment=p.get('segment_bytes');total=p.get('total_bytes')
    if not isinstance(roles,dict) or not 1<=len(roles)<=16 or any(not isinstance(r,str) or not ROLE.fullmatch(r) for r in roles):raise RetentionError('RAW_ROLES')
    if type(segment) is not int or not 1024*1024<=segment<=SEGMENT_BYTES:raise RetentionError('RAW_SEGMENT_LIMIT')
    if type(total) is not int or not (len(roles)+1)*segment<=total<=4*TOTAL_BYTES:raise RetentionError('RAW_TOTAL_LIMIT')
    if p.get('archive_budget_bytes')!=total-len(roles)*segment:raise RetentionError('RAW_BUDGET_RESERVATION')
    if type(p.get('manager_uid')) is not int or not 0<=p['manager_uid']<2**32:raise RetentionError('RAW_MANAGER_OWNER')
    if any(not isinstance(v,dict) or set(v)!={'uid','gid'} or any(type(n) is not int or not 0<=n<2**32 for n in v.values()) for v in roles.values()):raise RetentionError('RAW_OWNER')
    if p['archive_budget_bytes']//(segment*9//10)+1>128:raise RetentionError('RAW_SLOT_LIMIT')
    return p


def initialize(root,owners,manager_uid=10001,manager_gid=10001,segment_bytes=SEGMENT_BYTES,total_bytes=TOTAL_BYTES):
    """Called by the existing ownership preparer, BEFORE actors start."""
    root=Path(root)
    if root.is_symlink():raise RetentionError('RAW_ROOT_SYMLINK')
    root.mkdir(parents=True,exist_ok=True)
    if (root/'raw-policy.json').exists():
        existing=policy(root)
        if (existing['roles']!=owners or existing['manager_uid']!=manager_uid or
                existing['segment_bytes']!=segment_bytes or existing['total_bytes']!=total_bytes):
            raise RetentionError('RAW_POLICY_CHANGE_REQUIRES_MIGRATION')
        return existing
    if any(p.stat().st_size for p in root.glob('demo-*.jsonl')):raise RetentionError('EXISTING_RAW_REQUIRES_EXPLICIT_MIGRATION')
    if not owners or len(owners)>16 or any(not ROLE.fullmatch(r) for r in owners):raise RetentionError('RAW_ROLES')
    p=dict(schema_version=1,policy_id=uuid.uuid4().hex,roles=owners,manager_uid=manager_uid,
           segment_bytes=segment_bytes,total_bytes=total_bytes,archive_budget_bytes=total_bytes-len(owners)*segment_bytes,
           automatic_delete=False,scope='demo-<declared-role>.jsonl only; blackbox excluded')
    # Validate using the same bounds before creating ownership resources.
    if not 1024*1024<=segment_bytes<=SEGMENT_BYTES or not (len(owners)+1)*segment_bytes<=total_bytes<=4*TOTAL_BYTES:raise RetentionError('RAW_BUDGET')
    slots=p['archive_budget_bytes']//(segment_bytes*9//10)+1
    if slots>128:raise RetentionError('RAW_SLOT_LIMIT')
    archive=root/'raw-archive';pool=root/'raw-slots'
    for directory,mode in [(archive,0o755),(pool,0o700)]:
        directory.mkdir();directory.chmod(mode);os.chown(directory,manager_uid,manager_gid)
    slots=p['archive_budget_bytes']//(segment_bytes*9//10)+1
    state=dict(schema_version=1,policy_id=p['policy_id'],archives=[],next_slot={r:0 for r in owners},pending=None,status='READY')
    for role,owner in owners.items():
        if set(owner)!={'uid','gid'} or any(type(v) is not int or v<0 for v in owner.values()):raise RetentionError('RAW_OWNER')
        for target in [root/('demo-'+role+'.jsonl')]+[pool/(role+'-'+str(n)+'.empty') for n in range(slots)]:
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o644)
            try:
                if os.fstat(fd).st_size:raise RetentionError('RAW_SLOT_NOT_EMPTY')
                os.fchmod(fd,0o644);os.fchown(fd,owner['uid'],owner['gid'])
            finally:os.close(fd)
    for name,value in [('raw-policy.json',p),('raw-manifest.json',state)]:
        _write(root/name,value);os.chown(root/name,manager_uid,manager_gid)
    lock=root/'raw-archive.lock';fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.fchown(fd,manager_uid,manager_gid);os.close(fd)
    _sync_dir(root)
    return p


class ObservationWriter:
    def __init__(self,path):
        self.path=Path(path);self.root=self.path.parent;self.policy=policy(self.root)
        name=self.path.name
        self.role=name[5:-6] if name.startswith('demo-') and name.endswith('.jsonl') else ''
        if not ROLE.fullmatch(self.role):raise RetentionError('RAW_ROLE_PATH')
        if self.policy and self.role not in self.policy['roles']:raise RetentionError('RAW_ROLE_NOT_DECLARED')
    def append(self,event):
        raw=(json.dumps(event,allow_nan=False)+'\n').encode()
        if len(raw)>MAX_RECORD_BYTES:raise RetentionError('RAW_RECORD_TOO_LARGE')
        deadline=time.monotonic()+.2
        while True:
            try:fd=os.open(self.path,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_NONBLOCK|(0 if self.policy else os.O_CREAT),0o644)
            except FileNotFoundError:
                if not self.policy or time.monotonic()>=deadline:raise
                time.sleep(.001);continue
            try:
                _lock(fd,deadline)
                st=os.fstat(fd);current=self.path.lstat()
                if (st.st_dev,st.st_ino)!=(current.st_dev,current.st_ino):continue
                if not stat.S_ISREG(st.st_mode):raise RetentionError('RAW_SOURCE_TYPE')
                if self.policy and st.st_size+len(raw)>self.policy['segment_bytes']:raise RetentionError('RAW_LIMIT_REACHED')
                os.fchmod(fd,0o644)
                offset=0
                while offset<len(raw):offset+=os.write(fd,raw[offset:])
                return
            finally:os.close(fd)


class RotationManager:
    def __init__(self,root):
        self.root=Path(root);self.policy=policy(root);self.stop=threading.Event();self.thread=None
        if self.policy and os.geteuid()!=self.policy['manager_uid']:raise RetentionError('RAW_MANAGER_OWNER')
    def _finish(self,state):
        pending=state['pending'];role=pending['role']
        active=self.root/('demo-'+role+'.jsonl');archive=self.root/'raw-archive'/pending['name'];slot=self.root/'raw-slots'/pending['slot']
        def ident(p):
            st=p.lstat()
            if not stat.S_ISREG(st.st_mode):raise RetentionError('RAW_RECOVERY_TYPE')
            return [st.st_dev,st.st_ino]
        if not archive.exists():
            if not active.exists() or ident(active)!=pending['old_identity'] or active.stat().st_size!=pending['bytes']:raise RetentionError('RAW_RECOVERY_REQUIRED')
            os.rename(active,archive)
        if archive.stat().st_size!=pending['bytes']:raise RetentionError('RAW_ARCHIVE_SIZE_CHANGED')
        if not active.exists():
            if not slot.exists() or ident(slot)!=pending['new_identity']:raise RetentionError('RAW_RECOVERY_REQUIRED')
            os.rename(slot,active)
        if ident(active)!=pending['new_identity']:raise RetentionError('RAW_RECOVERY_REQUIRED')
        _sync_dir(self.root/'raw-archive');_sync_dir(self.root)
        state['archives'].append({k:pending[k] for k in ('role','name','bytes','generation')})
        state['next_slot'][role]+=1;state['pending']=None;state['status']='READY'
        _write(self.root/'raw-manifest.json',state)
    def poll(self):
        if not self.policy:return
        fd=os.open(self.root/'raw-archive.lock',os.O_RDWR|os.O_NOFOLLOW)
        try:
            _lock(fd)
            state=_manifest(self.root/'raw-manifest.json',self.policy)
            if state['policy_id']!=self.policy['policy_id']:raise RetentionError('RAW_POLICY_CHANGED')
            if state['pending']:
                # Serialize with a writer that survived the manager's failure.
                pending=state['pending']
                active=self.root/('demo-'+pending['role']+'.jsonl')
                archived=self.root/'raw-archive'/pending['name']
                source=archived if archived.exists() else active
                recovery_fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                try:
                    _lock(recovery_fd)
                    self._finish(state)
                finally:os.close(recovery_fd)
            for role in self.policy['roles']:
                path=self.root/('demo-'+role+'.jsonl');data=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                try:
                    _lock(data);st=os.fstat(data)
                    if st.st_size<self.policy['segment_bytes']*9//10:continue
                    if sum(a['bytes'] for a in state['archives'])+st.st_size>self.policy['archive_budget_bytes']:
                        if state['status']!='LIMIT_REACHED':state['status']='LIMIT_REACHED';_write(self.root/'raw-manifest.json',state)
                        continue
                    os.lseek(data,-1,os.SEEK_END)
                    if os.read(data,1)!=b'\n':raise RetentionError('RAW_PARTIAL_TAIL')
                    os.fsync(data)
                    number=state['next_slot'][role];slot=self.root/'raw-slots'/(role+'-'+str(number)+'.empty')
                    spare=slot.lstat()
                    if not stat.S_ISREG(spare.st_mode) or spare.st_size:raise RetentionError('RAW_SLOT_CHANGED')
                    gen=uuid.uuid4().hex
                    state['pending']=dict(role=role,name=role+'.'+gen+'.jsonl',generation=gen,slot=slot.name,
                        bytes=st.st_size,old_identity=[st.st_dev,st.st_ino],new_identity=[spare.st_dev,spare.st_ino])
                    _write(self.root/'raw-manifest.json',state);self._finish(state)
                finally:os.close(data)
        finally:os.close(fd)
        # Hash AFTER releasing append/rotation locks. This is observation work,
        # not a callback on the command path; never call a robot control API.
        for archive in state['archives']:
            if archive.get('sha256'):continue
            path=self.root/'raw-archive'/archive['name'];hasher=hashlib.sha256()
            rawfd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(rawfd,'rb') as f:
                before=os.fstat(f.fileno())
                for chunk in iter(lambda:f.read(1024*1024),b''):hasher.update(chunk)
                after=os.fstat(f.fileno())
            if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns) or after.st_size!=archive['bytes']:raise RetentionError('RAW_ARCHIVE_CHANGED')
            fd=os.open(self.root/'raw-archive.lock',os.O_RDWR|os.O_NOFOLLOW)
            try:
                _lock(fd);latest=_manifest(self.root/'raw-manifest.json',self.policy)
                for entry in latest['archives']:
                    if entry['generation']==archive['generation']:entry['sha256']=hasher.hexdigest()
                _write(self.root/'raw-manifest.json',latest)
            finally:os.close(fd)
    def start(self):
        if not self.policy:return self
        def run():
            backoff=.25
            while not self.stop.is_set():
                try:self.poll();backoff=.25
                except (OSError,ValueError,RetentionError) as e:
                    print('RAW_RETENTION_UNAVAILABLE:'+type(e).__name__,flush=True);backoff=min(30,max(1,backoff*2))
                self.stop.wait(backoff)
        self.thread=threading.Thread(target=run,name='raw-retention',daemon=True);self.thread.start();return self
    def close(self):
        self.stop.set()
        if self.thread:self.thread.join(2)
