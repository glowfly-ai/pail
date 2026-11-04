# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Local software-fleet lifecycle. Operator integrity, not a hostile-admin sandbox."""
import contextlib
import copy
import datetime
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import threading
import time
import uuid

from fleet import FleetError, atomic_json

STATES = {'PREPARING','STARTING','READY_IDLE','RUNNING_DEMO','QUIESCING',
          'STOP_REQUESTED','STOPPING','STOPPED','RESUME_CHECK','RECOVERY_REQUIRED'}


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def fingerprint_files(paths):
    out={}
    for raw in sorted(set(map(str,paths))):
        p=Path(raw)
        if p.is_symlink() or not p.exists():raise FleetError('PIN_PATH_INVALID')
        files=[p] if p.is_file() else sorted(p.rglob('*'))
        for f in files:
            if f.is_symlink():raise FleetError('PIN_SYMLINK')
            if '__pycache__' in f.parts:continue
            if f.is_file():out[str(f)]=sha(f)
    return out


def check_expiry(enrollment,now=None):
    if not enrollment:return
    now=now or datetime.datetime.now(datetime.timezone.utc)
    for cert in enrollment['certificates']:
        until=datetime.datetime.fromisoformat(cert['not_after'])
        if until.tzinfo is None or until <= now:raise FleetError('TLS_CREDENTIAL_EXPIRED')


class Lifecycle:
    def __init__(self,state):
        raw=Path(state)
        if raw.is_symlink():raise FleetError('STATE_SYMLINK')
        self.root=raw.resolve();self.control=self.root/'control';self.lock=None
        self.mu=threading.RLock();self.meta=None;self.last_seal=None

    def acquire(self,create=True):
        if (not self.control.is_dir() or self.control.is_symlink() or self.control.stat().st_uid!=os.getuid()
                or stat.S_IMODE(self.control.stat().st_mode)!=0o700):raise FleetError('CONTROL_DIRECTORY')
        if self.lock is not None:return
        p=self.control/'supervisor.lock'
        if p.is_symlink():raise FleetError('LOCK_SYMLINK')
        if not create and not p.exists():raise FleetError('CONTROLLER_LOCK_MISSING')
        fd=os.open(p,os.O_RDWR|(os.O_CREAT if create else 0)|os.O_NOFOLLOW,0o600)
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd);raise FleetError('CONTROLLER_ACTIVE') from None
        self.lock=fd

    def release(self):
        if self.lock is not None:os.close(self.lock);self.lock=None

    def key(self):
        p=self.control/'manifest.key'
        if self.control.is_symlink() or p.is_symlink() or stat.S_IMODE(p.stat().st_mode)!=0o600 or p.stat().st_uid!=os.getuid():
            raise FleetError('MANIFEST_KEY_PERMISSIONS')
        value=p.read_bytes()
        if len(value)!=32:raise FleetError('MANIFEST_KEY_INVALID')
        return value

    def initialize(self,meta):
        self.acquire()
        p=self.control/'manifest.key'
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(os.urandom(32));f.flush();os.fsync(f.fileno())
        self.meta=dict(meta,schema_version=2,controller_instance_id=str(uuid.uuid4()),
                       lifecycle_state='PREPARING',status='PREPARING',last_operation_id=str(uuid.uuid4()),
                       managed_containers={},managed_volumes={},managed_networks={})
        self.write()

    def read(self):
        p=self.root/'fleet-run.json'
        if p.is_symlink():raise FleetError('MANIFEST_SYMLINK')
        doc=json.loads(p.read_text())
        if doc.get('schema_version')!=2:raise FleetError('EXPLICIT_ADOPTION_REQUIRED')
        seal=doc.pop('integrity',None)
        if not isinstance(seal,str) or not hmac.compare_digest(seal,hmac.new(self.key(),canonical(doc),hashlib.sha256).hexdigest()):
            raise FleetError('MANIFEST_INTEGRITY')
        if doc.get('lifecycle_state') not in STATES or doc.get('state_root')!=str(self.root):raise FleetError('MANIFEST_STATE')
        self.meta=doc;self.last_seal=seal;return doc

    def write(self):
        if self.lock is None:raise FleetError('CONTROLLER_LOCK_REQUIRED')
        with self.mu:
            if self.last_seal is not None:
                current=json.loads((self.root/'fleet-run.json').read_text());seal=current.pop('integrity',None)
                if seal!=self.last_seal or seal!=hmac.new(self.key(),canonical(current),hashlib.sha256).hexdigest():
                    raise FleetError('MANIFEST_CHANGED_WHILE_ACTIVE')
            body=dict(self.meta);body.pop('integrity',None)
            body['integrity']=hmac.new(self.key(),canonical(body),hashlib.sha256).hexdigest()
            atomic_json(self.root/'fleet-run.json',body)
            self.last_seal=body['integrity']

    def transition(self,state,**detail):
        if state not in STATES:raise FleetError('LIFECYCLE_STATE')
        edges={'PREPARING':{'STARTING'},'STARTING':{'READY_IDLE'},
               'READY_IDLE':{'RUNNING_DEMO','QUIESCING'},'RUNNING_DEMO':{'QUIESCING','READY_IDLE'},
               'QUIESCING':{'READY_IDLE','RUNNING_DEMO'},'STOP_REQUESTED':{'STOPPING'},
               'STOPPING':{'STOPPED'},'STOPPED':{'RESUME_CHECK'},'RESUME_CHECK':{'STARTING'},
               'RECOVERY_REQUIRED':{'RESUME_CHECK'}}
        with self.mu:
            old=self.meta['lifecycle_state']
            if state!=old and state not in edges[old] and state not in ('RECOVERY_REQUIRED','STOP_REQUESTED'):
                raise FleetError('ILLEGAL_LIFECYCLE_TRANSITION')
            self.meta.update(lifecycle_state=state,status=state,operation_detail=detail)
            self.write()

    def verify_pins(self, expiry=True):
        if not all(k in self.meta for k in ('compose_sha256','file_pins','identity_pins','controller_source')):
            raise FleetError('MANIFEST_INCOMPLETE_RECOVERY_REQUIRED')
        if self.meta['compose_sha256']!=sha(self.root/'fleet.compose.json'):raise FleetError('COMPOSE_CHANGED')
        for name,want in self.meta.get('file_pins',{}).items():
            p=Path(name)
            if p.is_symlink() or not p.is_file() or sha(p)!=want:raise FleetError('PIN_CHANGED: '+p.name)
        if expiry:check_expiry(self.meta.get('tls_enrollment'))


def volume_projection(v):
    return copy.deepcopy({k:v.get(k) for k in ('Name','Driver','Mountpoint','CreatedAt','Options','Labels','Scope')})


def container_projection(c):
    # Excludes execution timestamps/PIDs: stopped services may restart with the SAME ID.
    return {'id':c['Id'],'image':c['Image'],'networks':sorted(c.get('NetworkSettings',{}).get('Networks',{})),'labels':copy.deepcopy(c['Config'].get('Labels')),
            'mounts':sorted([{k:m.get(k) for k in ('Type','Name','Source','Destination','RW')} for m in c.get('Mounts',[])],key=lambda m:m['Destination'])}


def network_member_owned(key,entry,owned_ids,owned_names):
    """Is one member of a fleet network ours? A container id we own is. While a container
    restarts, Docker lists it under a transitional key `ep-<endpoint id>` that carries the
    container's own name (measured 2026-10-01): that member is ours only
    when the key has exactly that form and the name is one of our containers. Container names
    are unique per host, so a foreign container cannot borrow one of ours while ours exists."""
    if key in owned_ids:return True
    entry=entry or {}
    return (isinstance(key,str) and key.startswith('ep-') and key[3:]==entry.get('EndpointID')
            and (entry.get('Name') or '').lstrip('/') in owned_names)


def validate_inventory(meta,containers,volumes,networks,allow_partial=False):
    services=set(meta['service_names']);seen={}
    for c in containers:
        labels=c['Config'].get('Labels') or {};name=labels.get('com.docker.compose.service')
        expected_image = meta.get('issuer_image', meta['image']) if name == 'issuer' else meta['image']
        if (name not in services or name in seen or labels.get('com.docker.compose.project')!=meta['project']
                or labels.get('org.pail.run')!=meta['run_id'] or c['Image']!=expected_image):
            raise FleetError('FOREIGN_CONTAINER')
        seen[name]=container_projection(c)
        pinned=meta.get('managed_containers',{}).get(name)
        if pinned is not None and pinned!=seen[name]:raise FleetError('CONTAINER_CHANGED')
    if not allow_partial and set(seen)!=services:raise FleetError('CONTAINER_SET_CHANGED')
    if not set(meta.get('managed_containers',{})) <= set(seen):raise FleetError('PINNED_CONTAINER_MISSING')
    got={}
    for v in volumes:
        labels=v.get('Labels') or {};key=labels.get('com.docker.compose.volume')
        if (key not in meta['volume_names'] or key in got or labels.get('org.pail.run')!=meta['run_id']
                or labels.get('com.docker.compose.project')!=meta['project']):raise FleetError('FOREIGN_VOLUME')
        got[key]=volume_projection(v)
    if set(got)!=set(meta['volume_names']):raise FleetError('VOLUME_SET_CHANGED')
    if meta.get('managed_volumes') and got!=meta['managed_volumes']:raise FleetError('VOLUME_CHANGED')
    nets={}
    owned_ids={c['Id'] for c in containers}
    owned_names={(c.get('Name') or '').lstrip('/') for c in containers}-{''}
    for n in networks:
        labels=n.get('Labels') or {};key=labels.get('com.docker.compose.network')
        if (key not in meta['network_names'] or key in nets or labels.get('com.docker.compose.project')!=meta['project']
                or any(not network_member_owned(k,v,owned_ids,owned_names) for k,v in (n.get('Containers') or {}).items())):
            raise FleetError('FOREIGN_NETWORK')
        nets[key]=n['Id']
    if meta.get('managed_networks') and nets!=meta['managed_networks']:raise FleetError('NETWORK_CHANGED')
    if not allow_partial and set(nets)!=set(meta['network_names']):raise FleetError('NETWORK_SET_CHANGED')
    return seen,got,nets


def inspect(state):
    life=Lifecycle(state)
    raw=json.loads((life.root/'fleet-run.json').read_text())
    if raw.get('schema_version')!=2:
        return {'schema_version':raw.get('schema_version'),'status':'EXPLICIT_ADOPTION_REQUIRED','read_only':True}
    doc=life.read();active=False;problem=None
    try:life.acquire(create=False)
    except FleetError as e:
        if str(e)=='CONTROLLER_ACTIVE':active=True
        elif str(e)=='CONTROLLER_LOCK_MISSING':problem='CONTROLLER_LOCK_MISSING'
        else:raise
    finally:life.release()
    state=doc['lifecycle_state']
    return {'schema_version':2,'run_id':doc['run_id'],'project':doc['project'],
            'lifecycle_state':state if not problem and (active or state in ('STOPPED','RECOVERY_REQUIRED')) else 'RECOVERY_REQUIRED',
            'recorded_state':state,'controller_active':active,'controller_instance_id':doc['controller_instance_id'],
            'runtime_checked':False,'reason':problem or (None if active or state in ('STOPPED','RECOVERY_REQUIRED') else 'INTERRUPTED'), 'read_only':True}


def control_path(state,create=False):
    # macOS AF_UNIX has a short path limit; arbitrary long state paths cannot
    # be used directly. This per-user private directory has no network exposure.
    parent=Path('/tmp')/('pail-ctl-'+str(os.getuid()))
    if create:parent.mkdir(mode=0o700,exist_ok=True)
    if (parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid!=os.getuid()
            or stat.S_IMODE(parent.stat().st_mode)!=0o700):raise FleetError('CONTROL_SOCKET_DIRECTORY')
    return parent/(hashlib.sha256(str(Path(state).resolve()).encode()).hexdigest()[:32]+'.sock')


class ControlServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads=True


def serve_control(fleet,shutdown):
    path=control_path(fleet.state,create=True)
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode):raise FleetError('CONTROL_SOCKET_CONFLICT')
        path.unlink()  # Only while holding the exclusive supervisor lock.
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.request.settimeout(120)
            stop_requested=False
            try:
                raw=self.rfile.readline(4097)
                if len(raw)>4096:raise FleetError('CONTROL_SIZE')
                req=json.loads(raw)
                if req!={'action':'stop','run_id':fleet.run_id}:raise FleetError('CONTROL_REQUEST')
                stop_requested=True
                fleet.stop_services()
                out={'status':fleet.meta['lifecycle_state']}
            except Exception as e:out={'error':str(e),'status':'RECOVERY_REQUIRED'}
            self.wfile.write(canonical(out)+b'\n');self.wfile.flush()
            if stop_requested:shutdown()
    server=ControlServer(str(path),Handler);path.chmod(0o600)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    return server


def request_stop(state):
    info=inspect(state)
    if not info.get('controller_active'):return None
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(120);s.connect(str(control_path(state)))
        s.sendall(canonical({'action':'stop','run_id':info['run_id']})+b'\n')
        out=b''
        while not out.endswith(b'\n'):
            chunk=s.recv(4096)
            if not chunk or len(out)>8192:raise FleetError('STOP_ACK_UNKNOWN')
            out+=chunk
    result=json.loads(out)
    if result.get('status')!='STOPPED':raise FleetError('STOP_RECOVERY_REQUIRED')
    deadline=time.monotonic()+5
    while inspect(state)['controller_active']:
        if time.monotonic()>=deadline:raise FleetError('CONTROLLER_RELEASE_PENDING')
        time.sleep(.05)
    return result
