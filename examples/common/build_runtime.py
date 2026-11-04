# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Explicit bounded builds and local immutable runtime receipts. No implicit pull/build."""
import fcntl
import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

CPU_PERIOD=100000
CPU_QUOTA=200000
MEMORY=3*1024**3
JOBS=2

class BuildRequired(ValueError):pass

def call(argv,log=None,timeout=180):
    if log:
        with Path(log).open('a') as out:
            p=subprocess.run(argv,stdout=out,stderr=subprocess.STDOUT,text=True,timeout=timeout)
    else:p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise BuildRequired('BUILD_REQUIRED: operation failed; '+('see '+str(log) if log else ' '.join(argv[:3])))
    return p

def resolve_image(reference):
    if not reference:raise BuildRequired('BUILD_REQUIRED: run explicit demo.py build or provide a prepared image')
    try:
        p=call(['docker','image','inspect',reference,'--format','{{.Id}}'])
        digest=p.stdout.strip()
    except (OSError,subprocess.SubprocessError,BuildRequired):
        raise BuildRequired('BUILD_REQUIRED: prepared image unavailable locally; run demo.py build') from None
    if not re.fullmatch(r'sha256:[a-f0-9]{64}',digest):raise BuildRequired('BUILD_REQUIRED: invalid local image digest')
    return digest

def source_entries(root):
    rows=[]
    for p in sorted(Path(root).rglob('*')):
        rel=p.relative_to(root)
        if any(x in ('.git','__pycache__','target','.venv') for x in rel.parts) or not p.is_file() or p.is_symlink():continue
        if rel.parts[:2] == ('cloud', 'bin') or p.name == '.DS_Store':continue
        if str(rel).startswith('spec/reports/') or str(rel)=='adapters/microduck/compatibility.json' or p.suffix=='.log':continue
        rows.append({'path':str(rel),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
    return rows

def source_digest(root):
    return hashlib.sha256(json.dumps(source_entries(root),sort_keys=True,separators=(',',':')).encode()).hexdigest()

def source_mismatch(root):
    """Name changed inputs against the delivery lock, never suggest rebuilding blindly."""
    detail = []
    try:
        expected = json.loads((Path(root).parent/'images.lock.json').read_text())['source_files']
        actual = {r['path']:r['sha256'] for r in source_entries(root)}
        for path in sorted(set(expected)|set(actual)):
            if actual.get(path) != expected.get(path):
                detail.append(path + (' (added)' if path not in expected else ' (missing)' if path not in actual else ' (modified)'))
    except (OSError,ValueError,KeyError):
        detail = ['source receipt unavailable']
    return ('SOURCE_CHANGED: ' + ', '.join(detail[:8]) +
            '. Supplied images require their original inputs. Restore a pristine delivery copy; '
            'keep edits/builds in a working copy. Rebuilding custom images is a separate online workflow.')

def default_record(kind):
    return Path.home()/'.cache/pail-demo'/kind/'prepared.json'

def atomic_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+uuid.uuid4().hex)
    with temp.open('x') as f:json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
    temp.chmod(0o600);temp.replace(path)

def load_record(path,kind,root):
    try:
        path=Path(path)
        if path.is_symlink():raise ValueError('symlink')
        data=json.loads(path.read_text())
        if data['schema_version']!=1 or data['kind']!=kind or data['source_digest']!=source_digest(root):raise ValueError('source')
        if set(data['images'])!=({'runtime'} if kind=='microduck' else {'cloud','gate'}):raise ValueError('image set')
        images={name:resolve_image(ref) for name,ref in data['images'].items()}
        if images!=data['images']:raise ValueError('image changed')
        native=data.get('dashboard')
        if native:
            p=Path(native['path'])
            if p.is_symlink() or native['host']!=[platform.system(),platform.machine()] or hashlib.sha256(p.read_bytes()).hexdigest()!=native['sha256']:raise ValueError('native artifact')
        return data
    except (ValueError,KeyError,OSError,TypeError):
        raise BuildRequired('BUILD_REQUIRED: prepared receipt missing, stale, or invalid; run explicit demo.py build') from None

class Builder:
    """Disposable Buildx docker-container worker; never switches the default builder."""
    def __init__(self,directory):
        self.directory=Path(directory);self.name='pail-mobs-auto-builder-'+uuid.uuid4().hex[:12]
        self.container=None;self.created=False;self.samples=[];self.lock=None;self.stop=threading.Event();self.sampler=None
    def __enter__(self):
        lockdir=Path.home()/'.cache/pail-demo'
        lockdir.mkdir(parents=True,exist_ok=True)
        path=lockdir/'builder.lock'
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        self.lock=os.fdopen(fd,'r+')
        try:fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close();self.lock=None;raise BuildRequired('BUILD_ALREADY_ACTIVE: no second PAIL builder started')
        try:
            active=call(['docker','ps','-q','--filter','name=buildx_buildkit_pail-mobs-auto-builder-']).stdout.strip()
            if active:raise BuildRequired('BUILD_ALREADY_ACTIVE: prior PAIL builder requires inspection')
            self.directory.mkdir(parents=True,exist_ok=True)
            self.config=self.directory/'buildkitd.toml'
            self.config.write_text('[worker.oci]\n  max-parallelism = 2\n')
            self.log=self.directory/'builder.log'
            call(['docker','buildx','create','--name',self.name,'--driver','docker-container',
                  '--driver-opt','memory=3g,memory-swap=3g,cpu-period=100000,cpu-quota=200000',
                  '--buildkitd-config',str(self.config)],self.log)
            self.created=True
            call(['docker','buildx','inspect',self.name,'--bootstrap'],self.log,timeout=300)
            info=json.loads(call(['docker','inspect','buildx_buildkit_'+self.name+'0']).stdout)[0]
            self.container=info['Id'];cfg=info['HostConfig']
            if cfg.get('CpuPeriod')!=CPU_PERIOD or cfg.get('CpuQuota')!=CPU_QUOTA or cfg.get('Memory')!=MEMORY or cfg.get('MemorySwap')!=MEMORY:
                raise BuildRequired('BUILD_BUDGET_NOT_ENFORCED')
            # Record exact effective limits; requested flags alone are not evidence.
            atomic_json(self.directory/'builder.json',dict(name=self.name,container=self.container,image=info['Image'],
                        cpu_period=cfg['CpuPeriod'],cpu_quota=cfg['CpuQuota'],memory=cfg['Memory'],memory_swap=cfg['MemorySwap'],parallelism=JOBS))
            from resource_budget import container_sample
            def sample():
                while not self.stop.is_set():
                    row=container_sample(self.container);self.samples.append(row)
                    with (self.directory/'resources.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
                    self.stop.wait(1)
            self.sampler=threading.Thread(target=sample,daemon=True);self.sampler.start()
            return self
        except Exception:
            self.__exit__(None,None,None);raise
    def build(self,root,dockerfile,tag=None,target=None,args=(),output=None,architecture=None):
        tag=tag or 'pail/prepared:'+uuid.uuid4().hex
        cmd=['docker','buildx','build','--builder',self.name,'--progress=plain','--build-arg','PAIL_BUILD_JOBS=2','-f',str(dockerfile)]
        if architecture is not None:
            if architecture not in ('arm64','amd64'):raise BuildRequired('UNSUPPORTED_BUILD_ARCHITECTURE')
            cmd+=['--platform','linux/'+architecture]
        if target:cmd+=['--target',target]
        for arg in args:cmd+=['--build-arg',arg]
        if output:cmd+=['--output','type=local,dest='+str(output)]
        else:cmd+=['--load','-t',tag]
        cmd+=[str(root)]
        call(cmd,self.log,timeout=3600)
        if output:return None
        image=resolve_image(tag)
        if architecture is not None:
            info=json.loads(call(['docker','image','inspect',image]).stdout)[0]
            if info['Os']!='linux' or info['Architecture']!=architecture:
                raise BuildRequired('BUILT_IMAGE_ARCHITECTURE_MISMATCH')
        return image
    def __exit__(self,*args):
        self.stop.set()
        if self.sampler:self.sampler.join(6)
        try:
            if self.created:
                # Only this invocation's unique worker; never prune other builders.
                call(['docker','buildx','rm',self.name],self.log,timeout=120)
                self.created=False
        finally:
            if self.lock:
                self.lock.close();self.lock=None

def prepare(kind,root,record,window_confirmed=False,dashboard=True):
    if not window_confirmed:raise BuildRequired('BUILD_WINDOW_REQUIRED: explicitly confirm an isolated software build window')
    if Path(record).is_symlink():raise BuildRequired('BUILD_RECORD_SYMLINK')
    root=Path(root).resolve();record=Path(record).resolve()
    if root==record or root in record.parents:raise BuildRequired('BUILD_RECORD_OUTSIDE_SOURCE_REQUIRED')
    digest=source_digest(root);work=record.parent/('build-'+uuid.uuid4().hex)
    with Builder(work) as builder:
        if kind=='microduck':
            images={'runtime':builder.build(root,root/'examples/microduck/Dockerfile',args=['PAIL_SOURCE_SHA256='+digest,'PAIL_VERSION='+(root/'VERSION').read_text().strip()])}
        elif kind=='tb3':
            from evaluation_runtime import split_distribution, issuer_image
            images={'cloud':issuer_image(root) if split_distribution(root) else builder.build(root,root/'docker/Dockerfile.cloud'),
                    'gate':builder.build(root,root/'docker/Dockerfile.gate',args=['PAIL_VERSION='+(root/'VERSION').read_text().strip()])}
        else:raise BuildRequired('BUILD_KIND')
        native=None
        if kind=='microduck' and dashboard:
            target_os={'Darwin':'darwin','Linux':'linux'}.get(platform.system());arch={'arm64':'arm64','aarch64':'arm64','x86_64':'amd64','AMD64':'amd64'}.get(platform.machine())
            if not target_os or not arch:raise BuildRequired('NATIVE_DASHBOARD_PLATFORM')
            # Extend the shipped cloud builder in a temporary Dockerfile; source stays unchanged.
            recipe=(root/'docker/Dockerfile.cloud').read_text()+'''\nFROM builder AS native-dashboard
ARG PAIL_BUILD_JOBS=2
ARG DEMO_GOOS
ARG DEMO_GOARCH
ENV GOMAXPROCS=2
WORKDIR /repo/cloud
RUN CGO_ENABLED=0 GOOS=$DEMO_GOOS GOARCH=$DEMO_GOARCH go build -p 2 -mod=readonly -tags pail_generated -o /out/pail_telemetryd ./cmd/pail_telemetryd
FROM scratch AS dashboard-export
COPY --from=native-dashboard /out/pail_telemetryd /pail_telemetryd
'''
            df=work/'Dockerfile.dashboard';df.write_text(recipe);dest=work/'native'
            builder.build(root,df,target='dashboard-export',args=['DEMO_GOOS='+target_os,'DEMO_GOARCH='+arch],output=dest)
            binary=dest/'pail_telemetryd';binary.chmod(0o700)
            native=dict(path=str(binary),sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),host=[platform.system(),platform.machine()])
    if source_digest(root)!=digest:raise BuildRequired('SOURCE_CHANGED_DURING_BUILD: no receipt published')
    data=dict(schema_version=1,kind=kind,source_digest=digest,images=images,dashboard=native,builder_evidence=str(work),prepared_at_ms=int(time.time()*1000))
    atomic_json(record,data);return data

def select_prepared(kind,args,root,needs_dashboard=False):
    record=args.build_record or default_record(kind)
    if args.build or args.action=='build':
        if args.skip_build or any(getattr(args,k,None) for k in ('image','cloud_image','gate_image','dashboard_binary')):raise BuildRequired('BUILD_FLAGS_CONFLICT')
        prepare(kind,root,record,args.build_window_confirmed,dashboard=needs_dashboard)
    if args.action=='build':return {'record':str(record)}
    if kind=='microduck' and args.image:
        value={'images':{'runtime':resolve_image(args.image)},'dashboard':None}
        if needs_dashboard:
            if not args.dashboard_binary or not Path(args.dashboard_binary).is_file():
                raise BuildRequired('BUILD_REQUIRED: start needs a prepared native dashboard binary or --no-dashboard')
            p=Path(args.dashboard_binary).resolve()
            value['dashboard']={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'host':[platform.system(),platform.machine()]}
        return value
    if kind=='tb3' and (args.cloud_image or args.gate_image):
        if not(args.cloud_image and args.gate_image):raise BuildRequired('BUILD_REQUIRED: both cloud and gate images are required')
        return {'images':{'cloud':resolve_image(args.cloud_image),'gate':resolve_image(args.gate_image)}}
    data=load_record(record,kind,root)
    if needs_dashboard and not data.get('dashboard'):raise BuildRequired('BUILD_REQUIRED: native dashboard not prepared')
    return data
