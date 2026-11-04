# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Explicit v4 headless SDK endpoint; actual GPU/ROS compatibility remains unverified.

No image pull, asset download, public streaming, raw planner path or root fallback.
An exercise is bound to an authenticated Issuer result and agent token observation.
"""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time
from isolation_runtime import IsolatedRig
from state_store import atomic,read,source_hashes
from runtime import HERE


def assets_digest(root):
    root=Path(root)
    if root.is_symlink() or not root.is_dir() or root==Path('/') or root.resolve()!=root:
        raise ValueError('canonical dedicated asset directory required')
    rows={}
    for p in sorted(root.rglob('*')):
        if p.is_symlink():raise ValueError('asset symlink refused')
        if p.is_file():
            h=hashlib.sha256()
            with p.open('rb') as f:
                for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
            rows[str(p.relative_to(root))]=h.hexdigest()
    if not rows:raise ValueError('empty assets')
    return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def missing_wheel_joints(root,usd,joints):
    """Joint names not defined in the converted tree (the entry/overlay file excluded).

    preview.15 P15-M1/L2: a tree imported from the unexpanded xacro URDF carries prefixed prim
    names (``tn__namespacewheel_left_joint_...``); the profile and the overlay still name
    ``wheel_left_joint`` (the overlay always does, which is why it is excluded here), and the
    first thing to notice was the endpoint dying with KeyError 30 s into a 10-minute wait.
    A USD prim definition quotes its name, so ``"<joint>"`` must appear in some converted file.
    """
    root=Path(root);entry=(root/usd).resolve() if usd else None;found=set()
    for p in sorted(root.rglob('*')):
        if not p.is_file() or p.is_symlink() or p.resolve()==entry:continue
        data=p.read_bytes()
        for j in joints:
            if ('"%s"'%j).encode() in data:found.add(j)
    return [j for j in joints if j not in found]


def validate_inputs(profile,state,core,binding):
    if platform.system()!='Linux' or platform.machine() not in ('x86_64','AMD64') or binding['architecture']!='amd64':
        raise ValueError('native Linux amd64 required for actual SDK')
    sim=profile['sim'];assets=Path(sim['asset_dir'])
    for other in (Path(state),Path(core)):
        if other==assets or other in assets.parents or assets in other.parents:raise ValueError('asset/source/state overlap')
    if assets_digest(assets)!=sim['assets_sha256']:raise ValueError('asset hash changed')
    if not (assets/sim['usd']).is_file():raise ValueError('USD absent')
    result=subprocess.run(['docker','image','inspect',sim['image']],capture_output=True,text=True,timeout=15)
    if result.returncode:raise ValueError('SDK image must already be loaded; no implicit pull')
    info=json.loads(result.stdout)[0]
    if info['Id']!=sim['image'] or info['Os']!='linux' or info['Architecture']!='amd64':raise ValueError('SDK identity/platform mismatch')


def plan_binding(response,agent_token,epoch):
    if response.get('status')!='ACCEPTED' or len(response.get('tokens',[]))!=1:
        raise ValueError('one accepted actual plan required')
    token=response['tokens'][0]
    if not isinstance(agent_token,dict) or any(not token.get(k) or token.get(k)!=agent_token.get(k) for k in ('id','signed_bytes_sha256')):
        raise ValueError('agent token differs from authenticated issuance')
    if not response.get('plan') or not response.get('chain') or not epoch:raise ValueError('incomplete plan binding')
    return {'epoch':epoch,'plan':response['plan'],'chain':response['chain'],'token':token['id'],'token_hash':token['signed_bytes_sha256']}


FIXTURE_ACTIONS=('timeline_pause','timeline_play','physics_reset','inject_wheels')


def wheel_rates(row):
    """Wheel motion the judges read: position-derived rates (snapshot schema 3) or, for older rows, the SDK-reported
    joint velocities. The reported velocities carried a one-wheel -0.05..-0.12 rad/s reading for seconds after an
    abrupt stop while the joint angle stayed within 1e-5 rad (gate_kill, Brev L40S, 2026-10-19); position change
    is the quantity that means motion, so schema 3 rows are judged on it and keep the reported values as evidence."""
    rates=row.get('wheel_velocity_from_angle')
    return rates if isinstance(rates,list) else row.get('wheel_velocity')


def body_speed(row):
    """Horizontal body speed the judges read: pose-derived (schema 3) or the reported linear velocity magnitude."""
    speed=row.get('speed_from_pose')
    if type(speed) in (int,float):return speed
    v=row.get('linear_velocity')
    return math.hypot(v[0],v[1]) if isinstance(v,list) and len(v)==3 and all(type(x) in (int,float) for x in v) else None


def yaw_rate(row):
    """Yaw rate the judges read: orientation-derived (schema 3) or the reported angular velocity about z."""
    rate=row.get('yaw_rate_from_pose')
    if type(rate) in (int,float):return rate
    w=row.get('angular_velocity')
    return w[2] if isinstance(w,list) and len(w)==3 and type(w[2]) in (int,float) else None


def observed_zero(row):
    if row.get('authority_source')!='ISAAC_SDK' or row.get('applied_linear_x')!=0 or row.get('applied_angular_z')!=0:return False
    for name,count in [('linear_velocity',3),('angular_velocity',3),('wheel_velocity',2)]:
        values=row.get(name)
        if not isinstance(values,list) or len(values)!=count or any(type(v) not in (int,float) or not math.isfinite(v) for v in values):return False
    rates=wheel_rates(row);speed=body_speed(row);yaw=yaw_rate(row)
    if not isinstance(rates,list) or len(rates)!=2 or any(type(v) not in (int,float) or not math.isfinite(v) or abs(v)>.05 for v in rates):return False
    if type(speed) not in (int,float) or not math.isfinite(speed) or speed>.005:return False
    if type(yaw) not in (int,float) or not math.isfinite(yaw) or abs(yaw)>.005:return False
    return True


class IsaacRig(IsolatedRig):
    def __init__(self,state):
        super().__init__(state);self.sim=self.data['profile']['sim'];self.grant=None
        self.used=False;self._assembling=False

    def extra_mounts(self):
        return [str(Path(self.sim['asset_dir']))+':/assets:ro',str(self.state/'sim-control')+':/sim-control:ro',str(self.state/'sim-cache')+':/cache']

    def bootstrap(self):
        self._assembling=True
        try:super().bootstrap()
        finally:self._assembling=False
        for name in ('sim-control','sim-cache'):
            (self.state/name).mkdir(mode=0o755,exist_ok=True)
        # Assign only writable SDK cache to the existing isolated endpoint UID.
        self.command(['docker','run','--rm','--network','none','-u','0','-v',str(self.state/'sim-cache')+':/cache','--entrypoint','chown',self.images['tb3_gate'],'11007:11007','/cache'],'sdk-cache-owner')
        for name in ('isaac_endpoint.py','live_control.py','network_guard.py','test_fixture.py'):
            shutil.copyfile(HERE/'sim'/name,self.ref/name);(self.ref/name).chmod(0o644)
        meta=dict(read(self.ref/'nv-meta.json'),sim=self.sim,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),fixture_allowed=self.data.get('fixture_run') is True)
        atomic(self.ref/'isaac-meta.json',meta,0o644)
        doc=read(self.state/'compose.json');endpoint=doc['services']['endpoint']
        endpoint.update(image=self.sim['image'],cpus=8,mem_limit='24g',memswap_limit='24g',pids_limit=512,shm_size='1g',deploy={'resources':{'reservations':{'devices':[{'driver':'nvidia','count':1,'capabilities':['gpu']}]}}})
        endpoint['volumes']+=self.extra_mounts()
        if self.sim.get('eula_accepted') is not True:raise ValueError('SDK EULA acknowledgement required')
        endpoint['environment'].update(HOME='/cache',XDG_CACHE_HOME='/cache/cache',CUDA_CACHE_PATH='/cache/ComputeCache',ROS_LOG_DIR='/cache/roslogs',ROS_DISTRO='humble',RMW_IMPLEMENTATION='rmw_fastrtps_cpp',PAIL_BACKEND='ISAAC_SDK',ACCEPT_EULA='Y')
        endpoint['entrypoint']=['bash','-c']
        endpoint['command']=['export LD_LIBRARY_PATH=/isaac-sim/exts/isaacsim.ros2.core/humble/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}; exec /isaac-sim/python.sh /reference/isaac_endpoint.py --config /reference/isaac-meta.json']
        atomic(self.state/'compose.json',doc);self.validate_layout(doc)
        seal=read(self.state/'runtime-seal.json');seal.update(compose=hashlib.sha256((self.state/'compose.json').read_bytes()).hexdigest(),reference=source_hashes(self.ref),isaac_assets=self.sim['assets_sha256'])
        atomic(self.state/'runtime-seal.json',seal)
        self.control(False,0,0)

    def validate_layout(self,doc):
        if self._assembling:return super().validate_layout(doc)
        endpoint=doc['services']['endpoint'];env=endpoint['environment']
        if endpoint['image']!=self.sim['image'] or env.get('PAIL_BACKEND')!='ISAAC_SDK':raise ValueError('SDK endpoint mismatch')
        expected_gpu={'resources':{'reservations':{'devices':[{'driver':'nvidia','count':1,'capabilities':['gpu']}]}}}
        if endpoint.get('deploy')!=expected_gpu:raise ValueError('explicit single GPU required')
        if env.get('ROS_SECURITY_ENABLE')!='true' or env.get('ROS_SECURITY_STRATEGY')!='Enforce' or env.get('ROS_SECURITY_ENCLAVE_OVERRIDE')!='/nv_endpoint':raise ValueError('SDK security weakened')
        if env.get('RMW_IMPLEMENTATION')!='rmw_fastrtps_cpp' or env.get('ROS_DISTRO')!='humble':raise ValueError('SDK ROS binding changed')
        cleaned=copy.deepcopy(doc)
        for mount in self.extra_mounts():
            if cleaned['services']['endpoint']['volumes'].count(mount)!=1:raise ValueError('SDK mount mismatch')
            cleaned['services']['endpoint']['volumes'].remove(mount)
        for role,service in doc['services'].items():
            if role!='endpoint' and (service.get('deploy') or service.get('device_requests')):raise ValueError('GPU access outside SDK role')
        return super().validate_layout(cleaned)

    def sealed(self):
        seal=super().sealed()
        if assets_digest(Path(self.sim['asset_dir']))!=seal['isaac_assets']:raise ValueError('assets changed')
        return seal

    def wait(self,fn,label,timeout=45):
        if label=='independent zero observation':
            fn=lambda:any(r.get('event')=='observed' and observed_zero(r['snapshot']) for r in self.rows('monitor'))
        return super().wait(fn,label,600 if label=='isolated actors ready' else timeout)

    def snapshot(self):
        # Tail read only: the 60 Hz endpoint log grows by tens of MB per minute and a
        # full parse here aged the latest record past the freshness window (i11, 2026-10-15).
        last=self.last_row('endpoint',lambda r:r.get('event')=='endpoint')
        row=last.get('snapshot') if isinstance(last,dict) else None
        if not isinstance(row,dict) or row.get('authority_source')!='ISAAC_SDK':raise ValueError('actual SDK observation absent')
        if row.get('run_id')!=self.data['run_id'] or row.get('generation')!=self.data['generation'] or row.get('clock_id')!='CLOCK_BOOTTIME:'+Path('/proc/sys/kernel/random/boot_id').read_text().strip():raise ValueError('SDK observation identity/clock mismatch')
        now=time.clock_gettime_ns(time.CLOCK_BOOTTIME)*1e-6
        if not 0<=now-row['elapsed_ms']<500:raise ValueError('SDK observation stale')
        return row

    def before_exercise(self):
        if self.used:raise ValueError('SDK_ONE_EXERCISE_PER_RUN: stop and prepare a fresh state')
        row=self.snapshot()
        if row['state']!='READY_LOCKED' or not observed_zero(row):raise ValueError('SDK zero state not observed')

    def bind_plan(self,response):
        row=self.snapshot();self.used=True
        args=self.c+['exec','-T','requester','tb3-probe','-addr','127.0.0.1:50051','-mode','peek']
        last=None
        for _ in range(8):
            p=subprocess.run(args,capture_output=True,text=True,timeout=15)
            if p.returncode:raise ValueError('agent mTLS readiness query failed')
            observed=json.loads(p.stdout)
            try:
                if observed.get('status')!='OK':raise ValueError('agent token not active')
                self.grant=plan_binding(response,observed.get('token'),row['epoch']);return
            except ValueError as exc:last=exc;time.sleep(.1)
        raise ValueError('agent never observed new issued token: '+str(last))

    def control(self,on,heartbeat,instruction,speed=.05):
        super().control(on,heartbeat,instruction,speed)
        folder=self.state/'sim-control';folder.mkdir(mode=0o755,exist_ok=True)
        atomic(folder/'control.json',dict(run_id=self.data['run_id'],generation=self.data['generation'],boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),elapsed_ms=time.clock_gettime_ns(time.CLOCK_BOOTTIME)*1e-6,on=bool(on and self.grant),heartbeat=heartbeat,grant=self.grant),0o644)

    def sim_failure(self):
        try:return self.snapshot()['state']=='FAULT_LOCKED'
        except ValueError:return True

    def latch(self):
        """(state, reason) of the SDK latch; an unreadable observation reads as a fault."""
        try:row=self.snapshot();return row.get('state'),row.get('reason')
        except ValueError as exc:return 'FAULT_LOCKED','OBSERVATION_UNREADABLE: '+str(exc)

    def fixture(self,payload):
        """Sim-only test channel (timeline pause/play, physics reset, wheel injection).

        Refused unless the state was prepared with --fixture; such runs carry
        fixture_run=true everywhere and never count toward a support claim.
        """
        if self.data.get('fixture_run') is not True:raise ValueError('fixture refused: not a fixture run')
        if not isinstance(payload,dict) or payload.get('action') not in FIXTURE_ACTIONS:raise ValueError('unknown fixture action')
        row={'action':payload['action']}
        if payload['action']=='inject_wheels':
            wheels=payload.get('wheels');ticks=payload.get('ticks',60)
            if not isinstance(wheels,list) or len(wheels)!=2 or any(type(w) not in (int,float) or not math.isfinite(w) or abs(w)>5 for w in wheels) or type(ticks) is not int or not 1<=ticks<=300:
                raise ValueError('fixture wheel injection out of range')
            row.update(wheels=[float(w) for w in wheels],ticks=ticks)
        self.fixture_seq=getattr(self,'fixture_seq',0)+1
        row.update(seq=self.fixture_seq,run_id=self.data['run_id'],generation=self.data['generation'],fixture=True)
        atomic(self.state/'sim-control'/'fixture.json',row,0o644)
        return row

    def stop_observed(self,row):return observed_zero(row)

    def observations(self):
        result=super().observations();row=self.snapshot()
        result.update(endpoint_backend='ISAAC_SDK',sdk_version=self.sim['version'],headless=True,actual_sim_observation=True,fixture_run=self.data.get('fixture_run') is True)
        result['runtime_ready']=result['runtime_ready'] and row['state']=='READY_LOCKED'
        return result
