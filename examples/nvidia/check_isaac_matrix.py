# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Actual-SDK BS-01~12 / BP-01~12 matrix on fresh owned v4 rigs. No mock fallback.

One fresh state per case; one exercise per state. Every case records four evidence
levels (AUTH_DECISION, COMMAND_PATH, CONTROLLER_APPLIED, SIM_OBSERVED). Fixture
cases are Sim-only controls (prepared with --fixture) and never count toward a
support claim; the BP-11 positive control must be DETECTED or every bypass PASS in
the suite is void. Timeouts and missing observations are never a denial or a stop.
"""
import argparse
import json
import math
import shutil
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path
from session import prepare,request,status,recover,Rig,HERE
from nvidia_profile import load
from state_store import read,atomic
from check_managed import await_value,actor_signal,attack
from check_isolation import inspect_mounts,matrix,boundary_writes,unauthenticated_tls
from check_isaac import moved,cancel_stop
from isaac_runtime import observed_zero,wheel_rates,body_speed,yaw_rate
from evidence import export

CASES=('normal','expired','constraint','target_mismatch','deadline','bridge_stall','gate_kill','endpoint_loss','monitor_loss','orphan','log_corruption')
FIXTURE_CASES=('pause_resume','reset','positive_control')
COVERAGE={'normal':['BS-01','BS-02','BS-03','BS-05','BP-01','BP-02','BP-03','BP-04','BP-05','BP-06','BP-07','BP-09','BP-10'],
          'expired':['BS-04','BS-09'],'constraint':['BS-04'],'target_mismatch':['BS-04'],'deadline':['BS-09','BS-01'],
          'bridge_stall':['BS-08','BP-08'],'gate_kill':['BP-08'],'endpoint_loss':['BS-08','BS-07'],'monitor_loss':['BS-08','BS-09'],
          'orphan':['BS-08'],'log_corruption':['BS-10'],'pause_resume':['BS-06'],'reset':['BS-07','BP-09'],'positive_control':['BP-11']}
EXPECTED_NODES={'/nv_endpoint','/nv_monitor','/nv_planner','/tb3_reference_safety','/tb3_reference_evidence','/pep_gate_node','/motion_bridge_node'}
FORBIDDEN_WORDS=('joint','effort','trajectory','wheel','articulation','teleop')
ATTACKS=[('/safe_cmd_vel','/oem_planner',None,None),('/drive_cmd_vel','/oem_planner',None,None),('/pail/permit','/oem_planner',None,None),
         ('/drive_cmd_vel','/pep_gate',None,None),('/drive_cmd_vel','/motion_bridge',None,None),('/drive_cmd_vel','/nv_monitor',None,None),
         ('/drive_cmd_vel','/oem_planner',{'ROS_DOMAIN_ID':'1'},'oem_planner-domain1'),('/pail/drive_cmd_vel','/oem_planner',None,'oem_planner-namespace')]
INVENTORY_CODE='''import json,time
import rclpy
from rclpy.node import Node
rclpy.init()
node=Node('nv_inventory',start_parameter_services=False,enable_rosout=False)
end=time.monotonic()+4
while time.monotonic()<end:rclpy.spin_once(node,timeout_sec=.2)
full=lambda name,ns:('/' if ns=='/' else ns+'/')+name
ep=lambda items:sorted(set(full(i.node_name,i.node_namespace) for i in items))
topics=sorted(node.get_topic_names_and_types())
services=sorted(n for n,_ in node.get_service_names_and_types())
# Hidden names are returned by the graph API; actions always surface as <name>/_action/* services and topics.
actions=sorted(set(n.rsplit('/_action/',1)[0] for n in services+[t for t,_ in topics] if '/_action/' in n))
out={'nodes':sorted(set(full(n,ns) for n,ns in node.get_node_names_and_namespaces())),
     'topics':[{'name':n,'types':t,'publishers':ep(node.get_publishers_info_by_topic(n)),'subscribers':ep(node.get_subscriptions_info_by_topic(n))} for n,t in topics],
     'services':services,'actions':actions}
print(json.dumps(out));node.destroy_node();rclpy.shutdown()
'''


# ---------------------------------------------------------------- pure judges

def graph_violations(inv):
    """Structural facts the authenticated graph inventory must satisfy (BP-02/03/05/06)."""
    bad=[];nodes=set(inv.get('nodes',[]))-{'/nv_inventory'}
    if nodes!=EXPECTED_NODES:bad.append({'rule':'node_set','extra':sorted(nodes-EXPECTED_NODES),'missing':sorted(EXPECTED_NODES-nodes)})
    by={t['name']:t for t in inv.get('topics',[])}
    drive=by.get('/drive_cmd_vel',{})
    if drive.get('subscribers')!=['/nv_endpoint'] or drive.get('publishers')!=['/motion_bridge_node']:bad.append({'rule':'drive_cmd_vel_endpoints','observed':drive})
    cmd=by.get('/cmd_vel',{})
    if cmd.get('subscribers')!=['/pep_gate_node'] or not set(cmd.get('publishers',[]))<={'/nv_planner'}:bad.append({'rule':'cmd_vel_endpoints','observed':cmd})
    for name in sorted(by):
        if any(w in name.lower() for w in FORBIDDEN_WORDS):bad.append({'rule':'forbidden_topic','topic':name,'subscribers':by[name].get('subscribers')})
    for name in inv.get('services',[]):
        if any(w in name.lower() for w in FORBIDDEN_WORDS+('cmd','drive')):bad.append({'rule':'forbidden_service','service':name})
    if inv.get('actions'):bad.append({'rule':'actions_present','actions':inv['actions']})
    if 'actions' not in inv:bad.append({'rule':'actions_unverified','error':inv.get('actions_error')})
    return bad


def moving(s):
    """Body-level motion or a nonzero applied target or both wheels turning.

    A single-wheel reading spike on a resting body (observed up to 0.155 rad/s after an
    abrupt stop, gate_kill m3 2026-10-15) is contact jitter, not motion; it still fails
    observed_zero, which stays the stricter test for the first zero sample after a stop.
    """
    if s.get('authority_source')!='ISAAC_SDK':return True
    if s.get('applied_linear_x') or s.get('applied_angular_z'):return True
    v=s.get('linear_velocity') or [1,1,1];w=s.get('angular_velocity') or [1,1,1];wheels=wheel_rates(s) or [1,1];speed=body_speed(s);yaw=yaw_rate(s)
    if len(v)!=3 or len(w)!=3 or len(wheels)!=2 or speed is None or yaw is None:return True
    return speed>.005 or abs(yaw)>.005 or all(abs(x)>.05 for x in wheels)


def unauthorized_motion(rows,grace_ms=2000,sustain=3):
    """Monitor rows -> sustained SDK motion (>= sustain consecutive moving samples) with no
    gate PERMIT within grace_ms before it. Isolated single-sample reading spikes on a resting
    body (orphan-2 m5, 2026-10-15) are not motion; a 60-tick injection is."""
    last_permit=None;hits=[];streak=[]
    for r in rows:
        if r.get('event')=='gate' and r.get('state')=='PERMIT':last_permit=r.get('elapsed_ms');streak=[]
        elif r.get('event')=='observed':
            s=r.get('snapshot',{});t=r.get('elapsed_ms')
            unauthorized=moving(s) and (last_permit is None or type(t) not in (int,float) or t-last_permit>grace_ms)
            if not unauthorized:streak=[];continue
            streak.append({'seq':s.get('seq'),'elapsed_ms':t,'wheel_velocity':s.get('wheel_velocity'),'linear_velocity':s.get('linear_velocity'),'applied_linear_x':s.get('applied_linear_x')})
            if len(streak)==sustain:hits.extend(streak)
            elif len(streak)>sustain:hits.append(streak[-1])
    return hits


def resting(snapshots,start=None):
    """Window verdict for 'the robot did not move': no sustained motion and no displacement.

    Strict observed_zero on every sample is kept as evidence (strict_zero_ratio) but a
    single reading spike after an abrupt stop no longer flips the verdict.
    """
    if not snapshots:return {'ok':False,'reason':'no SDK samples'}
    streak=0;longest=0
    for s in snapshots:
        streak=streak+1 if moving(s) else 0;longest=max(longest,streak)
    base=start or snapshots[0];dist=max(displacement(base,s) for s in snapshots)
    return {'ok':longest<3 and dist<.001,'samples':len(snapshots),'longest_moving_streak':longest,'max_horizontal_displacement_m':dist,'strict_zero_ratio':sum(1 for s in snapshots if observed_zero(s))/len(snapshots)}


def path_summary(rows):
    gate={};bridge={};permits=0
    for r in rows:
        if r.get('event')=='gate':
            key=str(r.get('state'))+':'+str(r.get('reason'));gate[key]=gate.get(key,0)+1
            if r.get('state')=='PERMIT':permits+=1
        elif r.get('event')=='bridge':bridge[str(r.get('state'))]=bridge.get(str(r.get('state')),0)+1
    return {'gate':gate,'bridge':bridge,'permits':permits}


def aggregate(results):
    """Suite verdict: NOT_APPLICABLE/DETECTED never count as PASS; one FAIL fails the suite."""
    verdicts=[r.get('verdict') for r in results]
    fixture=[r for r in results if r.get('fixture_run')]
    positive=[r for r in fixture if r.get('case')=='positive_control']
    if any(v=='FAIL' for v in verdicts):return 'FAIL'
    if positive and any(r.get('verdict')!='DETECTED' for r in positive):return 'FAIL'
    if any(v in ('INCONCLUSIVE','NOT_RUN') for v in verdicts):return 'INCONCLUSIVE'
    claimable=[r for r in results if not r.get('fixture_run')]
    return 'PASS' if claimable and all(r.get('verdict')=='PASS' for r in claimable) else 'INCONCLUSIVE'


def displacement(a,b):return math.hypot(b['pose'][0]-a['pose'][0],b['pose'][1]-a['pose'][1])


def lenient_rows(path):
    rows=[]
    for line in Path(path).read_text().splitlines():
        try:rows.append(json.loads(line))
        except ValueError:continue
    return rows


# ---------------------------------------------------------------- one case

def seed_cache(rig,seed):
    """Copy only a compiled SDK shader cache (same image/driver/GPU) into the fresh state.

    Never settings, logs, ROS identities, grant/control state or a previous robot run.
    Ownership is assigned with the same guarded image pattern as sdk-cache-owner.
    """
    seed=Path(seed).resolve()
    if not seed.is_dir() or seed.name!='cache' or seed.parent.name!='kit':raise ValueError('cache seed must be a <...>/kit/cache directory')
    rig.command(['docker','run','--rm','--network','none','-u','0','-v',str(rig.state/'sim-cache')+':/cache','-v',str(seed)+':/seed:ro','--entrypoint','bash',rig.images['tb3_gate'],'-c','mkdir -p /cache/kit && cp -a /seed /cache/kit/cache && chown -R 11007:11007 /cache'],'sdk-cache-seed',300)


class Case:
    def __init__(self,root,core,profile,name,index,fixture=False,cache_seed=None):
        self.name=name;self.index=index;self.fixture=fixture;self.state=root/(name+'-'+str(index))
        prepare(self.state,profile,core,fixture=fixture)
        if cache_seed:seed_cache(Rig(self.state),cache_seed)
        self.log=(self.state/'logs/supervisor.log').open('w')
        self.proc=subprocess.Popen([sys.executable,'-B',str(HERE/'session.py'),'serve','--state',str(self.state)],stdout=self.log,stderr=subprocess.STDOUT)
        self.rig=Rig(self.state);self.checks=[];self.auth=[];self.path=[];self.started=time.monotonic()
    def ready(self):
        # preview.15 P15-L2: the endpoint recorded SDK_ERROR 30 s in and the matrix still waited the full
        # 600 s for READY_LOCKED. Appended endpoint rows are scanned while waiting; an SDK_ERROR ends the
        # wait at once with the endpoint's own error text.
        cursor=0
        def observed():
            nonlocal cursor
            s=status(self.state)
            if s.get('execution_status')=='READY_LOCKED':return s
            rows,cursor=self.rig.tail_rows('endpoint',cursor)
            for r in rows:
                if r.get('event')=='SDK_ERROR':raise AssertionError(('endpoint SDK_ERROR before READY_LOCKED',r.get('error')))
            return None
        await_value(observed,'ready',600)
        self.ready_s=time.monotonic()-self.started
    def snapshot(self):return self.rig.snapshot()
    def mark(self,role='monitor'):return self.rig.tail_rows(role,None)[1]
    def since(self,cursor,role='monitor'):return self.rig.tail_rows(role,cursor)[0]
    def check(self,cid,**kw):self.checks.append(dict(id=cid,**kw));return kw
    def probe(self,*args,timeout=20):
        r=subprocess.run(self.rig.c+['exec','-T','requester','tb3-probe','-addr','127.0.0.1:50061',*args],capture_output=True,text=True,timeout=timeout)
        if r.returncode:raise RuntimeError('requester probe failed rc=%s %s'%(r.returncode,r.stderr[-300:]))
        out=json.loads(r.stdout);self.auth.append({'args':list(args),'status':out.get('status'),'rejected':out.get('rejected'),'denial':out.get('denial'),'plan':out.get('plan')});return out
    def agent_peek(self):
        r=subprocess.run(self.rig.c+['exec','-T','requester','tb3-probe','-addr','127.0.0.1:50051','-mode','peek'],capture_output=True,text=True,timeout=20)
        if r.returncode:raise RuntimeError('agent peek failed')
        out=json.loads(r.stdout);self.auth.append({'args':['agent','peek'],'status':out.get('status')});return out
    def input_window(self,seconds=10):
        """Allowed planner input path (/cmd_vel) for a bounded time; not a denial by itself."""
        cursor=self.mark();command='source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && timeout %d python3 -u /reference/ros_endpoint.py --role attack --topic /cmd_vel'%seconds
        attempts=self.rig.log_path('planner').parent/'attack.jsonl';before=attempts.stat().st_size if attempts.exists() else 0
        r=subprocess.run(self.rig.c+['exec','-T','planner','bash','-c',command],capture_output=True,text=True,timeout=seconds+10)
        if r.returncode!=124:raise AssertionError(('allowed input probe did not reach its bounded stop',r.returncode,(r.stdout+r.stderr)[-400:]))
        published=[json.loads(x) for x in attempts.read_text()[before:].splitlines() if x.strip()]
        if not any(x.get('event')=='PUBLISH_RETURNED' and x.get('topic')=='/cmd_vel' for x in published):raise AssertionError('input publisher made no progress')
        time.sleep(.6);rows=self.since(cursor);summary=path_summary(rows);summary['snapshots']=[r['snapshot'] for r in rows if r.get('event')=='observed']
        return summary
    def start_exercise(self):
        start=self.snapshot()
        if not observed_zero(start):raise AssertionError('initial actual zero missing')
        self.exercise_cursor=self.mark();self.exercise_endpoint_cursor=self.mark('endpoint')
        r=request(self.state,'exercise')
        if not r.get('request_accepted'):raise AssertionError(('exercise rejected',r.get('error')))
        self.auth.append({'args':['controller','exercise'],'status':'ACCEPTED_BY_CONTROLLER','execution_status':r.get('execution_status')})
        row=await_value(lambda:(lambda s:s if moved(start,s) else None)(self.snapshot()),'actual horizontal pose and velocity change',6)
        self.check('actual_motion',status='PASS',displacement_m=displacement(start,row),linear_velocity=row['linear_velocity'],wheel_velocity=row['wheel_velocity'])
        return start,row
    def expect_lock(self,reasons,within_s,label):
        t0=time.monotonic()
        row=await_value(lambda:(lambda s:s if s['state']=='FAULT_LOCKED' and s['reason'] in reasons else None)(self.snapshot()),label+' lock',within_s)
        lock_s=time.monotonic()-t0;marker=row['seq']
        zero=await_value(lambda:(lambda s:s if s['seq']>marker and observed_zero(s) else None)(self.snapshot()),label+' zero',5)
        status_word,window,coast=self.settle(zero,expect_state='FAULT_LOCKED',label=label)
        return self.check(label,status=status_word,reason=row['reason'],lock_wait_s=lock_s,post_lock_coast_m=coast,zero_seq=zero['seq'],post_stop_window=window)
    def settle(self,zero,expect_state,label):
        """Two seconds after the first zero sample: the body must rest (velocity, displacement,
        applied targets); wheel readings are classified, never ignored. Criteria fixed before
        the runs: wheel |v|<=0.05 rad/s in >=90% of samples -> PASS. Body at rest but wheel
        readings jittering (single-wheel spikes <=0.2 rad/s, both-wheel samples <=5%) ->
        INCONCLUSIVE 'wheel_reading_jitter' (observed in gate_kill/monitor_loss, 2026-10-15),
        never counted as PASS. Anything else -> failure.
        """
        cursor=self.mark('endpoint');time.sleep(2);later=self.snapshot();coast=displacement(zero,later)
        snaps=[r['snapshot'] for r in self.since(cursor,'endpoint') if r.get('event')=='endpoint']
        if not snaps:raise AssertionError((label,'no SDK samples in the post-stop window'))
        wheels=[abs(w) for s in snaps for w in wheel_rates(s)];reported=[abs(w) for s in snaps for w in s['wheel_velocity']]
        # Body criteria use body speed and applied targets only; wheel rates are classified below. Schema 3 rows are
        # judged on position-derived rates; the SDK-reported velocities stay in the window as evidence.
        body_moving=lambda s:body_speed(s)>.005 or abs(yaw_rate(s))>.005
        window={'samples':len(snaps),'body_moving_samples':sum(1 for s in snaps if body_moving(s)),'wheel_within_ratio':sum(1 for w in wheels if w<=.05)/len(wheels),'wheel_abs_max':max(wheels),
                'both_wheels_moving_samples':sum(1 for s in snaps if all(abs(w)>.05 for w in wheel_rates(s))),'applied_nonzero_samples':sum(1 for s in snaps if s['applied_linear_x'] or s['applied_angular_z']),'coast_m':coast,'final_state':later['state'],'final_reason':later['reason'],
                'wheel_basis':'position_derived' if all(isinstance(s.get('wheel_velocity_from_angle'),list) for s in snaps) else 'reported','wheel_reported_abs_max':max(reported),'wheel_reported_within_ratio':sum(1 for w in reported if w<=.05)/len(reported)}
        if later['state']!=expect_state or coast>.02 or window['applied_nonzero_samples']:
            raise AssertionError((label,'motion after stop',window))
        if window['body_moving_samples']==0 and window['wheel_within_ratio']>=.9:return 'PASS',window,coast
        # Isolated reading spikes on a body that did not displace (orphan m5: 1/112 body samples,
        # 6.5 um; gate_kill/monitor_loss: single-wheel spikes) are classified, never passed.
        jitter=[]
        if 0<window['body_moving_samples']<=.02*len(snaps):jitter.append('body_reading_jitter')
        if window['wheel_within_ratio']<.9 and window['wheel_abs_max']<=.2 and window['both_wheels_moving_samples']<=.05*len(snaps):jitter.append('wheel_reading_jitter')
        if jitter and window['body_moving_samples']<=.02*len(snaps) and window['wheel_abs_max']<=.2 and window['both_wheels_moving_samples']<=.05*len(snaps):
            window['classification']=','.join(jitter);return 'INCONCLUSIVE',window,coast
        raise AssertionError((label,'readings outside the jitter envelope after stop',window))
    def resources(self):
        out={'disk_free_bytes':shutil.disk_usage(str(self.state)).free}
        try:
            ids=[c['id'] for c in read(self.state/'ownership.json')['containers']]
            stats=subprocess.run(['docker','stats','--no-stream','--format','{{json .}}',*ids],capture_output=True,text=True,timeout=30).stdout
            out['containers']=[{k:v for k,v in json.loads(x).items() if k in ('Name','MemUsage','CPUPerc','PIDs')} for x in stats.splitlines() if x.strip()]
        except (OSError,ValueError,subprocess.SubprocessError) as ex:out['containers_error']=str(ex)
        try:out['gpu_memory_used']=subprocess.run(['nvidia-smi','--query-gpu=memory.used,utilization.gpu','--format=csv,noheader'],capture_output=True,text=True,timeout=15).stdout.strip()
        except (OSError,subprocess.SubprocessError) as ex:out['gpu_error']=str(ex)
        return out
    def finish(self):
        if self.proc.poll() is None and read(self.state/'status.json').get('execution_status') not in ('STOPPED',):
            try:request(self.state,'stop')
            except (OSError,ValueError):pass
            try:self.proc.wait(timeout=120)
            except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=10)
        self.log.close()
        if read(self.state/'status.json').get('execution_status') not in ('STOPPED',):
            try:recover(self.state,True)
            except Exception:pass
        return read(self.state/'public/summary.json') if (self.state/'public/summary.json').exists() else read(self.state/'status.json')


def inventories(case):
    rows=case.rig.rows('endpoint');found={}
    for r in rows:
        if r.get('event') in ('ASSET_INVENTORY','EXTENSION_INVENTORY','LISTENER_INVENTORY','RENDER_CAPTURE','FIXTURE_ARMED'):found[r['event']]=r
    ext=found.get('EXTENSION_INVENTORY',{});lst=found.get('LISTENER_INVENTORY',{});asset=found.get('ASSET_INVENTORY',{})
    if ext.get('forbidden_enabled')!=[]:raise AssertionError(('forbidden SDK writer extension enabled',ext.get('forbidden_enabled')))
    if asset.get('embedded_control_graphs')!=0 or asset.get('nonzero_initial_drive_targets')!=0:raise AssertionError(('asset inventory',asset))
    ports=sorted(l['port'] for l in lst.get('listeners',[]) if not (l['family']=='tcp' and l['address']=='0B00007F'))
    if any(p not in (50051,50061) for p in ports):raise AssertionError(('unexpected listener',ports))
    if 'FIXTURE_ARMED' in found and not case.fixture:raise AssertionError('fixture armed in a non-fixture run')
    r=subprocess.run(case.rig.c+['exec','-T','monitor','bash','-c','source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && timeout 40 python3 -c "$1"','probe',INVENTORY_CODE],capture_output=True,text=True,timeout=60)
    if r.returncode:raise AssertionError(('graph inventory probe failed',r.returncode,(r.stdout+r.stderr)[-600:]))
    graph=json.loads(r.stdout.strip().splitlines()[-1]);violations=graph_violations(graph)
    if violations:raise AssertionError(('graph inventory violations',violations))
    return {'extensions':{'enabled_count':ext.get('enabled_count'),'watched':ext.get('watched')},'listeners':lst.get('listeners'),'asset':{k:asset.get(k) for k in ('prim_count','articulation_root')},
            'render_capture':{k:found.get('RENDER_CAPTURE',{}).get(k) for k in ('status','bytes','error')},'graph':graph}


# ---------------------------------------------------------------- cases

def case_normal(case):
    case.check('mounts',status='PASS',observation=inspect_mounts(case.rig));case.check('matrix',status='PASS',roles=len(matrix(case.rig)))
    case.check('boundary_writes',status='PASS',observation=boundary_writes(case.rig));case.check('tls',status='PASS',observation=unauthenticated_tls(case.rig))
    case.check('inventories',status='PASS',observation=inventories(case))
    w=case.input_window(10);case.path.append({'step':'no_token_input','gate':w['gate'],'bridge':w['bridge']})
    denies=w['gate'].get('BLOCK:ERR_NO_TOKEN',0);rest=resting(w['snapshots'])
    if not denies or w['permits'] or not rest['ok']:raise AssertionError(('no-token gate refusal / actual rest not observed',w['gate'],w['permits'],rest))
    case.check('no_token_gate',status='PASS',gate_samples=denies,actual_zero_samples=len(w['snapshots']),rest=rest)
    for topic,enclave,env,label in ATTACKS:
        initial=case.snapshot()
        if not observed_zero(initial):raise AssertionError('initial physical zero absent before attack')
        cursor=case.mark();row=attack(case.rig,topic,enclave,env=env,label=label)
        rest=resting([x['snapshot'] for x in case.since(cursor) if x.get('event')=='observed'],initial)
        if not rest['ok']:raise AssertionError(('actual SDK rest not maintained',topic,enclave,env,rest))
        case.check('attack:'+(label or enclave.strip('/'))+':'+topic,status='PASS',observation=dict(row,**rest))
    start,_=case.start_exercise()
    before=case.snapshot()
    if before.get('state')!='ACTIVE':raise AssertionError(('exercise ended before the cancel request',before.get('reason')))
    r=request(case.state,'idle')
    if not r.get('request_accepted'):raise AssertionError(('cancel rejected',r.get('error')))
    zero=await_value(lambda:(lambda s:s if cancel_stop(before,s) else None)(case.snapshot()),'post-cancel zero with latch reason EXERCISE_ENDED',5)
    rows=case.since(case.exercise_cursor);case.path.append({'step':'exercise_cancel',**path_summary(rows)})
    if not path_summary(rows)['permits'] or not path_summary(rows)['bridge'].get('FORWARDING'):raise AssertionError('exercise without observed PERMIT/FORWARDING path')
    status_word,window,_=case.settle(zero,expect_state='FAULT_LOCKED',label='cancel_zero')
    case.check('cancel_zero',status=status_word,reason=zero['reason'],max_horizontal_displacement_m=displacement(start,zero),post_stop_window=window)
    # BP-09: a newly authorized plan after the end of the exercise must not move the robot in this run.
    cursor=case.mark();resp=case.probe('-mode','submit','-duration','6')
    if resp.get('status')!='ACCEPTED':raise AssertionError(('post-cancel plan not accepted',resp))
    try:
        w=case.input_window(6);case.path.append({'step':'post_cancel_reauthorized_input','gate':w['gate'],'bridge':w['bridge']})
        rest=resting(w['snapshots'],zero)
        if not rest['ok']:raise AssertionError(('motion after a post-cancel re-authorization',rest))
        verdict='PASS' if w['permits'] else 'INCONCLUSIVE'
        case.check('post_cancel_reauthorization_no_resume',status=verdict,permits=w['permits'],gate=w['gate'],bridge=w['bridge'],**rest)
    finally:
        try:case.probe('-mode','cancel','-plan',resp.get('plan',''))
        except Exception:pass
    return 'PASS'


TOKEN_TTL_S=30.  # rig policy token_ttl_ms (runtime.bootstrap); step durations count from activation, not issuance


def case_expired(case):
    if case.agent_peek().get('status')!='NO_TOKEN':raise AssertionError('precondition: agent already holds a token')
    resp=case.probe('-mode','submit','-steps','[{"linear":0.05,"angular":0.0,"duration":2.0}]')
    if resp.get('status')!='ACCEPTED':raise AssertionError(('short plan not accepted',resp))
    submitted=time.monotonic()
    try:
        await_value(lambda:case.agent_peek().get('status')=='OK','agent observed the token',5)
    except AssertionError:
        case.check('expired_precondition',status='INCONCLUSIVE',note='token never observed on the agent before expiry');return 'INCONCLUSIVE'
    # Observed 2026-10-15 (m3): a never-activated step keeps its full duration, so wall-clock
    # expiry is the token TTL. Wait past it before offering input.
    time.sleep(max(0.,TOKEN_TTL_S+3.-(time.monotonic()-submitted)))
    w=case.input_window(8);case.path.append({'step':'input_after_ttl_expiry','gate':w['gate'],'bridge':w['bridge'],'waited_s':time.monotonic()-submitted})
    if w['permits']:raise AssertionError(('PERMIT after step expiry',w['gate']))
    reasons={k.split(':',1)[1] for k in w['gate'] if k.startswith('BLOCK:')}
    if not reasons or not reasons<={'ERR_EXPIRED','ERR_NO_TOKEN'}:raise AssertionError(('unexpected gate reasons after expiry',w['gate']))
    rest=resting(w['snapshots'])
    if not rest['ok']:raise AssertionError(('actual rest not maintained after expiry',rest))
    case.check('expired_denied',status='PASS',gate=w['gate'],actual_zero_samples=len(w['snapshots']),rest=rest)
    try:case.probe('-mode','cancel','-plan',resp.get('plan',''))
    except Exception:pass
    return 'PASS'


def _denied_plan(case,label,args,gate_reason):
    resp=case.probe('-mode','submit',*args)
    accepted=resp.get('status')=='ACCEPTED'
    w=case.input_window(6);case.path.append({'step':label+'_input','gate':w['gate'],'bridge':w['bridge']})
    if w['permits']:raise AssertionError((label,'PERMIT observed',w['gate']))
    rest=resting(w['snapshots'])
    if not rest['ok']:raise AssertionError((label,'actual rest not maintained',rest))
    if accepted and not w['gate'].get('BLOCK:'+gate_reason):raise AssertionError((label,'issuer accepted and gate did not report '+gate_reason,w['gate']))
    case.check(label,status='PASS',issuer_status=resp.get('status'),issuer_rejected=resp.get('rejected'),issuer_denial=resp.get('denial'),gate=w['gate'],actual_zero_samples=len(w['snapshots']),rest=rest)
    if accepted:
        try:case.probe('-mode','cancel','-plan',resp.get('plan',''))
        except Exception:pass
    return 'PASS'


def case_constraint(case):return _denied_plan(case,'constraint_denied',['-steps','[{"linear":0.5,"angular":0.0,"duration":5.0}]'],'ERR_CONSTRAINT')


def case_target_mismatch(case):return _denied_plan(case,'target_mismatch_denied',['-target','not-in-site-model'],'ERR_TARGET_MISMATCH')


def case_deadline(case):
    start,first=case.start_exercise();active_at=first['elapsed_ms']
    lock=case.expect_lock(('EXERCISE_DEADLINE','EXERCISE_ENDED'),11,'deadline')
    endpoint_rows=case.since(case.exercise_endpoint_cursor,'endpoint')
    snaps=[r['snapshot'] for r in endpoint_rows if r.get('event')=='endpoint']
    locked=[s for s in snaps if s['state']=='FAULT_LOCKED'];active=[s for s in snaps if s['state']=='ACTIVE']
    if not locked or not active:raise AssertionError('deadline timeline incomplete')
    active_span_s=(locked[0]['elapsed_ms']-active[0]['elapsed_ms'])/1000.
    if not 7.5<=active_span_s<=9.5:raise AssertionError(('ACTIVE span outside 7.5-9.5 s',active_span_s))
    rtf=[s.get('real_time_factor') for s in active if type(s.get('real_time_factor')) in (int,float)]
    case.check('deadline_span',status='PASS',active_span_s=active_span_s,rtf_median=statistics.median(rtf) if rtf else None,rtf_min=min(rtf) if rtf else None,samples=len(active))
    case.path.append({'step':'deadline',**path_summary(case.since(case.exercise_cursor))})
    return 'PASS'


def case_bridge_stall(case):
    case.start_exercise();cursor=case.mark()
    sig=actor_signal(case.rig,'motion_bridge_node',signal.SIGSTOP)
    lock=case.expect_lock(('COMMAND_TIMEOUT',),3,'bridge_stall')
    case.path.append({'step':'bridge_paused',**path_summary(case.since(cursor))})
    actor_signal(case.rig,'motion_bridge_node',signal.SIGKILL)  # never resume queued old commands
    later=case.snapshot()
    if later['state']!='FAULT_LOCKED':raise AssertionError('latch reopened after bridge removal')
    case.check('bridge_stall_no_resume',status='PASS',signal=sig)
    return 'PASS'


def case_gate_kill(case):
    case.start_exercise();cursor=case.mark()
    sig=actor_signal(case.rig,'pep_gate_node',signal.SIGKILL)
    lock=case.expect_lock(('COMMAND_TIMEOUT',),3,'gate_kill')
    summary=path_summary(case.since(cursor));case.path.append({'step':'gate_killed',**summary})
    w=case.input_window(5);case.path.append({'step':'input_without_gate','gate':w['gate'],'bridge':w['bridge']})
    rest=resting(w['snapshots'])
    if w['permits'] or not rest['ok']:raise AssertionError(('input moved the robot without a gate',w['gate'],rest))
    case.check('gate_dead_input_no_motion',status='PASS',signal=sig,bridge_after_kill=summary['bridge'],actual_zero_samples=len(w['snapshots']),rest=rest)
    return 'PASS'


def case_endpoint_loss(case):
    case.start_exercise();cursor=case.mark()
    sig=actor_signal(case.rig,'endpoint',signal.SIGKILL)
    await_value(lambda:any(r.get('event')=='OBSERVATION_LOST' for r in case.since(cursor)),'observation lost',10)
    await_value(lambda:status(case.state).get('execution_status')=='FAULT_LOCKED','fault lock after endpoint death',10)
    case.check('endpoint_death_not_false_zero',status='PASS',signal=sig,expect_stop_confirmed=False)
    return 'PASS'


def case_monitor_loss(case):
    case.start_exercise()
    sig=actor_signal(case.rig,'monitor',signal.SIGKILL)
    await_value(lambda:(lambda s:s.get('execution_status')=='FAULT_LOCKED' and s.get('endpoint_observation')=='LOST')(status(case.state)),'observer loss fault lock',10)
    case.check('monitor_death_fault_lock',status='PASS',signal=sig,expect_stop_confirmed=False)
    # The observer is gone; the SDK's own record must still show the latch ending and the body at rest.
    case.expect_lock(('EXERCISE_ENDED','COMMAND_TIMEOUT','HEARTBEAT_LOST'),5,'monitor_loss_stop')
    return 'PASS'


def case_orphan(case):
    case.start_exercise()
    case.proc.kill();case.proc.wait(timeout=5)
    lock=case.expect_lock(('HEARTBEAT_LOST','CONTROL_STALE'),3,'orphan')
    await_value(lambda:status(case.state).get('execution_status')=='ORPHANED','orphaned',10)
    preview=recover(case.state,False)
    if not preview.get('owned_containers'):raise AssertionError('orphan preview found no owned containers')
    result=recover(case.state,True)
    if result.get('cleanup',{}).get('status')!='PASS':raise AssertionError(('orphan cleanup',result.get('cleanup')))
    case.check('orphan_owned_cleanup_no_resume',status='PASS',owned=len(preview['owned_containers']))
    return 'PASS'


def case_log_corruption(case):
    case.rig.command(case.rig.c+['exec','-T','monitor','python3','-c',"with open('/evidence/runtime/monitor.jsonl','a') as f:f.write('{broken\\n');f.flush()"],'corrupt-observation')
    # status.json is written a moment before public/summary.json; wait for the durable summary itself.
    await_value(lambda:(case.state/'public/summary.json').exists() and read(case.state/'public/summary.json').get('execution_status')=='STOPPED','cleanup after corrupt observation',60)
    summary=read(case.state/'public/summary.json')
    if summary.get('stop_confirmed') is not False or not summary.get('stop_errors'):raise AssertionError(('corrupt evidence confirmed a stop',summary.get('stop_confirmed'),summary.get('stop_errors')))
    case.check('corrupt_observation_cleanup_without_false_stop',status='PASS',stop_errors=summary['stop_errors'])
    return 'PASS'


def _fixture(case,payload):
    r=request(case.state,'fixture',payload)
    if not r.get('request_accepted') or not r.get('fixture'):raise AssertionError(('fixture refused',r.get('error')))
    return r['fixture']


def case_pause_resume(case):
    case.start_exercise();cursor=case.mark('endpoint')
    _fixture(case,{'action':'timeline_pause'})
    row=await_value(lambda:(lambda s:s if s['state']=='FAULT_LOCKED' and s['reason'] in ('TIMELINE_CHANGED_NEW_RUN_REQUIRED','NOT_PLAYING') else None)(case.snapshot()),'pause lock',3)
    time.sleep(1);_fixture(case,{'action':'timeline_play'})
    marker=case.snapshot()['seq']
    zero=await_value(lambda:(lambda s:s if s['seq']>marker and observed_zero(s) else None)(case.snapshot()),'zero after play',5)
    status_word,window,coast=case.settle(zero,expect_state='FAULT_LOCKED',label='pause_play_no_resume')
    applied=[r for r in case.since(cursor,'endpoint') if r.get('event')=='CONTROLLER_APPLIED' and r.get('elapsed_ms',0)>row['elapsed_ms']]
    if any(r.get('linear_x') or r.get('angular_z') for r in applied):raise AssertionError('nonzero target applied after the pause lock')
    case.check('pause_play_no_resume',status=status_word,reason=row['reason'],post_play_coast_m=coast,applied_after_lock=len(applied),post_stop_window=window)
    return 'PASS'


def case_reset(case):
    case.start_exercise();cursor=case.mark('endpoint')
    _fixture(case,{'action':'physics_reset'})
    lock=case.expect_lock(('PHYSICS_RESET','NOT_PLAYING','TIMELINE_CHANGED_NEW_RUN_REQUIRED'),5,'reset')
    rows=case.since(cursor,'endpoint')
    locked_at=next((r['elapsed_ms'] for r in rows if r.get('event')=='LOCKED' or (r.get('event')=='LATCH_STATE' and r.get('state')=='FAULT_LOCKED')),None)
    if locked_at is None:raise AssertionError('no lock transition recorded after reset')
    after=[r for r in rows if r.get('event')=='CONTROLLER_APPLIED' and r.get('elapsed_ms',0)>locked_at]
    if not after or any(r.get('linear_x') or r.get('angular_z') for r in after):raise AssertionError(('nonzero or missing target after the reset lock',len(after)))
    case.check('reset_fresh_run_required',status='PASS',reason=lock['reason'],applied_after_reset=len(after))
    return 'PASS'


def case_positive_control(case):
    initial=case.snapshot()
    if not observed_zero(initial) or initial['state']!='READY_LOCKED':raise AssertionError('positive control requires a locked zero start')
    cursor=case.mark();_fixture(case,{'action':'inject_wheels','wheels':[3.0,3.0],'ticks':60})
    time.sleep(3);rows=case.since(cursor);hits=unauthorized_motion(rows)
    moved_m=max([displacement(initial,r['snapshot']) for r in rows if r.get('event')=='observed'] or [0])
    if moved_m<.001:raise AssertionError(('injection did not move the robot; detector not exercised',moved_m))
    if not hits:raise AssertionError(('judge failed to detect unauthorized SDK motion',moved_m))
    case.check('judge_detects_unauthorized_motion',status='DETECTED',samples=len(hits),displacement_m=moved_m,first=hits[0])
    return 'DETECTED'


CASE_FUNCTIONS={'normal':case_normal,'expired':case_expired,'constraint':case_constraint,'target_mismatch':case_target_mismatch,'deadline':case_deadline,
                'bridge_stall':case_bridge_stall,'gate_kill':case_gate_kill,'endpoint_loss':case_endpoint_loss,'monitor_loss':case_monitor_loss,'orphan':case_orphan,
                'log_corruption':case_log_corruption,'pause_resume':case_pause_resume,'reset':case_reset,'positive_control':case_positive_control}


# ---------------------------------------------------------------- driver

def environment(profile):
    env={'sdk_image':profile['sim']['image'],'sdk_version':profile['sim']['version'],'assets_sha256':profile['sim']['assets_sha256'],'usd':profile['sim']['usd']}
    for key,cmd in [('gpu',['nvidia-smi','--query-gpu=name,driver_version,memory.total','--format=csv,noheader']),('kernel',['uname','-r']),('docker',['docker','version','--format','{{.Server.Version}}'])]:
        try:env[key]=subprocess.run(cmd,capture_output=True,text=True,timeout=15).stdout.strip()
        except (OSError,subprocess.SubprocessError) as ex:env[key+'_error']=str(ex)
    return env


def run_case(root,core,profile,name,index,cache_seed=None):
    fixture=name in FIXTURE_CASES;result={'case':name,'repeat':index,'coverage':COVERAGE[name],'fixture_run':fixture,'verdict':'FAIL','hardware_verified':False}
    case=None
    try:
        case=Case(root,core,profile,name,index,fixture=fixture,cache_seed=cache_seed);result['run_id']=case.rig.data['run_id'];case.ready();result['ready_s']=case.ready_s
        verdict=CASE_FUNCTIONS[name](case)
        if verdict=='PASS' and any(c.get('status')=='INCONCLUSIVE' for c in case.checks):verdict='INCONCLUSIVE'
        if not fixture:
            # log_corruption deliberately breaks one line; judge the records that still parse.
            hits=unauthorized_motion(lenient_rows(case.rig.log_path('monitor')) if name=='log_corruption' else case.rig.rows('monitor'))
            if hits:raise AssertionError(('unauthorized SDK motion in a claimable run',hits[:3]))
            result['unauthorized_motion_samples']=0
        result['verdict']=verdict
    except Exception as exc:
        import traceback
        result['error']=repr(exc)[:1500];result['traceback']=traceback.format_exc()[-2500:]
        if case is not None and name!='orphan' and case.proc.poll() is None:
            try:request(case.state,'idle')
            except Exception:pass
    finally:
        if case is not None:
            try:result['resources']=case.resources()
            except Exception as ex:result['resources_error']=str(ex)
            summary=case.finish()
            result.update(checks=case.checks,auth_decisions=case.auth,command_path=case.path,summary={k:summary.get(k) for k in ('execution_status','stop_confirmed','stop_errors','cancel_status','cleanup','fixture_run')})
            if summary.get('cleanup',{}).get('status')!='PASS':result['verdict']='FAIL';result.setdefault('error','cleanup not PASS')
            if name in ('endpoint_loss','monitor_loss','log_corruption') and summary.get('stop_confirmed') is not False:result['verdict']='FAIL';result['error']='stop_confirmed must be false when observation was lost/corrupt'
            atomic(case.state/'public/isaac-matrix-case.json',result)
            try:result['export']=export(case.state,root/('export-'+name+'-'+str(index)))
            except Exception as ex:result['export_error']=str(ex)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--core',required=True,type=Path);p.add_argument('--root',required=True,type=Path);p.add_argument('--profile',required=True,type=Path)
    p.add_argument('--cases',default='all',help='comma list or all');p.add_argument('--repeat',type=int,default=1);p.add_argument('--with-fixture',action='store_true',help='also run the Sim-only fixture cases')
    p.add_argument('--cache-seed',type=Path,help='compiled SDK shader cache (<...>/kit/cache) to copy into each fresh state')
    a=p.parse_args();profile=load(a.profile)
    if profile['schema_version']!=4:raise ValueError('actual SDK v4 profile required')
    if a.repeat<1:raise ValueError('positive repeat required')
    names=list(CASES)+(list(FIXTURE_CASES) if a.with_fixture else []) if a.cases=='all' else a.cases.split(',')
    unknown=[n for n in names if n not in CASE_FUNCTIONS]
    if unknown:raise ValueError('unknown cases: '+','.join(unknown))
    a.root.mkdir(mode=0o700,exist_ok=True);core=a.core.resolve()
    suite={'scope':'actual SDK BS/BP matrix on Brev; fresh state per case; not physical, not every NVIDIA platform','environment':environment(profile),'profile':str(a.profile),'started_unix':time.time(),'cases':[],'hardware_verified':False}
    atomic(a.root/'suite.json',dict(suite,verdict='NOT_RUN'))
    error=None
    try:
        for index in range(1,a.repeat+1):
            for name in names:
                suite['cases'].append(run_case(a.root,core,profile,name,index,cache_seed=a.cache_seed))
                atomic(a.root/'suite.json',dict(suite,verdict='RUNNING'))
    except Exception as exc:error=repr(exc)
    verdict=aggregate(suite['cases']) if not error else 'FAIL'
    expected=len(names)*a.repeat;done=len(suite['cases'])
    suite.update(verdict=verdict,complete=done==expected and verdict in ('PASS',),expected_cases=expected,completed_cases=done,error=error,finished_unix=time.time())
    atomic(a.root/'suite.json',suite)
    print(json.dumps({k:suite[k] for k in ('verdict','complete','expected_cases','completed_cases','error')}|{'cases':[(c['case'],c['repeat'],c['verdict']) for c in suite['cases']]}))
    return 0 if verdict=='PASS' else 2


if __name__=='__main__':raise SystemExit(main())
