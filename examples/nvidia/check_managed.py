# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Explicit development-only fault suite; creates only isolated synthetic rigs."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from state_store import atomic, read
from session import prepare, request, status, recover, Rig
from runtime import HERE
from nvidia_profile import load
from sim.lifecycle import Lifecycle
from sim.mock_port import MockPort


def await_value(fn,label,timeout=40):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            value=fn()
            if value:return value
        except (OSError,ValueError,KeyError):pass
        time.sleep(.05)
    raise AssertionError(label)


def actor_signal(rig, role, sig):
    # Inspect exact argv tokens inside one fully owned container, never pgrep substring.
    rig.owned()
    service=rig.service(role)
    if service!='robot':
        ids=subprocess.check_output(rig.c+['ps','-aq',service],text=True).split()
        if len(ids)!=1:raise ValueError('isolated target is not unique')
        cid=ids[0]
        if sig==signal.SIGSTOP:
            rig.command(['docker','pause',cid],'pause-'+service)
        elif sig==signal.SIGKILL:
            paused=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0]['State']['Paused']
            rig.command(['docker','rm','-f',cid] if paused else ['docker','kill','--signal','KILL',cid],'kill-'+service)
        else:raise ValueError('unsupported isolated fault signal')
        return {'container':cid,'signal':int(sig),'scope':'owned isolated service'}
    code='''import os,json,signal
from pathlib import Path
role=%r
found=[]
for p in Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:a=(p/'cmdline').read_bytes().decode().split('\\0')
 except (OSError,UnicodeError):continue
 match=(role in ('pep_gate_node','motion_bridge_node') and a and Path(a[0]).name==role) or any(a[i]=='--role' and a[i+1]==role for i in range(len(a)-1))
 if match:found.append(int(p.name))
if len(found)!=1:raise SystemExit('actor identity ambiguous: '+repr(found))
os.kill(found[0],%d)
print(json.dumps({'pid':found[0],'signal':%d}))
'''%(role,sig,sig)
    return json.loads(rig.command(rig.c+['exec','-T',rig.service(role),'python3','-c',code],'signal-'+role))


def normal(rig,state):
    start=len(rig.rows('monitor'))
    response=request(state,'exercise')
    assert response.get('request_accepted'),response
    await_value(lambda:any(r.get('event')=='observed' and r['snapshot']['applied_linear_x']>0 for r in rig.rows('monitor')[start:]),'positive endpoint control')


def attack(rig, topic, enclave, env=None, label=None):
    mark=len(rig.rows('monitor'))
    # This bounds test-process startup, not a robot stop/permit deadline. A cold
    # native Jetson ROS import may consume the former two-second budget itself.
    line='source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && timeout 10 python3 -u /reference/ros_endpoint.py --role attack --topic '+topic
    extra=[]
    for key,value in sorted((env or {}).items()):extra+=['-e',key+'='+str(value)]  # e.g. a different ROS_DOMAIN_ID variant
    started=time.monotonic()
    r=subprocess.run(rig.c+['exec','-T','-e','ROS_SECURITY_ENCLAVE_OVERRIDE='+enclave,*extra,rig.service('evidence' if enclave=='/perception' else 'planner'),'bash','-c',line],capture_output=True,text=True,timeout=20)
    elapsed_s=time.monotonic()-started
    log=r.stdout+r.stderr
    name=(label or enclave.strip('/'))+'-'+topic.replace('/','_')
    (state:=rig.state/'logs'/('attack-'+name+'.log')).write_text(log)
    time.sleep(.6)
    snapshots=[x['snapshot'] for x in rig.rows('monitor')[mark:] if x.get('event')=='observed']
    denied=any(word in log.lower() for word in ('not allowed','security directory','security artifacts','failed to create publisher','security error: directory'))
    assert r.returncode not in (0,124) and denied,(name,r.returncode,elapsed_s,'timeout is not a verified denial',log[-1000:])
    assert snapshots and not any(x['applied_linear_x'] or x['applied_angular_z'] for x in snapshots),name
    return {'topic':topic,'enclave':enclave,'env':dict(env or {}),'returncode':r.returncode,'denial_observed':True,'observer_samples':len(snapshots),'probe_elapsed_s':elapsed_s}


def lifecycle_check(directory):
    clock=[0];model=Lifecycle(directory/'lifecycle-state.json',lambda:clock[0],generation='model');port=MockPort();seq=[0]
    def send(event,**kw):seq[0]+=1;return model.event(event,str(seq[0]),'model',**kw)
    for event in ('PREPARE_OK','ENDPOINT_ZERO','OLD_PLAN_CANCELLED','PATH_RECREATED'):assert send(event)
    assert send('NEW_PLAN_ACCEPTED',chain='c',token='t');assert send('ROBOT_PLAN_READY',chain='c',token='t');assert send('PLAY_REQUEST')
    port.command(.1);assert port.tick(model)==.1;send('PAUSE');assert port.tick(model)==0
    old=model.event('PLAY_REQUEST','late','old');assert not old;assert port.tick(model)==0
    result={'authority_source':'MOCK','test_verdict':'PASS','retained_command_blocked':True,'actual_sim':False}
    atomic(directory/'public/lifecycle-result.json',result);return result


def finish_controller(state,proc):
    if proc.poll() is not None:return
    # The final state is durable before the process exits; do not reconnect to its closed socket.
    if read(state/'status.json').get('execution_status')!='STOPPED':request(state,'stop')
    proc.wait(timeout=45)


def run_case(root,core,mode,index,profile_path=None):
    state=root/(mode+'-'+str(index));profile=load(profile_path or HERE/'profiles/mock-humble-v2.json')
    prepare(state,profile,core)
    with (state/'logs/supervisor.log').open('w') as log:
        proc=subprocess.Popen([sys.executable,'-B',str(HERE/'session.py'),'serve','--state',str(state)],stdout=log,stderr=subprocess.STDOUT)
    rig=Rig(state);checks=[]
    try:
        await_value(lambda:status(state).get('execution_status')=='READY_LOCKED','ready',60)
        normal(rig,state);checks.append({'id':'positive_gate_bridge_endpoint','status':'PASS'})
        if mode=='normal':
            request(state,'idle');mark=len(rig.rows('monitor'))
            await_value(lambda:any(r.get('event')=='observed' and r['snapshot']['applied_linear_x']==0 for r in rig.rows('monitor')[mark:]),'stop observation')
            checks.append({'id':'cancel_zero_observed','status':'PASS'})
            for topic in ('/safe_cmd_vel','/drive_cmd_vel','/pail/permit'):
                checks.append({'id':'unauthorized'+topic,'status':'PASS','observation':attack(rig,topic,'/oem_planner')})
            checks.append({'id':'wrong_authorized_identity','status':'PASS','observation':attack(rig,'/drive_cmd_vel','/perception')})
            checks.append({'id':'missing_identity','status':'PASS','observation':attack(rig,'/drive_cmd_vel','/nv_absent')})
            lifecycle_check(state)
        elif mode=='bridge_stall':
            actor_signal(rig,'motion_bridge_node',signal.SIGSTOP);mark=len(rig.rows('monitor'))
            await_value(lambda:any(r.get('event')=='observed' and r['snapshot']['state']=='EXPIRED' for r in rig.rows('monitor')[mark:]),'endpoint timeout')
            checks.append({'id':'bridge_stall_endpoint_timeout','status':'PASS'})
            # Kill the frozen actor instead of resuming queued old commands.
            actor_signal(rig,'motion_bridge_node',signal.SIGKILL)
        elif mode=='endpoint_loss':
            mark=len(rig.rows('monitor'));actor_signal(rig,'endpoint',signal.SIGKILL)
            await_value(lambda:any(r.get('event')=='OBSERVATION_LOST' for r in rig.rows('monitor')[mark:]),'lost observation')
            await_value(lambda:status(state).get('execution_status')=='FAULT_LOCKED','fault lock')
            checks.append({'id':'endpoint_death_not_false_zero','status':'PASS','stop_confirmed':False})
        elif mode=='monitor_loss':
            actor_signal(rig,'monitor',signal.SIGKILL)
            await_value(lambda:status(state).get('execution_status')=='FAULT_LOCKED','observer fault lock')
            checks.append({'id':'monitor_death_fault_lock','status':'PASS','stop_confirmed':False})
        elif mode=='log_corruption':
            # A broken observation is not a stop confirmation and must not skip owned cleanup.
            if hasattr(rig,'service') and rig.service('monitor')!='robot':
                rig.command(rig.c+['exec','-T',rig.service('monitor'),'python3','-c',"with open('/evidence/runtime/monitor.jsonl','a') as f:f.write('{broken\\n');f.flush()"],'corrupt-observation')
            else:
                with rig.log_path('monitor').open('a') as f:f.write('{broken\n');f.flush()
            await_value(lambda:status(state).get('execution_status')=='STOPPED','cleanup after corrupt observation')
            summary=read(state/'public/summary.json')
            assert summary['stop_confirmed'] is False and summary.get('stop_errors'),summary
            checks.append({'id':'corrupt_observation_cleanup_without_false_stop','status':'PASS','stop_confirmed':False})
        elif mode=='permit_replay':
            actor_signal(rig,'pep_gate_node',signal.SIGKILL)
            # Leave the real bridge/launch process alive; allow its last permit to expire.
            mark0=len(rig.rows('monitor'))
            await_value(lambda:any(r.get('event')=='bridge' and r['state']=='HOLD' for r in rig.rows('monitor')[mark0:]),'old permit expires')
            rig.actor('permit_fixture','pep_gate')
            mark=len(rig.rows('monitor'))
            atomic(rig.rig/'control/permit-fixture.json',{'event':'replay','seq':17},0o644)
            await_value(lambda:any(r.get('event')=='bridge' and r['state']=='FORWARDING' for r in rig.rows('monitor')[mark:]),'fixture permits arrive')
            await_value(lambda:'non-monotonic' in subprocess.check_output(rig.c+['logs','--no-color','robot'],text=True,stderr=subprocess.DEVNULL),'duplicate permit rejected')
            checks.append({'id':'trusted_fixture_duplicate_permit_hold','status':'PASS','production_permissions_changed':False})
        elif mode=='orphan':
            proc.kill();proc.wait(timeout=5)
            await_value(lambda:status(state).get('execution_status')=='ORPHANED','orphaned')
            mark=len(rig.rows('monitor'))
            await_value(lambda:any(r.get('event')=='observed' and r['snapshot']['applied_linear_x']==0 for r in rig.rows('monitor')[mark:]),'orphan output zero')
            preview=recover(state,False);assert preview['owned_containers']
            recover(state,True);checks.append({'id':'orphan_owned_cleanup_no_resume','status':'PASS'})
        else:raise ValueError('unknown case')
        finish_controller(state,proc)
        summary=read(state/'public/summary.json');assert summary['cleanup']['status']=='PASS',summary
        if mode in ('endpoint_loss','monitor_loss','log_corruption'):assert summary['stop_confirmed'] is False,summary
        summary['test_verdict']='PASS';summary['coverage']={'ros_endpoint':True,'lifecycle_mock':mode=='normal','jetson_cpu':False,'isaac_ros_gpu':False,'actual_sim':False,'physical':False}
        atomic(state/'public/summary.json',summary);atomic(state/'public/checks.json',checks)
        return {'case':mode,'repeat':index,'test_verdict':'PASS','checks':checks,'cleanup':summary['cleanup']}
    finally:
        if proc.poll() is None:
            try:finish_controller(state,proc)
            except Exception:
                proc.kill();proc.wait(timeout=5)
                try:recover(state,True)
                except Exception:pass


def write_suite(root,results,expected,error=None):
    actual=[(r['case'],r['repeat']) for r in results]
    duplicate=len(set(actual))!=len(actual)
    complete=len(actual)==len(expected) and set(actual)==set(expected)
    verdict='FAIL' if error or duplicate or any(r.get('test_verdict')!='PASS' for r in results) else 'PASS' if complete else 'INCONCLUSIVE'
    atomic(root/'suite.json',{'test_verdict':verdict,'complete':complete and verdict=='PASS','expected_count':len(expected),
                            'completed':results,'hardware_verified':False,'error':error})


def main():
    p=argparse.ArgumentParser();p.add_argument('--core',required=True,type=Path);p.add_argument('--root',required=True,type=Path)
    p.add_argument('--case',choices=['normal','bridge_stall','endpoint_loss','monitor_loss','orphan','permit_replay','log_corruption','all'],default='all');p.add_argument('--repeat',type=int,default=1)
    p.add_argument('--profile',type=Path)
    a=p.parse_args()
    if a.profile and load(a.profile)['schema_version']==4:
        raise ValueError('Use actual Sim observations; this synthetic suite cannot certify SDK motion')
    if a.repeat<1:raise ValueError('positive repeat required')
    a.root.mkdir(mode=0o700,exist_ok=False)
    cases=['normal','bridge_stall','endpoint_loss','monitor_loss','orphan','permit_replay'] if a.case=='all' else [a.case]
    if a.profile and load(a.profile)['schema_version']==3:
        if a.case=='permit_replay':raise ValueError('trusted permit fixture not available in isolated roles')
        cases=[c for c in cases if c!='permit_replay']
    expected=[(case,i) for case in cases for i in range(a.repeat)]
    results=[];write_suite(a.root,results,expected)
    for case in cases:
        for i in range(a.repeat):
            print('START',case,i,flush=True)
            try:r=run_case(a.root.resolve(),a.core.resolve(),case,i,a.profile)
            except Exception as ex:
                write_suite(a.root,results,expected,error={'case':case,'detail':str(ex)});raise
            results.append(r);write_suite(a.root,results,expected);print('PASS',case,i,flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
