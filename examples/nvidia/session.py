# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Managed synthetic rigs; not a persistent physical robot service."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time
import uuid
import subprocess
from nvidia_profile import load, digest
from state_store import atomic, read, exclusive, read_journal, journal, source_hashes
from probes import collect
from runtime import Rig as SharedRig, HERE

def Rig(state):
    data=read(Path(state)/"prepared.json")
    if data.get('profile',{}).get('schema_version')==4:
        from isaac_runtime import IsaacRig
        return IsaacRig(state)
    if data.get("profile",{}).get("schema_version")==3:
        from isolation_runtime import IsolatedRig
        return IsolatedRig(state)
    return SharedRig(state)

from run import validate_core
from evidence import export

sys.dont_write_bytecode=True


def helper_hashes():
    return source_hashes(HERE)


def prepare(state,profile,core,fixture=False):
    if profile['schema_version'] not in (2,3,4):raise ValueError('session requires v2/v3/v4; v1 run.py is unchanged')
    if fixture and profile['schema_version']!=4:raise ValueError('fixture runs exist only for the actual SDK profile')
    if state.exists() or state.is_symlink():raise ValueError('new state required')
    if len(str(state/'.sock').encode())>=100:raise ValueError('use a shorter state path for Unix socket')
    if core==state or core in state.parents or state in core.parents:raise ValueError('source and state must be disjoint')
    doctor=collect(profile,state)
    if doctor['overall']!='PASS':raise ValueError('preflight '+doctor['overall']+': '+json.dumps(doctor['checks']))
    binding=validate_core(core)
    if profile['target']=='jetson' and binding['architecture']!='arm64':raise ValueError('Jetson image architecture')
    if profile['schema_version']==4:
        from isaac_runtime import validate_inputs
        validate_inputs(profile,state,core,binding)
    state.mkdir(mode=0o700)
    for d in ('public','logs'):(state/d).mkdir(mode=0o700)
    runid='nv2-'+uuid.uuid4().hex[:16]
    data={'schema_version':2,'run_id':runid,'generation':uuid.uuid4().hex,'project':runid,'nonce':uuid.uuid4().hex,
          'profile':profile,'profile_digest':digest(profile),'core':str(core),'runtime':binding,
          'source_hashes':source_hashes(core),'helper_hashes':helper_hashes(),'fixture_run':bool(fixture)}
    atomic(state/'prepared.json',data);atomic(state/'public/doctor.json',doctor)
    journal(state,'PREPARE_INTENT',{'run_id':runid})
    try:Rig(state).bootstrap()
    except Exception as ex:
        journal(state,'PREPARE_FAILED',{'error':type(ex).__name__});raise
    journal(state,'PREPARED');atomic(state/'status.json',{'execution_status':'PREPARED','run_id':runid,'hardware_verified':False,'fixture_run':bool(fixture)})
    return read(state/'status.json')


def request(state,command,payload=None):
    data=read(state/'prepared.json');challenge=uuid.uuid4().hex
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(30 if data['profile']['schema_version']==4 and command in ('exercise','idle') else 3);client.connect(str(state/'.sock'))
        client.sendall((json.dumps({'command':command,'nonce':data['nonce'],'challenge':challenge,'payload':payload})+'\n').encode())
        response=b''
        while not response.endswith(b'\n'):
            chunk=client.recv(65536)
            if not chunk or len(response)>1048576:raise ValueError('invalid controller response')
            response+=chunk
    result=json.loads(response)
    if result.get('challenge')!=challenge or result.get('run_id')!=data['run_id']:raise ValueError('identity challenge failed')
    return result


def safe_reply(client,result):
    try:client.sendall((json.dumps(result)+'\n').encode());return True
    except OSError:return False  # A disconnected status caller does not own the rig lifecycle.


def status(state):
    try:return request(state,'status')
    except (OSError,ValueError):
        result=read(state/'status.json')
        if result['execution_status'] not in ('PREPARED','STOPPED'):
            result=dict(result,execution_status='ORPHANED',observation='INCONCLUSIVE',controller_live=False)
        return result


class ObservationTracker:
    """Incremental monitor-log reader for the controller loop.

    The loop must stay bounded well under the 100 ms heartbeat and the endpoint's
    500 ms freshness window; it therefore consumes only bytes appended since the
    previous tick. Unreadable or shrinking evidence is reported as loss (fail-closed).
    """
    def __init__(self,rig,role='monitor',now=None):
        self.rig=rig;self.role=role;self.cursor=0;self.observed=0;self.last_event=None
        self.last_change=time.monotonic() if now is None else now
    def update(self,now):
        try:rows,self.cursor=self.rig.tail_rows(self.role,self.cursor)
        except (OSError,ValueError) as ex:
            # Unreadable, corrupt or shrinking evidence ends the run (fail-closed), as before.
            raise ValueError('observation evidence unreadable: '+str(ex))
        fresh=sum(1 for r in rows if r.get('event')=='observed')
        if fresh:self.observed+=fresh;self.last_change=now
        if rows:self.last_event=rows[-1].get('event')
        return now-self.last_change>=.5 or self.last_event=='OBSERVATION_LOST'


def serve(state):
    data=read(state/'prepared.json');profile=data['profile'];rig=Rig(state)
    if load_profile_digest(profile)!=data['profile_digest']:raise ValueError('profile changed')
    if helper_hashes()!=data['helper_hashes'] or source_hashes(Path(data['core']))!=data['source_hashes'] or validate_core(Path(data['core']))!=data['runtime']:
        raise ValueError('prepared input changed')
    with exclusive(state):
        read_journal(state)
        if (state/'served').exists():raise ValueError('fresh state required; no automatic restart')
        atomic(state/'served',{'generation':data['generation']})
        endpoint=state/'.sock'
        if endpoint.exists():raise ValueError('unexpected existing socket')
        stopped=False;on=False;heartbeat=0;instruction=0;plan=None;plan_deadline=0
        runstatus={'execution_status':'STARTING','run_id':data['run_id'],'generation':data['generation'],'controller_live':True,'hardware_verified':False,'support_status':'UNVERIFIED','fixture_run':data.get('fixture_run') is True}
        def save():atomic(state/'status.json',runstatus)
        def stop_handler(*_):
            nonlocal stopped
            stopped=True
        previous={s:signal.signal(s,stop_handler) for s in (signal.SIGTERM,signal.SIGINT)}
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            server.bind(str(endpoint));os.chmod(endpoint,0o600);server.listen(4);server.settimeout(.05);save()
            rig.up()
            observations=rig.observations();atomic(state/'public/runtime-observations.json',observations)
            if not observations['runtime_ready']:raise ValueError('owned runtime readiness failed')
            journal(state,'READY_LOCKED');runstatus['execution_status']='READY_LOCKED';save()
            last_beat=0;last_health=0;tracker=ObservationTracker(rig)
            while not stopped:
                now=time.monotonic()
                if on and now>plan_deadline:
                    on=False;runstatus['execution_status']='READY_LOCKED';save()
                if now-last_beat>=.1:
                    heartbeat+=1;rig.control(on,heartbeat,instruction);last_beat=now
                if now-last_health>=.2:
                    # Observation loss is never interpreted as a successful stop.
                    lost=tracker.update(now)
                    runstatus['endpoint_observation']='LOST' if lost else 'SEE_RUNTIME_EVIDENCE'
                    if lost and on:on=False;runstatus['execution_status']='FAULT_LOCKED'
                    if hasattr(rig,'latch'):
                        latch_state,latch_reason=rig.latch()
                        if latch_state=='FAULT_LOCKED':
                            # The latch ends every exercise with a lock. A cancel/deadline end (EXERCISE_ENDED)
                            # is the normal spent state of a one-exercise run, not a fault (preview.14 L-3).
                            on=False;runstatus['execution_status']='EXERCISE_COMPLETE' if latch_reason=='EXERCISE_ENDED' else 'FAULT_LOCKED'
                            runstatus['latch_reason']=latch_reason
                    elif hasattr(rig,'sim_failure') and rig.sim_failure():
                        on=False;runstatus['execution_status']='FAULT_LOCKED'
                    save();last_health=now
                try:client,_=server.accept()
                except socket.timeout:continue
                with client:
                    client.settimeout(1);raw=b'';msg=None
                    try:
                        while not raw.endswith(b'\n') and len(raw)<=4096:
                            chunk=client.recv(4096)
                            if not chunk:break
                            raw+=chunk
                    except OSError:continue
                    fixture_ack=None
                    try:
                        msg=json.loads(raw)
                        if msg.get('nonce')!=data['nonce']:raise ValueError('wrong owner')
                        command=msg['command']
                        if command=='fixture':
                            # Sim-only test channel; exists only in states prepared with --fixture.
                            if data.get('fixture_run') is not True:raise ValueError('fixture refused: not a fixture run')
                            if not hasattr(rig,'fixture'):raise ValueError('fixture unsupported by this rig')
                            fixture_ack=rig.fixture(msg.get('payload'))
                            journal(state,'FIXTURE_REQUEST',{'seq':fixture_ack['seq'],'action':fixture_ack['action']})
                        if command=='exercise':
                            if runstatus['execution_status'] != 'READY_LOCKED' or runstatus.get('endpoint_observation') != 'SEE_RUNTIME_EVIDENCE':raise ValueError('not ready for a new request')
                            if hasattr(rig,'before_exercise'):rig.before_exercise()
                            # Probe submits an actual authenticated plan; local state is not authorization.
                            response=rig.probe('submit')
                            if response.get('status')!='ACCEPTED':raise ValueError('plan not accepted')
                            plan=response.get('plan')
                            if hasattr(rig,'bind_plan'):
                                try:rig.bind_plan(response)
                                except Exception:
                                    try:rig.probe('cancel',plan=plan)
                                    finally:runstatus['execution_status']='FAULT_LOCKED';save()
                                    raise
                            instruction+=1;on=True;plan_deadline=time.monotonic()+8
                            journal(state,'PLAN_SUBMITTED',{'instruction':instruction});runstatus['execution_status']='ACTIVE_TEST';save()
                        elif command=='idle':
                            on=False;instruction+=1;rig.control(False,heartbeat,instruction)
                            if plan:
                                cancelled=rig.probe('cancel',plan=plan)
                                if cancelled.get('cancelled') is not True: raise ValueError('cancellation not acknowledged')
                                plan=None
                            if runstatus['execution_status'] not in ('FAULT_LOCKED','EXERCISE_COMPLETE'): runstatus['execution_status']='READY_LOCKED'
                            save()
                        elif command=='stop':stopped=True
                        elif command not in ('status','fixture'):raise ValueError('unknown command')
                        result=dict(runstatus,challenge=msg.get('challenge'),request_accepted=True,fixture=fixture_ack)
                    except (ValueError,KeyError,RuntimeError,subprocess.SubprocessError) as ex:
                        result=dict(runstatus,challenge=msg.get('challenge') if isinstance(locals().get('msg'),dict) else None,error=str(ex),request_accepted=False)
                    safe_reply(client,result)
        except Exception as ex:
            runstatus.update(execution_status='FAULT_LOCKED',error=str(ex));save()
        finally:
            stop_errors=[]
            try:rig.control(False,heartbeat+1,instruction+1)
            except (OSError,ValueError) as ex:stop_errors.append('input stop: '+str(ex))
            cancel='NOT_REQUESTED'
            try:
                if plan:
                    response=rig.probe('cancel',plan=plan)
                    cancel='ACK' if response.get('cancelled') is True else 'UNKNOWN'
            except Exception:cancel='UNKNOWN'
            stop_confirmed=False
            try:
                rig.rows('monitor')  # one-shot full validation at stop: corrupt evidence never confirms a stop
                observed,cursor=rig.tail_rows('monitor',None);end=time.monotonic()+(5 if profile['schema_version']==4 else 1)
                while time.monotonic()<end:
                    observed,cursor=rig.tail_rows('monitor',cursor)
                    if any(r.get('event')=='observed' and (rig.stop_observed(r['snapshot']) if hasattr(rig,'stop_observed') else r['snapshot']['applied_linear_x']==0 and r['snapshot']['applied_angular_z']==0) for r in observed):stop_confirmed=True;break
                    time.sleep(.05)
            except (OSError,ValueError,KeyError,TypeError) as ex:
                stop_errors.append('stop observation unavailable: '+str(ex))
            try:cleanup=rig.cleanup()
            except Exception as ex:cleanup={'status':'INCONCLUSIVE','reason':str(ex)}
            summary=dict(runstatus,execution_status='STOPPED' if cleanup['status']=='PASS' else 'FAULT_LOCKED',controller_live=False,
                         stop_confirmed=stop_confirmed,stop_errors=stop_errors,cancel_status=cancel,cleanup=cleanup,test_verdict='NOT_RUN',
                         coverage={'ros_endpoint':False,'lifecycle_mock':False,'jetson_cpu':False,'isaac_ros_gpu':False,'actual_sim':False,'physical':False})
            atomic(state/'status.json',summary);atomic(state/'public/summary.json',summary);journal(state,'STOPPED',{'cleanup':cleanup['status']})
            server.close()
            if endpoint.exists():endpoint.unlink()
            for s,handler in previous.items():signal.signal(s,handler)
        return summary


def load_profile_digest(profile):
    from nvidia_profile import validate, read_json
    validate(profile,read_json(HERE/('profiles/schema-v%d.json'%profile['schema_version'])))
    return digest(profile)


def recover(state,cleanup=False):
    with exclusive(state):
        read_journal(state)
        try:request(state,'status')
        except (OSError,ValueError):pass
        else:raise ValueError('controller is alive')
        rig=Rig(state);ids=rig.owned()
        if not cleanup:return {'execution_status':'ORPHANED','owned_containers':ids,'cleanup_requested':False,'hardware_verified':False}
        journal(state,'RECOVERY_CLEANUP_INTENT');result=rig.cleanup()
        out={'execution_status':'STOPPED','controller_live':False,'cleanup':result,'stop_confirmed':False,'test_verdict':'NOT_RUN','hardware_verified':False,'support_status':'UNVERIFIED'}
        atomic(state/'status.json',out);atomic(state/'public/summary.json',out);journal(state,'RECOVERED_LOCKED')
        return out


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('command',choices=['prepare','serve','status','stop','idle','exercise','recover','doctor','export','fixture'])
    ap.add_argument('--state',required=True,type=Path);ap.add_argument('--profile',type=Path);ap.add_argument('--core',type=Path)
    ap.add_argument('--cleanup',action='store_true');ap.add_argument('--dest',type=Path)
    ap.add_argument('--fixture',action='store_true',help='prepare a Sim-only fixture state; never a support claim')
    ap.add_argument('--payload',help='JSON payload for the fixture command')
    a=ap.parse_args()
    if a.state.is_symlink():raise ValueError('symlink state')
    state=a.state.resolve()
    if a.command in ('prepare','doctor'):
        if not a.profile:raise ValueError('--profile required')
        profile=load(a.profile)
        if profile['schema_version'] not in (2,3,4):raise ValueError('v2, v3 or v4 profile required')
        if a.command=='doctor':out=collect(profile,state)
        else:
            if not a.core:raise ValueError('--core required')
            out=prepare(state,profile,a.core.resolve(),fixture=a.fixture)
    elif a.command=='serve':out=serve(state)
    elif a.command=='fixture':out=request(state,'fixture',json.loads(a.payload) if a.payload else None)
    elif a.command=='status':out=status(state)
    elif a.command=='recover':out=recover(state,a.cleanup)
    elif a.command=='export':
        if not a.dest:raise ValueError('--dest required')
        out=export(state,a.dest)
    elif a.command=='stop':
        # Return only after the controller has written its durable summary, so `export` can follow immediately
        # (preview.14 L-3: an export issued right after the stop request found no summary yet).
        out=request(state,'stop')
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            current=read(state/'status.json')
            if current.get('controller_live') is False:out=current;break
            time.sleep(.5)
        else:out=dict(out,stop_wait='controller still finishing after 120 s; check status before export')
    else:out=request(state,a.command)
    print(json.dumps(out,indent=2))
    return 3 if out.get('overall')=='INCONCLUSIVE' or out.get('execution_status')=='ORPHANED' else 2 if out.get('overall')=='FAIL' or out.get('request_accepted') is False else 4 if out.get('execution_status')=='FAULT_LOCKED' else 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError,RuntimeError,subprocess.SubprocessError) as ex:
        print(json.dumps({'error':str(ex),'hardware_verified':False,'execution_status':'REFUSED'}));raise SystemExit(2)
