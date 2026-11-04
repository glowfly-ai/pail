# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Authorized tests against this tool's own isolated synthetic rig. Never prints key bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from state_store import read,atomic
from isolation_files import ROLES,UIDS
from isolation_runtime import IsolatedRig,SERVICES
from check_managed import normal,attack,await_value,finish_controller,write_suite
from session import prepare,request,status
from nvidia_profile import load
from runtime import HERE


def matrix(rig):
    rig.owned();manifest=read(rig.state/'role-views.json')
    code="""import hashlib,json,os,socket
from pathlib import Path
spec=json.load(__import__('sys').stdin);role=spec['role'];roles=spec['roles'];own=roles[role]
seen=[]
for p in Path('/etc/pail').rglob('*'):
 if p.is_file():
  try:seen.append(hashlib.sha256(p.read_bytes()).hexdigest())
  except OSError:pass
own_ok=all(item['sha256'] in seen for item in own['files'].values() if item['private'])
foreign=[name for name,data in roles.items() if name!=role and any(x['private'] and x['sha256'] in seen for x in data['files'].values())]
reserved=['/etc/pail/grpc_certs/ca.key','/etc/pail/sros2_keystore/private/identity_ca.key.pem','/etc/pail/sros2_keystore/private/permissions_ca.key.pem','/etc/pail/keys/operator_ed25519.json','/root-keys/root.json','/var/run/docker.sock']
reserved_readable=0
for path in reserved:
 try:
  with open(path,'rb') as f:reserved_readable+=bool(f.read(1))
 except OSError:pass
try:
 raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));raw.close();raw_allowed=True
except OSError:raw_allowed=False
print(json.dumps({'uid':os.getuid(),'pid_namespace':os.readlink('/proc/self/ns/pid'),'ipc_namespace':os.readlink('/proc/self/ns/ipc'),'own_material_available':own_ok,'foreign_material_available':foreign,'reserved_material_readable':reserved_readable,'raw_socket_allowed':raw_allowed}))
"""
    results={}
    for role in ROLES:
        python='/isaac-sim/kit/python/bin/python3' if role=='endpoint' and rig.data['profile']['schema_version']==4 else 'python3'
        r=subprocess.run(rig.c+['exec','-T',role,python,'-c',code],input=json.dumps({'role':role,'roles':manifest['roles']}),capture_output=True,text=True,timeout=15)
        if r.returncode:raise AssertionError('matrix probe failed: %s rc=%s stderr=%s'%(role,r.returncode,r.stderr[-400:].strip()))
        data=json.loads(r.stdout)
        assert data['uid']==UIDS[role] and data['own_material_available'] and not data['foreign_material_available'] and data['reserved_material_readable']==0 and not data['raw_socket_allowed'],(role,data)
        results[role]=data
    assert len({d['pid_namespace'] for d in results.values()})==len(ROLES),'PID sharing'
    assert len({d['ipc_namespace'] for d in results.values()})==len(ROLES),'IPC sharing'
    return results


def boundary_writes(rig):
    code="""import json,os
paths=['/control/managed.json','/etc/pail/.write-probe','/evidence/monitor/.write-probe','/var/lib/pail_robot_agent/report_queue/.write-probe']
result=[]
for p in paths:
 try:
  f=open(p,'ab');f.write(b'ISOLATION_TEST');f.close();result.append(False)
 except OSError:result.append(True)
print(json.dumps({'blocked':result}))
"""
    r=subprocess.run(rig.c+['exec','-T','planner','python3','-c',code],capture_output=True,text=True,timeout=10)
    if r.returncode:raise AssertionError('write probe failed')
    d=json.loads(r.stdout);assert all(d['blocked']),d;return d


def inspect_mounts(rig):
    ids=rig.owned();infos=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
    rows=[]
    for c in infos:
        role=c['Config']['Labels']['org.pail.role'];h=c['HostConfig']
        assert h['ReadonlyRootfs'] and not h['Privileged'] and not h['PidMode'] and h['IpcMode']=='private'
        assert h['CapDrop']==['ALL'] and any('no-new-privileges' in x for x in h['SecurityOpt'])
        assert c['Config']['User']==str(UIDS.get(role,11100))+':'+str(UIDS.get(role,11100))
        conf=[m for m in c['Mounts'] if m['Destination']=='/etc/pail']
        if role!='netspace':assert len(conf)==1 and not conf[0]['RW'] and Path(conf[0]['Source']).parts[-3:]==('role-views',role,'config')
        else:assert not conf
        assert not any(m['Destination'] in ('/var/run/docker.sock','/state','/work') for m in c['Mounts'])
        rows.append({'role':role,'uid':c['Config']['User'],'readonly_root':True,'capabilities_dropped':True,'own_view_only':True})
    assert len(rows)==len(SERVICES);return rows


def unauthenticated_tls(rig):
    # Public CA only; giving the test its trust anchor does not give it a client identity.
    ca=subprocess.check_output(rig.c+['exec','-T','requester','cat','/etc/pail/grpc_certs/ca.crt'])
    code="""import ssl,socket,sys,json
ca=sys.stdin.read();out=[]
for port in (50051,50061):
 ctx=ssl.create_default_context(cadata=ca);ctx.maximum_version=ssl.TLSVersion.TLSv1_2
 try:
  with socket.create_connection(('127.0.0.1',port),timeout=5) as raw:
   with ctx.wrap_socket(raw,server_hostname='127.0.0.1'):out.append({'port':port,'refused':False})
 except ssl.SSLError as e:out.append({'port':port,'refused':True,'reason':e.reason})
print(json.dumps(out))
"""
    result=subprocess.run(rig.c+['exec','-T','planner','python3','-c',code],input=ca,capture_output=True,timeout=15)
    if result.returncode:raise AssertionError('anonymous TLS probe did not execute')
    rows=json.loads(result.stdout)
    # A server that requires a client certificate refuses this probe with a fatal alert; the alert's name depends on
    # the protocol and the server's TLS stack: TLS 1.3 says certificate_required, TLS 1.2 said bad_certificate with
    # Go up to 1.26 and says handshake_failure (RFC 5246 section 7.4.6) from Go 1.27. All three are the same refusal;
    # a completed handshake (refused=False) is the only failure.
    REFUSALS=('SSLV3_ALERT_BAD_CERTIFICATE','TLSV13_ALERT_CERTIFICATE_REQUIRED','SSLV3_ALERT_HANDSHAKE_FAILURE')
    assert len(rows)==2 and all(r['refused'] and r['reason'] in REFUSALS for r in rows),rows
    positive_code="""import ssl,socket,json
ctx=ssl.create_default_context(cafile='/etc/pail/grpc_certs/ca.crt');ctx.maximum_version=ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain('/etc/pail/grpc_certs/robot-01/client.crt','/etc/pail/grpc_certs/robot-01/client.key')
out=[]
for port in (50051,50061):
 with socket.create_connection(('127.0.0.1',port),timeout=5) as raw:
  with ctx.wrap_socket(raw,server_hostname='127.0.0.1') as tls:out.append({'port':port,'accepted':True,'protocol':tls.version()})
print(json.dumps(out))
"""
    positive=subprocess.run(rig.c+['exec','-T','requester','python3','-c',positive_code],capture_output=True,text=True,timeout=15)
    assert positive.returncode==0,'authenticated TLS control failed'
    accepted=json.loads(positive.stdout);assert len(accepted)==2 and all(r['accepted'] and r['protocol']=='TLSv1.2' for r in accepted)
    return {'anonymous':rows,'authenticated_control':accepted}


def check_running(state):
    rig=IsolatedRig(state);normal(rig,state)
    request(state,'idle');mark=len(rig.rows('monitor'))
    await_value(lambda:any(x.get('event')=='observed' and x['snapshot']['applied_linear_x']==0 for x in rig.rows('monitor')[mark:]),'post-cancel zero')
    result={'normal_authorization':True,'mounts':inspect_mounts(rig),'matrix':matrix(rig),'writes':boundary_writes(rig),'anonymous_tls':unauthenticated_tls(rig),'impersonation':[],'own_identity_denials':[],'hardware_verified':False}
    # A compromised planner can choose its environment, but has no foreign identity material.
    for identity in ('/pep_gate','/motion_bridge','/nv_monitor'):
        result['impersonation'].append(attack(rig,'/drive_cmd_vel',identity))
    for topic in ('/safe_cmd_vel','/drive_cmd_vel','/pail/permit'):
        result['own_identity_denials'].append(attack(rig,topic,'/oem_planner'))
    result['test_verdict']='PASS';atomic(state/'public/isolation-checks.json',result)
    return result


def run(root,core,count):
    results=[];expected=[('isolation',i) for i in range(count)];write_suite(root,results,expected)
    for i in range(count):
        state=root/('isolation-'+str(i));print('START isolation',i,flush=True)
        prepare(state,load(HERE/'profiles/mock-humble-v3.json'),core)
        with (state/'logs/supervisor.log').open('w') as log:
            proc=subprocess.Popen([sys.executable,'-B',str(HERE/'session.py'),'serve','--state',str(state)],stdout=log,stderr=subprocess.STDOUT)
        try:
            await_value(lambda:status(state).get('execution_status')=='READY_LOCKED','isolated ready',90)
            report=check_running(state);finish_controller(state,proc)
            final=read(state/'public/summary.json');assert final['cleanup']['status']=='PASS' and not final['cleanup']['remaining_containers']
            final.update(test_verdict='PASS',role_isolation_verified=True);atomic(state/'public/summary.json',final)
            results.append({'case':'isolation','repeat':i,'test_verdict':'PASS','roles':len(report['matrix']),'cleanup':final['cleanup']});write_suite(root,results,expected);print('PASS isolation',i,flush=True)
        except Exception as e:
            write_suite(root,results,expected,error={'case':i,'detail':str(e)});raise
        finally:
            if proc.poll() is None:
                try:finish_controller(state,proc)
                except Exception:
                    proc.terminate()
                    try:proc.wait(timeout=40)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait()


def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--core',type=Path);a.add_argument('--root',type=Path);a.add_argument('--repeat',type=int,default=3);a.add_argument('--existing',type=Path)
    args=a.parse_args()
    if args.existing:
        r=check_running(args.existing.resolve());print(json.dumps({'test_verdict':r['test_verdict'],'roles':len(r['matrix'])}));return
    if not args.core or not args.root or args.repeat<1:raise ValueError('core, new root and positive repeat required')
    args.root.mkdir(mode=0o700,exist_ok=False);run(args.root.resolve(),args.core.resolve(),args.repeat)

if __name__=='__main__':main()
