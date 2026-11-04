# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Container-side software-preview fixtures, readiness and evidence collection."""
import argparse, hashlib, importlib.util, json, os, shutil, socket, sys, time
from pathlib import Path
import grpc
import yaml
import pail_pb2 as pb
import pail_pb2_grpc as rpc

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'common'))
from core_operation_wire import check_no_contract_setting,submit_outcome
STATE=Path('/state')

def write_json(p,obj,mode=0o644):
    p.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,mode)
    os.fchmod(fd,mode)
    with os.fdopen(fd,'w') as f: json.dump(obj,f,indent=2);f.write('\n')

def prepare():
    priv=STATE/'private/config';pub=STATE/'public/config'
    for path,mode in [(STATE/'private',0o700),(priv,0o700),(STATE/'private/blackbox',0o700),(STATE/'private/observe-blackbox',0o700),(STATE/'private/agent-key',0o700),(STATE/'public',0o755),(pub,0o755),(pub/'keys',0o755),(STATE/'evidence',0o755),(Path('/run/duck'),0o755),(Path('/run/duck/raw'),0o750)]:
        path.mkdir(parents=True,exist_ok=True);path.chmod(mode)
    spec=importlib.util.spec_from_file_location('keygen','/opt/pail/keygen.py');kg=importlib.util.module_from_spec(spec);spec.loader.exec_module(kg)
    kg.KEYS=str(priv/'keys');kg.selftest();kg.generate(False)
    shutil.copyfile(priv/'keys/agent_ed25519.json',STATE/'private/agent-key/agent_ed25519.json');(STATE/'private/agent-key/agent_ed25519.json').chmod(0o600)
    for base in [priv,pub]:
        for n in ['policy.yaml','duck_skills.yaml','skills.microduck.yaml']:
            shutil.copyfile(HERE/'fixtures'/n,base/n);(base/n).chmod(0o644)
        shutil.copyfile(HERE/'fixtures/site.yaml',base/'site_model.yaml');(base/'site_model.yaml').chmod(0o644)
    # Synthetic, unused TLS fingerprint: transport is explicitly dev-only on an isolated network.
    (priv/'robot_registry.yaml').write_text(yaml.safe_dump({'version':1,'robots':[{'robot_id':'robot-1','role':'robot','fingerprints':[hashlib.sha256(b'microduck-software-only-unused-tls-binding').hexdigest()]}]}));(priv/'robot_registry.yaml').chmod(0o644)
    shutil.copyfile(priv/'robot_registry.yaml',pub/'robot_registry.yaml');(pub/'robot_registry.yaml').chmod(0o644)
    shutil.copyfile(priv/'keys/keyring.json',pub/'keys/keyring.json');(pub/'keys/keyring.json').chmod(0o644)
    observe=yaml.safe_load((pub/'policy.yaml').read_text());observe['gate_mode']='observe'
    (pub/'policy.observe.yaml').write_text(yaml.safe_dump(observe,sort_keys=False));(pub/'policy.observe.yaml').chmod(0o644)
    for base in [STATE/'private',Path('/run/duck')]:
        for p in [base]+list(base.rglob('*')):
            if p.is_symlink():raise ValueError('Unexpected symlink in generated state')
            os.chown(p,10001,10001)
    print('PREPARED: fresh private keys, public verification material, scoped socket volume')

def uds(path,msg):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(3);s.connect(str(path));s.sendall((json.dumps(msg)+'\n').encode());f=s.makefile('rb');return json.loads(f.readline())

def ready():
    hello=uds('/run/duck/raw/robotd.sock',{'jsonrpc':'2.0','id':1,'method':'hello','params':{'api_version':44}})
    uds('/run/duck/pail.sock',{'jsonrpc':'2.0','id':2,'method':'hello','params':{'api_version':44}})
    if hello.get('result',{}).get('api_version') != 44: raise RuntimeError('Unexpected upstream API: '+str(hello))
    grpc.channel_ready_future(grpc.insecure_channel('issuer:50051')).result(timeout=3)
    import token_service_pb2 as token_pb, token_service_pb2_grpc as token_rpc
    token_rpc.TokenServiceStub(grpc.insecure_channel('agent:50051')).GetActiveToken(token_pb.GetActiveTokenRequest(robot_id='robot-1'),timeout=3)
    if not Path('/run/duck/gate.ndjson').exists():raise RuntimeError('Missing gate observation file')
    print(json.dumps({'ready':True,'upstream':hello}))

def permissions():
    import stat,subprocess
    checks=[]
    for p in (STATE/'private/config/keys').glob('*ed25519*.json'):
        mode=stat.S_IMODE(p.stat().st_mode)
        if mode!=0o600 or p.stat().st_uid!=10001:raise RuntimeError('Private key ownership/mode contract failed')
    # The same unprivileged requester can reach the public socket and read public
    # verification material, but cannot reach the raw socket or read private keys.
    child="""import os,socket,errno
os.setgroups([]);os.setgid(10002);os.setuid(12345)
s=socket.socket(socket.AF_UNIX);s.connect('/run/duck/pail.sock');s.close()
open('/state/public/config/keys/keyring.json').read(1)
for path,kind in [('/run/duck/raw/robotd.sock','socket'),('/state/private/config/keys/issuer_ed25519.json','file')]:
 try:
  if kind=='socket':s=socket.socket(socket.AF_UNIX);s.connect(path)
  else:open(path).read(1)
 except OSError as e:
  if e.errno not in (errno.EACCES,errno.EPERM):raise
 else:raise RuntimeError('Restricted resource was reachable: '+kind)
print('PUBLIC_AND_PRIVATE_ACCESS_PASS')
"""
    subprocess.run([sys.executable,'-B','-c',child],check=True)
    write_json(STATE/'evidence/permissions.json',{'status':'PASS','private_key_mode':'0600','service_uid':10001,'requester_uid':12345,'public_access':True,'raw_access_denied':True,'private_key_read_denied':True})


def demo():
    from runner.adapters.microduck_backend import _FarSide,_MovePublisher,_GateLogTail
    far=_FarSide('/run/duck/raw/robotd.sock');far.start()
    tail=_GateLogTail('/run/duck/gate.ndjson');tail.start();checks=[]
    def wait(pred,seconds=12):
        until=time.monotonic()+seconds
        while time.monotonic()<until:
            if pred():return
            time.sleep(.05)
        raise RuntimeError('Observation deadline expired')
    def check(name,ok,detail):
        checks.append({'id':name,'status':'PASS' if ok else 'FAIL','detail':detail})
        print(('PASS 'if ok else 'FAIL ')+name,flush=True)
        if not ok:raise RuntimeError(name)
    wait(lambda:len(far.history)>2)
    def events(start,state=None,reason=None):
        return [x for x in tail.since(start) if x.get('kind')=='outcome' and (state is None or x.get('state')==state) and (reason is None or x.get('reason')==reason)]
    pub=None
    try:
        start=time.time();far.clear();pub=_MovePublisher('/run/duck/pail.sock',.12,0.,20.,20.);pub.start()
        wait(lambda:events(start,'BLOCK','ERR_NO_TOKEN'));time.sleep(.5)
        check('no_token_blocks',not any(abs(x.linear_x-.12)<1e-6 for x in far.requested_history),'Live observer plus explicit NO_TOKEN refusal')
        pub.stop();pub=None
        plan=pb.ActionPlan(plan_id='preview-'+str(time.time_ns()));step=plan.steps.add(step_id='move-1',type=pb.STEP_TWIST)
        step.twist.linear_x=.12;step.twist.duration_sec=20
        stub=rpc.PailNorthboundStub(grpc.insecure_channel('issuer:50051'))
        request=pb.SubmitActionPlanRequest(session_id='preview',robot_id='robot-1',plan=plan)
        check_no_contract_setting();request.operation_id=plan.plan_id
        result=stub.SubmitActionPlan(request,timeout=5)
        if submit_outcome(request,result)!='AUTHORIZED':raise RuntimeError('AUTHORIZATION_NOT_CONFIRMED')
        write_json(STATE/'evidence/plan-response.json',{'status':str(result.status),'reason':str(result)[:1000]})
        start=time.time();pub=_MovePublisher('/run/duck/pail.sock',.12,0.,20.,20.);pub.start();wait(lambda:events(start,'PERMIT'))
        wait(lambda:any(abs(x.linear_x-.12)<1e-6 for x in far.requested_history));check('authorized_forward',True,'PERMIT plus far-side observation')
        pub.stop();pub=None
        start=time.time();pub=_MovePublisher('/run/duck/pail.sock',1.2,0.,20.,20.);pub.start();wait(lambda:events(start,'BLOCK','ERR_CONSTRAINT'));time.sleep(.5)
        check('over_limit_blocks',not any(abs(x.linear_x-1.2)<1e-6 for x in far.requested_history),'1.2 exceeds configured 1.0; no far-side matching command')
    finally:
        if pub:pub.stop()
        write_json(STATE/'evidence/far-side.json',{'applied':[vars(x)for x in far.history],'requested':[vars(x)for x in far.requested_history]})
        write_json(STATE/'evidence/demo.json',{'schema_version':1,'hardware_tested':False,'checks':checks})

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('action',choices=['prepare','ready','permissions','demo']);a=ap.parse_args();globals()[a.action]()
