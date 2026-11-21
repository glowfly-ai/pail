# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Isolated managed synthetic rig. Reuses PAIL's guarded images and provisioning."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from state_store import atomic, read, source_hashes, journal

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'common'))
from compose_failure import failed_step  # P24-L1: a failed compose/docker step names the daemon's condition

class Rig:
    def __init__(self,state):
        self.state=Path(state);self.data=read(self.state/'prepared.json');self.core=Path(self.data['core'])
        self.rig=self.state/'rig';self.cfg=self.rig/'runtime/config';self.ref=self.rig/'runtime/reference'
        self.project=self.data['project'];self.images=self.data['runtime']['images']
        self.c=['docker','compose','-p',self.project,'-f',str(self.state/'compose.json')]
    def command(self,args,label,timeout=120):
        log=self.state/'logs'/(label+'.log')
        # Docker platform warnings are diagnostics, not part of JSON stdout.
        # Preserve both streams without feeding stderr into machine parsers.
        with log.open('w') as f,log.with_suffix('.stderr.log').open('w') as err:
            r=subprocess.run(args,stdout=f,stderr=err,timeout=timeout)
        if r.returncode:raise RuntimeError(failed_step(label,r.returncode,log,log.with_suffix('.stderr.log'))+' and .stderr.log')
        return log.read_text()
    def bootstrap(self):
        ci=self.images['issuer'];gi=self.images['tb3_gate']
        self.command([sys.executable,'-B',str(self.core/'examples/tb3/permissions.py'),'init','--state',str(self.rig)],'directories')
        for name in ('policy.yaml','sros2_policy.xml','skills.diff_drive_amr.yaml'):
            shutil.copyfile(self.core/'config'/name,self.cfg/name)
        pol=(self.cfg/'policy.yaml').read_text().replace('max_linear_speed_mps: 1.0','max_linear_speed_mps: 0.1').replace('sls.linear_mps: 1.0','sls.linear_mps: 0.1').replace('token_ttl_ms: 3600000','token_ttl_ms: 30000')
        if '\ntoken_schema:' in pol:raise ValueError('review token schema override')
        (self.cfg/'policy.yaml').write_text(pol+'\ntoken_schema: 5\n')
        shutil.copyfile(self.core/'examples/tb3/site_model.yaml',self.cfg/'site_model.yaml')
        # Extend only generated development policy, never the existing Core/TB3 policy.
        tree=ET.parse(self.cfg/'sros2_policy.xml');enclaves=tree.getroot().find('enclaves')
        for name,pubs,subs in [('nv_endpoint',['pail/nvidia/endpoint_state'],['drive_cmd_vel']),('nv_monitor',[],['pail/nvidia/endpoint_state','pail/gate_state','pail/bridge_state'])]:
            enclave=ET.SubElement(enclaves,'enclave',path='/'+name)
            profile=ET.SubElement(ET.SubElement(enclave,'profiles'),'profile',ns='/',node=name)
            for action,topics in [('publish',pubs+['rosout','parameter_events']),('subscribe',subs+['parameter_events'])]:
                group=ET.SubElement(profile,'topics',**{action:'ALLOW'})
                for topic in topics:ET.SubElement(group,'topic').text=topic
        tree.write(self.cfg/'sros2_policy.xml',encoding='unicode',xml_declaration=True)
        shutil.copyfile(self.core/'scripts/gen_dev_keys.py',self.rig/'runtime/scripts/gen_dev_keys.py')
        self.command([sys.executable,'-B',str(self.rig/'runtime/scripts/gen_dev_keys.py')],'dev-keys')
        self.command(['docker','run','--rm','--network','none','-u',str(os.getuid())+':'+str(os.getgid()),'-e','HOME=/tmp','-v',str(self.core)+':/src:ro','-v',str(self.rig)+':/state','--entrypoint','bash',gi,'-c','source /opt/ros/humble/setup.bash && bash /src/scripts/sros2_provision.sh /state/runtime/config robot-01'],'provision',180)
        der=subprocess.check_output(['openssl','x509','-in',str(self.cfg/'grpc_certs/robot-01/client.crt'),'-outform','DER'])
        fingerprint=hashlib.sha256(der).hexdigest()
        (self.cfg/'requesters.yaml').write_text('version: 1\nrequesters:\n  - match: {caller: mtls, cert_sha256: "'+fingerprint+'"}\n    kind: agentic_ai\n    id: reference-planner\n    skills: [twist]\n')
        def sign(args,label):
            return self.command(['docker','run','--rm','--network','none','-u',str(os.getuid())+':'+str(os.getgid()),'-v',str(self.cfg)+':/config','-v',str(self.rig/'root-keys')+':/root-keys','--entrypoint','pail-keyring-sign',ci]+args,label)
        output=sign(['gen-root','--out','/root-keys/root.json','--key-id','reference-root'],'root-key')
        pub=next(line.split('=',1)[1] for line in output.splitlines() if line.startswith('ROOT_PUBKEY_B64='))
        (self.cfg/'keys/root_pub.b64').write_text(pub+'\n')
        now=int(time.time());atomic(self.cfg/'keys/payload.json',dict(bundle_version=1,issued_at_unix=now,expires_at_unix=now+3600,keys=read(self.cfg/'keys/keyring.json')['keys']))
        sign(['sign','--root','/root-keys/root.json','--payload','/config/keys/payload.json','--out','/config/keys/keyring_bundle.json'],'sign-keyring')
        self.command([sys.executable,'-B',str(self.core/'examples/tb3/permissions.py'),'stage','--state',str(self.rig),'--core',str(self.core)],'reference-files')
        shutil.copyfile(HERE/'ros_endpoint.py',self.ref/'ros_endpoint.py');(self.ref/'ros_endpoint.py').chmod(0o644)
        atomic(self.ref/'nv-meta.json',dict(run_id=self.data['run_id'],generation=self.data['generation'],timeout_ms=self.data['profile']['endpoint']['model_timeout_ms']),0o644)
        # Public policy copy is the effective readonly mount; host need not read UID10001 private config after chown.
        shutil.copyfile(self.cfg/'sros2_policy.xml',self.ref/'sros2_policy.xml');(self.ref/'sros2_policy.xml').chmod(0o644)
        self.control(False,0,0)
        self.command(['docker','run','--rm','--network','none','-u','0','-v',str(self.rig)+':/state','--entrypoint','python3',gi,'/state/runtime/reference/permissions.py','prepare','--state','/state'],'permissions')
        env={'ROS_DOMAIN_ID':'0','ROS_SECURITY_ENABLE':'true','ROS_SECURITY_STRATEGY':'Enforce','ROS_SECURITY_KEYSTORE':'/etc/pail/sros2_keystore','FASTRTPS_DEFAULT_PROFILES_FILE':'/reference/fastdds_loopback.xml','PAIL_PROFILE':'dev','PAIL_ROBOT_ID':'robot-01','PAIL_GRPC_TLS':'on','PAIL_KEYRING_MODE':'bundle','PAIL_KEYRING_BUNDLE':'/etc/pail/keys/keyring_bundle.json','PAIL_ROOT_PUBKEY_FILE':'/etc/pail/keys/root_pub.b64','PAIL_KEYRING_STATE':'/var/lib/pail_keyring/state.json','PAIL_KEYRING_MAX_LIFETIME_SEC':'86400'}
        labels={'org.pail.nvidia.run':self.data['run_id'],'org.pail.nvidia.generation':self.data['generation']}
        common={'cap_drop':['ALL'],'pids_limit':256,'labels':labels,'restart':'no'}
        def mounts(role):
            values=[str(self.cfg)+':/etc/pail:ro',str(self.ref/'sros2_policy.xml')+':/etc/pail/sros2_policy.xml:ro',str(self.rig/'keyring-state')+':/var/lib/pail_keyring']
            if role=='issuer':values.append(str(self.rig/'blackbox')+':/var/log/pail_blackbox')
            else:values += [str(self.ref)+':/reference:ro',str(self.rig/'control')+':/control:ro',str(self.rig/'evidence')+':/evidence']
            return values
        services={'netspace':dict(common,image=ci,command=['/usr/local/bin/pail_split','hold'],ipc='shareable',cpus=.05,mem_limit='64m',memswap_limit='64m'),
                  'issuer':dict(common,image=ci,command=['/usr/local/bin/pail_split'],network_mode='service:netspace',cpus=.6,mem_limit='512m',memswap_limit='512m',volumes=mounts('issuer'),environment=dict(env,PAIL_ISSUER_KEY_ID='dev-key-1',PAIL_GRPC_CLIENT_CERT='/etc/pail/grpc_certs/robot-01/client.crt',PAIL_GRPC_CLIENT_KEY='/etc/pail/grpc_certs/robot-01/client.key',PAIL_KEYRING_POLL_SEC='0',PAIL_SITE_MODEL='/etc/pail/site_model.yaml',PAIL_REQUESTERS='/etc/pail/requesters.yaml',PAIL_CHECKPOINT_EVERY_RECORDS='10')),
                  'robot':dict(common,image=gi,network_mode='service:netspace',ipc='service:netspace',cpus=1.35,mem_limit='2496m',memswap_limit='2496m',volumes=mounts('robot'),entrypoint=['/bin/bash','-c'],command=['source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && exec ros2 launch /reference/tb3_reference.launch.py'],environment=dict(env,PAIL_GRPC_CERT='/etc/pail/grpc_certs/robot-01/client.crt',PAIL_GRPC_KEY='/etc/pail/grpc_certs/robot-01/client.key',PAIL_TOKEN_PROVIDER_MODE='grpc',PAIL_TOKEN_SERVICE_ADDR='127.0.0.1:50051'))}
        atomic(self.state/'compose.json',{'services':services,'networks':{'default':{'internal':True,'labels':labels}}})
        seal={'compose':hashlib.sha256((self.state/'compose.json').read_bytes()).hexdigest(),'reference':source_hashes(self.ref),'policy':hashlib.sha256((self.ref/'sros2_policy.xml').read_bytes()).hexdigest()}
        atomic(self.state/'runtime-seal.json',seal)
        # Cross-UID hash witness before any command-producing node starts.
        witness=self.command(['docker','run','--rm','--network','none','-u','10001:10001','-v',str(self.ref)+':/reference:ro','--entrypoint','python3',gi,'-c','import hashlib,json;from pathlib import Path;print(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("/reference").iterdir() if p.is_file()}))'],'reference-witness')
        if json.loads(witness)!=seal['reference']:raise ValueError('reference bytes differ inside container')
    def sealed(self):
        seal=read(self.state/'runtime-seal.json')
        if hashlib.sha256((self.state/'compose.json').read_bytes()).hexdigest()!=seal['compose'] or source_hashes(self.ref)!=seal['reference'] or hashlib.sha256((self.ref/'sros2_policy.xml').read_bytes()).hexdigest()!=seal['policy']:
            raise ValueError('runtime configuration/reference changed')
        return seal
    def up(self):
        self.sealed();journal(self.state,'CREATE_INTENT',{'project':self.project})
        self.command(self.c+['create'],'create')
        ids=subprocess.check_output(self.c+['ps','-aq'],text=True).split()
        containers=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
        owned=[]
        for c in containers:
            if c['HostConfig']['Privileged'] or c['HostConfig'].get('Devices') or c['HostConfig'].get('PortBindings') or c['HostConfig']['NetworkMode']=='host':raise ValueError('unsafe runtime layout')
            owned.append({'id':c['Id'],'image':c['Image'],'labels':c['Config']['Labels']})
        if len(owned)!=3:raise ValueError('incomplete container set')
        atomic(self.state/'ownership.json',{'containers':owned});journal(self.state,'CREATED',{'ids':ids})
        self.command(self.c+['start'],'start')
        self.wait(lambda:self.probe('peek').get('status')=='NO_TOKEN','issuer ready')
        for role,enclave in [('endpoint','nv_endpoint'),('monitor','nv_monitor'),('planner','oem_planner')]:self.actor(role,enclave)
        for role,enclave in [('safety','safety_adapter'),('evidence','perception')]:self.actor(role,enclave,original=True)
        self.wait(lambda:all(any(r['event']=='ready' for r in self.rows(role)) for role in ('endpoint','monitor','planner')),'actors ready')
        self.wait(lambda:any(r['event']=='gate' for r in self.rows('monitor')) or 'S33 OK' in subprocess.check_output(self.c+['logs','--no-color','robot'],text=True,stderr=subprocess.DEVNULL),'gate readiness')
        # Node construction is not DDS delivery readiness. Do not arm until the independent observer is actually connected.
        self.wait(lambda:any(r.get('event')=='observed' and r['snapshot']['applied_linear_x']==0 and r['snapshot']['applied_angular_z']==0 for r in self.rows('monitor')),'independent zero observation')
    def actor(self,role,enclave,original=False):
        if role not in ('endpoint','monitor','planner','safety','evidence','permit_fixture'):raise ValueError('unknown actor')
        script='mock_io.py' if original else 'ros_endpoint.py'
        line='source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && exec python3 -u /reference/'+script+' --role '+role+' > /evidence/runtime/'+role+'-process.log 2>&1'
        self.command(self.c+['exec','-d','-e','ROS_SECURITY_ENCLAVE_OVERRIDE=/'+enclave,'robot','bash','-c',line],'actor-'+role)
    def probe(self,mode,plan=None):
        args=self.c+['exec','-T','issuer','tb3-probe','-mode',mode]
        if mode=='submit':args+=['-duration','20']
        if plan:args+=['-plan',plan]
        r=subprocess.run(args,capture_output=True,text=True,timeout=15)
        if r.returncode:raise RuntimeError('probe failed')
        return json.loads(r.stdout)
    def control(self,on,heartbeat,instruction,speed=.05):
        atomic(self.rig/'control/managed.json',dict(generation=self.data['generation'],on=on,heartbeat=heartbeat,instruction=instruction,speed=speed),0o644)
    def service(self,role):return 'robot'
    def log_path(self,role):return self.rig/'evidence/runtime'/(role+'.jsonl')
    def rows(self,role):
        path=self.log_path(role)
        if not path.exists():return []
        data=path.read_text()
        # Concurrent append may have a partial final line; only closed records count.
        return [json.loads(x) for x in data[:data.rfind('\n')+1].splitlines()]
    def tail_rows(self,role,cursor=0):
        """Closed records appended after byte offset ``cursor``; returns (rows,new_cursor).

        A 60 Hz SDK endpoint writes tens of MB per few minutes. Re-parsing the whole
        role log on every controller tick starved the 100 ms heartbeat and aged the
        latest observation past its 500 ms freshness window (Brev i10/i11, 2026-10-15),
        so periodic readers must consume only appended bytes. ``cursor=None`` starts at
        the current end. A shrinking log is evidence loss, never an empty update.
        """
        path=self.log_path(role)
        if not path.exists():
            if cursor:raise ValueError('role log disappeared: '+role)
            return [],0
        with path.open('rb') as f:
            f.seek(0,2);size=f.tell()
            if cursor is None:return [],size
            if size<cursor:raise ValueError('role log truncated: '+role)
            f.seek(cursor);data=f.read()
        end=data.rfind(b'\n')+1
        return [json.loads(x) for x in data[:end].splitlines()],cursor+end
    def last_row(self,role,match=lambda row:True,window=65536):
        """Latest closed record satisfying ``match``, read from the file tail only."""
        path=self.log_path(role)
        if not path.exists():return None
        with path.open('rb') as f:
            f.seek(0,2);size=f.tell();span=window
            while True:
                start=max(0,size-span);f.seek(start);data=f.read(size-start)
                closed=data[:data.rfind(b'\n')+1]
                if start:closed=closed[closed.find(b'\n')+1:]  # drop the partial head line of a mid-file window
                for line in reversed(closed.splitlines()):
                    row=json.loads(line)
                    if match(row):return row
                if start==0:return None
                span*=4
    def wait(self,fn,label,timeout=45):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            try:
                if fn():return
            except (RuntimeError,ValueError,subprocess.SubprocessError):pass
            time.sleep(.1)
        raise RuntimeError('unobserved: '+label)
    def observations(self):
        ids=self.owned()
        if len(ids)!=3:raise ValueError('incomplete runtime')
        code="""import json,os,time,shutil
from pathlib import Path
from rclpy.utilities import get_rmw_implementation_identifier
read=lambda p:Path(p).read_text().strip() if Path(p).exists() else None
print(json.dumps(dict(ros=os.getenv('ROS_DISTRO'),rmw=get_rmw_implementation_identifier(),uid=os.getuid(),security=os.getenv('ROS_SECURITY_STRATEGY'),memory_max=read('/sys/fs/cgroup/memory.max'),memory_current=read('/sys/fs/cgroup/memory.current'),runtime_root_disk_free=shutil.disk_usage('/').free,wall_ns=time.time_ns(),elapsed_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME))))
"""
        args=self.c+['exec','-T','-e','PYTHONDONTWRITEBYTECODE=1','robot','bash','-c','source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && python3 -c "$1"','probe',code]
        proc=subprocess.run(args,capture_output=True,text=True,timeout=10)
        if proc.returncode:raise RuntimeError('runtime probe unavailable')
        result=json.loads(proc.stdout)
        checks=[]
        for key,expected in [('ros','humble'),('rmw','rmw_fastrtps_cpp'),('uid',10001),('security','Enforce')]:
            checks.append({'id':key,'status':'PASS' if result.get(key)==expected else 'FAIL','expected':expected,'observed':result.get(key)})
        try:
            headroom=int(result['memory_max'])-int(result['memory_current'])
            minimum=self.data['profile']['resources']['min_host_available_memory_bytes']
            checks.append({'id':'cgroup_headroom','status':'PASS' if headroom>=minimum else 'FAIL','observed':headroom,'expected_minimum':minimum,'basis':'estimated admission threshold, not hardware performance guarantee'})
        except (ValueError,TypeError):checks.append({'id':'cgroup_headroom','status':'UNKNOWN'})
        result['checks']=checks;result['runtime_ready']=all(c['status']=='PASS' for c in checks)
        result['source']='owned_runtime';result['hardware_verified']=False
        result['config_seal']=read(self.state/'runtime-seal.json')
        result['note']='memory.max/current are cgroup values; root disk is runtime overlay, not host state filesystem'
        return result

    def owned(self):
        self.sealed()
        subprocess.run(['docker','info'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10,check=True)
        expected=read(self.state/'ownership.json')['containers']
        actual_ids=subprocess.check_output(['docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project='+self.project],text=True).split()
        if not set(actual_ids)<=set(c['id'] for c in expected):raise ValueError('UNKNOWN_OWNERSHIP: unexpected project member')
        for c in expected:
            if c['id'] not in actual_ids:continue
            got=json.loads(subprocess.check_output(['docker','inspect',c['id']],text=True))[0]
            labels=got['Config']['Labels'] or {}
            if got['Image']!=c['image'] or labels.get('org.pail.nvidia.run')!=self.data['run_id'] or labels.get('org.pail.nvidia.generation')!=self.data['generation'] or labels.get('com.docker.compose.project')!=self.project:
                raise ValueError('UNKNOWN_OWNERSHIP: identity mismatch')
        return actual_ids
    def cleanup(self):
        ids=self.owned()
        log_errors=[]
        for cid in ids:
            try:self.command(['docker','logs',cid],'final-container-'+cid[:12],10)
            except (RuntimeError,subprocess.SubprocessError) as ex:log_errors.append(str(ex))
        # Remove only exact owned IDs, no project-wide kill. Networks are individually checked.
        for cid in ids:self.command(['docker','rm','-f',cid],'remove-'+cid[:12],30)
        nets=subprocess.check_output(['docker','network','ls','-q','--filter','label=com.docker.compose.project='+self.project],text=True).split()
        for net in nets:
            info=json.loads(subprocess.check_output(['docker','network','inspect',net],text=True))[0]
            labels=info.get('Labels') or {}
            if labels.get('org.pail.nvidia.run')!=self.data['run_id'] or labels.get('org.pail.nvidia.generation')!=self.data['generation'] or info.get('Containers'):
                raise ValueError('UNKNOWN_OWNERSHIP network')
            self.command(['docker','network','rm',net],'remove-network')
        return {'status':'PASS','remaining_containers':self.owned(),'log_capture_errors':log_errors}
