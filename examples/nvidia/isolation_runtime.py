# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Per-role credential/mount/PID isolation for a synthetic reference, not a VM boundary."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from runtime import Rig as SharedRig, HERE
from state_store import atomic, read, source_hashes, journal
from isolation_files import ROLES,UIDS,ENCLAVES

SERVICES=('netspace',)+ROLES
ROLE_FOR_ACTOR={'pep_gate_node':'gate','motion_bridge_node':'bridge',**{r:r for r in ('planner','endpoint','monitor','safety','evidence')}}

class IsolatedRig(SharedRig):
    def service(self,role):
        if role=='permit_fixture':raise ValueError('trusted permit fixture is not part of the isolated role set')
        return ROLE_FOR_ACTOR.get(role,role)
    def log_path(self,role):return self.state/'role-logs'/self.service(role)/(role+'.jsonl')
    def bootstrap(self):
        super().bootstrap()
        self.command(['docker','run','--rm','--network','none','-u','0','-v',str(self.state)+':/work','-v',str(HERE)+':/setup:ro','--entrypoint','python3',self.images['tb3_gate'],'/setup/isolation_files.py','--work','/work','--uid',str(os.getuid()),'--gid',str(os.getgid())],'isolation-views',180)
        views=read(self.state/'role-views.json')
        if set(views['roles'])!=set(ROLES):raise ValueError('incomplete role projection')
        old=read(self.state/'compose.json')
        labels={'org.pail.nvidia.run':self.data['run_id'],'org.pail.nvidia.generation':self.data['generation']}
        services={}
        for role in SERVICES:
            uid=UIDS.get(role,11100)
            image=self.images['microduck'] if role=='requester' else self.images['issuer'] if role in ('netspace','issuer','agent') else self.images['tb3_gate']
            service={'image':image,'user':str(uid)+':'+str(uid),'read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'ipc':'private','pids_limit':128,'restart':'no','labels':dict(labels,**{'org.pail.role':role}),'tmpfs':['/tmp:rw,nosuid,nodev,size=128m,mode=1777'],'environment':{'HOME':'/tmp','ROS_LOG_DIR':'/tmp/roslogs','PYTHONDONTWRITEBYTECODE':'1'},'cpus':.3,'mem_limit':'256m','memswap_limit':'256m'}
            if role=='netspace':
                service.update(entrypoint=['/usr/local/bin/pail_split','hold'],cpus=.05,mem_limit='64m',memswap_limit='64m');services[role]=service;continue
            cfg=self.state/'role-views'/role/'config';state=self.state/'role-views'/role/'state'
            service['network_mode']='service:netspace'
            mounts=[str(cfg)+':/etc/pail:ro',str(state)+':/var/lib/pail_role',str(state/'keyring')+':/var/lib/pail_keyring']
            env=service['environment']
            if role in ('issuer','agent','gate'):
                env.update(PAIL_PROFILE='dev',PAIL_ROBOT_ID='robot-01',PAIL_GRPC_TLS='on',PAIL_KEYRING_MODE='bundle',PAIL_KEYRING_BUNDLE='/etc/pail/keys/keyring_bundle.json',PAIL_ROOT_PUBKEY_FILE='/etc/pail/keys/root_pub.b64',PAIL_KEYRING_STATE='/var/lib/pail_keyring/state.json',PAIL_KEYRING_MAX_LIFETIME_SEC='86400',PAIL_KEYRING_POLL_SEC='0')
            if role=='issuer':
                mounts.append(str(state)+':/var/log/pail_blackbox')
                env.update(PAIL_ISSUER_KEY_ID='dev-key-1',PAIL_SITE_MODEL='/etc/pail/site_model.yaml',PAIL_REQUESTERS='/etc/pail/requesters.yaml',PAIL_CHECKPOINT_EVERY_RECORDS='10')
                service.update(entrypoint=['/usr/local/bin/pail_cloud'],cpus=.6,mem_limit='512m',memswap_limit='512m')
            elif role=='agent':
                env.update(PAIL_GRPC_CLIENT_CERT='/etc/pail/grpc_certs/robot-01/client.crt',PAIL_GRPC_CLIENT_KEY='/etc/pail/grpc_certs/robot-01/client.key',PAIL_REPORT_QUEUE_DIR='/var/lib/pail_role/report_queue')
                service['entrypoint']=['/usr/local/bin/pail_robot_agent']
            elif role=='requester':service['entrypoint']=['sleep','infinity']
            else:
                mounts.append(str(self.ref)+':/reference:ro')
                env.update(PAIL_PROFILE='dev',PAIL_ROBOT_ID='robot-01',ROS_DOMAIN_ID='0',ROS_SECURITY_ENABLE='true',ROS_SECURITY_STRATEGY='Enforce',ROS_SECURITY_KEYSTORE='/etc/pail/sros2_keystore',ROS_SECURITY_ENCLAVE_OVERRIDE='/'+ENCLAVES[role],FASTRTPS_DEFAULT_PROFILES_FILE='/reference/fastdds_loopback.xml')
                if role=='gate':
                    env.update(PAIL_ROBOT_CLASS='diff_drive_amr',PAIL_GRPC_CERT='/etc/pail/grpc_certs/robot-01/client.crt',PAIL_GRPC_KEY='/etc/pail/grpc_certs/robot-01/client.key',PAIL_TOKEN_PROVIDER_MODE='grpc',PAIL_TOKEN_SERVICE_ADDR='127.0.0.1:50051')
                    service.update(entrypoint=['/usr/local/bin/pep_gate_entrypoint.sh'],cpus=.8,mem_limit='1024m',memswap_limit='1024m')
                elif role=='bridge':service['entrypoint']=['/usr/local/bin/motion_bridge_entrypoint.sh']
                else:
                    mounts.append(str(self.state/'role-logs'/role)+':/evidence/runtime')
                    if role=='planner':mounts.append(str(self.rig/'control')+':/control:ro')
                    script='mock_io.py' if role in ('safety','evidence') else 'ros_endpoint.py'
                    service['entrypoint']=['bash','-c'];service['command']=['source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && exec python3 -u /reference/'+script+' --role '+role]
            service['volumes']=mounts;services[role]=service
        atomic(self.state/'compose.json',{'services':services,'networks':old['networks']})
        self.validate_layout(read(self.state/'compose.json'))
        seal=read(self.state/'runtime-seal.json');seal['compose']=hashlib.sha256((self.state/'compose.json').read_bytes()).hexdigest();seal['role_views']=hashlib.sha256((self.state/'role-views.json').read_bytes()).hexdigest()
        atomic(self.state/'runtime-seal.json',seal)
    def validate_layout(self,compose):
        if set(compose['services'])!=set(SERVICES):raise ValueError('unexpected role service set')
        for role,c in compose['services'].items():
            if c.get('user')!=str(UIDS.get(role,11100))+':'+str(UIDS.get(role,11100)):raise ValueError('wrong UID')
            if not c.get('read_only') or c.get('ipc')!='private' or c.get('cap_drop')!=['ALL'] or c.get('security_opt')!=['no-new-privileges:true']:raise ValueError('role isolation weakened')
            if c.get('pid') or c.get('privileged') or c.get('devices') or c.get('ports') or c.get('cap_add'):raise ValueError('unsafe role privileges')
            if role!='netspace' and c.get('network_mode')!='service:netspace':raise ValueError('network escape')
            expected={str(self.state/'role-views'/role/'config')+':/etc/pail:ro',str(self.state/'role-views'/role/'state')+':/var/lib/pail_role',str(self.state/'role-views'/role/'state/keyring')+':/var/lib/pail_keyring'} if role!='netspace' else set()
            if role=='issuer':expected.add(str(self.state/'role-views'/role/'state')+':/var/log/pail_blackbox')
            if role in ENCLAVES:expected.add(str(self.ref)+':/reference:ro')
            if role in ('planner','endpoint','monitor','safety','evidence'):expected.add(str(self.state/'role-logs'/role)+':/evidence/runtime')
            if role=='planner':expected.add(str(self.rig/'control')+':/control:ro')
            if set(c.get('volumes',[]))!=expected:raise ValueError('unexpected mount for '+role)
    def sealed(self):
        seal=super().sealed()
        if seal.get('role_views')!=hashlib.sha256((self.state/'role-views.json').read_bytes()).hexdigest():raise ValueError('role projection metadata changed')
        self.validate_layout(read(self.state/'compose.json'));return seal
    def audit_views(self):
        manifest=read(self.state/'role-views.json')
        code="""import json,hashlib,os,stat
from pathlib import Path
role=os.environ['AUDIT_ROLE'];expected=json.loads(Path('/manifest.json').read_text())['roles'][role]
root=Path('/etc/pail');files={str(p.relative_to(root)):p for p in root.rglob('*') if p.is_file() or p.is_symlink()}
ok=set(files)==set(expected['files']) and os.getuid()==expected['uid']
for rel,p in files.items():
 item=expected['files'].get(rel,{})
 ok=ok and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==item.get('sha256') and (stat.S_IMODE(p.stat().st_mode)==int(item.get('mode','0'),8))
print(json.dumps({'role':role,'passed':ok,'file_count':len(files),'contents_logged':False}));raise SystemExit(0 if ok else 2)
"""
        audits=[]
        for role in ROLES:
            args=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','-u',str(UIDS[role])+':'+str(UIDS[role]),'-e','AUDIT_ROLE='+role,'-v',str(self.state/'role-views'/role/'config')+':/etc/pail:ro','-v',str(self.state/'role-views.json')+':/manifest.json:ro','--entrypoint','python3',self.images['tb3_gate'],'-c',code]
            # Manifest is public verification metadata; temporary audit projection needs read access.
            audits.append(json.loads(self.command(args,'view-audit-'+role)))
        atomic(self.state/'public/role-view-audit.json',audits)
    def up(self):
        self.sealed();self.audit_views();journal(self.state,'CREATE_INTENT',{'project':self.project})
        self.command(self.c+['create'],'create')
        ids=subprocess.check_output(self.c+['ps','-aq'],text=True).split();containers=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
        if len(containers)!=len(SERVICES):raise ValueError('incomplete isolated container set')
        owned=[]
        for c in containers:
            h=c['HostConfig'];role=c['Config']['Labels'].get('org.pail.role')
            if role not in SERVICES or not h['ReadonlyRootfs'] or h['IpcMode']!='private' or h['PidMode'] or h['Privileged'] or h.get('Devices') or h.get('PortBindings'):raise ValueError('unsafe runtime layout')
            owned.append({'id':c['Id'],'image':c['Image'],'labels':c['Config']['Labels']})
        atomic(self.state/'ownership.json',{'containers':owned});journal(self.state,'CREATED',{'ids':ids})
        self.command(self.c+['start'],'start')
        self.wait(lambda:self.probe('peek').get('status')=='NO_TOKEN','issuer ready')
        self.wait(lambda:all(any(r['event']=='ready' for r in self.rows(role)) for role in ('endpoint','monitor','planner')),'isolated actors ready')
        self.wait(lambda:'S33 OK' in subprocess.check_output(self.c+['logs','--no-color','gate'],text=True,stderr=subprocess.DEVNULL),'gate readiness')
        self.wait(lambda:any(r.get('event')=='observed' and r['snapshot']['applied_linear_x']==0 for r in self.rows('monitor')),'independent zero observation')
    def actor(self,*args,**kwargs):raise ValueError('isolated roles are separate fixed services, not shared-container exec actors')
    def probe(self,mode,plan=None):
        args=self.c+['exec','-T','requester','tb3-probe','-addr','127.0.0.1:50061','-mode',mode]
        if mode=='submit':args+=['-duration','20']
        if plan:args+=['-plan',plan]
        r=subprocess.run(args,capture_output=True,text=True,timeout=15)
        if r.returncode:raise RuntimeError('isolated probe failed')
        return json.loads(r.stdout)
    def rows(self,role):
        path=self.log_path(role)
        if not path.exists():return []
        text=path.read_text();return [json.loads(x) for x in text[:text.rfind('\n')+1].splitlines()]
    def observations(self):
        ids=self.owned()
        if len(ids)!=len(SERVICES):raise ValueError('incomplete runtime')
        code="import json,os;from rclpy.utilities import get_rmw_implementation_identifier;print(json.dumps({'uid':os.getuid(),'rmw':get_rmw_implementation_identifier(),'security':os.getenv('ROS_SECURITY_STRATEGY')}))"
        r=subprocess.run(self.c+['exec','-T','gate','bash','-c','source /opt/ros/humble/setup.bash && python3 -c "$1"','probe',code],capture_output=True,text=True,timeout=15)
        if r.returncode:raise ValueError('gate runtime probe unavailable')
        result=json.loads(r.stdout);result.update(runtime_ready=result['uid']==UIDS['gate'] and result['security']=='Enforce' and result['rmw']=='rmw_fastrtps_cpp',hardware_verified=False,role_isolation=True,roles=len(ROLES))
        return result
