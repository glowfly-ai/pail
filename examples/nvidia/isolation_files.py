# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Trusted offline setup only. Projects explicit per-role credential views."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

ROLES=('issuer','agent','requester','gate','bridge','planner','endpoint','monitor','safety','evidence')
UIDS={role:11001+i for i,role in enumerate(ROLES)}
ENCLAVES={'gate':'pep_gate','bridge':'motion_bridge','planner':'oem_planner','endpoint':'nv_endpoint','monitor':'nv_monitor','safety':'safety_adapter','evidence':'perception'}
DDS_FILES=('cert.pem','key.pem','permissions.p7s','governance.p7s','identity_ca.cert.pem','permissions_ca.cert.pem','permissions.xml')
PUBLIC_CONFIG=('policy.yaml','skills.diff_drive_amr.yaml','site_model.yaml','robot_registry.yaml','requesters.yaml','sros2_policy.xml')
PUBLIC_KEYS=('keys/keyring.json','keys/keyring_bundle.json','keys/root_pub.b64')


def resolve_under(path,root):
    target=Path(path).resolve(strict=True);base=Path(root).resolve(strict=True)
    if not target.is_file() or base not in target.parents:raise ValueError('credential source escapes setup root')
    return target


def issue(cfg, name, server=False):
    folder=cfg/'grpc_certs'/name;folder.mkdir(exist_ok=False)
    key=folder/'key.pem';csr=folder/'request.csr';crt=folder/'cert.pem';ext=folder/'extensions.cnf'
    ext.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage='+('serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' if server else 'clientAuth\n'))
    def run(args):
        r=subprocess.run(args,capture_output=True,text=True,timeout=20)
        if r.returncode:raise RuntimeError('certificate generation failed (no credential contents logged)')
    run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-subj','/CN=pail-'+(name if server else 'robot-robot-01'),'-keyout',str(key),'-out',str(csr)])
    run(['openssl','x509','-req','-in',str(csr),'-CA',str(cfg/'grpc_certs/ca.crt'),'-CAkey',str(cfg/'grpc_certs/ca.key'),'-set_serial','0x'+secrets.token_hex(16),'-days','1','-sha256','-extfile',str(ext),'-out',str(crt)])
    key.chmod(0o600)
    return key,crt


def project(work,host_uid,host_gid):
    work=Path(work);cfg=work/'rig/runtime/config';dest=work/'role-views'
    if dest.exists():raise ValueError('fresh views required')
    leaves={}
    for role in ('gate','requester'):leaves[role]=issue(cfg,role)
    agent_server=issue(cfg,'agent-server',True)
    def fingerprint(path):
        r=subprocess.run(['openssl','x509','-in',str(path),'-outform','DER'],capture_output=True,check=True)
        return hashlib.sha256(r.stdout).hexdigest()
    original=cfg/'grpc_certs/robot-01/client.crt'
    fps=[fingerprint(original)]+[fingerprint(leaves[r][1]) for r in ('gate','requester')]
    if len(set(fps))!=3:raise ValueError('client identities must be distinct')
    registry='version: 1\nrobots:\n  - robot_id: robot-01\n    role: robot\n    fingerprints:\n'+''.join('      - '+fp+'\n' for fp in fps)
    (cfg/'robot_registry.yaml').write_text(registry)
    (cfg/'requesters.yaml').write_text('version: 1\nrequesters:\n  - match: {caller: mtls, cert_sha256: "'+fps[2]+'"}\n    kind: agentic_ai\n    id: isolated-requester\n    skills: [twist]\n')
    dest.mkdir(mode=0o700);man={}
    logs=work/'role-logs';logs.mkdir(mode=0o700);os.chown(logs,host_uid,host_gid)
    for role in ROLES:
        view=dest/role/'config';view.mkdir(parents=True,mode=0o700)
        files={}
        def copy(src,rel,private=False):
            original=Path(src)
            if original.is_symlink():
                permitted={'identity_ca.cert.pem':cfg/'sros2_keystore/public/identity_ca.cert.pem','permissions_ca.cert.pem':cfg/'sros2_keystore/public/permissions_ca.cert.pem','governance.p7s':cfg/'sros2_keystore/enclaves/governance.p7s'}
                if private or original.name not in permitted or original.resolve()!=permitted[original.name].resolve():raise ValueError('unsupported credential symlink')
            src=resolve_under(src,cfg);target=view/rel;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(src,target);target.chmod(0o600 if private else 0o644)
            files[rel]={'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'private':private,'mode':'0600' if private else '0644'}
        if role in ('issuer','agent','gate'):
            for rel in PUBLIC_CONFIG+PUBLIC_KEYS:copy(cfg/rel,rel)
        if role in ('issuer','agent','gate','requester'):copy(cfg/'grpc_certs/ca.crt','grpc_certs/ca.crt')
        if role=='issuer':
            copy(cfg/'keys/issuer_ed25519.json','keys/issuer_ed25519.json',True)
            copy(cfg/'grpc_certs/server.key','grpc_certs/server.key',True);copy(cfg/'grpc_certs/server.crt','grpc_certs/server.crt')
        if role=='agent':
            copy(cfg/'keys/agent_ed25519.json','keys/agent_ed25519.json',True)
            copy(agent_server[0],'grpc_certs/server.key',True);copy(agent_server[1],'grpc_certs/server.crt')
            copy(cfg/'grpc_certs/robot-01/client.key','grpc_certs/robot-01/client.key',True);copy(original,'grpc_certs/robot-01/client.crt')
        if role in leaves:
            copy(leaves[role][0],'grpc_certs/robot-01/client.key',True);copy(leaves[role][1],'grpc_certs/robot-01/client.crt')
        if role in ENCLAVES:
            enclave=ENCLAVES[role]
            for name in DDS_FILES:
                rel='sros2_keystore/enclaves/'+enclave+'/'+name
                copy(cfg/rel,rel,name=='key.pem')
        (dest/role/'state').mkdir(mode=0o700)
        (dest/role/'state/keyring').mkdir(mode=0o700)
        logdir=logs/role;logdir.mkdir(mode=0o755);os.chown(logdir,UIDS[role],UIDS[role])
        for f in [dest/role]+list((dest/role).rglob('*')):
            if f.is_symlink():raise ValueError('unexpected projected symlink')
            os.chown(f,UIDS[role],UIDS[role])
            if f.is_dir():f.chmod(0o700)
        man[role]={'uid':UIDS[role],'files':files,'enclave':ENCLAVES.get(role)}
    identities={}
    for role,entry in man.items():
        for item in entry['files'].values():
            if item['private']:
                if item['sha256'] in identities:raise ValueError('credential shared across role views')
                identities[item['sha256']]=role
    # Public metadata only; private key bytes never leave the setup directories.
    manifest=work/'role-views.json';manifest.write_text(json.dumps({'schema_version':1,'roles':man},indent=2)+'\n');manifest.chmod(0o644);os.chown(manifest,host_uid,host_gid)
    print(json.dumps({'roles':len(man),'runtime_ca_private_keys':0,'contents_logged':False}))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--work',required=True,type=Path);p.add_argument('--uid',required=True,type=int);p.add_argument('--gid',required=True,type=int)
    a=p.parse_args();project(a.work,a.uid,a.gid)
