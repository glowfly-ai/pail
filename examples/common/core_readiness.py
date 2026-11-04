# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Owner-checked, nonce-bound read-only readiness. Never an actuation probe."""
import hashlib
import json
import os
import secrets
import socket
import stat
import struct
import subprocess
import base64
import time
from pathlib import Path

class ReadinessError(RuntimeError):
    pass

def query(path, expected, deadline):
    """Run on the robot, in the same host clock domain as the local UDS peer."""
    if not hasattr(socket, 'SO_PEERCRED'):
        raise ReadinessError('PEER_IDENTITY_UNAVAILABLE')
    p=Path(path)
    for parent in (p,*p.parents):
        if parent.is_symlink():raise ReadinessError('SYMLINK_ENDPOINT')
    info=p.stat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=expected['uid']:
        raise ReadinessError('ENDPOINT_OWNER_MISMATCH')
    nonce=secrets.token_hex(32);before=time.monotonic_ns()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ReadinessError('DEADLINE_EXCEEDED')
        sock.settimeout(min(2.,remaining));sock.connect(str(p))
        pid,uid,gid=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=expected['uid']:raise ReadinessError('PEER_UID_MISMATCH')
        exe=Path('/proc')/str(pid)/'exe'
        peer_stat=(Path('/proc')/str(pid)/'stat').read_text()
        start_ticks=peer_stat[peer_stat.rfind(')')+1:].split()[19]
        own_ns=os.readlink('/proc/self/ns/time');peer_ns=os.readlink('/proc/%s/ns/time'%pid)
        if own_ns!=peer_ns and Path('/proc/self/timens_offsets').read_text()!=Path('/proc/%s/timens_offsets'%pid).read_text():
            raise ReadinessError('PEER_CLOCK_DOMAIN_MISMATCH')
        sock.sendall((nonce+'\n').encode());buf=bytearray()
        while b'\n' not in buf:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ReadinessError('DEADLINE_EXCEEDED')
            sock.settimeout(min(2.,remaining));part=sock.recv(2048)
            if not part:raise ReadinessError('INCOMPLETE_STATUS')
            buf.extend(part)
            if len(buf)>16384:raise ReadinessError('STATUS_TOO_LARGE')
    digest=hashlib.sha256(exe.read_bytes()).hexdigest()
    current_stat=(Path('/proc')/str(pid)/'stat').read_text()
    if digest!=expected['exe_sha256'] or current_stat[current_stat.rfind(')')+1:].split()[19]!=start_ticks:
        raise ReadinessError('PEER_EXECUTABLE_OR_GENERATION_MISMATCH')
    if bytes(buf).count(b'\n')!=1 or not bytes(buf).endswith(b'\n'):raise ReadinessError('INVALID_STATUS_FRAME')
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise ReadinessError('DUPLICATE_STATUS_KEY')
            out[k]=v
        return out
    row=json.loads(buf,object_pairs_hook=unique)
    if row.get("process_start_ticks")!=start_ticks:raise ReadinessError("STATUS_PEER_GENERATION_MISMATCH")
    validate(row,expected,nonce,before,time.monotonic_ns())
    return row

def validate(row,expected,nonce,before,after):
    if not isinstance(row,dict) or any(not isinstance(k,str) or not isinstance(v,str) for k,v in row.items()):raise ReadinessError('STATUS_NOT_STRING_MAP')
    if row.get('nonce')!=nonce:raise ReadinessError('NONCE_MISMATCH')
    for key in ('robot_id','deployment_id','component','boot_id','config_generation'):
        if not expected.get(key) or row.get(key)!=expected[key]:raise ReadinessError('IDENTITY_MISMATCH:'+key)
    if not row.get('instance_id') or not row.get('process_start_ticks'):raise ReadinessError('PROCESS_IDENTITY_MISSING')
    sample=int(row['sample_mono_ns'])
    if sample<before or sample>after or after-sample>2_000_000_000:raise ReadinessError('STATUS_CLOCK_OR_FRESHNESS_MISMATCH')
    io=json.loads(row.get('io_snapshot_json','{}'))
    if io.get('contract_version')!='core-comm-ready/1' or io.get('physical_execution')!='NOT_OBSERVED':raise ReadinessError('READINESS_CONTRACT_MISSING')
    roles={'cmd','evidence','safety','safe','permit'} if row['component']=='pep_gate' else {'safe','permit','drive'}
    if set(expected.get('endpoints',{}))!=roles:raise ReadinessError('ENDPOINT_DECLARATION_INCOMPLETE')
    for role,binding in expected['endpoints'].items():
        found=json.loads(io.get(role,'{}'))
        if found.get('limited') is not False:raise ReadinessError('READINESS_LIMITED:'+role)
        matches=[e for e in found.get('endpoints',[]) if e.get('node_name')==binding['node_name'] and e.get('node_namespace')==binding['node_namespace'] and e.get('qos_compatible')=='true' and e.get('endpoint_gid')]
        if len(matches)!=1:raise ReadinessError('EXPECTED_ENDPOINT_NOT_UNIQUE:'+role)
    if row['component']=='pep_gate':
        for role in ('evidence','safety'):
            try:age=int(io[role+'_age_ms'])
            except (KeyError,ValueError,TypeError):raise ReadinessError('REQUIRED_INPUT_UNKNOWN:'+role)
            if age<0 or age>2000:raise ReadinessError('REQUIRED_INPUT_STALE:'+role)
    return True

def check_pair(first,second):
    for field in ('boot_id','instance_id','process_start_ticks','config_generation','deployment_id','robot_id','component'):
        if not first.get(field) or first[field]!=second.get(field):raise ReadinessError('GENERATION_CHANGED:'+field)
    if int(second['sample_mono_ns'])<int(first['sample_mono_ns']):raise ReadinessError('CLOCK_REGRESSED')

def collect(manifest,deadline):
    """Manifest is an operator-trusted declaration, not an observed success file."""
    if manifest.get('version')!=1:raise ReadinessError('MANIFEST_VERSION')
    peers=manifest.get('components',[])
    if len(peers)!=2 or {p.get('component') for p in peers}!={'pep_gate','motion_bridge'}:raise ReadinessError('COMPONENT_SET')
    for key in ('robot_id','deployment_id'):
        if not manifest.get(key) or any(p.get(key)!=manifest[key] for p in peers) or manifest['gateway'].get(key)!=manifest[key]:raise ReadinessError('DEPLOYMENT_SCOPE_MISMATCH')
    gateway_first=probe_gateway(manifest['gateway'],deadline)
    driver_first=probe_driver(manifest['driver'],deadline)
    first=[query(p['socket'],p,deadline) for p in peers]
    second=[query(p['socket'],p,deadline) for p in peers]
    gateway_second=probe_gateway(manifest['gateway'],deadline)
    driver_second=probe_driver(manifest['driver'],deadline)
    for key in ('agent_instance_id','agent_loaded_generation','deployment_id','agent_robot_id'):
        if gateway_first.get(key)!=gateway_second.get(key):raise ReadinessError('GATEWAY_CHANGED')
    if driver_first!=driver_second:raise ReadinessError('DRIVER_CHANGED')
    for a,b in zip(first,second):check_pair(a,b)
    return dict(state='READY',scope='IO_TOPOLOGY_AND_REQUIRED_INPUTS',physical_execution='NOT_OBSERVED',components=second,gateway=gateway_second,driver=driver_second)


def bounded_run(argv,deadline):
    remaining=deadline-time.monotonic()
    if remaining<=0:raise ReadinessError('DEADLINE_EXCEEDED')
    p=subprocess.run(argv,capture_output=True,text=True,timeout=min(4.,remaining),check=False)
    if p.returncode:raise ReadinessError('PROBE_COMMAND_FAILED')
    if len(p.stdout)>65536:raise ReadinessError('PROBE_OUTPUT_TOO_LARGE')
    return p.stdout

def probe_gateway(expected,deadline):
    binary=Path(expected['probe_binary'])
    if not binary.is_absolute() or binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest()!=expected['probe_sha256']:
        raise ReadinessError('GATEWAY_PROBE_BINARY_MISMATCH')
    nonce=secrets.token_bytes(32)
    out=json.loads(bounded_run([str(binary),'probe-agent','--socket',expected['socket'],'--robot',expected['robot_id'],
        '--deployment',expected['deployment_id'],'--generation',expected['generation'],'--nonce',nonce.hex()],deadline))
    if out.get('nonce')!=base64.b64encode(nonce).decode() or out.get('agent_robot_id')!=expected['robot_id'] or out.get('deployment_id')!=expected['deployment_id'] or out.get('agent_loaded_generation')!=expected['generation']:
        raise ReadinessError('GATEWAY_PROBE_BINDING')
    if out.get('unavailable_reason') or out.get('report_storage_state')!='LOCAL_DISK' or out.get('core_comm_contract')!='v1':raise ReadinessError('GATEWAY_NOT_READY')
    return out

def probe_driver(expected,deadline):
    ident=expected['container_id']
    if not isinstance(ident,str) or len(ident)!=64 or any(c not in '0123456789abcdef' for c in ident):raise ReadinessError('DRIVER_ID_REQUIRED')
    raw=bounded_run(['docker','inspect','--format','{{json .State}}',ident],deadline)
    state=json.loads(raw)
    if state.get('Running') is not True or state.get('Paused') or state.get('Restarting') or state.get('Dead'):
        raise ReadinessError('DRIVER_NOT_RUNNING')
    return {'container_id':ident,'pid':state.get('Pid'),'started_at':state.get('StartedAt')}


def main():
    import argparse
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest',required=True)
    ap.add_argument('--timeout',type=float,default=10)
    args=ap.parse_args()
    try:
        if not 0<args.timeout<=60:raise ReadinessError('TIMEOUT_RANGE')
        path=Path(args.manifest)
        for p in (path,*path.parents):
            if p.is_symlink():raise ReadinessError('SYMLINK_DECLARATION')
        st=path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_size>65536 or st.st_uid not in (0,os.geteuid()) or st.st_mode&0o022:
            raise ReadinessError('UNTRUSTED_DECLARATION')
        result=collect(json.loads(path.read_text()),time.monotonic()+args.timeout)
        print(json.dumps(result,sort_keys=True));return 0
    except (ReadinessError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as e:
        print(json.dumps(dict(state='NOT_READY',reason=str(e),physical_execution='NOT_OBSERVED')));return 3

if __name__=='__main__':raise SystemExit(main())
