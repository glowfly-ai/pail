# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Host-only role allowlist for isolated conformance faults."""
import json,os,re,subprocess,time
ROLES={'adapter':'adapter','issuer':'issuer','token-seam':'token-seam','pail-duckd-observe':'observe','observe-issuer':'observe-issuer'}

def handle(req,meta,compose,env):
    if set(req)-{'run_id','request_id','target_role','action','signal'}:raise ValueError('Unknown fault request fields')
    if req.get('run_id')!=meta['run_id'] or not re.fullmatch('[a-f0-9]{32}',req.get('request_id','')):raise ValueError('Fault identity mismatch')
    role=ROLES.get(req.get('target_role'));action=req.get('action')
    if role is None or action not in ['running','start','stop']:raise ValueError('Fault role/action not allowed')
    p=subprocess.run(compose+['ps','--all','--quiet',role],env=env,capture_output=True,text=True,check=True)
    ids=p.stdout.split()
    if len(ids)!=1:raise ValueError('Expected one task container for '+role)
    info=json.loads(subprocess.check_output(['docker','inspect',ids[0]],text=True))[0]
    if info['Config']['Labels'].get('com.docker.compose.project')!=meta['project']:raise ValueError('Foreign container')
    if action=='running':value=bool(info['State']['Running'])
    elif action=='start':subprocess.run(['docker','start',ids[0]],check=True,stdout=subprocess.DEVNULL);value=True
    else:
        signal=req.get('signal')
        if signal not in [9,15]:raise ValueError('Only test stop signals 9/15 allowed')
        subprocess.run(['docker','kill','--signal',str(signal),ids[0]],check=True,stdout=subprocess.DEVNULL);value=True
    return dict(run_id=meta['run_id'],request_id=req['request_id'],status='OK',value=value,observed_container_id=ids[0],completed_monotonic_ns=time.monotonic_ns())

def serve_pending(state,meta,compose,env,write):
    for path in sorted((state/'control').glob('*.request.json')):
        ident=path.name.removesuffix('.request.json')
        if not re.fullmatch('[a-f0-9]{32}',ident):continue
        out=path.with_name(ident+'.response.json')
        if out.exists():continue
        try:
            if path.is_symlink() or path.stat().st_size>4096:raise ValueError('Invalid request file')
            req=json.loads(path.read_text())
            if req.get('request_id')!=ident:raise ValueError('Request filename mismatch')
            result=handle(req,meta,compose,env)
        except Exception as e:result=dict(run_id=meta['run_id'],request_id=ident,status='ERROR',error=str(e))
        write(out,result)
