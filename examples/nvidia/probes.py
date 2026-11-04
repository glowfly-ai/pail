# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Read-only host/daemon/runtime diagnostics; unobserved is not PASS."""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time
from doctor import diagnose


def collect(profile, state, command=subprocess.run):
    base = dict(profile)
    base['platform'] = dict(profile['platform'])
    base['target'] = 'mock' if profile['target'] == 'sim_model' else profile['target']
    checks = diagnose(base)['checks']
    for c in checks: c.update(mandatory=True, source='host', expected='profile prerequisite')
    def add(id, status, observed, source='host', mandatory=True):
        checks.append(dict(id=id, status=status, observed=observed, source=source, mandatory=mandatory))
    try:
        info = command(['docker','info','--format','{{json .}}'], capture_output=True,text=True,timeout=10)
        if info.returncode: raise ValueError('Docker unavailable')
        d = json.loads(info.stdout)
        total = d.get('MemTotal')
        add('daemon_total_memory', 'PASS' if isinstance(total,int) else 'UNKNOWN', total, 'daemon', False)
        add('daemon_memory_available', 'NOT_RUN', 'total memory is not free memory', 'daemon', False)
        arch=d.get('Architecture',''); normalized={'arm64':'aarch64','amd64':'x86_64'}.get(arch,arch)
        expected=profile['platform']['arch']
        add('daemon_arch', 'PASS' if normalized in ('aarch64','x86_64') and expected in ('any',normalized) else 'FAIL', arch, 'daemon')
    except (OSError,ValueError,subprocess.SubprocessError) as e:
        add('docker_daemon','UNKNOWN',str(e),'daemon')
    try:
        compose=command(['docker','compose','version','--short'],capture_output=True,text=True,timeout=10)
        add('compose','PASS' if compose.returncode==0 else 'UNKNOWN',compose.stdout.strip(),'daemon')
    except (OSError,subprocess.SubprocessError) as e: add('compose','UNKNOWN',str(e),'daemon')
    try:
        path=Path(state)
        while not path.exists(): path=path.parent
        free=shutil.disk_usage(path).free
        add('state_disk_free','PASS' if free>=profile['resources']['min_state_free_bytes'] else 'FAIL',free)
    except OSError as e: add('state_disk_free','UNKNOWN',str(e))
    add('daemon_disk_free','NOT_RUN','not inferred from host filesystem','daemon',False)
    if platform.system()=='Linux':
        try:
            values=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
            free=int(values['MemAvailable'].split()[0])*1024
            add('host_memory_available','PASS' if free>=profile['resources']['min_host_available_memory_bytes'] else 'FAIL',free)
        except (OSError,ValueError,KeyError) as e: add('host_memory_available','UNKNOWN',str(e),mandatory=False)
    else: add('host_memory_available','NOT_RUN','Mac host is not Docker VM memory',mandatory=False)
    add('clock_sample','PASS',{'wall_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()},mandatory=False)
    sim=profile.get('sim')
    if isinstance(sim,dict) and sim.get('asset_dir'):
        # preview.15 P15-L2: a converted tree without the profile's wheel joints passed doctor and died at the endpoint.
        try:
            from isaac_runtime import missing_wheel_joints
            root=Path(sim['asset_dir'])
            if not root.is_dir():add('sim_asset_wheel_joints','FAIL',{'asset_dir':str(root),'error':'asset_dir missing'})
            else:
                missing=missing_wheel_joints(root,sim.get('usd'),list(sim.get('wheel_joints') or []))
                add('sim_asset_wheel_joints','PASS' if not missing else 'FAIL',{'asset_dir':str(root),'missing':missing,'checked':list(sim.get('wheel_joints') or [])})
        except (OSError,ValueError,ImportError) as e:add('sim_asset_wheel_joints','UNKNOWN',str(e))
    for key in ('runtime_ros_rmw','runtime_security','runtime_endpoint','clock_sync'):
        add(key,'NOT_RUN','query a running owned rig; host preflight is not runtime readiness','runtime',False)
    required=[c for c in checks if c['mandatory']]
    overall='FAIL' if any(c['status']=='FAIL' for c in required) else 'INCONCLUSIVE' if any(c['status']!='PASS' for c in required) else 'PASS'
    return {'schema_version':2,'overall':overall,'checks':checks,'scope':'prepare readiness only',
            'hardware_verified':False,'runtime_ready':False,'support_status':'UNVERIFIED'}
