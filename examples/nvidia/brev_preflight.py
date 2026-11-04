# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Read-only Brev candidate checks. Never provisions, pulls, installs or certifies Sim."""
import argparse
import csv
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess


def collect(directory):
    facts={'system':platform.system(),'arch':platform.machine(),'cpus':os.cpu_count(),
           'disk_free':shutil.disk_usage(directory).free}
    try:
        mem=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
        facts['memory_total']=int(mem['MemTotal'].split()[0])*1024
    except (OSError,ValueError,KeyError):facts['memory_total']=None
    for name,argv in [('docker',['docker','info','--format','{{.Architecture}}']),
                      ('compose',['docker','compose','version','--short']),
                      ('gpu',['nvidia-smi','--query-gpu=name,memory.total,driver_version','--format=csv,noheader,nounits'])]:
        try:
            p=subprocess.run(argv,capture_output=True,text=True,timeout=15)
            facts[name]={'rc':p.returncode,'stdout':p.stdout.strip(),'stderr':p.stderr.strip()[:300]}
        except (OSError,subprocess.SubprocessError) as exc:facts[name]={'rc':None,'error':str(exc)}
    return facts


def assess(facts):
    rows=[]
    def check(name,ok,value):rows.append({'id':name,'status':'PASS' if ok else 'FAIL','observed':value})
    check('native_linux_amd64',facts.get('system')=='Linux' and facts.get('arch') in ('x86_64','AMD64'),[facts.get('system'),facts.get('arch')])
    check('minimum_8_vcpu',isinstance(facts.get('cpus'),int) and facts['cpus']>=8,facts.get('cpus'))
    for name,key,minimum in [('minimum_32GiB_RAM','memory_total',32*1024**3),('minimum_200GiB_free','disk_free',200*1024**3)]:
        value=facts.get(key);check(name,isinstance(value,int) and value>=minimum,value)
    docker=facts.get('docker',{});check('native_daemon_amd64',docker.get('rc')==0 and docker.get('stdout') in ('x86_64','amd64'),docker)
    compose=facts.get('compose',{});check('compose',compose.get('rc')==0 and bool(compose.get('stdout')),compose)
    gpu=facts.get('gpu',{});parsed=[]
    try:
        if gpu.get('rc')!=0:raise ValueError('GPU query unavailable')
        for row in csv.reader(gpu['stdout'].splitlines()):
            name,mem,driver=[v.strip() for v in row]
            parsed.append({'name':name,'memory_MiB':float(mem),'driver':driver})
        valid=len(parsed)==1 and 'L40S' in parsed[0]['name'] and math.isfinite(parsed[0]['memory_MiB']) and parsed[0]['memory_MiB']>=40*1024
    except (KeyError,ValueError):valid=False
    check('one_L40S_40GiB_or_more',valid,parsed or gpu)
    # A driver observation is not a Vulkan/renderer compatibility assertion.
    return {'schema_version':1,'preflight':'PASS' if all(x['status']=='PASS' for x in rows) else 'FAIL',
            'checks':rows,'recommended':{'vcpus':16,'RAM_GiB':64,'SSD_GiB':500},
            'runtime':{k:'NOT_RUN' for k in ('vulkan','rendering','ros','security','lifecycle','streaming')},
            'support_status':'UNVERIFIED','hardware_verified':False,
            'notes':['Driver must be checked against the chosen pinned Isaac Sim release.',
                     'Billing, port reachability, CPU sharing and stop/start are not proven by this host check.']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state-parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if not a.state_parent.is_dir():raise ValueError('existing persistent state parent required')
    if a.output.exists() or a.output.is_symlink():raise ValueError('new output required')
    facts=collect(a.state_parent);result=assess(facts);result['facts']=facts
    with a.output.open('x') as out:json.dump(result,out,indent=2);out.write('\n')
    print(json.dumps({'preflight':result['preflight'],'support_status':result['support_status']}))
    return 0 if result['preflight']=='PASS' else 2

if __name__=='__main__':raise SystemExit(main())
