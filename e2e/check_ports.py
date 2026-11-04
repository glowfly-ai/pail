#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Check the E2E's Docker host-network TCP listeners without starting the service."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def listeners(text):
    ports=set();headers=0;entries=0
    for line in text.splitlines():
        cols=line.split()
        if not cols:continue
        if cols[0]=='sl':headers+=1;continue
        if len(cols)<4 or not cols[0].endswith(':'):raise ValueError('unreadable proc TCP row')
        port=int(cols[1].rsplit(':',1)[1],16);entries+=1
        if cols[3]=='0A':ports.add(port)
    if headers!=2:raise ValueError('both IPv4 and IPv6 TCP tables must be readable')
    return sorted(ports)


def diagnose(text):
    patterns=[('PORT_IN_USE','address already in use'),('PERMISSION_DENIED','permission denied'),
              ('MISSING_FILE','no such file'),('STARTUP_REFUSED','startup refused'),
              ('STARTUP_REFUSED','preflight refusal')]
    findings=[]
    for line in text.splitlines():
        for code,needle in patterns:
            if needle in line.lower():
                findings.append({'code':code,'observed':line.strip()[:600]});break
    return findings[-8:]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--image',default='alpine:3.22')
    ap.add_argument('--ports',nargs=2,type=int)
    ap.add_argument('--report',type=Path)
    ap.add_argument('--diagnose',type=Path)
    a=ap.parse_args()
    if a.diagnose:
        try:found=diagnose(a.diagnose.read_text())
        except OSError as exc:print('STARTUP_DIAGNOSIS_UNAVAILABLE:',exc);return 2
        for row in found:print('OBSERVED '+row['code']+': '+row['observed'])
        if not found:print('No recognized startup cause; inspect the preserved service log.')
        return 0
    if not a.ports or len(set(a.ports))!=2 or any(p<1 or p>65535 for p in a.ports):
        print('PORT_CHECK: two distinct TCP ports in 1..65535 are required',file=sys.stderr);return 2
    try:
        # Pull only when absent, with a separate bounded acquisition timeout.
        present=subprocess.run(['docker','image','inspect',a.image],capture_output=True,text=True,timeout=15)
        if present.returncode:
            raise ValueError('Probe image not loaded: '+a.image+'; load the evaluation images and pass --image. No implicit pull.')
        r=subprocess.run(['docker','run','--rm','--network','host','--entrypoint','sh',a.image,
                          '-c','cat /proc/net/tcp && cat /proc/net/tcp6'],capture_output=True,text=True,timeout=25)
        if r.returncode:raise ValueError('Docker TCP-table probe failed: '+r.stderr.strip()[:500])
        found=listeners(r.stdout);busy=sorted(set(found)&set(a.ports))
        result={'scope':'Docker host network namespace','requested_ports':a.ports,'busy_ports':busy,
                'preflight_only':True,'note':'Availability can change before service bind; runtime logs remain authoritative.'}
        if a.report:a.report.write_text(json.dumps(result,indent=2)+'\n')
        if busy:
            print('PORT_CHECK: BUSY '+','.join(map(str,busy))+' in the Docker host network namespace.')
            print('On Docker Desktop, host lsof/netstat may not see this namespace. No existing process was stopped.')
            print('Choose free ports, for example: PAIL_NORTHBOUND_PORT=50151 PAIL_CLOUD_PORT=50161 bash e2e/run_e2e.sh')
            return 2
        print('PORT_CHECK: available at observation time: '+','.join(map(str,a.ports)))
        return 0
    except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
        print('PORT_CHECK: CANNOT_CHECK: '+str(exc),file=sys.stderr);return 2

if __name__=='__main__':sys.exit(main())
