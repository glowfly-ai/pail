#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Container-side (root) step after `support.py prepare`: install the live-demo fixtures over
the preview ones and create the shared observation files with the owners that will write
them. Then prove the access contract by trying it, not by reading modes:
  - uid 12345 (planner) can append to its record file and cannot open the raw socket dir
  - uid 10001 (observer/evidence) can create files under the shared runtime directory
Result: /state/evidence/demo-access.json. Private keys are never touched.
"""
import json, os, shutil, subprocess, sys
from pathlib import Path

STATE = Path('/state')
REF = Path('/reference/fixtures')
PRIV, PUB = STATE / 'private/config', STATE / 'public/config'


def install():
    for base in (PRIV, PUB):
        for src, dst in [('policy.yaml', 'policy.yaml'), ('skills.microduck.yaml', 'skills.microduck.yaml'), ('site.yaml', 'site_model.yaml')]:
            shutil.copyfile(REF / src, base / dst)
            (base / dst).chmod(0o644)
            os.chown(base / dst, 10001, 10001)
    rt = STATE / 'evidence/runtime'
    rt.mkdir(parents=True, exist_ok=True)
    rt.chmod(0o755)
    os.chown(rt, 10001, 10001)
    planner = rt / 'demo-planner.jsonl'
    planner.touch()
    planner.chmod(0o644)
    os.chown(planner, 12345, 10002)
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'common'))
    from raw_retention import initialize as prepare_raw
    prepare_raw(rt,{r:{'uid':12345 if r=='planner' else 10001,'gid':10002 if r=='planner' else 10001} for r in ('planner','observer','evidence','ledger')})
    ledger = STATE / 'evidence/ledger'
    ledger.mkdir(exist_ok=True)
    ledger.chmod(0o755)


def probe(uid, gid, code):
    child = 'import os,sys\nos.setgroups([%d]);os.setgid(%d);os.setuid(%d)\n%s\nprint("OK")' % (gid, gid, uid, code)
    p = subprocess.run([sys.executable, '-B', '-c', child], capture_output=True, text=True)
    return {'uid': uid, 'ok': p.returncode == 0 and p.stdout.strip().endswith('OK'), 'detail': (p.stderr or p.stdout).strip()[-300:]}


def main():
    install()
    checks = {
        'planner_appends_own_record': probe(12345, 10002, "open('/state/evidence/runtime/demo-planner.jsonl','a').write('')"),
        'planner_cannot_list_raw_dir': probe(12345, 10002, "import errno\ntry:\n os.listdir('/run/duck/raw');raise SystemExit('raw dir readable')\nexcept PermissionError:\n pass"),
        'observer_creates_shared_record': probe(10001, 10001, "open('/state/evidence/runtime/demo-observer.jsonl','a').write('')"),
    }
    ok = all(c['ok'] for c in checks.values())
    out = {'passed': ok, 'checks': checks, 'note': 'shared observation files 0644 in a 0755 directory; private keys untouched'}
    (STATE / 'evidence/demo-access.json').write_text(json.dumps(out, indent=2) + '\n')
    (STATE / 'evidence/demo-access.json').chmod(0o644)
    print(json.dumps(out))
    return 0 if ok else 2


if __name__ == '__main__':
    sys.exit(main())
