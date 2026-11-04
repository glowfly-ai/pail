#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Retain upstream license notices from cargo metadata's resolved build closure."""
import argparse
import json
import hashlib
from pathlib import Path
import shutil

ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('metadata',type=Path)
ap.add_argument('destination',type=Path)
ap.add_argument('--packages', nargs='+', required=True)
a=ap.parse_args()
metadata=json.loads(a.metadata.read_text())
nodes={node['id']:node for node in metadata['resolve']['nodes']}
roots={p['id'] for p in metadata['packages'] if p['name'] in a.packages and p['id'] in metadata['workspace_members']}
if len(roots)!=len(a.packages):raise SystemExit('BUILD_ROOT_PACKAGE_MISSING')
selected=set();pending=list(roots)
while pending:
    key=pending.pop()
    if key in selected:continue
    selected.add(key)
    for dep in nodes[key]['deps']:
        if any(kind['kind'] != 'dev' for kind in dep['dep_kinds']):pending.append(dep['pkg'])
rows=[]
for package in metadata['packages']:
    if package['id'] not in selected:continue
    if not package.get('source'):
        continue  # workspace notices are supplied by the parent image
    name=package['name']+'-'+package['version']
    if Path(name).name!=name:raise SystemExit('Unsafe dependency name')
    root=Path(package['manifest_path']).parent
    files=[p for p in root.iterdir() if p.is_file() and
           p.name.lower().startswith(('license','copying','notice','copyright','unlicense'))]
    explicit=package.get('license_file')
    if explicit:
        p=root/explicit
        if p.is_file() and p not in files:files.append(p)
    if not files:
        # Git workspace crates can inherit the repository's license at a parent.
        for parent in list(root.parents)[:3]:
            candidates = [p for p in parent.iterdir() if p.is_file() and
                          p.name.lower().startswith(('license', 'copying', 'notice', 'copyright', 'unlicense'))]
            if candidates:
                files = candidates
                break
    if not files:
        supplied = Path(__file__).parent / 'license-notices' / name
        record = supplied / 'SOURCE.json'
        if record.is_file():
            value = json.loads(record.read_text())
            notice = supplied / 'LICENSE'
            if (value['package'] != package['name'] or value['version'] != package['version']
                    or hashlib.sha256(notice.read_bytes()).hexdigest() != value['license_sha256']):
                raise SystemExit('UPSTREAM_NOTICE_MISMATCH: ' + name)
            files = [notice, record]
    if not files:
        raise SystemExit('LICENSE_NOTICE_MISSING: '+name)
    dest=a.destination/name;dest.mkdir(parents=True,exist_ok=True)
    for p in files:shutil.copyfile(p,dest/p.name)
    rows.append({'name':package['name'],'version':package['version'],'license':package.get('license'),
                 'source':package['source'],'notices':[p.name for p in files]})
a.destination.mkdir(parents=True,exist_ok=True)
(a.destination/'inventory.json').write_text(json.dumps({'scope':'cargo resolved target build closure; runtime and build dependencies of the selected binaries, excluding dev-only and other-platform dependencies','packages':rows},indent=2)+'\n')
