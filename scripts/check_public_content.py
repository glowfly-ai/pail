#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Audit public-facing text without rewriting code, test data or copyright notices."""
import argparse
import ast
import json
import hashlib
from pathlib import Path
import re
import sys
import unicodedata

HANGUL = re.compile('[가-힣]')
PRIVATE_DOC = re.compile(r'PAIL-[^\s`<>"\'()]*[가-힣][^\s`<>"\'()]*\.(?:md|html|txt)')

PRIVATE_TITLE = re.compile(r'PAIL-[^\s`<>\"\'()]*[가-힣][^\s`<>\"\'()]*-v[0-9]+')

PRIVATE_ID = re.compile(r'\b(?:LLD-[A-Z][A-Za-z0-9-]*|FD-\d+)')
PRIVATE_PATH = re.compile(r'(?<![\w/])(?:oss/|tests/golden/|asvs/)')
BROWSER_ID = re.compile(r'\bAL-\d+')

def inspect(root):
    failures=[];korean=[];protected=[];checked=0;compatibility=[]
    entries=json.loads((root/'scripts/public_content_policy.json').read_text())['frozen_files']
    policy={row['path']:row['sha256'] for row in entries}
    if len(policy)!=len(entries):raise ValueError('Duplicate frozen-data path')
    for rel,want in policy.items():
        f=root/rel
        if not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest()!=want:
            failures.append({'file':rel,'reason':'frozen data missing or bytes changed; review versioning before updating policy'})
    for p in sorted(root.rglob('*')):
        if not p.is_file() or '.git' in p.parts or '__pycache__' in p.parts:continue
        rel=p.relative_to(root).as_posix()
        try:s=p.read_text(encoding='utf-8')
        except UnicodeDecodeError:continue
        s=unicodedata.normalize("NFC",s)
        checked+=1
        if HANGUL.search(s):korean.append(rel)
        if rel in policy:
            protected.append(rel);continue
        browser=rel.startswith('cloud/cmd/pail_telemetryd/dashboard/') and p.suffix in ['.html','.js','.css']
        reader=p.suffix=='.md' or rel in ['NOTICE','LICENSE'] or rel.startswith('.github/workflows/')
        for i,line in enumerate(s.splitlines(),1):
            if PRIVATE_ID.search(line):failures.append({'file':rel,'line':i,'reason':'private design-document coordinate'})
            if browser and (BROWSER_ID.search(line) or PRIVATE_PATH.search(line)):
                failures.append({'file':rel,'line':i,'reason':'browser asset private reference'})
            if reader and PRIVATE_PATH.search(line):failures.append({'file':rel,'line':i,'reason':'reader documentation private source path'})
            if not reader and not browser and PRIVATE_PATH.search(line):
                compatibility.append({'file':rel,'line':i,'reason':'source-layout compatibility or checker implementation; not reader instructions'})
            if PRIVATE_DOC.search(line) or PRIVATE_TITLE.search(line):failures.append({'file':rel,'line':i,'reason':'private development document filename'})
        # Only canonical reader documentation, not translations or intentional UI examples.
        doc=(rel in ['README.md','CONTRIBUTING.md','CLA.md','NOTICE'] or
             (rel.startswith('spec/') and p.suffix=='.md' and '.ko.' not in rel) or
             rel.startswith('cloud/cmd/pail_telemetryd/EXPORT_SCHEMA'))
        if doc:
            prose=re.sub(r'```.*?```|<!--.*?-->','',s,flags=re.S)
            for i,line in enumerate(prose.splitlines(),1):
                if '.ko.md' in line:continue
                if HANGUL.search(line):failures.append({'file':rel,'prose_line':i,'reason':'untranslated canonical prose'})
        if rel.startswith('spec/tools/spec_') and p.suffix=='.py':
            tree=ast.parse(s)
            for returned in ast.walk(tree):
                if isinstance(returned,ast.Return):
                    for value in ast.walk(returned):
                        if isinstance(value,ast.Constant) and isinstance(value.value,str) and HANGUL.search(value.value) and (value.value.startswith('unmeasurable:') or (isinstance(returned.value,ast.Tuple) and returned.value.elts and isinstance(returned.value.elts[0],ast.Constant) and returned.value.elts[0].value is None)):
                            failures.append({'file':rel,'line':value.lineno,'reason':'untranslated unmeasurable return'})
            for n in ast.walk(tree):
                if not isinstance(n,ast.Call):continue
                name=n.func.id if isinstance(n.func,ast.Name) else n.func.attr if isinstance(n.func,ast.Attribute) else ''
                if name not in ['die','say','write','print','append','skip','add_argument']:continue
                if name=='append' and (not isinstance(n.func,ast.Attribute) or not isinstance(n.func.value,ast.Name) or n.func.value.id not in ['fails','errors','SKIPS','skips']):continue
                for arg in n.args:
                    for v in ast.walk(arg):
                        if isinstance(v,ast.Constant) and isinstance(v.value,str) and HANGUL.search(v.value):
                            failures.append({'file':rel,'line':v.lineno,'reason':'untranslated diagnostic literal'})
    if checked==0:raise ValueError('No public text files read')
    return {'checked_files':checked,'failures':failures,'korean_containing_files':korean,
            'preserved_vector_files':protected,'source_layout_references':compatibility,
            'scope':'Private document names/coordinates, reader paths, browser references, canonical prose and checker diagnostics. Exact frozen bytes pinned separately; source-layout compatibility paths inventoried; Korean is not globally banned.'}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    ap.add_argument('--report',type=Path)
    a=ap.parse_args()
    try:r=inspect(a.root.resolve())
    except (OSError,ValueError,SyntaxError) as e:print('PUBLIC-CONTENT: CANNOT_CHECK:',e);return 2
    if a.report:a.report.write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n')
    for f in r['failures']:print('FAIL:',f)
    print('PUBLIC-CONTENT: %s (%d findings; %d text files; %d contain Korean)' % ('FAIL' if r['failures'] else 'PASS',len(r['failures']),r['checked_files'],len(r['korean_containing_files'])))
    return 1 if r['failures'] else 0

if __name__=='__main__':sys.exit(main())
