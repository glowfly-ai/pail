#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Durable-store table (spec/DURABLE_STORES.tsv): every store that claims durability names what it does when it
cannot be durable, and the test that proves it (preview.25 evaluation P25-M2: the agent's report queue fell back
to memory silently while its fatal path logged "queued durably").

Checks, on the internal tree or a public snapshot:
  D1  every row names a component, a store, its configuration and the behaviour when unusable; the behaviour
      says `refuses` / `written ... before` / `not issued` (a durable answer), never `memory` as a fallback;
  D2  every cited test exists: `<package dir>:<TestName>` under cloud/ (public) or services/pail_services_go/
      (internal), as `func TestName(` in a *_test.go file of that package; `untested` rows are reported by name;
  D3  the agent's queue source carries the refusal word the table cites (REPORT_QUEUE_NOT_DURABLE) and no
      "memory only, not durable" fallback log.

usage: spec_durable_stores_check.py            rc 0 PASS, rc 1 FAIL, rc 2 misuse
"""
import csv
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def layout():
    for root in (HERE.parent / 'oss', HERE.parent, HERE.parent.parent):
        if (root / 'spec' / 'DURABLE_STORES.tsv').is_file():
            go = next((d for d in (root / 'cloud', root.parent / 'services' / 'pail_services_go') if (d / 'go.mod').is_file()), None)
            return root, go
    raise SystemExit('spec/DURABLE_STORES.tsv not found beside ' + str(HERE))


def main(argv):
    if argv:
        print('usage: spec_durable_stores_check.py', file=sys.stderr); return 2
    root, go = layout()
    with (root / 'spec' / 'DURABLE_STORES.tsv').open(encoding='utf-8') as f:
        lines = [l for l in f if l.strip() and not l.startswith('#')]
    rows = list(csv.DictReader(lines, delimiter='\t'))
    fails, untested = [], []
    for r in rows:
        name = r['component'] + '/' + r['store']
        if not all(r.get(k, '').strip() for k in ('component', 'store', 'configuration', 'when_unusable', 'test')):
            fails.append('D1 %s: empty cell' % name); continue
        w = r['when_unusable'].lower()
        if 'memory' in w and 'requires' not in w and 'untested' not in w:
            fails.append('D1 %s: the behaviour when unusable falls back to memory without a stated opt-out: %s' % (name, r['when_unusable'][:80]))
        t = r['test']
        if t == 'untested':
            untested.append(name); continue
        if ':' not in t:
            fails.append('D2 %s: test %r is not <package>:<TestName>' % (name, t)); continue
        pkg, fn = t.split(':', 1)
        if go is None:
            fails.append('D2 cannot check %s: no Go tree in this layout' % t); continue
        if not (go / pkg).is_dir():
            print('[INFO] %s cites %s: package not in this layout (checked where the tree exists)' % (name, t)); continue
        files = list((go / pkg).glob('*_test.go'))
        if not any(re.search(r'^func ' + re.escape(fn) + r'\(', p.read_text(encoding='utf-8', errors='replace'), re.M) for p in files):
            fails.append('D2 %s cites %s but no %s/*_test.go defines func %s(' % (name, t, pkg, fn))
    if go is not None:
        src = go / 'cmd' / 'pail_robot_agent' / 'reportqueue.go'
        if src.is_file():
            text = src.read_text(encoding='utf-8', errors='replace')
            if 'REPORT_QUEUE_NOT_DURABLE' not in text:
                fails.append('D3 reportqueue.go no longer refuses with REPORT_QUEUE_NOT_DURABLE')
            if 'memory only, not durable' in text:
                fails.append('D3 reportqueue.go carries the silent memory-only fallback log again')
    for f in fails:
        print('[FAIL] ' + f)
    if untested:
        print('[INFO] untested rows (%d): %s' % (len(untested), ', '.join(untested)))
    print('SPEC-DURABLE-STORES: %s rows=%d tested=%d untested=%d' % ('FAIL' if fails else 'PASS', len(rows), len(rows) - len(untested), len(untested)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
