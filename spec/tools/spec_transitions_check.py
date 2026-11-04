#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Gate session transition table (spec/GATE_SESSION_TRANSITIONS.tsv): shape and test citations (request A1, skeleton).

Checks, on the internal tree or a public snapshot:
  T1  every (state, event) pair appears at most once and every state named in `next` is a declared state;
  T2  every cited test exists: a libpail_gate CTest name (libpail_gate/test/<name>.cpp) or `untested`;
  T3  the table reports its coverage: rows with a test / rows untested — untested rows are gaps, printed by name,
      not failures (the generated tests that close them are the next candidate's work; a row that cites a test
      which does not exist IS a failure).

usage: spec_transitions_check.py            rc 0 PASS, rc 1 FAIL, rc 2 misuse
"""
import csv
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def layout():
    for root in (HERE.parent / 'oss', HERE.parent, HERE.parent.parent):
        if (root / 'spec' / 'GATE_SESSION_TRANSITIONS.tsv').is_file():
            gate = next((d for d in (root / 'libpail_gate' / 'test', root.parent / 'libpail_gate' / 'test') if d.is_dir()), None)
            return root, gate
    raise SystemExit('spec/GATE_SESSION_TRANSITIONS.tsv not found beside ' + str(HERE))


def main(argv):
    if argv:
        print('usage: spec_transitions_check.py', file=sys.stderr); return 2
    root, gate = layout()
    rows = []
    with (root / 'spec' / 'GATE_SESSION_TRANSITIONS.tsv').open(encoding='utf-8') as f:
        lines = [l for l in f if l.strip() and not l.startswith('#')]
    reader = csv.DictReader(lines, delimiter='\t')
    rows = list(reader)
    fails = []
    states = {r['state'] for r in rows}
    seen = set()
    for r in rows:
        key = (r['state'], r['event'])
        if key in seen:
            fails.append('T1 duplicate row %s/%s' % key)
        seen.add(key)
        if r['next'] not in states:
            fails.append('T1 %s/%s: next state %r is not a declared state' % (key + (r['next'],)))
    tests = {p.stem for p in gate.glob('test_*.cpp')} if gate else set()
    node_dir = next((d for d in (root / 'pail_ws' / 'src' / 'pail_pep_gate' / 'test', root.parent / 'pail_ws' / 'src' / 'pail_pep_gate' / 'test') if d.is_dir()), None)
    node_tests = {p.stem for p in node_dir.glob('test_*.cpp')} if node_dir else None
    cited = {r['test'] for r in rows if r['test'] != 'untested'}
    unchecked = []
    for t in sorted(cited):
        if t.startswith('node:'):
            if node_tests is None:
                unchecked.append(t)   # the ROS gate node is not part of the public Core; the citation is checked in the internal tree
            elif t[5:] not in node_tests:
                fails.append('T2 row cites %s but pail_ws/src/pail_pep_gate/test/%s.cpp does not exist' % (t, t[5:]))
            continue
        if gate is None:
            fails.append('T2 cannot check %s: libpail_gate/test not in this layout' % t); break
        if t not in tests:
            fails.append('T2 row cites %s but libpail_gate/test/%s.cpp does not exist' % (t, t))
    if unchecked:
        print('[INFO] node test citations not checkable in this layout (%d): %s' % (len(unchecked), ', '.join(unchecked)))
    untested = [r['state'] + '/' + r['event'] for r in rows if r['test'] == 'untested']
    for f in fails:
        print('[FAIL] ' + f)
    print('[INFO] untested rows (%d): %s' % (len(untested), ', '.join(untested)))
    print('SPEC-TRANSITIONS: %s rows=%d states=%d tested=%d untested=%d cited_tests=%d' % (
        'FAIL' if fails else 'PASS', len(rows), len(states), len(rows) - len(untested), len(untested), len(cited)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
