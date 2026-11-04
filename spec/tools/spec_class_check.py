#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Class pins: static checks for defect *kinds* that returned under new names (root-cause analysis 2026-10-20 §2.3).

An instance pin fixes one sentence in one file; a class pin reads the whole tree for the shape of the defect.
Five classes, each with a red fixture in the contract suite (a checker that was never seen red proves nothing):

  C1 bind-first       a URL / JUDGE / CONSOLE announcement is printed only after the listener is bound
                      (port family: rc1, rc12, rc13-15, rc23, p1-m1, p22-N2 — seven times under new names)
  C2 no-traceback     every user-facing entry point ends a failure with a named refusal line, never a bare traceback
                      (message family, 33 findings)
  C3 wall-clock       elapsed time and deadlines are not computed by subtracting two wall-clock readings
                      (clock family, 10 findings); an intentional wall reading is annotated `# wall-clock: <reason>`
  C4 ko-en-structure  a Korean edition has the same heading / fenced-block / table-row counts as its English edition,
                      or declares the difference (`<!-- ko-structure: abridged -->`, or `<!-- ko-structure: differs: <why> -->`) so it is a decision, not drift
  C5 feature-off      dashboard scripts never request an endpoint the served page declared absent, and a 503 from
                      the capabilities endpoint is read as "unsupported", not as a transient stale state
  C6 compose-cause    every file that starts a compose project (a `['docker', 'compose', ...]` command other than
                      `version`) imports examples/common/compose_failure, so a stack that did not come up is reported
                      by the daemon's condition, not by `rc=1; see log` or an exception class name (P23-L1 closed the
                      test runners; P24-L1 found the three interactive demos outside that fix)

C1 is a static reading of line order inside one file; the contract suite adds the executed form (a held port, the
launcher started, zero announcement lines on stdout), because a bind early in a file would satisfy the static
reading regardless of execution order (preview.24 evaluation P24-N1).

usage: spec_class_check.py [--root DIR]      rc 0 PASS, rc 1 FAIL, rc 2 misuse. Runs on the internal tree and on a
public snapshot (the tool finds whichever layout holds it). Annotations:
  # class-pin: bind-first <reason>     on an announcement line that is provably after the bind in another way
  # class-pin: no-traceback <reason>   on the __main__ line of an entry point that reports failures elsewhere
  # class-pin: compose-cause <reason>  on a compose command line that cannot fail to bring a stack up (a probe)
  # wall-clock: <reason>               on a wall-clock subtraction that is a measurement of the wall clock itself
"""
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def layout():
    for cand in (HERE.parent, HERE.parent / 'oss', HERE.parent.parent, HERE.parent.parent / 'oss'):
        if (cand / 'examples').is_dir() and (cand / 'README.md').is_file():
            dash = None
            for d in (cand / 'cloud' / 'cmd' / 'pail_telemetryd' / 'dashboard',
                      cand.parent / 'services' / 'pail_services_go' / 'cmd' / 'pail_telemetryd' / 'dashboard'):
                if d.is_dir():
                    dash = d
                    break
            return cand, dash
    raise SystemExit('cannot find the examples/ tree beside ' + str(HERE))


ANNOUNCE = re.compile(r"print\(.*(CONSOLE=|FLEET_CONSOLE=|JUDGE:|http://127\.0\.0\.1)")
BIND = re.compile(r"\.bind\(|HTTPServer\(|server_address|serve_forever|\.listen\(|start_server\(|\.start\(\)")
ENTRY_POINTS = ('distribution/evaluation.py', 'examples/microduck/run.py', 'examples/microduck/demo.py', 'examples/tb3/run.py',
                'examples/tb3/demo.py', 'examples/tb3/demo_scenes.py', 'examples/tb3/hardware/console_hw.py',
                'examples/tb3/hardware/fault_inject.py', 'examples/viewer/run.py', 'examples/nvidia/run.py',
                'distribution/supersede_check.py')
WALL = re.compile(r"time\.time\(\)\s*-\s*[A-Za-z_]|[A-Za-z_\]\)]\s*-\s*time\.time\(\)|\['t'\]\s*-\s*[A-Za-z_]+\['t'\]")
PY_DIRS = ('examples', 'distribution', 'scripts')


def py_files(root):
    for d in PY_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob('*.py')):
            if '__pycache__' in p.parts or p.name.endswith('_test.py') or '/tests/' in p.as_posix():
                continue
            yield p


def c1_bind_first(root):
    fails = []
    for p in py_files(root):
        lines = p.read_text(encoding='utf-8', errors='replace').splitlines()
        first_bind = next((i for i, l in enumerate(lines) if BIND.search(l)), None)
        for i, l in enumerate(lines):
            if ANNOUNCE.search(l) and 'class-pin: bind-first' not in l:
                if first_bind is None or first_bind > i:
                    fails.append('C1 %s:%d announces a listener before any bind in this file: %s' % (p.relative_to(root), i + 1, l.strip()[:70]))
    return fails


def c2_no_traceback(root):
    fails = []
    for rel in ENTRY_POINTS:
        p = root / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding='utf-8', errors='replace')
        m = re.search(r"^if __name__\s*==\s*['\"]__main__['\"]\s*:(.*)$", text, re.M)
        if not m:
            # a script-style tool (no __main__ block) must still catch its failures at top level and print a verdict word
            if not re.search(r"^except\b", text, re.M) or 'RESULT=' not in text:
                fails.append('C2 %s: script-style tool without a top-level except and a RESULT= line' % rel)
            continue
        if 'class-pin: no-traceback' in m.group(0):
            continue
        block = text[m.end():]
        if not re.search(r"^\s+except\b", block, re.M):
            fails.append('C2 %s: the __main__ block does not catch failures (a refusal line, not a traceback, ends a run)' % rel); continue
        if not re.search(r"(REFUSED|RESULT=|ERROR|BLOCKED|FAIL)", block):
            fails.append('C2 %s: the __main__ except branch names no refusal/verdict word' % rel)
    return fails


def c3_wall_clock(root):
    fails = []
    for p in py_files(root):
        for i, l in enumerate(p.read_text(encoding='utf-8', errors='replace').splitlines()):
            if WALL.search(l) and '# wall-clock:' not in l and not l.strip().startswith('#'):
                fails.append('C3 %s:%d elapsed time from two wall-clock readings (use time.monotonic(), or annotate `# wall-clock: <reason>`): %s' % (p.relative_to(root), i + 1, l.strip()[:70]))
    return fails


def shape(text):
    return (len(re.findall(r'^#{1,6} ', text, re.M)), text.count('\n```'), len(re.findall(r'^\|', text, re.M)))


def ko_candidates(root):
    """Every *.ko.md of the public documents. In the internal layout (root = oss/) the public governance documents and the
    adapter READMEs live beside oss/ and are mapped in by the public-tree list; scan them too so the pin reads what a
    recipient reads."""
    seen = set(sorted(root.rglob('*.ko.md')))
    if root.name == 'oss':
        seen |= set(root.parent.glob('*.ko.md'))
        seen |= set((root.parent / 'adapters').rglob('*.ko.md')) if (root.parent / 'adapters').is_dir() else set()
    return sorted(seen)


def c4_ko_en(root):
    fails = []
    for ko in ko_candidates(root):
        if 'node_modules' in ko.parts or '/target/' in ko.as_posix() or '/demo/' in ko.as_posix():
            continue
        en = ko.with_name(ko.name[:-6] + '.md')
        if not en.is_file():
            continue
        kt = ko.read_text(encoding='utf-8', errors='replace')
        if '<!-- ko-structure: abridged -->' in kt or '<!-- ko-structure: differs' in kt:
            continue   # a declared decision (abridged, or a stated structural difference), not drift
        a, b = shape(en.read_text(encoding='utf-8', errors='replace')), shape(kt)
        if a != b:
            fails.append('C4 %s: headings/fences/table-rows %s vs Korean %s (align the edition or declare `<!-- ko-structure: abridged -->` / `<!-- ko-structure: differs: <why> -->`)' % (en.name if root not in en.parents else en.relative_to(root), a, b))
    return fails


def c5_feature_off(dash):
    fails = []
    if dash is None:
        return ['C5 dashboard directory not found']
    for js in sorted(dash.glob('*.js')):
        t = js.read_text(encoding='utf-8', errors='replace')
        if '/v1/telemetry/robotops' in t and 'meta[name="pail-robotops"]' not in t:
            fails.append('C5 %s requests the robot-operations endpoint without reading the page capability' % js.name)
    fleet = dash / 'fleet.js'
    if fleet.is_file():
        t = fleet.read_text(encoding='utf-8', errors='replace')
        if 'CAPABILITY_UNSUPPORTED' not in t:
            fails.append('C5 fleet.js does not read a capabilities 503 as unsupported (rc23: stale banner on a feature that is off)')
    index = dash / 'index.html'
    if index.is_file() and '<meta name="pail-robotops"' not in index.read_text(encoding='utf-8', errors='replace'):
        fails.append('C5 index.html carries no pail-robotops capability meta')
    return fails


COMPOSE = re.compile(r"\[\s*['\"]docker['\"]\s*,\s*['\"]compose['\"]")


def c6_compose_cause(root):
    fails = []
    for p in py_files(root):
        if p.name == 'compose_failure.py':
            continue
        lines = p.read_text(encoding='utf-8', errors='replace').splitlines()
        starts = [i for i, l in enumerate(lines) if COMPOSE.search(l) and "'version'" not in l and '"version"' not in l
                  and 'class-pin: compose-cause' not in l and not l.strip().startswith('#')]
        if starts and not any('compose_failure' in l for l in lines):
            fails.append('C6 %s:%d builds a compose command but never reads compose_failure (a stack that does not come up must name the daemon condition)' % (p.relative_to(root), starts[0] + 1))
    return fails


def main(argv):
    if argv and argv != ['--root'] and not (len(argv) == 2 and argv[0] == '--root'):
        print('usage: spec_class_check.py [--root DIR]', file=sys.stderr); return 2
    if len(argv) == 2:
        root = Path(argv[1]).resolve()
        dash = next((d for d in (root / 'cloud' / 'cmd' / 'pail_telemetryd' / 'dashboard', root.parent / 'services' / 'pail_services_go' / 'cmd' / 'pail_telemetryd' / 'dashboard') if d.is_dir()), None)
    else:
        root, dash = layout()
    fails = c1_bind_first(root) + c2_no_traceback(root) + c3_wall_clock(root) + c4_ko_en(root) + c5_feature_off(dash) + c6_compose_cause(root)
    for f in fails:
        print('[FAIL] ' + f)
    print('SPEC-CLASS: %s failures=%d classes=6 root=%s' % ('FAIL' if fails else 'PASS', len(fails), root))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
