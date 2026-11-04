#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Guard registry and mutation checks for cmd/pail-verify/GUARDS.tsv.

이 검사기가 겨누는 실패는 실측이다 (2026-08-31). `cmd/pail-verify/main.go` 의
거부 관문을 하나씩 통째로 떼고 **실린 테스트를 그대로** 돌렸더니 39개 중 23개가
rc=0 이었다. 서명을 보지 않는 검증기 하나는 공개 CI 의 양성 대조가 잡아 주고
있었지만, 나머지 스물셋은 지워도 초록이었다 — 그 초록은 「관문이 산다」가 아니라
「관문의 생사를 아무도 재지 않는다」였고, 요약에서 둘은 같은 글자로 도착한다
(`H-B2`). 받은 사람 입장에서 더 나쁘다: 그는 우리 하네스를 갖고 있지 않으므로
실린 테스트의 초록 말고는 이 도구를 믿을 근거가 없다.

처분은 테스트를 늘리는 것만으로 끝나지 않는다. 관문 중 일부는 옆 관문이 먼저
걸려 **혼자서는 붉힐 수 없다**. 그것을 「가려짐」이라고 적는 순간 그 낱말이 새로운
「통과」가 된다 — 가려졌다는 주장 자체에 관측점이 없으면, 실은 아무도 안 지나는
죽은 경로였다는 사실과 구별되지 않는다. 그래서 등재부의 `shadowed` 행은 반증
가능해야 한다: 그 관문과 짝을 **함께** 떼면 붉어야 한다.

  N1   등재부가 파싱된다: 여섯 칸, 아는 `status`, 빈 칸 없음
  N2   관문 id 가 유일하고 조밀하다 (`G01`..`GNN`, 구멍 없음)
  N3   모든 `old` 앵커가 `main.go` 안에서 **정확히 한 번** 나타난다
  N4   모든 변형이 실제로 바이트를 바꾼다 (`new != old`)
  N5   `covered` 의 증거가 실린 테스트 파일에 실제 함수로 있다
  N6   `shadowed` 의 짝이 등재부의 다른 관문이고, 그 짝이 또 가려져 있지 않다
  N7   거부 자리 집합의 크기와 SHA-256 이 등재부의 핀과 같다
  N8   등재부 머리말이 산문으로 적은 「조용한 칸」 수 == 유도한 `shadowed` 수
  N9   이 파일이 구현한 관측점 == 등재부 머리말이 광고한 관측점 (양방향)
  M1   (`--mutate`) `covered` 를 홀로 떼면 지목한 테스트가 붉는다
  M2   (`--mutate`) `shadowed` 를 홀로 떼면 조용하다 — 아니면 `covered` 로 올려라
  M3   (`--mutate`) `shadowed` 를 짝과 **함께** 떼면 붉는다

N7 이 수만이 아니라 해시를 핀하는 것은 규칙이다. 수만 핀하면 관문 하나를 지우고
하나를 더한 편집이 조용히 지나간다 — 그리고 그 편집이야말로 리뷰가 봐야 하는
모양이다.

N5 가 「테스트가 존재한다」까지만 재는 것은 정직하게 좁은 주장이다. 그 테스트가
정말 그 관문을 재는지는 정적으로 알 수 없고, `M1` 이 실측으로만 답한다. 그래서
`--mutate` 없는 실행이 스스로를 「완전 검증」이라고 부르지 않도록 마지막 줄에
어느 모드로 돌았는지를 함께 찍는다.

M2 가 있는 이유: 가려졌다고 적힌 관문이 실은 혼자서도 붉는다면 그 행은 사실보다
약하게 적힌 것이고, 등재부는 실제보다 덜 검증된 것처럼 스스로를 그린다. 약한
쪽으로 틀린 등재도 등재의 표류다.

N8 은 처음에 `covered + shadowed == len(rows)` 였는데, 파서가 모르는 `status` 인
행을 `rows` 에 넣지 않으므로 그 등식은 **항등식**이었다 — 표에 실리고 이름도
불리는데 어떤 편집으로도 붉힐 수 없는 칸, 곧 요약에서 영원한 「통과」다. 지금은
머리말의 산문이 적은 수를 잰다. 사람이 읽는 것은 표가 아니라 그 문장이고,
문장은 표보다 먼저 낡는다.

rc: 0 = FAIL 0, 1 = FAIL 있음, 2 = 검사기가 자기 전제를 세우지 못함.
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys

# Preserve diagnostic text on legacy consoles without changing checked bytes.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="backslashreplace")
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# (배치 이름, 스크립트 자리 꼬리, 검증기 디렉터리)
LAYOUTS = (
    ('internal', ('scripts',), 'oss/cmd/pail-verify'),
    ('public', ('spec', 'tools'), 'cmd/pail-verify'),
)

IDS = ('N1', 'N2', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8', 'N9', 'M1', 'M2', 'M3')

STATUSES = ('covered', 'shadowed')

# main.go 의 거부 자리. 에러를 만들거나, 0 아닌 종료를 돌려주거나, stderr 에
# 사유를 찍는 줄이다. 한 규칙으로 뽑는 것이 핵심이다 — 자리마다 사람이 표를
# 다는 방식은 표를 안 단 자리를 영원히 안 보이게 만든다.
SITE_RE = re.compile(
    r'^\s*(return (nil, )?(err\b|errMalformed|errSignature|errOrigin|errors\.New'
    r'|fmt\.Errorf|exitCannot|exitFinding)'
    r'|fmt\.Fprint\w*\(os\.Stderr)')

SITES_RE = re.compile(r'^#[ \t]*refusal-sites:[ \t]*([0-9]+)[ \t]*$', re.M)
DIGEST_RE = re.compile(r'^#[ \t]*refusal-digest:[ \t]*([0-9a-f]{64})[ \t]*$', re.M)
# 등재부 머리말이 광고하는 관측점. N9 가 양방향으로 대조한다.
ADVERT_RE = re.compile(r'^[ \t]+(N[0-9]+|M[0-9]+)[ \t]+\S', re.M)
GOFUNC_RE = re.compile(r'^func (Test\w+)\(t \*testing\.T\) \{$', re.M)
# 머리말이 산문으로 적은 「조용한 칸」의 수. 두 자리에 같은 수가 나오므로 둘 다 잰다.
QUIET_RE = re.compile(r'조용한 칸이 ([0-9]+)이고 그 ([0-9]+)은')
GOFAIL_RE = re.compile(r'^\s*--- FAIL: (\S+)', re.M)

FAILS = []


def die(msg):
    # 전제 실패만 인쇄하면 「무엇이 빠졌는지」의 칸이 영원히 안 보인다 (AC-1 의 교훈).
    for code, m in FAILS:
        sys.stdout.write('[FAIL] %s %s\n' % (code, m))
    sys.stdout.write("SPEC-GUARDS: prerequisite failure — %s\n" % msg)
    raise SystemExit(2)


def read(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return fh.read()
    except OSError as exc:
        die("Cannot read: %s (%s)" % (path, exc))


def locate(here=HERE):
    parts = here.replace(os.sep, '/').split('/')
    hit = []
    for name, tail, cmddir in LAYOUTS:
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            hit.append((name, root, os.path.join(root, *cmddir.split('/'))))
    if len(hit) != 1:
        die("Cannot determine layout (%d matches); script location: %s" % (len(hit), here))
    return hit[0]


def unescape(field):
    """`\\\\` `\\t` `\\n` 을 푼다. 역슬래시를 먼저 보는 것이 규칙이다 — 나중에 보면
    `\\\\n` 이 줄바꿈으로 풀려 Go 문자열 리터럴 안의 `\\n` 을 못 적는다."""
    out = []
    i = 0
    while i < len(field):
        c = field[i]
        if c == '\\' and i + 1 < len(field):
            nxt = field[i + 1]
            if nxt in '\\tn':
                out.append({'\\': '\\', 't': '\t', 'n': '\n'}[nxt])
                i += 2
                continue
        out.append(c)
        i += 1
    return ''.join(out)


def parse(path, fails):
    """등재부를 (guard, status, evidence, what, old, new) 로 읽는다."""
    rows = []
    for n, line in enumerate(read(path).split('\n'), 1):
        if not line.strip() or line.startswith('#'):
            continue
        f = line.split('\t')
        if len(f) != 6:
            fails.append(('N1', "Line %d: %d columns, expected six" % (n, len(f))))
            continue
        if any(not x.strip() for x in f):
            fails.append(('N1', "Line %d (%s): empty field; unknown must not be treated as absent" % (n, f[0])))
            continue
        if f[1] not in STATUSES:
            fails.append(('N1', "Line %d (%s): unrecognized status %r; recognized values %s"
                          % (n, f[0], f[1], list(STATUSES))))
            continue
        rows.append((f[0], f[1], f[2], f[3], unescape(f[4]), unescape(f[5])))
    if not rows:
        die("No registry rows read: %s" % path)
    return rows


def refusal_sites(go_src):
    """main.go 의 거부 자리를 정규화·정렬해 낸다."""
    return sorted(l.strip() for l in go_src.split('\n') if SITE_RE.match(l))


def gotest(mount, rel):
    """떼어낸 사본에서 실린 테스트를 돌린다.

    Go 가 PATH 에 있으면 그대로 쓰고, 없으면 컨테이너로 내려간다. 받는 사람에게
    도커를 요구하지 않는 것이 요점이다 — 검증기 자체는 표준 라이브러리 전용인데
    그것을 재는 도구가 도커를 요구하면 재현 가능성이 한 단계 좁아진다.

    어느 쪽이든 실행의 뿌리는 모듈 디렉터리가 아니라 그 **위**다. 테스트가 벡터를
    `../../spec/...` 으로 찾으므로, 모듈만 보이게 하면 벡터가 안 보이고 그 부재는
    「변형이 물었다」와 같은 붉은 줄로 도착한다 (실측 2026-08-31: 무변형 기준선이
    19건 붉었다).
    """
    if shutil.which('go'):
        argv = ['go', 'test', '-count=1', './...']
        cwd = os.path.join(mount, *rel.split('/'))
    else:
        argv = ['docker', 'run', '--rm', '-v', mount + ':/work',
                '-v', 'pail-gocache:/go', '-w', '/work/' + rel,
                'golang:1.27.3', 'go', 'test', '-count=1', './...']
        cwd = None
    proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


SPEC_REF_RE = re.compile(r'"\.\./\.\./(spec/[^"]+)"')
SANDBOX_SPEC_DEFAULT = ('spec/vectors', 'spec/proof-vectors')


def sandbox_spec_dirs(cmddir):
    """The `../../spec/<p>` directories the distributed tests read, as paths relative to the tree root.

    Derived from the test sources rather than listed by hand. The internal tree keeps the vectors under
    spec/vectors/{proof,merkle} while the public snapshot renames them to spec/{proof,merkle}-vectors; a
    fixed list covered the first layout only, and in the public layout the unmodified baseline went red on
    the Merkle corpus tests (first public CI run, 2026-11-04) — a prerequisite failure that looks like a
    detected mutation unless the control reads it. Only directories that exist are returned, in the same
    relative place the tests look for them; an empty result falls back to the historical pair.
    """
    root = os.path.dirname(os.path.dirname(cmddir))
    refs = set()
    for name in sorted(os.listdir(cmddir)):
        if name.endswith('_test.go'):
            refs |= set(SPEC_REF_RE.findall(read(os.path.join(cmddir, name))))
    found = sorted(r for r in refs if os.path.isdir(os.path.join(root, *r.split('/'))))
    if not found:
        found = [r for r in SANDBOX_SPEC_DEFAULT if os.path.isdir(os.path.join(root, *r.split('/')))]
    return found


def public_layout_copy(root):
    """Rebuild the public snapshot layout from the internal tree in a temporary directory and return its
    cmd/pail-verify path, following gen_public_tree.py: spec/vectors <- tests/golden/, and
    oss/spec/vectors/{merkle,proof,subgraph} -> spec/{merkle,proof,subgraph}-vectors. Returns None when the
    tree is not the internal layout (the public tree already is that layout). The caller removes the copy."""
    golden = os.path.join(root, 'tests', 'golden')
    vectors = os.path.join(root, 'oss', 'spec', 'vectors')
    cmd = os.path.join(root, 'oss', 'cmd', 'pail-verify')
    if not (os.path.isdir(golden) and os.path.isdir(vectors) and os.path.isdir(cmd)):
        return None
    work = tempfile.mkdtemp(prefix='pailguards-public.')
    shutil.copytree(cmd, os.path.join(work, 'cmd', 'pail-verify'))
    shutil.copytree(golden, os.path.join(work, 'spec', 'vectors'))
    for src, dst in (('merkle', 'merkle-vectors'), ('proof', 'proof-vectors'), ('subgraph', 'subgraph-vectors')):
        if os.path.isdir(os.path.join(vectors, src)):
            shutil.copytree(os.path.join(vectors, src), os.path.join(work, 'spec', dst))
    return os.path.join(work, 'cmd', 'pail-verify')


def mutate_run(cmddir, edits, fails):
    """`edits` 를 모두 심은 사본에서 테스트를 돌리고 (rc, 붉은 테스트 이름들) 을 낸다.

    사본에서 돈다 — 재려던 상태를 없애는 프로브는 그 부재를 측정한다. 실린 트리는
    이 함수가 끝난 뒤에도 한 바이트도 다르지 않다.
    """
    work = tempfile.mkdtemp(prefix='pailguards.')
    try:
        # 실린 테스트는 벡터를 `../../spec/...` 로 찾는다. 사본의 깊이가 다르면
        # 벡터를 못 찾고, 그 실패는 「변형이 물었다」와 같은 붉은 줄로 도착한다.
        dst = os.path.join(work, 'cmd', 'pail-verify')
        os.makedirs(os.path.dirname(dst))
        shutil.copytree(cmddir, dst)
        # 벡터는 `../../spec/...` 로 찾는다. 사본에서도 같은 상대 자리에 둔다.
        tree_root = os.path.dirname(os.path.dirname(cmddir))
        for rel in sandbox_spec_dirs(cmddir):
            src = os.path.join(tree_root, *rel.split('/'))
            out = os.path.join(work, *rel.split('/'))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            shutil.copytree(src, out)
        main = os.path.join(dst, 'main.go')
        text = read(main)
        for gid, old, new in edits:
            if text.count(old) != 1:
                fails.append(('M1', "%s: anchor occurs %d times in the copy; cannot apply mutation" % (gid, text.count(old))))
                return None, None
            text = text.replace(old, new, 1)
        with open(main, 'w', encoding='utf-8') as fh:
            fh.write(text)
        rc, out = gotest(work, 'cmd/pail-verify')
        if 'build failed' in out or 'syntax error' in out:
            # 컴파일되지 않는 변형은 검사기를 증명하지 않는다 (가짜 RED).
            return 'build', out
        return rc, sorted(set(GOFAIL_RE.findall(out)))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(add_help=True, description=__doc__.split('\n')[0])
    ap.add_argument('--mutate', action='store_true',
                    help='Measure registry claims using Docker and Go tests (several minutes)')
    ap.add_argument('--only', default='',
                    help='Limit mutations to these comma-separated guard IDs')
    ap.add_argument('--baseline-only', action='store_true',
                    help='With --mutate: run the unmodified sandbox baseline only (one Go test run) and stop')
    ap.add_argument('--public-layout', action='store_true',
                    help='In the internal tree: measure a temporary copy laid out like the public snapshot; ignored in the public tree')
    args = ap.parse_args()

    layout, root, cmddir = locate()
    public_copy = None
    if args.public_layout:
        public_copy = public_layout_copy(root)
        if public_copy is not None:
            cmddir = public_copy
            layout = layout + '/public-copy'
    ledger = os.path.join(cmddir, 'GUARDS.tsv')
    main_go = os.path.join(cmddir, 'main.go')
    for p in (ledger, main_go):
        if not os.path.isfile(p):
            die("Missing: %s" % p)

    fails = FAILS
    rows = parse(ledger, fails)
    go_src = read(main_go)
    raw = read(ledger)

    # --- N2: id 유일 · 조밀 ---------------------------------------------------
    ids = [r[0] for r in rows]
    if len(set(ids)) != len(ids):
        dup = sorted(i for i in set(ids) if ids.count(i) > 1)
        fails.append(('N2', "Duplicate guard ID: %s; evidence would be ambiguous" % dup))
    want = ['G%02d' % (i + 1) for i in range(len(ids))]
    if sorted(ids) != want:
        fails.append(('N2', "IDs are not contiguous: expected %s..%s, missing %s, extra %s" % (want[0], want[-1],
                                         sorted(set(want) - set(ids)),
                                         sorted(set(ids) - set(want)))))

    # --- N3/N4: 앵커 유일성 · 변형이 바이트를 바꾸는가 --------------------------
    for gid, _st, _ev, _wh, old, new in rows:
        n = go_src.count(old)
        if n != 1:
            fails.append(('N3', "%s: old anchor occurs %d times in main.go; mutation target must be unique"
                          % (gid, n)))
        if old == new:
            fails.append(('N4', "%s: new equals old; a no-op mutation cannot establish detection or shadowing" % gid))

    # --- N5/N6: 증거 --------------------------------------------------------
    tests = set()
    for name in sorted(os.listdir(cmddir)):
        if name.endswith('_test.go'):
            tests |= set(GOFUNC_RE.findall(read(os.path.join(cmddir, name))))
    if not tests:
        die("No distributed test functions found: %s" % cmddir)
    by_id = {r[0]: r for r in rows}
    for gid, status, ev, _wh, _o, _n in rows:
        if status == 'covered':
            if ev not in tests:
                fails.append(('N5', "%s: evidence cites `%s`, which is not a distributed test"
                              % (gid, ev)))
        else:
            if ev == gid:
                fails.append(('N6', "%s: guard cannot shadow itself" % gid))
            elif ev not in by_id:
                fails.append(('N6', "%s: shadowing partner `%s` is absent from the registry" % (gid, ev)))
            elif by_id[ev][1] != 'covered':
                fails.append(('N6', "%s is said to be shadowed by %s, but %s is also shadowed; unsupported shadow chain"
                              % (gid, ev, ev)))

    # --- N7: 거부 자리 핀 ----------------------------------------------------
    sites = refusal_sites(go_src)
    digest = hashlib.sha256('\n'.join(sites).encode('utf-8')).hexdigest()
    pin_n = SITES_RE.findall(raw)
    pin_d = DIGEST_RE.findall(raw)
    if len(pin_n) != 1 or len(pin_d) != 1:
        fails.append(('N7', "Pins contain refusal-sites %d times and refusal-digest %d times; exactly one each is required" % (len(pin_n), len(pin_d))))
    else:
        if int(pin_n[0]) != len(sites):
            fails.append(('N7', "Observed %d refusal sites; pin declares %s"
                          % (len(sites), pin_n[0])))
        if pin_d[0] != digest:
            fails.append(('N7', "Refusal-site SHA-256 differs: pinned %s / observed %s; review changed guards and update the registry/pin"
                          % (pin_d[0][:16] + '…', digest[:16] + '…')))

    # --- N8: 머리말의 산문이 표와 같은 수를 말하는가 ----------------------------
    # 독자가 읽는 것은 표가 아니라 이 문장이다. 문장은 표보다 먼저 낡는다.
    n_cov = sum(1 for r in rows if r[1] == 'covered')
    n_sha = sum(1 for r in rows if r[1] == 'shadowed')
    quiet = QUIET_RE.findall(raw)
    if len(quiet) != 1:
        fails.append(('N8', "Found %d statements counting unobserved guards; exactly one is required" % len(quiet)))
    elif {int(x) for x in quiet[0]} != {n_sha}:
        fails.append(('N8', "Header declares %s unobserved guards; registry contains %d rows"
                      % (' / '.join(quiet[0]), n_sha)))

    # --- N9: 머리말이 광고한 관측점 == 구현한 관측점 ---------------------------
    # 머리말이 관측점 하나를 더 적고 구현이 안 따라오면, 독자는 재지 않는 것을
    # 재고 있다고 읽는다. 양방향으로 잰다 — 한 방향만 재면 한쪽만 늘어난다.
    impl = set(IDS)
    doc_ids = set(ADVERT_RE.findall(__doc__ or ''))
    if doc_ids != impl:
        fails.append(('N9', "Header observation points %s differ from implemented list %s"
                      % (sorted(doc_ids), sorted(impl))))

    # --- M1/M2/M3: 실측 -------------------------------------------------------
    mode = 'static'
    measured = 0
    if args.mutate:
        mode = 'mutate'
        only = set(x.strip() for x in args.only.split(',') if x.strip())
        if only - set(by_id):
            die("--only contains guards absent from the registry: %s" % sorted(only - set(by_id)))
        base_rc, base = mutate_run(cmddir, [], fails)
        if base_rc != 0:
            if public_copy:
                shutil.rmtree(os.path.dirname(os.path.dirname(public_copy)), ignore_errors=True)
            die("Unmodified baseline failed (rc=%r %r); mutations cannot be evaluated" % (base_rc, base))
        if args.baseline_only:
            mode = 'baseline-only'
            sys.stdout.write("SPEC-GUARDS: BASELINE PASS (sandbox copies %s)\n" % ', '.join(sandbox_spec_dirs(cmddir)))
        for gid, status, ev, what, old, new in rows:
            if args.baseline_only:
                break
            if only and gid not in only:
                continue
            measured += 1
            rc, names = mutate_run(cmddir, [(gid, old, new)], fails)
            if rc == 'build':
                fails.append(('M1' if status == 'covered' else 'M2',
                              "%s: mutation does not compile; this is not behavioral detection" % gid))
                continue
            if rc is None:
                continue
            if status == 'covered':
                if rc == 0:
                    fails.append(('M1', "%s (%s): deleting the guard still returns rc=0; `%s` does not detect it"
                                  % (gid, what, ev)))
                elif ev not in names:
                    fails.append(('M1', "%s (%s): failure did not come from the named test `%s`; failed tests: %s" % (gid, what, ev, names)))
            else:
                if rc != 0:
                    fails.append(('M2', "%s (%s): claimed shadowed guard fails on its own (%s); classify it as covered" % (gid, what, names)))
                    continue
                pair = by_id[ev]
                rc2, names2 = mutate_run(
                    cmddir, [(gid, old, new), (ev, pair[4], pair[5])], fails)
                if rc2 == 'build':
                    fails.append(('M3', "%s+%s: paired mutation does not compile" % (gid, ev)))
                elif rc2 == 0:
                    fails.append(('M3', "%s (%s): deleting together with %s still passes; this is unobserved, not established shadowing"
                                  % (gid, what, ev)))

    sys.stdout.write(
        "layout %s · entries %d (covered %d · shadowed %d) · refusal sites %d (sha256 %s…) · tests %d · mode %s · observations %d\n"
        % (layout, len(rows), n_cov, n_sha, len(sites), digest[:16],
           len(tests), mode, measured))
    if mode == 'static':
        sys.stdout.write(
            "Note: static mode checks that cited tests exist; only --mutate measures whether they detect the named guards.\n")
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-GUARDS: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), 0, 0, layout))
    if public_copy:
        shutil.rmtree(os.path.dirname(os.path.dirname(public_copy)), ignore_errors=True)
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
