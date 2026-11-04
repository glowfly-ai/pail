#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""BT-1f — 공개 문서가 실린 검증기에 대해 하는 주장을 **검증기 자신에서** 유도한다.

BT-1d 는 `cmd/pail-verify` 를 공개 트리에 실었고 BT-1e 는 신뢰근을 실었다. 그런데
그 둘을 소개하는 산문이 하는 주장에는 관측점이 없었다 — 실측이다 (2026-08-31).
스냅숏에서 세 가지를 깨고 실린 검사기 아홉 종과 공개 CI 를 전부 돌렸다:

  * `go.mod` 에 `require google.golang.org/grpc v1.62.0` 을 넣었다.
    검사기 9종 rc=0 · `go vet` rc=0 · `go test` rc=0. 그동안 두 판의 README 는
    「imports **only the standard library** — it shares no code with the service
    that produced the bytes」를 계속 말하고 있었다.
  * 산문의 `81` 을 `999` 로 바꿨다. 붉은 줄 0건. 실린 테스트는 말뭉치가 **비지
    않았는지**(`len(cases) == 0`)만 재는 바닥이지 수가 아니다.
  * `exitCannot = 2` 를 `= 1` 로 바꿨다. **실린 테스트가 통과했다.**

셋째가 가장 날카롭다. `main_test.go` 는 전부 `got != exitCannot` 처럼 **상수끼리**
비교하므로 상수의 값을 바꾸면 양변이 함께 움직인다. 즉 문서가 약속한 리터럴
`0/1/2` 는 어디에서도 재지지 않고, 「확인 못 했다」가 「확인했고 결함이다」와 같은
바이트로 호출자에게 도착해도 초록이다 — `H-B2` 를 집행하려고 만든 도구 안에서
`H-B2` 가 재현된 것이다. 자기 상수로 자기를 재는 테스트는 무엇을 적든 자기와
일치한다 (BT-1e T2 가 등재부에서 만난 것과 같은 형태다).

  V1   `go.mod` 이 `require` 를 선언하지 않는다            (선언 평면)
  V2   실린 `.go` 전부의 import 경로가 표준 라이브러리다    (코드 평면)
  V3   종료 상수의 **리터럴 값**이 문서가 선언한 셋과 같다
  V4   세 종료 값이 서로 다르고 셋 다 실제로 반환된다 (도달 가능)
  V5   문서가 선언한 벡터 수 == 실린 벡터에서 유도한 수 (en+ko)
  V6   선언 마커의 값이 **눈에 보이는 산문**에 실재한다 (en+ko)
  V7   검증 사슬 자산 전부가 공개 트리에 실린다
  V8   문서가 링크로 광고하는 검증 사슬 경로가 트리에 실재한다 (en+ko)

V1 과 V2 를 나눈 것은 두 평면이 따로 표류하기 때문이다. `require` 없이도 import 는
들어갈 수 있고(모듈 밖 경로를 `replace` 로 끌어오면 된다), import 없이도 `require`
는 남는다 — 위 실측에서 깨진 것은 V1 의 평면뿐인데 빌드도 테스트도 통과했다.
한 평면만 재면 다른 쪽 표류는 초록 아래에 산다.

V6 이 따로 있는 것은 마커가 산문의 **대역**이 아니기 때문이다. 마커만 고치고 산문을
그대로 두면 검사기는 만족하는데 독자는 다른 수를 읽는다 — 그때 문서는 기계에게
참이고 사람에게 거짓이다.

rc: 0 = FAIL 0, 1 = FAIL 있음, 2 = 검사기가 자기 전제를 세우지 못함.
"""

import json
import os
import re
import sys

# Preserve diagnostic text on legacy consoles without changing checked bytes.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="backslashreplace")

HERE = os.path.dirname(os.path.abspath(__file__))

# (배치 이름, 스크립트 자리 꼬리, 영문 README, 한국어 README, 검증기 디렉터리,
#  머클 벡터 디렉터리, 공개 트리 목록 or None)
LAYOUTS = (
    ('internal', ('scripts',),
     'oss/README.md', 'oss/README.ko.md',
     'oss/cmd/pail-verify', 'oss/spec/vectors/merkle',
     'oss/PUBLIC_TREE.tsv'),
    ('public', ('spec', 'tools'),
     'README.md', 'README.ko.md',
     'cmd/pail-verify', 'spec/merkle-vectors',
     None),
)

IDS = ('V1', 'V2', 'V3', 'V4', 'V5', 'V6', 'V7', 'V8')

# 검증 사슬. 「공개 트리 편입」이 무엇을 뜻하는지의 정본이고, 공개 경로로 적는다.
# 하나라도 빠지면 제3자는 나머지를 손에 들고도 검증을 시작하지 못한다.
CHAIN = (
    'spec/VERIFICATION_INPUTS.md',
    'spec/MERKLE_VECTORS.md',
    'spec/TRUST_ROOT.md',
    'spec/trust-roots.tsv',
    'spec/proof-vectors/RESPONSES.tsv',
    'spec/proof-vectors/checkpoint.note',
    'spec/proof-vectors/checkpoint.vkey',
    'spec/merkle-vectors/MANIFEST.sha256',
    'spec/merkle-vectors/inclusion.json',
    'spec/merkle-vectors/consistency.json',
    'cmd/pail-verify/go.mod',
    'cmd/pail-verify/main.go',
    'cmd/pail-verify/main_test.go',
)

# 종료 상태. 이름이 아니라 **값**이 계약이다 — 호출자가 보는 것은 정수뿐이다.
EXIT_CONSTS = ('exitVerified', 'exitFinding', 'exitCannot')

VECTORS_RE = re.compile(r'^<!--[ \t]*verifier-vectors:[ \t]*([0-9]+)[ \t]*-->[ \t]*$', re.M)
EXITS_RE = re.compile(r'^<!--[ \t]*verifier-exits:[ \t]*([0-9,]+)[ \t]*-->[ \t]*$', re.M)
# `const ( ... )` 블록 안의 `이름 = 정수`.
CONST_RE = re.compile(r'^\t([A-Za-z][A-Za-z0-9_]*)\s*=\s*(-?[0-9]+)\s*$', re.M)
RETURN_RE = re.compile(r'\breturn\s+(?:[^\n]*,\s*)?(exit[A-Za-z]+)\b')
# Go 의 import 한 줄: 선택적 별칭 뒤 따옴표 친 경로.
IMPORT_RE = re.compile(r'^\t(?:[A-Za-z_.][A-Za-z0-9_]*\s+)?"([^"]+)"\s*$', re.M)
IMPORT_BLOCK_RE = re.compile(r'^import\s*\(\n(.*?)^\)\s*$', re.M | re.S)
IMPORT_ONE_RE = re.compile(r'^import\s+(?:[A-Za-z_.][A-Za-z0-9_]*\s+)?"([^"]+)"\s*$', re.M)
REQUIRE_RE = re.compile(r'^\s*require\b', re.M)
FENCE_RE = re.compile(r'^```[a-zA-Z0-9]*\n(.*?)^```[ \t]*$', re.M | re.S)
REPLACE_RE = re.compile(r'^\s*replace\b', re.M)
# README 가 마크다운 링크로 광고하는 상대 경로.
LINK_RE = re.compile(r'\]\((?!https?:|#)([^)\s]+)\)')

FAILS = []


def die(msg):
    # 전제 실패만 인쇄하면 「무엇이 빠졌는지」의 칸이 영원히 안 보인다 (AC-1 의 교훈).
    for code, m in FAILS:
        sys.stdout.write('[FAIL] %s %s\n' % (code, m))
    sys.stdout.write("SPEC-VERIFIER-CLAIMS: prerequisite failure — %s\n" % msg)
    raise SystemExit(2)


def read(path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return fh.read()
    except OSError as exc:
        die("Cannot read: %s (%s)" % (path, exc))


def locate(here=HERE):
    parts = here.replace(os.sep, '/').split('/')
    hit = []
    for name, tail, en, ko, vdir, mdir, tree in LAYOUTS:
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            j = lambda p: os.path.join(root, *p.split('/'))
            hit.append((name, root, j(en), j(ko), j(vdir), j(mdir),
                        j(tree) if tree else None))
    if len(hit) != 1:
        die("Cannot determine layout (%d matches); script location: %s" % (len(hit), here))
    return hit[0]


def shipped(root, tree_path):
    """{공개경로: 실재경로}. 이 검사기가 '공개 트리' 라고 부르는 것의 정본이다.

    내부 배치에서는 `oss/PUBLIC_TREE.tsv` 의 INCLUDE 행이 유일 정본이다 — 내부
    트리를 걸어 다니면 공개되지 않는 파일까지 세게 되고, 그 목록은 「실린다」의
    근거가 될 수 없다. 공개 배치에서는 트리 자신이 답이다."""
    out = {}
    if tree_path is None:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d != '.git']
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                out[os.path.relpath(p, root).replace(os.sep, '/')] = p
        return out
    for ln in read(tree_path).splitlines():
        if ln.startswith('#') or not ln.strip():
            continue
        cells = ln.split('\t')
        if len(cells) < 3 or cells[0] != 'INCLUDE':
            continue
        out[cells[2].strip()] = os.path.join(root, *cells[1].strip().split('/'))
    if not out:
        die("No INCLUDE rows read from public manifest: %s" % tree_path)
    return out


def go_imports(text, path, fails):
    """`.go` 한 파일의 import 경로 전부. 블록형과 한 줄형을 둘 다 읽는다.

    한 줄형을 빼면 `import "github.com/x/y"` 한 줄로 이 검사가 통째로 우회된다 —
    검사의 종단이 곧 사각지대다."""
    got = []
    for blk in IMPORT_BLOCK_RE.finditer(text):
        got.extend(IMPORT_RE.findall(blk.group(1)))
    got.extend(IMPORT_ONE_RE.findall(text))
    if not got:
        fails.append(('V2', "%s: no imports read; empty scan cannot establish standard-library-only status" % path))
    return got


def is_stdlib(path):
    """표준 라이브러리 경로인가.

    Go 의 규칙 그대로다: 첫 경로 조각에 점이 있으면 그것은 도메인이고, 도메인은
    모듈 밖이다. 목록을 손으로 들지 않는 것이 요점이다 — 손으로 든 목록은
    표준 라이브러리에 패키지가 하나 늘 때마다 낡는다."""
    return '.' not in path.split('/', 1)[0]


def main():
    layout, root, en_path, ko_path, vdir, mdir, tree_path = locate()
    fails = FAILS
    tree = shipped(root, tree_path)

    # --- V1: 선언 평면 --------------------------------------------------------
    gomod_path = os.path.join(vdir, 'go.mod')
    gomod = read(gomod_path)
    if REQUIRE_RE.search(gomod):
        fails.append(('V1', "go.mod declares require entries, contradicting the README standard-library-only claim"))
    if REPLACE_RE.search(gomod):
        fails.append(('V1', "go.mod declares replace entries; verifier may depend on the producer's implementation"))

    # --- V2: 코드 평면 --------------------------------------------------------
    go_files = sorted(n for n in os.listdir(vdir) if n.endswith('.go'))
    if not go_files:
        die("No Go files in verifier directory: %s" % vdir)
    imports, foreign = 0, []
    for fn in go_files:
        for p in go_imports(read(os.path.join(vdir, fn)), fn, fails):
            imports += 1
            if not is_stdlib(p):
                foreign.append('%s: %s' % (fn, p))
    for f in foreign:
        fails.append(('V2', "Imports outside the standard library: %s" % f))

    # --- V3 / V4: 종료 상태 ---------------------------------------------------
    main_go = read(os.path.join(vdir, 'main.go'))
    consts = dict(CONST_RE.findall(main_go))
    missing = [c for c in EXIT_CONSTS if c not in consts]
    if missing:
        die("Cannot read exit constants: %s; comparison target unavailable" % missing)
    got_exits = [int(consts[c]) for c in EXIT_CONSTS]

    declared = None
    for label, path in (('en', en_path), ('ko', ko_path)):
        text = read(path)
        found = EXITS_RE.findall(text)
        if len(found) != 1:
            fails.append(('V3', "%s: verifier-exits declaration occurs %d times; a unique declaration is required"
                          % (label, len(found))))
            continue
        want = [int(x) for x in found[0].split(',')]
        if declared is None:
            declared = want
        elif want != declared:
            fails.append(('V3', "English and Korean exit declarations differ: %s / %s"
                          % (declared, want)))
        if want != got_exits:
            fails.append(('V3', "%s: documented exit states %s differ from implementation %s"
                          % (label, want, got_exits)))

    if len(set(got_exits)) != len(got_exits):
        fails.append(('V4', "Exit constants are not distinct (%s); cannot-verify must not share another verdict's code"
                      % dict(zip(EXIT_CONSTS, got_exits))))
    returned = set(RETURN_RE.findall(main_go))
    for name in EXIT_CONSTS:
        if name not in returned:
            fails.append(('V4', "No return site for `%s`; an unreachable exit is not an implemented verdict" % name))

    # --- V5 / V6: 벡터 수 ------------------------------------------------------
    counts = {}
    for name in ('inclusion', 'consistency'):
        p = os.path.join(mdir, '%s.json' % name)
        try:
            with open(p, 'r', encoding='utf-8') as fh:
                cases = json.load(fh).get('cases')
        except (OSError, ValueError) as exc:
            die("Cannot read Merkle vectors: %s (%s)" % (p, exc))
        if not isinstance(cases, list) or not cases:
            die("%s.json cases are empty or not a list; no vector coverage" % name)
        counts[name] = len(cases)
    derived = sum(counts.values())

    for label, path in (('en', en_path), ('ko', ko_path)):
        text = read(path)
        found = VECTORS_RE.findall(text)
        if len(found) != 1:
            fails.append(('V5', "%s: verifier-vectors declaration occurs %d times" % (label, len(found))))
            continue
        if int(found[0]) != derived:
            fails.append(('V5', "%s: documented vector count %s differs from derived %d (inclusion %d + consistency %d)"
                          % (label, found[0], derived,
                             counts['inclusion'], counts['consistency'])))
        # V6: 마커는 산문의 대역이 아니다. 마커만 고치고 산문을 그대로 두면 검사기는
        # 만족하는데 독자는 다른 수를 읽는다.
        #
        # 「마커 값이 문서 어딘가에 부분문자열로 있는가」로 재면 안 된다 — 실측
        # 2026-08-31: 산문의 `81` 을 `999` 로 바꿨는데 초록이었다. `81` 이 저 아래
        # 예시 출력의 `active_token_id=d4819fb4-…` 안에 우연히 살아 있었기 때문이다.
        # 그래서 세는 자리를 지목한다: 마커 뒤 첫 코드 울타리의 `go test` 줄.
        at = VECTORS_RE.search(text)
        fence = FENCE_RE.search(text, at.end()) if at else None
        if fence is None:
            fails.append(('V6', "%s: no fenced example after vector-count marker" % label))
        else:
            lines = [l for l in fence.group(1).splitlines() if 'go test' in l]
            if len(lines) != 1:
                fails.append(('V6', "%s: fenced example contains %d go-test lines"
                              % (label, len(lines))))
            else:
                nums = re.findall(r'[0-9]+', lines[0])
                if len(nums) != 1:
                    fails.append(('V6', "%s: go-test line contains %d integers; vector count is ambiguous (%s)"
                                  % (label, len(nums), lines[0].strip()[:60])))
                elif nums[0] != found[0]:
                    fails.append(('V6', "%s: marker says %s, prose says %s; machine and reader receive different claims"
                                  % (label, found[0], nums[0])))

        # 종료 상태도 같은 규율. 마커 뒤에 처음 나오는 백틱 정수들이 선언과 순서까지
        # 같아야 한다 — 「문서 어딘가에 `2` 가 있다」는 `2` 를 `3` 으로 고친 문장 옆에서
        # 만족될 수 있다.
        ex = EXITS_RE.search(text)
        if ex:
            want = ex.group(1).split(',')
            seen = re.findall(r'`([0-9]+)`', text[ex.end():])[:len(want)]
            if seen != want:
                fails.append(('V6', "%s: marker declares exit states %s, but prose first presents %s" % (label, want, seen or ["(none)"])))

    # --- V7: 공개 트리 편입 ----------------------------------------------------
    for want in CHAIN:
        local = tree.get(want)
        if local is None:
            fails.append(('V7', "Verification-chain asset is absent from public tree: %s; recipients cannot start verification" % want))
            continue
        if not os.path.exists(local):
            fails.append(('V7', "Listed for distribution but missing: %s (%s)" % (want, local)))

    # --- V8: 문서가 광고하는 경로 ---------------------------------------------
    links = 0
    for label, path in (('en', en_path), ('ko', ko_path)):
        for target in sorted(set(LINK_RE.findall(read(path)))):
            t = target.rstrip('/')
            if not (t.startswith('spec/') or t.startswith('cmd/')):
                continue
            links += 1
            if t in tree:
                continue
            # 디렉터리 링크는 그 아래 무엇이든 실리면 실린 것이다.
            if any(k.startswith(t + '/') for k in tree):
                continue
            fails.append(('V8', "%s: README links to a target absent from public tree: %s"
                          % (label, target)))

    sys.stdout.write(
        "layout %s · public files %d · verifier Go files %d (imports %d, external %d) · exits %s · vectors %d (incl %d + cons %d) · chain assets %d · links %d\n"
        % (layout, len(tree), len(go_files), imports, len(foreign),
           got_exits, derived, counts['inclusion'], counts['consistency'],
           len(CHAIN), links))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-VERIFIER-CLAIMS: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), 0, 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
