#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""D8 — `spec/KNOWN_DEV_KEYS.md` 의 포맷 기술을 실린 파일의 바이트에 핀한다 (OR6).

`CANON.md` 와 같은 문제를 다른 재료에서 푼다. 손으로 쓴 포맷 기술은 파서가 바뀌어도
그대로 남고, 그것을 읽고 목록을 만든 사람은 우리 파서가 거부하는 파일을 만든다.
그래서 이 문서의 인용은 **실린 파일의 바이트 부분문자열**이고, 어휘는 **생성기
소스의 리터럴**과 대조된다. 문서 · 데이터 · 코드 셋이 서로를 잡는다.

  K1  `pin` 이 딸린 인용 블록은 그 파일의 **바이트 부분문자열**이어야 한다
  K2  `pin` 이 가리키는 경로는 **공개 트리에 실려야** 한다
      (독자가 대조할 수 없는 인용은 인용이 아니라 주장이다)
  K3  실린 지문 목록의 전 행이 문서가 선언한 문법에 맞아야 한다
  K4  문서가 선언한 `kind` 어휘 == 생성기 파서의 어휘 == 목록에 실제로 나타나는 어휘

K4 의 세 값을 모두 재는 이유는 둘만 재면 어느 쌍이든 함께 틀릴 수 있기 때문이다.
문서와 목록만 재면 파서가 모르는 어휘를 둘이 합의할 수 있고, 문서와 파서만 재면
목록이 조용히 낡는다.

rc: 0 = FAIL 0, 1 = FAIL 있음, 2 = 검사기가 자기 전제를 세우지 못함.
"""

import os
import re
import sys

# Preserve diagnostic text on legacy consoles without changing checked bytes.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="backslashreplace")

HERE = os.path.dirname(os.path.abspath(__file__))

# (배치 이름, 스크립트 자리 꼬리, 문서, 공개 경로 지도)
# 공개 배치에는 지도가 없다 — 거기서는 문서가 적은 경로가 이미 실재하는 경로다.
# `oss/PUBLIC_TREE.tsv` 는 내부 도구라 스냅숏에 실리지 않는다.
LAYOUTS = (
    ('internal', ('scripts',), 'oss/spec/KNOWN_DEV_KEYS.md', 'oss/PUBLIC_TREE.tsv'),
    ('public', ('spec', 'tools'), 'spec/KNOWN_DEV_KEYS.md', None),
)

PIN_RE = re.compile(r'^<!--[ \t]*pin:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
FENCE_RE = re.compile(r'^```[a-zA-Z0-9]*\n(.*?)^```[ \t]*$', re.M | re.S)
SYNTAX_RE = re.compile(
    r'^<!--[ \t]*syntax:[ \t]*(\S+)[ \t]+cols=([0-9]+)[ \t]+'
    r'fingerprint=(\S+)[ \t]+kind=(\S+)[ \t]*-->[ \t]*$', re.M)
# 생성기가 실제로 받는 어휘. 이 줄이 파서의 판정 지점이다.
PARSER_KIND_RE = re.compile(r"col\[1\] not in \(([^)]*)\)")


def die(msg):
    sys.stdout.write("SPEC-KEYS: prerequisite failure — %s\n" % msg)
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
    for name, tail, doc, tree in LAYOUTS:
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            hit.append((name, root,
                        os.path.join(root, *doc.split('/')),
                        os.path.join(root, *tree.split('/')) if tree else None))
    if len(hit) != 1:
        die("Cannot determine layout (%d matches); script location: %s" % (len(hit), here))
    return hit[0]


def public_map(tree_path):
    """공개 경로 -> 내부 경로. 지도가 없는 배치(공개)에서는 항등이다."""
    if tree_path is None:
        return None
    rows = 0
    out = {}
    for ln in read(tree_path).splitlines():
        if ln.startswith('#') or not ln.strip():
            continue
        cells = ln.split('\t')
        if len(cells) < 3 or cells[0] != 'INCLUDE':
            continue
        rows += 1
        out[cells[2].strip()] = cells[1].strip()
    if rows == 0:
        die("No INCLUDE rows read from public manifest: %s" % tree_path)
    return out


def resolve(target, root, pmap):
    """문서가 적은 **공개 경로**를 이 배치의 실재 경로로 옮긴다.

    반환 (실재경로 or None, 실려있는가)."""
    if pmap is None:
        p = os.path.join(root, *target.split('/'))
        return (p if os.path.exists(p) else None), os.path.exists(p)
    internal = pmap.get(target)
    if internal is None:
        return None, False
    return os.path.join(root, *internal.split('/')), True


def main():
    layout, root, doc_path, tree_path = locate()
    doc = read(doc_path)
    pmap = public_map(tree_path)

    fails = []

    # --- K1 / K2 ------------------------------------------------------------
    pins = list(PIN_RE.finditer(doc))
    if not pins:
        die("No documentation pins found; zero comparisons cannot establish quote correctness")

    checked = 0
    for m in pins:
        target = m.group(1)
        local, shipped = resolve(target, root, pmap)
        if not shipped:
            fails.append(('K2', "%s — quoted target is not distributed and cannot be checked by recipients" % target))
            continue
        if local is None or not os.path.exists(local):
            fails.append(('K2', "%s — quoted target does not exist in this layout" % target))
            continue
        fence = FENCE_RE.search(doc, m.end())
        if not fence:
            fails.append(('K1', "%s — no quotation block after the pin" % target))
            continue
        quoted = fence.group(1)
        if quoted not in read(local):
            head = quoted.splitlines()[0] if quoted.splitlines() else ''
            fails.append(('K1', "%s — quote is not a byte substring (first line: %s)"
                          % (target, head[:70])))
            continue
        checked += 1

    # --- K3 / K4 ------------------------------------------------------------
    syn = SYNTAX_RE.search(doc)
    if not syn:
        die("Document has no syntax declaration; comparison target is undefined")
    tsv_target, cols, fpr_pat, kinds_decl = syn.group(1), int(syn.group(2)), \
        syn.group(3), syn.group(4)
    declared_kinds = tuple(sorted(kinds_decl.split(',')))

    tsv_local, tsv_shipped = resolve(tsv_target, root, pmap)
    if not tsv_shipped or tsv_local is None:
        die("Cannot find the syntax-declared list in this layout: %s" % tsv_target)

    try:
        fpr_re = re.compile(fpr_pat)
    except re.error as exc:
        die("Invalid fingerprint regex in syntax declaration: %s (%s)" % (fpr_pat, exc))

    seen_kinds = set()
    # 요약줄이 읽는 것과 판정이 읽는 것을 갈라 둔다. seen_kinds 는 선언된 kind 만
    # 담으므로(아래 K3 가 나머지를 걸러낸다) 그것으로 요약을 찍으면 어긋난 행이
    # 있는 실행에서도 "관측 = 선언" 으로 나온다 — 붉은 줄 옆에서 요약이 정상을
    # 말하는 형태다.
    raw_kinds = set()
    rows = 0
    for n, ln in enumerate(read(tsv_local).splitlines(), 1):
        if ln.startswith('#') or not ln.strip():
            continue
        rows += 1
        cell = ln.split('\t')
        if len(cell) != cols:
            fails.append(('K3', "%s:%d — %d columns; document declares %d"
                          % (tsv_target, n, len(cell), cols)))
            continue
        raw_kinds.add(cell[1])
        if not fpr_re.fullmatch(cell[0]):
            fails.append(('K3', "%s:%d — fingerprint violates documented format: %r"
                          % (tsv_target, n, cell[0][:24])))
            continue
        if cell[1] not in declared_kinds:
            fails.append(('K3', "%s:%d — undocumented kind: %r"
                          % (tsv_target, n, cell[1])))
            continue
        seen_kinds.add(cell[1])
    if rows == 0:
        die("No fingerprint entries read from %s; zero rows cannot establish agreement" % tsv_target)

    gen_local, gen_shipped = resolve('spec/tools/gen_known_dev_keys.py', root, pmap)
    if not gen_shipped or gen_local is None:
        die("Generator is absent from this layout; cannot derive parser vocabulary")
    pm = PARSER_KIND_RE.search(read(gen_local))
    if not pm:
        die("Cannot find the generator's kind-classification site")
    parser_kinds = tuple(sorted(re.findall(r"'([a-z0-9_]+)'", pm.group(1))))
    if not parser_kinds:
        die("No vocabulary read from the generator's kind-classification site")

    if declared_kinds != parser_kinds:
        fails.append(('K4', "Document %s vs parser %s: vocabulary mismatch"
                      % (list(declared_kinds), list(parser_kinds))))
    observed = tuple(sorted(seen_kinds))
    # 여기에 "목록에 문서가 모르는 kind 가 있다" 는 K4 분기를 두지 않는다. 그 조건은
    # 위 K3 가 행 단위로 이미 잡고, 잡은 행은 seen_kinds 에 들어가지 않으므로 분기는
    # 어떤 입력으로도 발동하지 않는다. 발동할 수 없는 검사는 두 번째 관측점이 아니라
    # 관측점이 둘이라는 착각이고, 그 착각은 K3 가 지워진 날 대신 붉어져 주지 않는다.
    # 아래 분기는 다르다 — 선언됐으나 한 행도 실리지 않은 어휘는 K3 가 볼 수 없다.
    if set(declared_kinds) - set(observed):
        fails.append(('K4', "Documented kinds with no distributed entries: %s; no corresponding evidence"
                      % sorted(set(declared_kinds) - set(observed))))

    sys.stdout.write(
        "layout %s · quotes %d/%d · rows %d · kinds documented%s parser%s observed%s\n"
        % (layout, checked, len(pins), rows,
           list(declared_kinds), list(parser_kinds), sorted(raw_kinds)))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-KEYS: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), 0, 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.stderr.write("%s: no arguments accepted\n" % os.path.basename(sys.argv[0]))
        raise SystemExit(2)
    raise SystemExit(main())
