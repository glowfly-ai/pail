#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""D8 — `spec/CANON.md` 의 canon 기술을 실린 동결 벡터에 핀한다 (OR6 / implementation contract).

공개 스펙은 손으로 쓰인다. 손으로 쓰인 유도식은 코드가 바뀌어도 그대로 남고, 그것을
읽고 두 번째 구현을 만든 사람은 우리가 싣지 않은 형식을 구현하게 된다. 그래서 이
문서의 유도식은 **동결 벡터의 바이트를 그대로 인용**하고, 이 검사기가 그 인용이
실제로 부분문자열인지 잰다. 인용이 틀리면 붉어지고, 벡터가 바뀌면 인용이 깨진다.

  B1  실린 벡터에서 관측되는 접두어 전건에 절이 있어야 한다
  B2  벡터에 핀한 절의 접두어가 실린 벡터에 실제로 나타나야 한다
  B3  `pin` 이 딸린 인용 블록은 그 벡터 파일의 **바이트 부분문자열**이어야 한다
  B4  `pin` 이 가리키는 벡터는 매니페스트에 등재(동결)돼 있어야 한다
  B5  `pin: none` 은 `UNPINNED.tsv` 에 **핀 없음(pin_vec='-')** 으로 등록돼 있고,
      그 접두어가 실린 벡터에 나타나지 **않아야** 한다

관측 코퍼스는 **값이 실린 파일**뿐이다. 매니페스트와 등록부는 벡터 뿌리 안에 살지만
벡터가 아니라 벡터에 *대한* 기술이고, 그것을 코퍼스에 넣으면 「언급됐다」가
「실려 나간다」로 내려앉는다 — 등록부가 자기를 세게 된다. 어느 쪽으로도 분류되지
않는 파일이 나타나면 조용히 건너뛰지 않고 rc=2 로 멈춘다(범주를 없애면 새 구멍이
하나 생긴다).

rc: 0 = FAIL 0, 1 = FAIL 있음, 2 = 검사기가 자기 전제를 세우지 못함.

전제를 FAIL 로 내리지 않는 이유는 `H-B2` 다 — 벡터를 한 편도 읽지 못한 실행은
"위반 0" 과 같은 바이트를 낸다. 못 읽었으면 못 읽었다고 말한다.

`B5` 가 있어야 `pin: none` 이 무엇이든 덮는 구멍이 되지 않는다. 등록부에 없는
접두어를 "핀 없음" 으로 적는 것은 면제이지 기록이 아니다.
"""

import hashlib
import os
import re
import sys

# Preserve diagnostic text on legacy consoles without changing checked bytes.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="backslashreplace")

HERE = os.path.dirname(os.path.abspath(__file__))

# 공개 문서가 인용하는 경로는 **공개 배치의 것**이다. 문서는 공개 리포에서 읽히므로
# 거기서 실재하는 경로를 적어야 한다. 내부 트리에서 돌 때는 이 접두어를 벗기고
# 그 배치의 벡터 뿌리에 붙인다.
PUB_VEC_PREFIX = 'spec/vectors/'

# (배치 이름, 스크립트 자리 꼬리, 문서, 벡터 뿌리)
LAYOUTS = (
    ('internal', ('scripts',), 'oss/spec/CANON.md', 'tests/golden'),
    ('public', ('spec', 'tools'), 'spec/CANON.md', 'spec/vectors'),
)

# 벡터 뿌리 아래의 두 갈래. 값은 스캔하고, 기술은 스캔하지 않는다.
VALUE_EXT = ('.vec', '.json')
DESCRIBER_NAMES = ('MANIFEST.sha256', 'UNPINNED.tsv')
DESCRIBER_EXT = ('.md',)

PREFIX_RE = re.compile(r'pail-[a-z0-9-]+:v[0-9]+')
HEAD_RE = re.compile(r'^###[ \t]+`(pail-[a-z0-9-]+:v[0-9]+)`[ \t]*$', re.M)
PIN_RE = re.compile(r'^<!--[ \t]*pin:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
FENCE_RE = re.compile(r'^```[a-zA-Z0-9]*\n(.*?)^```[ \t]*$', re.M | re.S)


def die(msg):
    sys.stdout.write("SPEC-CANON: prerequisite failure — %s\n" % msg)
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
    for name, tail, doc, vec in LAYOUTS:
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            hit.append((name, root,
                        os.path.join(root, *doc.split('/')),
                        os.path.join(root, *vec.split('/'))))
    if len(hit) != 1:
        die("Cannot determine layout (%d matches); script location: %s" % (len(hit), here))
    return hit[0]


def vector_files(vecroot):
    """벡터 뿌리 아래에서 **값이 실린 파일**만. 목록을 따로 두지 않는다 — 실린 것이 곧 등록부다."""
    out = []
    unknown = []
    for base, dirs, names in os.walk(vecroot):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
        for n in sorted(names):
            p = os.path.join(base, n)
            if n.endswith(VALUE_EXT):
                out.append(p)
            elif n in DESCRIBER_NAMES or n.endswith(DESCRIBER_EXT):
                continue
            else:
                unknown.append(os.path.relpath(p, vecroot))
    if unknown:
        die("Unclassified file under vector root; refusing to silently omit a possible value file: %s" % ', '.join(sorted(unknown)))
    if not out:
        die("No vector files read: %s" % vecroot)
    return out


def observed_prefixes(files):
    """실린 바이트에서 관측되는 접두어. 선언이 아니라 관측이다."""
    seen = {}
    for p in files:
        try:
            with open(p, encoding='utf-8') as fh:
                t = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        for m in PREFIX_RE.findall(t):
            seen.setdefault(m, set()).add(p)
    if not seen:
        die("No prefixes observed in vectors; an empty scan cannot establish agreement")
    return seen


def frozen_names(manifest):
    """매니페스트에 등재된 파일명. 등재가 곧 동결이다."""
    names = set()
    for ln in read(manifest).splitlines():
        if ln.startswith('#') or not ln.strip():
            continue
        m = re.match(r'^[0-9a-f]{64}\s\s(\S.*)$', ln)
        if m:
            names.add(m.group(1).strip())
    if not names:
        die("No file rows read from manifest: %s" % manifest)
    return names


def unpinned_without_vector(unpinned):
    """`UNPINNED.tsv` 중 **핀 벡터가 없는** 행의 접두어."""
    rows = 0
    out = set()
    for ln in read(unpinned).splitlines():
        if ln.startswith('#') or not ln.strip():
            continue
        cells = ln.split('\t')
        if len(cells) < 7:
            continue
        rows += 1
        if cells[6].strip() == '-':
            out.add(cells[0].strip())
    if rows == 0:
        die("No entries read from registry: %s" % unpinned)
    return out


def sections(doc_text, doc_path):
    """`### \\`<접두어>\\`` 로 문서를 자른다. → [(접두어, 본문)]"""
    heads = list(HEAD_RE.finditer(doc_text))
    if not heads:
        die("No prefix sections read from document: %s" % doc_path)
    out = []
    seen = set()
    for i, m in enumerate(heads):
        pfx = m.group(1)
        if pfx in seen:
            die("Duplicate prefix section: %s; canonical section is ambiguous" % pfx)
        seen.add(pfx)
        end = heads[i + 1].start() if i + 1 < len(heads) else len(doc_text)
        out.append((pfx, doc_text[m.end():end]))
    return out


def main():
    layout, root, doc_path, vecroot = locate()
    manifest = os.path.join(vecroot, 'canon', 'MANIFEST.sha256')
    unpinned = os.path.join(vecroot, 'canon', 'UNPINNED.tsv')

    files = vector_files(vecroot)
    seen = observed_prefixes(files)
    frozen = frozen_names(manifest)
    novec = unpinned_without_vector(unpinned)
    secs = sections(read(doc_path), doc_path)

    fails = []
    pinned = 0
    declared_none = 0

    for pfx, body in secs:
        pin = PIN_RE.search(body)
        if not pin:
            fails.append(('B3', "%s — missing pin; the quoted bytes have no checkable source" % pfx))
            continue

        target = pin.group(1)
        if target == 'none':
            declared_none += 1
            # B5 — "핀 없음" 은 등록부가 뒷받침해야 하고, 실린 벡터와도 맞아야 한다.
            if pfx not in novec:
                fails.append(('B5', "%s — pin:none is not registered as pin_vec=- in UNPINNED.tsv; unregistered exemption" % pfx))
            elif pfx in seen:
                fails.append(('B5', "%s — pin:none conflicts with a distributed vector (%s); available bytes should be pinned"
                              % (pfx, os.path.relpath(sorted(seen[pfx])[0], root))))
            continue

        # B2 — 문서가 지어낸 접두어에 벡터를 갖다 붙이지 못하게 한다.
        if pfx not in seen:
            fails.append(('B2', "%s — pinned prefix does not occur in any distributed vector" % pfx))
            continue

        if not target.startswith(PUB_VEC_PREFIX):
            fails.append(('B4', "%s — pin is not a public vector path: %s" % (pfx, target)))
            continue

        rel = target[len(PUB_VEC_PREFIX):]
        local = os.path.join(vecroot, *rel.split('/'))
        base = os.path.basename(rel)

        # B4 — 동결되지 않은 파일에 핀하면 그 인용은 언제든 조용히 바뀔 수 있다.
        contract_pinned = False
        if os.path.dirname(rel) == 'contract':
            manifest = os.path.join(vecroot, 'contract', 'MANIFEST.sha256')
            if os.path.isfile(manifest) and os.path.isfile(local):
                entries = [line.split() for line in read(manifest).splitlines() if line and not line.startswith('#')]
                matches = [parts[0] for parts in entries if len(parts) == 2 and parts[1] == base]
                contract_pinned = (len(matches) == 1 and re.fullmatch(r'[0-9a-f]{64}', matches[0]) is not None
                                   and hashlib.sha256(open(local, 'rb').read()).hexdigest() == matches[0])
        if not ((os.path.dirname(rel) == 'canon' and base in frozen) or contract_pinned):
            fails.append(('B4', "%s — pin target is not registered in the frozen manifest: %s"
                          % (pfx, target)))
            continue
        if not os.path.exists(local):
            fails.append(('B4', "%s — pin target does not exist: %s" % (pfx, target)))
            continue

        fence = FENCE_RE.search(body, pin.end())
        if not fence:
            fails.append(('B3', "%s — no quotation block after the pin" % pfx))
            continue

        quoted = fence.group(1)
        with open(local, encoding='utf-8') as fh:
            vec_text = fh.read()
        if quoted not in vec_text:
            head = quoted.splitlines()[0] if quoted.splitlines() else ''
            fails.append(('B3', "%s — quote is not a substring of %s (first line: %s)"
                          % (pfx, target, head[:70])))
            continue
        pinned += 1

    # B1 — 실린 것 중 문서가 다루지 않는 접두어. 빠뜨림은 언제나 조용하다.
    covered = set(p for p, _ in secs)
    for pfx in sorted(seen):
        if pfx not in covered:
            fails.append(('B1', "%s — distributed vector prefix has no specification section (%s)"
                          % (pfx, os.path.relpath(sorted(seen[pfx])[0], root))))

    sys.stdout.write(
        "layout %s · vector files %d · observed prefixes %d · sections %d · pins %d · unpinned %d · frozen files %d\n"
        % (layout, len(files), len(seen), len(secs), pinned, declared_none, len(frozen)))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-CANON: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), 0, 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # 묻는 인자와 실행하는 인자를 같이 취급하지 않는다 — 모르는 인자는 거부한다.
        sys.stderr.write("%s: no arguments accepted\n" % os.path.basename(sys.argv[0]))
        raise SystemExit(2)
    raise SystemExit(main())
