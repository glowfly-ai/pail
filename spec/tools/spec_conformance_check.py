#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""공개 문서가 게시하는 **적합성 주장**이 실린 벡터 세트와 같은 것을 가리키는지 본다.

`spec/CONFORMANCE.md` 는 적합성 주장의 단위를 이렇게 정한다:

    적합성 주장의 단위는 "프로파일 이름 + 세트 해시" 한 쌍이다.
    두 값을 함께 적지 않은 주장은 무엇에 대한 주장인지 정해지지 않는다.

그 규칙을 지금까지 아무도 집행하지 않았다. 실측(2026-08-17): 공개 트리의 문서 셋이
`set_sha256 766d2787…`(8파일, A1-3 시절)을 인용하는 동안 실제로 실린 세트는
`5e58bc67…`(11파일)이었고, 넷째 문서는 프로파일 이름만 적고 해시를 빼먹었다. 넷 다
매니페스트 경로로 `tests/golden/canon/…` 를 적었는데 그것은 **공개 트리에 없는
내부 경로**다. 즉 공개 리포를 받은 사람이 C2 를 그대로 따르면, 우리가 싣지도 않은
세트에 적합하다고 주장하게 된다.

원인은 문서가 아니라 배선이다. 동결 벡터는 `spec/vectors/` 로 실려 나가는데 **공개
트리 안의 아무것도 그것을 열지 않았다** — 그래서 문서 넷이 함께 낡아도 붉어지는
줄이 없었다. `E-C3` 이 남긴 규율("동결은 소비될 때만 동결이다")의 같은 형태다.
이 검사기가 공개 트리에서 벡터 세트를 여는 첫 소비자다.

검사:
  A1  프로파일 이름을 인용한 문서는 세트 해시도 인용해야 한다   (문서 자신의 규칙)
  A2  인용된 세트 해시는 실린 매니페스트의 값이어야 한다        (축약 인용 허용)
  A3  인용된 프로파일 이름이 매니페스트의 것과 같아야 한다
  A4  인용된 매니페스트 경로는 **공개 트리에서** 실재해야 한다
  A5  매니페스트가 **이전 판으로 기록해 둔** 세트 해시가 문서에 살아 있으면 안 된다
  A6  Verify the bytes of every manifest-listed canon vector against its file hash.

A5 가 A2 와 겹치는 것처럼 보이지만 다르다. A2 는 `set_sha256` 이라는 낱말과 짝지어
적힌 값만 본다. 낱말 없이 hex 만 흘린 인용은 A2 의 눈 밖이고, 그것이 낡는 것이
가장 조용하다 — 매니페스트가 폐기 이력을 이미 적고 있으므로 대조 상대가 공짜다.

rc: 0 = FAIL 0, 1 = FAIL 있음, 2 = 검사기가 자기 전제를 세우지 못함.
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

# `gen_known_dev_keys.py` 와 같은 방식으로 배치를 정한다 — 스크립트 자신이 놓인 자리.
# 두 트리에서 같은 검사를 돌려야 하는데 벡터의 자리가 서로 다르기 때문이다. 한쪽
# 경로로 굳히면 다른 쪽에서 첫날 죽고, 그때 오는 수정은 대개 "그 단계를 지우는 것"이다.
LAYOUTS = (
    ('internal', ('scripts',), 'tests/golden/canon/MANIFEST.sha256'),
    ('public', ('spec', 'tools'), 'spec/vectors/canon/MANIFEST.sha256'),
)

PROFILE_RE = re.compile(r'PAIL-CORE-[0-9]+\.[0-9]+')
# `set_sha256` 과 짝지어 적힌 값. 축약(`766d2787…`)을 받아들이는 이유는 문서가 실제로
# 그렇게 적기 때문이다 — 형식을 문서에 맞추지 않으면 검사기가 자기만 아는 형식을
# 요구하게 되고, 그러면 사람은 검사를 통과시키려고 문서를 읽기 나쁘게 고친다.
CITED_HASH_RE = re.compile(r'set_sha256[ \t]+([0-9a-f]{8,64})')
HEX_RE = re.compile(r'\b[0-9a-f]{8,64}\b')
MANIFEST_PATH_RE = re.compile(r'`([^`\s]*MANIFEST\.sha256)`')

fails = []


def say(msg):
    sys.stdout.write(msg + '\n')


def die(msg):
    sys.stderr.write('[ABORT] ' + msg + '\n')
    raise SystemExit(2)


def read(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def locate(here=HERE):
    parts = here.replace(os.sep, '/').split('/')
    hit = []
    for name, tail, manifest in LAYOUTS:
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            hit.append((name, root, os.path.join(root, *manifest.split('/'))))
    if len(hit) != 1:
        die("Cannot determine layout (%d matches); script location: %s\n  recognized locations: %s"
            % (len(hit), here, ' · '.join('/'.join(l[1]) for l in LAYOUTS)))
    return hit[0]


def manifest_facts(path):
    """(프로파일, 현재 세트 해시, 폐기된 세트 해시 집합, 파일 수).

    `set_sha256` 줄을 믿지 않고 다시 계산한다. 줄만 읽으면 이 검사기는 "문서가
    매니페스트와 같은 값을 적었다"까지만 말할 수 있고, 그 값이 실린 바이트에서
    나온 것인지는 말하지 못한다 — 둘이 함께 틀리면 초록이다.
    """
    if not os.path.exists(path):
        die("Vector-set manifest is missing: %s" % path)
    text = read(path)

    prof = PROFILE_RE.search(text)
    if not prof:
        die("Manifest does not identify a profile: %s" % path)

    files, declared, retired = [], None, set()
    for line in text.splitlines():
        if line.startswith('set_sha256'):
            m = re.search(r'([0-9a-f]{64})', line)
            if not m:
                die("Cannot parse the set_sha256 value")
            declared = m.group(1)
        elif line.startswith('#'):
            retired.update(HEX_RE.findall(line))
        elif line.strip():
            m = re.match(r'([0-9a-f]{64})\s\s(\S+)$', line.strip())
            if not m:
                die("Unrecognized manifest line: %r" % line[:60])
            files.append((m.group(1), m.group(2)))

    if not files:
        die("Manifest contains zero file rows; nothing was compared")
    if declared is None:
        die("Manifest lacks a set_sha256 line")

    # A6: the set digest binds manifest rows only. Verify each actual byte input
    # independently, otherwise changing a vector without its row stays invisible.
    base = os.path.realpath(os.path.dirname(path))
    seen = set()
    for expected, name in files:
        if name in seen:
            fails.append("A6 %s: duplicate manifest file row" % name)
            continue
        seen.add(name)
        target = os.path.join(base, name)
        if (os.path.isabs(name) or '\\' in name or '..' in name.split('/')
                or os.path.commonpath([base, os.path.realpath(target)]) != base):
            fails.append("A6 %s: manifest file path escapes the vector directory" % name)
            continue
        if not os.path.isfile(target):
            fails.append("A6 %s: listed in manifest but not a regular file" % name)
            continue
        try:
            with open(target, 'rb') as stream:
                observed = hashlib.sha256(stream.read()).hexdigest()
        except OSError as exc:
            fails.append("A6 %s: cannot read listed vector: %s" % (name, exc))
            continue
        if observed != expected:
            fails.append("A6 %s: bytes do not match pinned hash (manifest %s, actual %s)"
                         % (name, expected, observed))

    buf = ''.join('%s  %s\n' % (h, n) for h, n in sorted(files, key=lambda x: x[1]))
    actual = hashlib.sha256(buf.encode()).hexdigest()
    if actual != declared:
        die("Manifest is inconsistent: declared %s / recomputed %s; cannot establish a comparison target"
            % (declared, actual))

    # 폐기 이력에서 현재 값(과 그 접두어)은 뺀다. 매니페스트 머리말은 개정 때마다
    # 이전 값을 남기는데, 거기 현재 값이 섞여 들어오면 A5 가 옳은 인용을 문다.
    retired = {h for h in retired if not (declared.startswith(h) or h.startswith(declared))}
    # 파일 해시는 세트 해시가 아니다. 문서가 파일 해시를 인용하는 것은 위반이 아니다.
    for h, _ in files:
        retired.discard(h)
    return prof.group(0), declared, retired, len(files)


def docs(layout, root):
    """대조할 문서 집합.

    **공개 트리로 나가는 `.md` 만** 본다. 내부 설계 문서는 개정 이력에 옛 세트 해시를
    일부러 남기며(그것이 동결 창의 기록이다) 그것을 위반으로 읽으면 이 검사기는
    기록을 지우라고 요구하게 된다.

    벡터 디렉터리 안의 문서(`MKVEC-CANON.md` 등)도 뺀다. 그것은 적합성 **주장**이
    아니라 세트를 만드는 절차서이고, 게다가 동결 대상이라 검사가 요구해도 못 고친다 —
    고칠 수 없는 RED 는 결함을 가린다.
    """
    if layout == 'public':
        found = []
        for base, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for n in sorted(names):
                if n.endswith('.md'):
                    found.append(os.path.relpath(os.path.join(base, n), root))
    else:
        # 내부 배치에서는 `oss/PUBLIC_TREE.tsv` 가 '공개로 나가는 것'의 유일 정본이다.
        # 목록을 여기 따로 두면 두 목록이 갈라지고, 갈라진 날 이 검사는 자기 목록만큼만
        # 본 채로 초록이 된다.
        tsv = os.path.join(root, 'oss', 'PUBLIC_TREE.tsv')
        if not os.path.exists(tsv):
            die("Public manifest is missing: %s" % tsv)
        found = []
        for line in read(tsv).splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            cells = line.split('\t')
            if len(cells) < 3 or cells[0].strip() != 'INCLUDE':
                continue
            src, dst = cells[1].strip(), cells[2].strip()
            if dst.endswith('.md'):
                found.append((src, dst))
        found = [s for s, d in found if not d.startswith('spec/vectors/')]

    out = {}
    for rel in found:
        if rel.replace(os.sep, '/').startswith('spec/vectors/'):
            continue
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            die("Manifest-listed document is missing: %s" % rel)
        out[rel] = read(p)
    if not out:
        die("No documents to compare (layout %s); nothing was checked" % layout)
    return out


def public_resolver(layout, root):
    """"이 경로가 **공개 트리에** 있는가" 를 판정하는 술어를 낸다.

    문서가 읽히는 곳은 공개 리포다. 그러므로 문서가 적는 경로는 공개 경로여야 하고,
    두 배치가 그것을 서로 다른 방식으로 확인한다. 내부에서 내부 경로를 통과시키면
    스냅숏을 뜨는 날까지 아무도 모른다 — 실제로 그렇게 세 문서가
    `tests/golden/canon/MANIFEST.sha256` 을 적은 채 살아 있었다.
    """
    if layout == 'public':
        return lambda p: os.path.exists(os.path.join(root, *p.split('/')))

    tsv = os.path.join(root, 'oss', 'PUBLIC_TREE.tsv')
    dests = set()
    for line in read(tsv).splitlines():
        cells = line.split('\t')
        if len(cells) >= 3 and cells[0].strip() == 'INCLUDE':
            dests.add(cells[2].strip())
    if not dests:
        die("No INCLUDE rows read from public manifest: %s" % tsv)
    return lambda p: p in dests


def main(argv):
    if argv:
        sys.stderr.write("usage: spec_conformance_check.py (no arguments)\n")
        return 2

    layout, root, manifest = locate()
    profile, cur, retired, nfiles = manifest_facts(manifest)
    corpus = docs(layout, root)
    in_public = public_resolver(layout, root)

    say("layout %s · profile %s · set %s (%d files) · retired sets %d · documents %d"
        % (layout, profile, cur[:16] + '…', nfiles, len(retired), len(corpus)))

    # 공개 트리에서 매니페스트가 놓이는 자리. 내부 배치에서도 **공개 경로**를 알려준다 —
    # 문서에 적혀야 하는 것이 그것이기 때문이다.
    want_path = next(p for n, _, p in LAYOUTS if n == 'public')

    for rel in sorted(corpus):
        text = corpus[rel]
        names = set(PROFILE_RE.findall(text))
        cited = set(CITED_HASH_RE.findall(text))

        # --- A3: 프로파일 이름의 신선도 ------------------------------------
        for n in sorted(names - {profile}):
            fails.append("A3 %s: quoted profile %s differs from distributed profile %s"
                         % (rel, n, profile))

        # --- A1: 이름을 적었으면 해시도 적는다 (spec/CONFORMANCE.md §1 의 규칙) ----
        if names and not cited:
            fails.append("A1 %s: profile name without set hash does not identify the conformance target" % rel)

        # --- A2: 인용된 해시가 실린 세트인가 -------------------------------
        for h in sorted(cited):
            if not cur.startswith(h):
                fails.append("A2 %s: stale set hash — quoted %s / distributed %s"
                             % (rel, h, cur[:len(h)]))

        # --- A5: 폐기 이력에 적힌 값이 살아 있는가 -------------------------
        for h in sorted(set(HEX_RE.findall(text)) & retired):
            if h not in cited:
                fails.append("A5 %s: document still quotes a retired set hash: %s" % (rel, h))

        # --- A4: 매니페스트 경로 인용이 공개 트리에서 실재하는가 ------------
        for p in sorted(set(MANIFEST_PATH_RE.findall(text))):
            if not in_public(p):
                fails.append("A4 %s: non-public manifest path %s; public path is %s" % (rel, p, want_path))

    for f in fails:
        say('[FAIL] ' + f)
    sys.stdout.write('SPEC-CONFORMANCE: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), 0, 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
