#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""SK-8 — `spec/SKILLS.md` 의 행 스키마를 **두 파서와 실린 예제**에 핀한다.

스킬 등재부는 제3자가 코드가 아니라 파일 하나로 자기 로봇의 권한을 적는 자리다.
그래서 이 문서가 낡으면 증상이 조용하다: 읽은 사람은 두 구현이 거부하는 YAML 을
쓰고, 거부 메시지는 자기 오타처럼 보인다.

이 등재부에는 파서가 **둘**이라는 특별한 사정이 있다 — 이슈어(Go)와 게이트(C++)가
같은 바이트를 각자 읽는다(SK-1·SK-2). 둘이 갈라지면 이슈어가 발급한 행을 게이트가
거부하고, 그 거부는 배치 실수처럼 보인다. 그래서 넷을 함께 잰다:

    문서(필드 표) == Go 파서(rowShape yaml 태그) == C++ 파서(kRowKeys) == 실린 예제

셋만 재면 어느 쌍이든 함께 틀릴 수 있다. 문서와 한쪽 파서만 재면 다른 파서가 조용히
갈라지고, 문서와 예제만 재면 두 파서가 모르는 어휘를 둘이 합의한다.

  K1  `source`·`example` 이 가리키는 경로는 **공개 트리에 실려야** 한다
      (독자가 대조할 수 없는 인용은 인용이 아니라 주장이다)
  K2  문서의 필드 어휘 == Go `rowShape` 의 yaml 태그(중첩은 `a.b` 로 편다)
  K3  문서의 최상위 필드 어휘 == C++ `kRowKeys`
      (문서는 `evidence.when` 처럼 펴서 적고 C++ 은 `evidence` 를 통째로 본다 —
       비교는 최상위 마디로 접어서 한다)
  K4  실린 예제가 쓰는 키가 전부 문서에 있다
  K5  예제의 `envelope`·`classes`·`robot_class` 값이 실린 어휘 파일 안에 있다
  K6  한국어판이 같은 필드를 가르친다 (재지 않는 번역본은 낡는 것이 아니라
      **낡은 채로 초록**이다)

`tests/tools/check_skills.py` 와 겹치지 않는다: 저쪽은 **내부 등재부 파일들**이 서로
정합인지 보고, 이쪽은 **공개 규격서**가 구현과 예제를 정확히 그리는지 본다. 공개
트리에 실리는 것은 이쪽이 재는 문서다.

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

# (배치 이름, 스크립트 자리 꼬리, 영문 정본, 한국어판, 공개 경로 지도)
# 공개 배치에는 지도가 없다 — 거기서는 문서가 적은 경로가 이미 실재하는 경로다.
LAYOUTS = (
    ('internal', ('scripts',),
     'oss/spec/SKILLS.md', 'oss/spec/SKILLS.ko.md', 'oss/PUBLIC_TREE.tsv'),
    ('public', ('spec', 'tools'),
     'spec/SKILLS.md', 'spec/SKILLS.ko.md', None),
)

SOURCE_RE = re.compile(r'^<!--[ \t]*source:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
EXAMPLE_RE = re.compile(r'^<!--[ \t]*example:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
FIELD_ROW_RE = re.compile(r'^\|\s*`([a-z_.]+)`\s*\|', re.M)

GO_TAG_RE = re.compile(r'`yaml:"(\w+)"`')
GO_ROWSHAPE_RE = re.compile(r'type rowShape struct \{(.*?)\n\}', re.S)
CPP_ROWKEYS_RE = re.compile(r'kRowKeys\s*=\s*\{(.*?)\}', re.S)
QUOTED_RE = re.compile(r'"([a-z_]+)"')


def die(msg):
    sys.stdout.write("SPEC-SKILLS: prerequisite failure — %s\n" % msg)
    raise SystemExit(2)


def read(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return fh.read()
    except OSError as exc:
        die("Cannot read: %s (%s)" % (path, exc))


def pick_layout():
    here_parts = HERE.split(os.sep)
    hit = [l for l in LAYOUTS if tuple(here_parts[-len(l[1]):]) == l[1]]
    if len(hit) != 1:
        die("Cannot determine layout (%d matches); script location: %s" % (len(hit), HERE))
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

    디렉터리 규칙(`a/b/` -> `c/`)도 따른다 — 공개 트리는 파일 단위와 디렉터리
    단위 규칙을 섞어 쓴다. 반환 (실재경로 or None, 목록에 실려있는가)."""
    if pmap is None:
        p = os.path.join(root, *target.split('/'))
        return (p if os.path.exists(p) else None), os.path.exists(p)
    internal = pmap.get(target)
    if internal is None:
        for pub, ins in pmap.items():
            if pub.endswith('/') and target.startswith(pub):
                internal = ins + target[len(pub):]
                break
    if internal is None:
        return None, False
    return os.path.join(root, *internal.split('/')), True


def doc_fields(doc):
    """필드 표의 첫 칸(백틱 식별자)들. 표가 없으면 전제 실패."""
    fields = FIELD_ROW_RE.findall(doc)
    if not fields:
        die("Cannot read field table; no rows of the form | `name` |")
    return set(fields)


def go_fields(src):
    """rowShape 의 yaml 태그를 `a.b` 로 편다. 중첩 구조체는 한 겹만 있다."""
    m = GO_ROWSHAPE_RE.search(src)
    if not m:
        die("Cannot find type rowShape struct in Go parser")
    body = m.group(1)
    out = set()
    pending = []          # 여는 중첩 구조체의 내부 태그
    depth = 0
    for line in body.splitlines():
        tags = GO_TAG_RE.findall(line)
        opens = line.count('{')
        closes = line.count('}')
        if depth > 0:
            if tags:
                pending.append(tags[-1])
            depth += opens - closes
            if depth == 0 and tags:
                parent = tags[-1]
                for inner in pending[:-1]:
                    out.add('%s.%s' % (parent, inner))
                pending = []
            continue
        if opens > closes:
            depth = opens - closes
            pending = list(tags)
            continue
        if tags:
            out.add(tags[-1])
    if not out:
        die("No YAML tags read from Go parser")
    return out


def cpp_fields(src):
    m = CPP_ROWKEYS_RE.search(src)
    if not m:
        die("Cannot find kRowKeys in C++ parser")
    out = set(QUOTED_RE.findall(m.group(1)))
    if not out:
        die("No names read from C++ kRowKeys")
    return out


def top(names):
    """`evidence.when` -> `evidence`. 최상위 마디로 접는다."""
    return {n.split('.', 1)[0] for n in names}


def example_keys(text):
    """예제 등재부가 `skills:` 아래에서 쓰는 키(최상위 마디)."""
    keys = set()
    in_skills = False
    for ln in text.splitlines():
        if re.match(r'^skills:', ln):
            in_skills = True
            continue
        if in_skills and ln and not ln.startswith((' ', '\t', '-')):
            in_skills = False
        if not in_skills:
            continue
        m = re.match(r'^\s*-?\s*([a-z_]+):', ln)
        if m:
            keys.add(m.group(1))
    return keys


def tsv_column(text, kind=None, col=0):
    """TSV 의 한 열을 집합으로. `kind` 가 있으면 그 종류 행만."""
    out = set()
    for i, ln in enumerate(text.splitlines()):
        if i == 0 or not ln.strip() or ln.startswith('#'):
            continue
        cells = ln.split('\t')
        if kind is not None:
            if len(cells) < 2 or cells[0].strip() != kind:
                continue
            out.add(cells[1].strip())
        else:
            out.add(cells[col].strip())
    return out


def main():
    layout, tail, en_rel, ko_rel, tree_rel = pick_layout()
    root = os.path.abspath(os.path.join(HERE, *(['..'] * len(tail))))
    doc = read(os.path.join(root, *en_rel.split('/')))
    pmap = public_map(os.path.join(root, *tree_rel.split('/')) if tree_rel else None)
    fails = []

    # ── K1: 인용 경로가 공개 트리에 실려 있는가 ──────────────────────────────
    sources = SOURCE_RE.findall(doc)
    examples = EXAMPLE_RE.findall(doc)
    if not sources or not examples:
        die("Document lacks source/example markers; comparison targets are undefined")
    resolved = {}
    for target in sources + examples:
        path, listed = resolve(target, root, pmap)
        if not listed:
            fails.append(('K1', "%s is absent from public manifest; readers cannot check the quote" % target))
            continue
        if path is None or not os.path.exists(path):
            fails.append(('K1', "%s is listed but its file is missing" % target))
            continue
        resolved[target] = path

    go_src = cpp_src = None
    for target, path in resolved.items():
        if target.endswith('.go'):
            go_src = read(path)
        elif target.endswith('.cpp'):
            cpp_src = read(path)
    if go_src is None or cpp_src is None:
        die("Cannot read both parsers (go=%s cpp=%s)"
            % (go_src is not None, cpp_src is not None))

    # ── K2·K3: 문서 == Go == C++ ──────────────────────────────────────────────
    dfields = doc_fields(doc)
    gfields = go_fields(go_src)
    if dfields != gfields:
        fails.append(('K2', "Only documented %s / only in Go parser %s"
                      % (sorted(dfields - gfields), sorted(gfields - dfields))))
    cfields = cpp_fields(cpp_src)
    if top(dfields) != cfields:
        fails.append(('K3', "Only documented top-level fields %s / only in C++ parser %s"
                      % (sorted(top(dfields) - cfields), sorted(cfields - top(dfields)))))

    # ── K4·K5: 실린 예제 ──────────────────────────────────────────────────────
    guard_path, guard_listed = resolve('spec/GUARDRAILS.tsv', root, pmap)
    vocab_path, vocab_listed = resolve('spec/SKILL_VOCAB.tsv', root, pmap)
    if not (guard_listed and vocab_listed):
        fails.append(('K1', "Vocabulary file is absent from public manifest and unavailable to readers"))
        guard_names = action_classes = robot_classes = None
    else:
        guard_names = tsv_column(read(guard_path))
        vocab = read(vocab_path)
        action_classes = tsv_column(vocab, kind='action_class')
        robot_classes = tsv_column(vocab, kind='robot_class')

    for target in examples:
        path = resolved.get(target)
        if path is None:
            continue
        text = read(path)
        keys = example_keys(text)
        stray = keys - top(dfields) - {'version', 'robot_class', 'skills'}
        if stray:
            fails.append(('K4', "%s uses undocumented keys: %s" % (target, sorted(stray))))
        if guard_names is None:
            continue
        used_env = set(re.findall(r'^\s*envelope:\s*\[([^\]]*)\]', text, re.M))
        names = {n.strip() for grp in used_env for n in grp.split(',') if n.strip()}
        if names - guard_names:
            fails.append(('K5', "%s uses envelope names outside the vocabulary: %s"
                          % (target, sorted(names - guard_names))))
        used_cls = set(re.findall(r'^\s*classes:\s*\[([^\]]*)\]', text, re.M))
        cls = {c.strip() for grp in used_cls for c in grp.split(',') if c.strip()}
        if cls - action_classes:
            fails.append(('K5', "%s uses classes outside the vocabulary: %s"
                          % (target, sorted(cls - action_classes))))
        rc = re.search(r'^robot_class:\s*(\S+)', text, re.M)
        if rc and rc.group(1) not in robot_classes:
            fails.append(('K5', "%s uses robot_class outside the vocabulary: %s" % (target, rc.group(1))))

    # ── K6: 한국어판 ──────────────────────────────────────────────────────────
    ko = read(os.path.join(root, *ko_rel.split('/')))
    kfields = set(FIELD_ROW_RE.findall(ko))
    if kfields != dfields:
        fails.append(('K6', "Korean fields differ: only canonical %s / only translated %s"
                      % (sorted(dfields - kfields), sorted(kfields - dfields))))

    sys.stdout.write("layout %s · quotes %d/%d · fields %d (documentation==Go==C++) · examples %d\n"
                     % (layout, len(resolved), len(sources) + len(examples),
                        len(dfields), len(examples)))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-SKILLS: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), 0, 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
