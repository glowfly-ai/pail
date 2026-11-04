#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""AC-4 — `spec/SITE_MODEL.md` 의 어휘를 컴파일러 소스와 실린 예제에 핀한다.

사이트 모델은 제3자가 **코드가 아니라 파일 하나로** 자기 현장을 기술하는 자리다.
그래서 이 문서가 낡으면 증상이 조용하다: 읽은 사람은 우리 컴파일러가 거부하는
YAML 을 쓰고, 거부 메시지는 자기 오타처럼 보인다. 손으로 쓴 규격이 파서보다 오래
사는 것 — 그것이 이 검사기가 겨누는 실패다.

그래서 문서의 어휘는 주장이 아니라 **유도값과의 대조 대상**이다. 셋을 함께 잰다:

    문서(표)  ==  컴파일러 소스(구조체 태그·레지스트리·필드 화이트리스트)  ==  실린 예제

둘만 재면 어느 쌍이든 함께 틀릴 수 있다. 문서와 예제만 재면 파서가 모르는 어휘를
둘이 합의할 수 있고, 문서와 파서만 재면 예제가 조용히 낡아 「돌려보기」가 깨진다.

  M1  `pin` 이 딸린 인용 블록은 그 파일의 **바이트 부분문자열**이어야 한다
  M2  `pin`·`source`·`example` 이 가리키는 경로는 **공개 트리에 실려야** 한다
      (독자가 대조할 수 없는 인용은 인용이 아니라 주장이다)
  M3  최상위 키 어휘·필수성 == `yamlSite` 구조체 태그 + 필수 판정 리터럴
  M4  절별 필드 어휘·필수성 == 그 절의 원소 구조체 태그 + 빈 id 판정 리터럴
  M5  제약 `type` 어휘 == `constraintRegistry` 의 키 (목록 표와 필드 표 **양쪽**)
  M6  제약별 필드 어휘·필수성 == `ensureOnlyFields` 화이트리스트 + `reqString`/`optFloat`
  M7  실린 예제가 쓰는 어휘가 전부 문서에 있다
  M8  한국어판이 같은 어휘를 가르친다 (번역본이 조용히 갈라지지 않는다)

M8 이 있는 이유는 M3~M6 이 영문 정본만 읽기 때문이다. 재지 않는 번역본은 낡는
것이 아니라 **낡은 채로 초록**이다.

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
     'oss/spec/SITE_MODEL.md', 'oss/spec/SITE_MODEL.ko.md', 'oss/PUBLIC_TREE.tsv'),
    ('public', ('spec', 'tools'),
     'spec/SITE_MODEL.md', 'spec/SITE_MODEL.ko.md', None),
)

PIN_RE = re.compile(r'^<!--[ \t]*pin:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
FENCE_RE = re.compile(r'^```[a-zA-Z0-9]*\n(.*?)^```[ \t]*$', re.M | re.S)
SOURCE_RE = re.compile(r'^<!--[ \t]*source:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
EXAMPLE_RE = re.compile(r'^<!--[ \t]*example:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
VOCAB_RE = re.compile(r'^<!--[ \t]*vocab:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
CTYPES_RE = re.compile(r'^<!--[ \t]*ctypes[ \t]*-->[ \t]*$', re.M)

IDENT_CELL_RE = re.compile(r'^`([A-Za-z_][A-Za-z0-9_]*)`$')
GO_FIELD_RE = re.compile(r'^\t(\w+)\s+(\S+)\s+`yaml:"(\w+)"`', re.M)

REQUIRED, OPTIONAL = 'required', 'optional'


def die(msg):
    sys.stdout.write("SPEC-SITE-MODEL: prerequisite failure — %s\n" % msg)
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
    for name, tail, doc, ko, tree in LAYOUTS:
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            hit.append((name, root,
                        os.path.join(root, *doc.split('/')),
                        os.path.join(root, *ko.split('/')),
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


# ── 문서 쪽: 표 읽기 ────────────────────────────────────────────────────────
def table_after(doc, pos):
    """마커 뒤 첫 표를 (행, 셀목록) 으로 돌려준다. 머리행·구분행은 뺀다."""
    lines = doc[pos:].splitlines()
    rows = []
    started = False
    for ln in lines:
        s = ln.strip()
        if not s:
            if started:
                break
            continue
        if not s.startswith('|'):
            if started:
                break
            return []
        started = True
        cells = [c.strip() for c in s.strip('|').split('|')]
        if all(set(c) <= set('-: ') for c in cells):
            continue
        rows.append(cells)
    return rows[1:] if rows else []


def doc_vocab(doc, code, marker, fails, want_requiredness=True):
    """표에서 (식별자 -> 필수성) 을 읽는다. 필수성을 안 읽을 때는 값이 None."""
    out = {}
    for row in table_after(doc, marker):
        m = IDENT_CELL_RE.match(row[0])
        if not m:
            fails.append((code, "First table column is not a backtick identifier: %r" % row[0][:40]))
            continue
        name = m.group(1)
        if not want_requiredness:
            out[name] = None
            continue
        if len(row) < 2:
            fails.append((code, "Row `%s` lacks the requiredness column" % name))
            continue
        word = row[1].strip().lower()
        if word not in (REQUIRED, OPTIONAL):
            fails.append((code, "Requiredness for `%s` is %r; expected %s or %s"
                          % (name, row[1][:24], REQUIRED, OPTIONAL)))
            continue
        out[name] = word
    return out


def compare(code, what, doc_map, src_map, fails):
    """어휘와 필수성을 **양방향**으로 잰다. 한 방향만 재면 반대쪽이 조용히 낡는다."""
    missing = sorted(set(src_map) - set(doc_map))
    phantom = sorted(set(doc_map) - set(src_map))
    if missing:
        fails.append((code, "%s — parsed but undocumented: %s" % (what, missing)))
    if phantom:
        fails.append((code, "%s — documented but not parsed: %s" % (what, phantom)))
    for name in sorted(set(doc_map) & set(src_map)):
        if doc_map[name] is None or src_map[name] is None:
            continue
        if doc_map[name] != src_map[name]:
            fails.append((code, "%s `%s` — documented %s / parser %s"
                          % (what, name, doc_map[name], src_map[name])))


# ── 소스 쪽: 어휘 유도 ──────────────────────────────────────────────────────
def struct_fields(src, name):
    m = re.search(r'^type ' + name + r' struct \{\n(.*?)^\}', src, re.M | re.S)
    if not m:
        die("Cannot find struct %s in compiler source; comparison unavailable" % name)
    out = [(f.group(3), f.group(2)) for f in GO_FIELD_RE.finditer(m.group(1))]
    if not out:
        die("No YAML tags read from %s; empty scan cannot establish agreement"
            % name)
    return out


def derive(compile_src, constraints_src):
    """파서 소스에서 문서가 주장해야 할 값을 뽑는다."""
    top_required = set(re.findall(r'missing required `(\w+)`', compile_src))
    if not top_required:
        die("Cannot find required top-level key checks in compiler")
    # "<singular> with empty <field>" literals in the compiler are the parser's own
    # statement that the field is required (id historically; any field since AG-8).
    empty_field = set(re.findall(r'(\w+) with empty (\w+)', compile_src))

    top, sections = {}, {}
    for tag, gotype in struct_fields(compile_src, 'yamlSite'):
        top[tag] = REQUIRED if tag in top_required else OPTIONAL
        m = re.match(r'^\[\]yaml(\w+)$', gotype)
        if m and m.group(1) != 'Constraint':
            singular = m.group(1).lower()
            fields = {}
            for ftag, _ in struct_fields(compile_src, 'yaml' + m.group(1)):
                fields[ftag] = REQUIRED if (singular, ftag) in empty_field else OPTIONAL
            sections[tag] = fields

    if not sections:
        die("No sections with element structs found")

    reg = re.search(r'^var constraintRegistry = map\[string\]constraintCompiler\{\n'
                    r'(.*?)^\}', constraints_src, re.M | re.S)
    if not reg:
        die("Constraint registry missing; no authoritative vocabulary")
    registry = dict(re.findall(r'^\t"([a-z0-9_]+)":\s*(\w+),', reg.group(1), re.M))
    if not registry:
        die("No entries read from constraint registry")

    ctypes = {}
    for ctype, fname in sorted(registry.items()):
        body = re.search(r'^func ' + fname + r'\(.*?(?=^func |\Z)',
                         constraints_src, re.M | re.S)
        if not body:
            die("Cannot find constraint compiler body %s" % fname)
        body = body.group(0)
        only = re.search(r'ensureOnlyFields\(rc,\s*([^)]*)\)', body)
        if not only:
            die("%s has no field allow-list; vocabulary cannot be derived" % fname)
        allowed = re.findall(r'"([a-z0-9_]+)"', only.group(1))
        req = set(re.findall(r'reqString\(rc,\s*"([a-z0-9_]+)"\)', body))
        opt = set(re.findall(r'optFloat\(rc,\s*"([a-z0-9_]+)"\)', body))
        unknown = [f for f in allowed if f not in req and f not in opt]
        if unknown:
            # 분류할 수 없는 필드가 있으면 필수성을 "모른다". 모름을 optional 로
            # 적어 두면 그 칸은 영원히 통과한다 — 판독 불가는 초록이 아니다.
            die("Cannot classify %s field %s as required or optional" % (fname, unknown))
        ctypes[ctype] = {f: (REQUIRED if f in req else OPTIONAL) for f in allowed}
    return top, sections, ctypes


# ── 예제 쪽: 쓰인 어휘 ──────────────────────────────────────────────────────
def example_vocab(text):
    """실린 예제가 실제로 쓰는 어휘를 훑는다.

    (최상위 키, 절 -> 필드, ctype -> 필드) 를 돌려준다. YAML 파서에 기대지 않는다 —
    공개 검사기는 표준 라이브러리 밖 의존을 두지 않는다."""
    top, sections, ctypes = set(), {}, {}
    section, ctype, pending = None, None, []
    for raw in text.splitlines():
        ln = raw.split('#')[0].rstrip() if not raw.lstrip().startswith('#') else ''
        if not ln.strip():
            continue
        m = re.match(r'^([A-Za-z_][\w]*):', ln)
        if m:
            section, ctype, pending = m.group(1), None, []
            top.add(section)
            continue
        if section is None:
            continue
        m = re.match(r'^\s+-\s+([A-Za-z_][\w]*):\s*(.*)$', ln)
        if m:
            if section == 'constraints':
                # 새 항목이 시작되면 이전 항목의 미분류 필드는 그 항목의 type 으로
                # 이미 접혔다. type 이 항목 안 어디에 오든 상관없게 보류한다.
                pending = []
            key, val = m.group(1), m.group(2).strip()
        else:
            m = re.match(r'^\s+([A-Za-z_][\w]*):\s*(.*)$', ln)
            if not m:
                continue
            key, val = m.group(1), m.group(2).strip()
        if section == 'constraints':
            if key == 'type':
                ctype = val.strip('"\' ')
                ctypes.setdefault(ctype, set()).update(pending)
                pending = []
            elif ctype is None:
                pending.append(key)
            else:
                ctypes.setdefault(ctype, set()).add(key)
        else:
            sections.setdefault(section, set()).add(key)
    return top, sections, ctypes


def main():
    layout, root, doc_path, ko_path, tree_path = locate()
    doc = read(doc_path)
    pmap = public_map(tree_path)
    fails = []

    # --- M1 / M2: 인용 --------------------------------------------------------
    pins = list(PIN_RE.finditer(doc))
    if not pins:
        die("No documentation pins found; zero comparisons cannot establish quote correctness")
    checked = 0
    for m in pins:
        target = m.group(1)
        local, shipped = resolve(target, root, pmap)
        if not shipped:
            fails.append(('M2', "%s — quoted target is not distributed and cannot be checked by recipients" % target))
            continue
        if local is None or not os.path.exists(local):
            fails.append(('M2', "%s — quoted target does not exist in this layout" % target))
            continue
        fence = FENCE_RE.search(doc, m.end())
        if not fence:
            fails.append(('M1', "%s — no quotation block after the pin" % target))
            continue
        if fence.group(1) not in read(local):
            head = (fence.group(1).splitlines() or [''])[0]
            fails.append(('M1', "%s — quote is not a byte substring (first line: %s)"
                          % (target, head[:70])))
            continue
        checked += 1

    # --- 소스·예제 자리 ------------------------------------------------------
    srcs = {}
    for m in SOURCE_RE.finditer(doc):
        target = m.group(1)
        local, shipped = resolve(target, root, pmap)
        if not shipped or local is None or not os.path.exists(local):
            fails.append(('M2', "%s — documented parser source is absent from this layout" % target))
            continue
        srcs[os.path.basename(target)] = local
    for need in ('compile.go', 'constraints.go'):
        if need not in srcs:
            die("%s is not declared as a source or is not distributed; no vocabulary source" % need)

    ex_m = EXAMPLE_RE.search(doc)
    if not ex_m:
        die("Document lacks an example declaration")
    ex_local, ex_shipped = resolve(ex_m.group(1), root, pmap)
    if not ex_shipped or ex_local is None or not os.path.exists(ex_local):
        die("Example is absent from this layout: %s" % ex_m.group(1))

    top_src, sec_src, ct_src = derive(read(srcs['compile.go']),
                                      read(srcs['constraints.go']))

    # --- 문서의 표를 한 번만 읽는다 -------------------------------------------
    # 같은 표를 검사마다 다시 읽으면 형식 오류 하나가 여러 칸에서 중복 계상되어
    # FAIL 수가 결함 수를 넘는다. 세는 값이 뜻을 잃으면 판정도 잃는다.
    vocab_pos = {m.group(1): m.end() for m in VOCAB_RE.finditer(doc)}
    if 'top' not in vocab_pos:
        die("Document lacks vocab:top table")
    ct_pos = CTYPES_RE.search(doc)
    if not ct_pos:
        die("Document lacks ctypes table; no documented constraint vocabulary")

    doc_maps = {k: doc_vocab(doc, 'M3' if k == 'top' else
                             ('M6' if k.startswith('constraint/') else 'M4'),
                             p, fails)
                for k, p in vocab_pos.items()}
    ct_doc = doc_vocab(doc, 'M5', ct_pos.end(), fails, want_requiredness=False)

    doc_sections = {k: v for k, v in doc_maps.items()
                    if k != 'top' and not k.startswith('constraint/')}
    doc_ctf = {k.split('/', 1)[1]: v for k, v in doc_maps.items()
               if k.startswith('constraint/')}

    # --- M3 / M4: 최상위 키와 절별 필드 ---------------------------------------
    compare('M3', '최상위 키', doc_maps['top'], top_src, fails)
    if set(doc_sections) != set(sec_src):
        fails.append(('M4', "Section list differs: documented %s / parser %s"
                      % (sorted(doc_sections), sorted(sec_src))))
    for name in sorted(set(doc_sections) & set(sec_src)):
        compare('M4', '`%s` 필드' % name, doc_sections[name], sec_src[name], fails)

    # --- M5 / M6: 제약 --------------------------------------------------------
    # 어느 type 이 있는가는 M5 가 **혼자** 진다 — 목록 표와 필드 표 둘 다에 대해서다.
    # 집합 판정을 M6 에도 두면 레지스트리 한 줄이 바뀔 때 두 칸이 함께 붉어지고,
    # 그러면 둘 중 하나가 죽어도 나머지가 가려 준다(H-B9). M6 은 **양쪽에 다 있는**
    # type 의 필드만 잰다. 두 표를 따로 대조하지 않는 것도 같은 이유다 — 그러면 한
    # 결함이 두 줄로 세어지고, 세는 값이 결함 수를 넘으면 판정도 뜻을 잃는다.
    half = set(ct_doc) ^ set(doc_ctf)
    if half:
        fails.append(('M5', "Type-list and field tables differ; types appearing on only one side: %s"
                      % sorted(half)))
    compare('M5', '제약 type', {k: None for k in set(ct_doc) & set(doc_ctf)},
            {k: None for k in ct_src}, fails)
    for name in sorted(set(doc_ctf) & set(ct_src)):
        compare('M6', '제약 `%s` 필드' % name, doc_ctf[name], ct_src[name], fails)

    # --- M7: 실린 예제 --------------------------------------------------------
    ex_top, ex_sec, ex_ct = example_vocab(read(ex_local))
    if not ex_top:
        die("No top-level keys read from example: %s" % ex_m.group(1))
    for k in sorted(ex_top - set(doc_maps['top'])):
        fails.append(('M7', "Example uses undocumented top-level key `%s`" % k))
    for sec, keys in sorted(ex_sec.items()):
        if sec not in doc_sections:
            # 절 자체가 문서에 없는 것은 M4 가 이미 적었다. 여기서 또 세면 한 결함이
            # 두 칸에서 붉어져 어느 관측점이 살아 있는지 구분되지 않는다.
            continue
        for k in sorted(keys - set(doc_sections[sec])):
            fails.append(('M7', "Example section `%s` uses undocumented field `%s`" % (sec, k)))
    for ctype, keys in sorted(ex_ct.items()):
        if ctype not in doc_ctf:
            fails.append(('M7', "Example uses undocumented constraint type `%s`" % ctype))
            continue
        for k in sorted(keys - set(doc_ctf[ctype])):
            fails.append(('M7', "Example constraint `%s` uses undocumented field `%s`"
                          % (ctype, k)))

    # --- M8: 한국어판 ---------------------------------------------------------
    ko = read(ko_path)
    ko_pos = {m.group(1): m.end() for m in VOCAB_RE.finditer(ko)}
    ko_ct = CTYPES_RE.search(ko)
    if set(ko_pos) != set(vocab_pos) or ko_ct is None:
        fails.append(('M8', "Korean vocabulary tables differ from canonical tables: canonical %s / Korean %s"
                      % (sorted(vocab_pos), sorted(ko_pos))))
    else:
        ko_fails = []  # 번역본의 표 형식 오류는 M8 한 칸으로 접는다
        for name in sorted(vocab_pos):
            kv = doc_vocab(ko, 'M8', ko_pos[name], ko_fails)
            if set(doc_maps[name]) != set(kv):
                fails.append(('M8', "Table `%s` identifiers differ: canonical %s / Korean %s"
                              % (name, sorted(doc_maps[name]), sorted(kv))))
        kv_ct = set(doc_vocab(ko, 'M8', ko_ct.end(), ko_fails,
                              want_requiredness=False))
        if set(ct_doc) != kv_ct:
            fails.append(('M8', "ctypes identifiers differ: canonical %s / Korean %s"
                          % (sorted(ct_doc), sorted(kv_ct))))
        fails.extend(ko_fails)

    sys.stdout.write(
        "layout %s · quotes %d/%d · top-level keys %d · sections %s · constraints %s\n"
        % (layout, checked, len(pins), len(top_src),
           sorted(sec_src), sorted(ct_src)))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-SITE-MODEL: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), 0, 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
