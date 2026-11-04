#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""C-2 — `THREAT_MODEL.md` 두 판을 **실린 소스**와 `TRUST_BOUNDARY.md` 에 핀한다.

위협 모델은 생성물이다. 그러나 생성기와 등재부는 공개 트리에 실리지 않는다 —
제3자가 받는 것은 문서와 소스뿐이고, 그 손 안에서 생성 문서는 손으로 쓴 문서와
바이트가 같다. 그래서 CI 가 문서 == 등재부 를 아무리 단단히 재도, 받는 쪽에서는
**등재부 == 코드** 를 아무도 재지 않는다. 이 검사기가 겨누는 것이 그 격차다.

셋을 함께 잰다:

    위협 모델(문서)  ==  TRUST_BOUNDARY(문서)  ==  실린 소스(선언)

둘만 재면 어느 쌍이든 함께 틀릴 수 있다. 두 문서만 재면 코드가 잃은 게이트를
두 문서가 나란히 계속 광고하고, 문서와 소스만 재면 같은 사실에 대해 두 공개
문서가 서로 다른 답을 주는 상태가 조용히 산다.

  N1   실린 소스가 선언한 게이트가 §6 표에 있고 「설계에만 있다」로 적혀 있지 않다
  N2   §6 표가 「구현됨」이라 적은 게이트가 실린 소스에 있다 (N1 의 역방향)
  N3   위협 모델이 인용한 기동 게이트가 실린 소스에 있다
  N4   그 게이트의 한 줄 설명이 §6 표의 것과 같다
  N5   위협 모델이 인용한 위임이 TRUST_BOUNDARY §3 에 있고 위임처 문안이 같다
  N6   TRUST_BOUNDARY §3 이 선언한 위임이 위협 모델 7절 표에 전부 있다 (N5 의 역방향)
  N7   쓰이는 공격자·자산·공격면 id 가 선언돼 있고(유령), 선언된 것이 전부 쓰인다(고아)
  N8   위협 행렬과 위협 상세가 같은 집합·같은 삼중·같은 문장이다
  N9   7절의 「인용한 곳」 열이 상세의 실제 인용과 양방향으로 일치한다
  N10  본문이 선언한 개수가 실제로 걷은 개수와 같다
  N11  한국어판이 같은 어휘·같은 인용·같은 개수를 싣는다

관측점은 **유도의 출처**로 갈랐다 — 한 구성물이 바뀌면 한 칸만 붉는다. N1 과 N2 를
나눈 것이 그 예다. 한 칸에 두면 방향 하나가 죽어도 다른 쪽이 가려 주고, 실제로
가려졌던 것이 N1 쪽이다(실측 2026-08-29: 소스가 선언한 게이트 여덟이 §6 표에서
빠졌거나 「설계에만 있다」로 적혀 있었다 — 단방향 검사만 있으면 이것은 영원히
초록이다). N5 와 N6 도 같은 이유로 나눈다.

N11 이 있는 이유는 N3~N10 이 영문 정본만 읽기 때문이다. 재지 않는 번역본은 낡는
것이 아니라 **낡은 채로 초록**이다. 다만 N11 은 문안이 아니라 **어휘와 개수**를
잰다 — 번역본의 산문은 당연히 다른 바이트이고, 같아야 하는 것은 가르치는 어휘다.

한국어판 `TRUST_BOUNDARY.ko.md` 는 읽지 않는다. 두 문서 사이의 대조를 두 언어로
각각 하면 한 결함이 두 칸으로 세어지고, 그 문서의 두 판이 서로 어긋나는지는
그 문서 자신의 생성 대조가 잰다.

배치가 둘이다. 내부 트리에서는 실린 소스를 `oss/PUBLIC_TREE.tsv` 의 INCLUDE 행으로
정하고, 공개 트리에서는 트리 자체가 실린 소스다. 두 배치가 **같은 것을 잰다** —
"제3자가 받는 코드에 그 게이트가 있는가". 스캔 경로 목록을 손으로 들고 있지
않는 이유가 여기 있다: 그 목록이 낡으면 스캔이 조용히 작아지고, 작아진 스캔은
「위반 0」과 같은 바이트로 도착한다.

생성기(`gen_trust_boundary` · `gen_threat_model`)에서 아무것도 가져오지 않는다.
생산기와 검증기가 스캔을 공유하면 그 스캔이 틀린 날 둘이 함께 틀린 채로 초록이다.

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

# (배치 이름, 스크립트 자리 꼬리, 영문 정본, 한국어판, 경계 문서, 공개 트리 목록)
# 공개 배치에는 목록이 없다 — 거기서는 트리에 있는 것이 곧 실린 것이다.
LAYOUTS = (
    ('internal', ('scripts',),
     'THREAT_MODEL.md', 'THREAT_MODEL.ko.md', 'TRUST_BOUNDARY.md',
     'oss/PUBLIC_TREE.tsv'),
    ('public', ('spec', 'tools'),
     'THREAT_MODEL.md', 'THREAT_MODEL.ko.md', 'TRUST_BOUNDARY.md',
     None),
)

SRC_EXT = ('.hpp', '.cpp', '.go', '.sh')

# 소스에서 게이트 id 가 선언되는 형태. 자릿수를 셋까지 받는 것은 의도다 — 한 자
# 패턴은 관측점이 열을 넘는 순간 `S10` 을 `S1` 로 읽고, 그 오독은 조용하다.
# 문자열 리터럴만 보고 호출 형태(`deploysec.Cfg(...)`)는 보지 않는다: C++ 쪽은
# 다른 자리에서 같은 id 를 세우고, 호출 형태로 좁히면 그쪽이 통째로 사라진다.
GATE_IN_SOURCE = re.compile(r'(?:"|PAIL PREFLIGHT(?: FAIL| WARN| %s)?: )(S\d{1,3}[a-z]?)(?="|[ :])')

ID_RE = {
    'attacker': re.compile(r'^A\d{1,3}$'),
    'asset': re.compile(r'^AS\d{1,3}$'),
    'surface': re.compile(r'^X\d{1,3}$'),
    'threat': re.compile(r'^T-\d{2,3}$'),
    'delegation': re.compile(r'^G-DEL-L?\d{2,3}$'),
}

# 표 분류는 첫 데이터 행의 첫 칸 모양으로 한다. 표제 문구로 하면 한국어판에서
# 같은 코드가 쓰이지 못하고, 판마다 파서를 하나씩 두면 번역본 쪽이 먼저 낡는다.
TABLE_KINDS = ('attacker', 'asset', 'surface', 'threat', 'delegation')

BACKTICK = re.compile(r'`([^`]+)`')
# 표의 칸 나누기. 이스케이프된 파이프(`\|`)는 칸 경계가 아니다 — 날 파이프로 쪼개면
# `S0` 행이 한 칸 밀려 상태 칸에 `dev\`` 가 들어오고, 그것은 「모르는 상태」로
# 도착한다. 값이 아니라 **읽기**가 틀린 것이다.
CELL_SPLIT = re.compile(r'(?<!\\)\|')
BOLD_ID = re.compile(r'\*\*(A\d{1,3}|AS\d{1,3}|X\d{1,3})\*\*')
THREAT_HEAD = re.compile(r'^###\s+(T-\d{2,3})\s+—\s+(.*?)\s*$', re.M)
DEL_HEAD = re.compile(r'^###\s+(G-DEL-L?\d{2,3})\s+—', re.M)
DELEGATED_TO = re.compile(r'^\*\*Delegated to\*\*\s+(.*?)\s+·\s+\*\*Layer\*\*', re.M)
BULLET = re.compile(r'^-\s+`([^`]+)`\s+—\s+(.*?)\s*$', re.M)
INT_RE = re.compile(r'\d+')

# §6 표의 상태 문구. 정본의 바이트를 그대로 든다 — 문구가 바뀌면 이 검사기가
# 붉어 두 자리를 함께 고치게 만든다(핀). 모르는 문구는 어느 통에도 넣지 않고
# FAIL 로 낸다: `else` 로 삼키면 새 상태 하나가 조용히 「있음」이 된다.
GATE_NONREFUSING = (
    'warning only (startup continues)',
    'does not refuse — recorded as an axis in the seal',
)
GATE_PRESENT = ('implemented',) + GATE_NONREFUSING
# Declared only in the PAIL-Issuer bundle (cloud/issuer/; not part of a PAIL-Core delivery). Present when that
# bundle is in the tree; legitimately absent — and said so — in a PAIL-Core-only tree.
GATE_PRESENT_ISSUER = ('implemented (PAIL-Issuer bundle)',)
GATE_ABSENT = (
    '**not in the shipped source**',
)
GATE_EXCLUDED = (
    "adapter-side — not in this tree's ROS 2 node (implemented by the Microduck adapter, to be published separately)",
    'not applicable (closed track)',
    'unassigned — will not be implemented',
)

# 바닥. 파싱이 무너지면 걷은 것이 비고, 빈 집합끼리의 대조는 **자동으로 참**이다.
# 이 수들은 목표가 아니라 「표를 읽기는 했는가」의 하한이다.
FLOOR = {
    'attacker': 6, 'asset': 4, 'surface': 5, 'threat': 10, 'delegation': 10,
    'gate_source': 20,      # 실린 소스에서 걷은 게이트
    'gate_table': 20,       # §6 표 행
    'gate_cited': 3,        # 게이트를 인용하는 위협의 수
    'src_files': 60,        # 스캔한 소스 파일
}

# 여기까지 모은 위반. `die()` 가 이것을 함께 인쇄한다 — 전제 실패만 인쇄하면
# 「무엇이 빠졌는지」의 칸은 영원히 인쇄되지 않는다.
FAILS = []


def die(msg):
    for code, m in FAILS:
        sys.stdout.write('[FAIL] %s %s\n' % (code, m))
    sys.stdout.write("SPEC-THREAT-MODEL: prerequisite failure — %s\n" % msg)
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
    for name, tail, doc, ko, tb, tree in LAYOUTS:
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            j = lambda rel: os.path.join(root, *rel.split('/'))
            hit.append((name, root, j(doc), j(ko), j(tb), j(tree) if tree else None))
    if len(hit) != 1:
        die("Cannot determine layout (%d matches); script location: %s" % (len(hit), here))
    return hit[0]


def is_test(rel):
    path = rel.replace(os.sep, '/')
    return (path.endswith('_test.go') or any(part in ('test', 'tests') for part in path.split('/'))
            or path.startswith(('pvs-public/', 'pvs/', 'examples/', 'e2e/')))


def shipped_sources(root, tree_path):
    """제3자가 받는 소스 파일. 내부 배치는 공개 목록으로, 공개 배치는 트리로."""
    out = []
    if tree_path is None:
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                if not fn.endswith(SRC_EXT):
                    continue
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, root)
                if not is_test(rel):
                    out.append((rel.replace(os.sep, '/'), p))
        return out
    rows = 0
    for ln in read(tree_path).splitlines():
        if ln.startswith('#') or not ln.strip():
            continue
        cells = ln.split('\t')
        if len(cells) < 3 or cells[0] != 'INCLUDE':
            continue
        rows += 1
        internal, public = cells[1].strip(), cells[2].strip()
        if not public.endswith(SRC_EXT) or is_test(public):
            continue
        out.append((public, os.path.join(root, *internal.split('/'))))
    if rows == 0:
        die("No INCLUDE rows read from public manifest: %s" % tree_path)
    return out


def scan_gates(files):
    """실린 소스가 선언한 게이트 id -> 그것이 나타나는 공개 경로들."""
    found = {}
    for public, path in files:
        try:
            with open(path, encoding='utf-8', errors='replace') as fh:
                src = fh.read()
        except OSError:
            die("Cannot read distributed source %s; manifest and files are inconsistent" % public)
        for m in GATE_IN_SOURCE.finditer(src):
            found.setdefault(m.group(1), set()).add(public)
    return found


# ── 문서 쪽: 표와 절 읽기 ──────────────────────────────────────────────────
def tables(doc):
    """문서의 모든 마크다운 표를 (시작줄번호, 행목록) 으로 걷는다."""
    out, cur, start = [], None, 0
    lines = doc.splitlines()
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('|') and s.endswith('|'):
            if cur is None:
                cur, start = [], i
            cells = [c.strip() for c in CELL_SPLIT.split(s[1:-1])]
            if not all(set(c) <= set('-: ') for c in cells):
                cur.append(cells)
        elif cur is not None:
            out.append((start, cur))
            cur = None
    if cur is not None:
        out.append((start, cur))
    return [(st, rows[1:]) for st, rows in out if len(rows) > 1]


def classify(doc):
    """표를 첫 칸 모양으로 분류한다. 같은 종류가 둘이면 전제가 무너진 것이다."""
    got = {}
    for start, rows in tables(doc):
        m = BACKTICK.match(rows[0][0])
        if not m:
            continue
        for kind in TABLE_KINDS:
            if ID_RE[kind].match(m.group(1)):
                if kind in got:
                    die("Duplicate %s table; canonical target is ambiguous" % kind)
                got[kind] = (start, rows)
                break
    missing = [k for k in TABLE_KINDS if k not in got]
    if missing:
        die("Cannot find table: %s" % ', '.join(missing))
    return got


def cell_id(kind, cell, code, fails, where):
    m = BACKTICK.match(cell)
    if not m or not ID_RE[kind].match(m.group(1)):
        fails.append((code, "%s column is not a %s ID: %r" % (where, kind, cell[:40])))
        return None
    return m.group(1)


def announced(doc, start):
    """표 바로 앞 문단이 선언하는 개수. 정수가 정확히 하나여야 한다."""
    lines = doc.splitlines()
    i = start - 1
    while i >= 0 and not lines[i].strip():
        i -= 1
    block = []
    while i >= 0 and lines[i].strip():
        block.append(lines[i])
        i -= 1
    ns = INT_RE.findall(' '.join(block))
    return ([int(n) for n in ns], ' '.join(reversed(block))[:60])


def threat_blocks(doc):
    """위협 상세를 id -> (제목 문장, 본문) 으로 자른다."""
    hits = list(THREAT_HEAD.finditer(doc))
    out = {}
    for n, m in enumerate(hits):
        end = hits[n + 1].start() if n + 1 < len(hits) else len(doc)
        if m.group(1) in out:
            die("Duplicate detailed-threat heading %s" % m.group(1))
        out[m.group(1)] = (m.group(2), doc[m.end():end])
    return out


def block_refs(body):
    """상세 본문의 글머리에서 게이트와 위임을 갈라 걷는다.

    글머리를 id 모양으로 가르는 것은 판을 타지 않기 위해서다 — 「기동 게이트」와
    「위임」의 표제는 번역되지만 id 는 번역되지 않는다."""
    gates, dele = {}, {}
    for m in BULLET.finditer(body):
        ident, desc = m.group(1), m.group(2)
        if ID_RE['delegation'].match(ident):
            dele[ident] = desc
        elif GATE_IN_SOURCE.match('"%s"' % ident):
            gates[ident] = desc
    return gates, dele


def unpipe(s):
    return s.replace('\\|', '|').strip()


NONREFUSE_NOTE = re.compile(r'^\s+\*\(([^)]+)\)\*$')


def gate_desc_fail(gid, got, want, status):
    """게이트 한 줄이 두 공개 문서에서 같은가.

    위협 모델 쪽은 거부하지 않는 게이트에 이탤릭 주기를 덧붙인다. 주기를 무시하고
    앞부분만 재면 「거부한다」와 「경고만 한다」가 같은 바이트가 되므로, 주기의
    유무를 상태와 **함께** 잰다 — 어느 한쪽만 바뀌어도 붉는다."""
    if not got.startswith(want):
        return [('N4', '`%s` 의 한 줄 설명이 두 공개 문서에서 다르다 — 위협 모델 %r '
                       '/ 경계 문서 %r' % (gid, got[:60], want[:60]))]
    rest = got[len(want):]
    if status in GATE_NONREFUSING:
        if not NONREFUSE_NOTE.match(rest):
            return [('N4', '`%s` 는 거부하지 않는 게이트인데 위협 모델이 그 사실을 '
                           '적지 않았다 — 거부 게이트들 사이에 표시 없이 섞이면 읽는 '
                           '쪽은 이것도 자기 배치를 막아 준다고 읽는다' % gid)]
    elif rest.strip():
        return [('N4', '`%s` 는 거부하는 게이트인데 위협 모델이 주기를 달았다: %r'
                 % (gid, rest.strip()[:40]))]
    return []


# ── 본체 ───────────────────────────────────────────────────────────────────
def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        # 묻는 인자와 실행하는 인자를 같이 취급하지 않는다.
        sys.stderr.write("spec_threat_model_check: arguments are not accepted: %r\n" % (argv,))
        return 2

    layout, root, doc_path, ko_path, tb_path, tree_path = locate()
    doc, ko, tb = read(doc_path), read(ko_path), read(tb_path)
    fails = FAILS

    files = shipped_sources(root, tree_path)
    if len(files) < FLOOR['src_files']:
        die("Only %d distributed source files found (minimum %d); scan coverage is insufficient" % (len(files), FLOOR['src_files']))
    src_gates = scan_gates(files)
    if len(src_gates) < FLOOR['gate_source']:
        die("Only %d gates derived from distributed sources (minimum %d)"
            % (len(src_gates), FLOOR['gate_source']))

    # --- TRUST_BOUNDARY §6 게이트 표 -----------------------------------------
    tb_gate, tb_bad = {}, []
    for _start, rows in tables(tb):
        m = BACKTICK.match(rows[0][0])
        if not m or not GATE_IN_SOURCE.match('"%s"' % m.group(1)):
            continue
        if tb_gate:
            die("Boundary document contains two gate tables")
        for row in rows:
            mm = BACKTICK.match(row[0])
            if not mm or len(row) < 3:
                tb_bad.append(row[0][:40])
                continue
            tb_gate[mm.group(1)] = (unpipe(row[1]), row[2].strip())
    if len(tb_gate) < FLOOR['gate_table']:
        die("Only %d rows read from boundary gate table (minimum %d)"
            % (len(tb_gate), FLOOR['gate_table']))
    for b in tb_bad:
        fails.append(('N1', "Unreadable row in boundary gate table: %r" % b))

    state = {}
    for gid, (_desc, st) in tb_gate.items():
        if st in GATE_PRESENT:
            state[gid] = 'present'
        elif st in GATE_PRESENT_ISSUER:
            state[gid] = 'present-issuer'
        elif st in GATE_ABSENT:
            state[gid] = 'absent'
        elif st in GATE_EXCLUDED:
            state[gid] = 'excluded'
        else:
            fails.append(('N1', "Unrecognized status for `%s`: %r; cannot classify as implemented or absent" % (gid, st)))

    # --- N1: 실린 소스 -> 경계 문서 -------------------------------------------
    for gid in sorted(src_gates):
        if gid not in tb_gate:
            fails.append(('N1', "`%s` is declared in distributed source but absent from boundary gate table (%s)"
                          % (gid, ', '.join(sorted(src_gates[gid])[:2]))))
        elif state.get(gid) == 'absent':
            fails.append(('N1', "`%s` exists in distributed source but is documented as design-only (%s)"
                          % (gid, ', '.join(sorted(src_gates[gid])[:2]))))

    # --- N2: 경계 문서 -> 실린 소스 -------------------------------------------
    issuer_present = any(rel.startswith('cloud/issuer/') for rel, _p in files)
    issuer_only_absent = []
    for gid in sorted(tb_gate):
        if state.get(gid) == 'present' and gid not in src_gates:
            fails.append(('N2', "Boundary declares `%s` implemented, but it is absent from distributed source" % gid))
        elif state.get(gid) == 'present-issuer' and gid not in src_gates:
            if issuer_present:
                fails.append(('N2', "Boundary declares `%s` implemented in the PAIL-Issuer bundle, which is shipped here, but it is absent from its source" % gid))
            else:
                issuer_only_absent.append(gid)
        elif state.get(gid) == 'present-issuer' and gid in src_gates and not any(
                r.startswith('cloud/issuer/') for r in src_gates[gid]):
            fails.append(('N2', "Boundary declares `%s` as PAIL-Issuer-only, but it is declared outside cloud/issuer/ (%s)"
                          % (gid, ', '.join(sorted(src_gates[gid])[:2]))))
    if issuer_only_absent:
        print("N2: PAIL-Issuer bundle not in this tree — %d gate(s) declared only there are absent as documented: %s"
              % (len(issuer_only_absent), ', '.join(issuer_only_absent)))

    # --- 위협 모델 파싱 --------------------------------------------------------
    tab = classify(doc)
    decl = {}
    for kind in ('attacker', 'asset', 'surface'):
        start, rows = tab[kind]
        ids = []
        for row in rows:
            i = cell_id(kind, row[0], 'N7', fails, '%s 표' % kind)
            if i:
                ids.append(i)
        if len(ids) < FLOOR[kind]:
            die("%s table has only %d rows (minimum %d)" % (kind, len(ids), FLOOR[kind]))
        if len(set(ids)) != len(ids):
            fails.append(('N7', "Duplicate ID in %s table" % kind))
        decl[kind] = set(ids)

    matrix = {}
    for row in tab['threat'][1]:
        tid = cell_id('threat', row[0], 'N8', fails, '위협 행렬')
        if not tid or len(row) < 5:
            continue
        trip = []
        for kind, idx in (('attacker', 1), ('asset', 2), ('surface', 3)):
            trip.append(cell_id(kind, row[idx], 'N8', fails, '위협 행렬 %s' % tid))
        matrix[tid] = (tuple(trip), row[4].strip())
    if len(matrix) < FLOOR['threat']:
        die("Only %d threat-matrix rows read (minimum %d)" % (len(matrix), FLOOR['threat']))

    blocks = threat_blocks(doc)
    dele_tab = {}
    for row in tab['delegation'][1]:
        did = cell_id('delegation', row[0], 'N6', fails, '위임 표')
        if not did or len(row) < 4:
            continue
        dele_tab[did] = (row[1].strip(),
                         [m.group(1) for m in BACKTICK.finditer(row[2])],
                         set(m.group(1) for m in BACKTICK.finditer(row[3])))
    if len(dele_tab) < FLOOR['delegation']:
        die("Only %d delegation rows read (minimum %d)" % (len(dele_tab), FLOOR['delegation']))

    # --- N8: 행렬 == 상세 ------------------------------------------------------
    if set(matrix) != set(blocks):
        fails.append(('N8', "Threat sets differ: only matrix %s / only detailed sections %s"
                      % (sorted(set(matrix) - set(blocks)) or "none",
                         sorted(set(blocks) - set(matrix)) or "none")))
    for tid in sorted(set(matrix) & set(blocks)):
        sentence, body = blocks[tid]
        trip, msent = matrix[tid]
        if sentence != msent:
            fails.append(('N8', "%s text differs between matrix and details: matrix %r / details %r" % (tid, msent[:50], sentence[:50])))
        got = tuple(m.group(1) for m in BOLD_ID.finditer(body.split('\n\n')[0]
                                                         if body else ''))
        if got != trip:
            fails.append(('N8', "%s triple differs between matrix and details: matrix %s / details %s" % (tid, list(trip), list(got))))

    # --- N3·N4: 상세가 인용한 게이트 -------------------------------------------
    cited_gates, cited_dele, gate_cite_n = {}, {}, 0
    for tid in sorted(blocks):
        gates, dele = block_refs(blocks[tid][1])
        if gates:
            gate_cite_n += 1
        for gid, desc in gates.items():
            cited_gates.setdefault(gid, set()).add(tid)
            cited_gates.setdefault('#desc:' + gid, set()).add(unpipe(desc))
        for did, desc in dele.items():
            cited_dele.setdefault(did, set()).add(tid)
            cited_dele.setdefault('#desc:' + did, set()).add(desc)
    if gate_cite_n < FLOOR['gate_cited']:
        die("Only %d threats cite gates (minimum %d); missing citations cannot establish agreement"
            % (gate_cite_n, FLOOR['gate_cited']))

    # 게이트마다 한 번씩 판정한다. 인용한 위협마다 세면 한 결함이 여러 칸으로
    # 도착해 「몇 건을 고쳐야 하는가」가 인용 횟수로 부풀어 오른다.
    for gid in sorted(k for k in cited_gates if not k.startswith('#desc:')):
        if gid not in src_gates:
            fails.append(('N3', "Threat model cites `%s`, absent from distributed source (%s)"
                          % (gid, ' '.join(sorted(cited_gates[gid])))))
        if gid not in tb_gate:
            fails.append(('N4', "Threat model cites `%s`, absent from boundary gate table" % gid))
            continue
        for got in sorted(cited_gates['#desc:' + gid]):
            fails.extend(gate_desc_fail(gid, got, tb_gate[gid][0], tb_gate[gid][1]))

    # --- N5·N6: 위임 -----------------------------------------------------------
    tb_dele = set(m.group(1) for m in DEL_HEAD.finditer(tb))
    tb_to = {}
    for m in DEL_HEAD.finditer(tb):
        nxt = DELEGATED_TO.search(tb, m.end())
        if nxt:
            tb_to[m.group(1)] = nxt.group(1).strip()
    if not tb_dele:
        die("No delegation headings read from boundary document")

    for did in sorted(set(dele_tab) | set(k for k in cited_dele
                                          if not k.startswith('#desc:'))):
        if did not in tb_dele:
            fails.append(('N5', "Threat model cites `%s`, but the boundary has no corresponding delegation heading" % did))
            continue
        want = tb_to.get(did)
        if want is None:
            fails.append(('N5', "Cannot read delegated party from boundary entry `%s`" % did))
            continue
        seen = set()
        if did in dele_tab:
            seen.add(dele_tab[did][0])
        seen |= cited_dele.get('#desc:' + did, set())
        for got in sorted(seen):
            if got != want:
                fails.append(('N5', "Delegated party for `%s` differs: threat model %r / boundary %r" % (did, got[:50], want[:50])))

    for did in sorted(tb_dele - set(dele_tab)):
        fails.append(('N6', "Boundary declares delegation `%s` absent from the delegation table; threat model is incomplete" % did))

    # --- N7: 유령과 고아 -------------------------------------------------------
    used = {'attacker': set(), 'asset': set(), 'surface': set()}
    for trip, _s in matrix.values():
        for kind, val in zip(('attacker', 'asset', 'surface'), trip):
            if val:
                used[kind].add(val)
    for _to, atk, _cb in dele_tab.values():
        used['attacker'] |= set(atk)
    for kind in ('attacker', 'asset', 'surface'):
        for i in sorted(used[kind] - decl[kind]):
            fails.append(('N7', "`%s` is used but not declared in table %s" % (i, kind)))
        for i in sorted(decl[kind] - used[kind]):
            fails.append(('N7', "`%s` is declared in table %s but never used" % (i, kind)))

    # --- N9: 「인용한 곳」 열 ---------------------------------------------------
    for did in sorted(dele_tab):
        _to, atk, cby = dele_tab[did]
        if not atk:
            fails.append(('N9', "`%s` has no stated assumed attacker" % did))
        real = cited_dele.get(did, set())
        if cby != real:
            fails.append(('N9', "`%s` citation locations differ: table %s / details %s" % (did, sorted(cby), sorted(real))))

    # --- N10: 선언한 개수 == 걷은 개수 ------------------------------------------
    counted = {'attacker': len(decl['attacker']), 'asset': len(decl['asset']),
               'surface': len(decl['surface']), 'threat': len(matrix),
               'delegation': len(dele_tab)}
    for kind in TABLE_KINDS:
        ns, txt = announced(doc, tab[kind][0])
        if len(ns) != 1:
            fails.append(('N10', "Cannot read a unique count before %s table (%d integers): %r" % (kind, len(ns), txt)))
        elif ns[0] != counted[kind]:
            fails.append(('N10', "%s table has %d rows, but the preceding paragraph declares %d"
                          % (kind, counted[kind], ns[0])))

    # --- N11: 한국어판 ---------------------------------------------------------
    ko_tab = classify(ko)
    for kind in ('attacker', 'asset', 'surface'):
        kf = []
        ids = set()
        for row in ko_tab[kind][1]:
            i = cell_id(kind, row[0], 'N11', kf, '한국어판 %s 표' % kind)
            if i:
                ids.add(i)
        fails.extend(kf)
        if ids != decl[kind]:
            fails.append(('N11', "Korean %s ID set differs: only canonical %s / only translated %s"
                          % (kind, sorted(decl[kind] - ids) or "none",
                             sorted(ids - decl[kind]) or "none")))
    ko_matrix = {}
    for row in ko_tab['threat'][1]:
        tid = cell_id('threat', row[0], 'N11', fails, '한국어판 위협 행렬')
        if tid and len(row) >= 4:
            ko_matrix[tid] = tuple(
                (BACKTICK.match(row[i]).group(1) if BACKTICK.match(row[i]) else None)
                for i in (1, 2, 3))
    if set(ko_matrix) != set(matrix):
        fails.append(('N11', "Korean threat set differs from canonical set"))
    for tid in sorted(set(ko_matrix) & set(matrix)):
        if ko_matrix[tid] != matrix[tid][0]:
            fails.append(('N11', "%s triple differs: canonical %s / translated %s"
                          % (tid, list(matrix[tid][0]), list(ko_matrix[tid]))))
    ko_blocks = threat_blocks(ko)
    if set(ko_blocks) != set(blocks):
        fails.append(('N11', "Korean detailed-threat set differs from canonical set"))
    for tid in sorted(set(ko_blocks) & set(blocks)):
        kg, kd = block_refs(ko_blocks[tid][1])
        eg, ed = block_refs(blocks[tid][1])
        if set(kg) != set(eg):
            fails.append(('N11', "%s cited gates differ: canonical %s / translated %s" % (tid, sorted(eg), sorted(kg))))
        if set(kd) != set(ed):
            fails.append(('N11', "%s cited delegations differ: canonical %s / translated %s" % (tid, sorted(ed), sorted(kd))))
    ko_dele = set()
    for row in ko_tab['delegation'][1]:
        did = cell_id('delegation', row[0], 'N11', fails, '한국어판 위임 표')
        if did:
            ko_dele.add(did)
    if ko_dele != set(dele_tab):
        fails.append(('N11', "Korean delegation set differs from canonical set"))
    for kind in TABLE_KINDS:
        ns, txt = announced(ko, ko_tab[kind][0])
        if len(ns) != 1:
            fails.append(('N11', "Cannot read a unique count before Korean %s table (%d integers): %r" % (kind, len(ns), txt)))
        elif ns[0] != counted[kind]:
            fails.append(('N11', "Korean paragraph before %s table declares %d (actual %d)"
                          % (kind, ns[0], counted[kind])))

    sys.stdout.write(
        'layout %s · shipped sources %d · source gates %d · documented gates %d · threats %d · '
        'delegations %d · cited gates %d\n'
        % (layout, len(files), len(src_gates), len(tb_gate), len(matrix),
           len(dele_tab),
           len([k for k in cited_gates if not k.startswith('#desc:')])))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-THREAT-MODEL: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), 0, 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
