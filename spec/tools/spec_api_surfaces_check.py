#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""AC-1 — `spec/API_SURFACES.md` 의 어휘를 실린 소스와 실린 예제에 핀한다.

네 표면(거부·증거·안전상태·운영자면)은 제3자가 우리 내부를 읽지 않고 붙는 자리다.
그래서 이 문서가 낡으면 증상이 조용하다: 읽은 사람은 우리 쪽이 선언한 적 없는 이름을
쓰고, 돌아오는 것은 거부가 아니라 **아무 일도 일어나지 않음**이다. 손으로 쓴 규격이
`.proto`/`.msg`/`.hpp` 보다 오래 사는 것 — 그것이 이 검사기가 겨누는 실패다.

셋을 함께 잰다:

    문서(표)  ==  실린 소스(선언)  ==  실린 예제(실제로 쓰는 이름)

둘만 재면 어느 쌍이든 함께 틀릴 수 있다. 문서와 예제만 재면 소스가 모르는 어휘를 둘이
합의할 수 있고, 문서와 소스만 재면 예제가 조용히 낡아 「돌려보기」가 깨진다.

  N1   `pin` 이 딸린 인용 블록은 그 파일의 **바이트 부분문자열**이어야 한다
  N2   `pin`·`source`·`example` 이 가리키는 경로는 **공개 트리에 실려야** 한다
       (이 칸이 서면 유도의 정본이 사라져 곧 rc=2 로 이어진다 — 그래서 `die()` 가
        여기까지 모은 위반을 함께 인쇄한다)
  N3   ROS `.msg` 필드 어휘·형 == 메시지 정의
  N4   proto 메시지 필드 어휘·형 == `.proto` 선언
  N5   proto 열거 어휘·번호 == `.proto` 선언
  N6   안전 레벨 표(철자 → 값 → E-STOP 동작) == `ParseSafetyLevel` + `EstopActionFor`
  N7   `EstopAction` 어휘 == `enum class` 선언
  N8   증거 source 등급 == `Evidence.msg` 주석 ∩ `policy.yaml` 등급 (정확히 한 번)
  N9   신뢰 등급 어휘·랭크 == `policy.yaml`
  N10  실린 예제가 쓰는 이름이 전부 문서에 있다 (예제마다 바닥을 둔다)
  N11  한국어판이 같은 어휘를 가르치고 같은 인용을 싣는다

관측점은 **유도의 출처**로 갈랐다 — 한 소스 구성물이 바뀌면 한 칸만 붉는다. N6 과 N7 을
나눈 것이 그 예다: 열거에 값이 하나 늘면 N7 만, 분기 하나가 바뀌면 N6 만 붉는다. 둘을
한 칸에 두면 한쪽이 죽어도 다른 쪽이 가려 준다.

N11 이 있는 이유는 N3~N10 이 영문 정본만 읽기 때문이다. 재지 않는 번역본은 낡는 것이
아니라 **낡은 채로 초록**이다. 인용은 소스가 아니라 정본과 대조한다 — 소스와 대조하면
소스가 바뀌는 날 N1 과 N11 이 함께 붉어 한 결함이 두 칸으로 세어진다.

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
     'oss/spec/API_SURFACES.md', 'oss/spec/API_SURFACES.ko.md', 'oss/PUBLIC_TREE.tsv'),
    ('public', ('spec', 'tools'),
     'spec/API_SURFACES.md', 'spec/API_SURFACES.ko.md', None),
)

PIN_RE = re.compile(r'^<!--[ \t]*pin:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
FENCE_RE = re.compile(r'^```[a-zA-Z0-9]*\n(.*?)^```[ \t]*$', re.M | re.S)
SOURCE_RE = re.compile(r'^<!--[ \t]*source:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
EXAMPLE_RE = re.compile(r'^<!--[ \t]*example:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
VOCAB_RE = re.compile(r'^<!--[ \t]*vocab:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)

# 첫 칸은 백틱 식별자다. `*` 만 예외 — 안전 레벨 표의 else 가지를 가리키는 자리표시자이고,
# 그 가지는 소스에서 fallback `return` 으로 유도된다.
CELL_RE = re.compile(r'^`([A-Za-z_][A-Za-z0-9_]*|\*)`$')
TYPE_CELL_RE = re.compile(r'^`([A-Za-z_][A-Za-z0-9_/]*)`$')

# 문서가 가리키는 공개 경로 (정본 이름은 여기 한 벌만 산다)
P_PAIL = 'sdk/proto/pail.proto'
P_OPER = 'sdk/proto/operator_service.proto'
P_EVID = 'robot/pail_msgs/msg/Evidence.msg'
P_SAFE = 'robot/pail_msgs/msg/SafetyState.msg'
P_STOP = 'robot/pail_msgs/msg/StopRequest.msg'
P_HPP = 'libpail_gate/include/pail_gate/safety_level.hpp'
P_POL = 'config/policy.yaml'
P_OPGO = 'cloud/internal/operator/operator.go'
NEED_SOURCES = (P_PAIL, P_OPER, P_EVID, P_SAFE, P_STOP, P_HPP, P_POL, P_OPGO)

E_FEED = 'e2e/feeders.py'
E_DENY = 'cloud/cmd/fms_denial_example/main.go'
E_CGE1 = 'cloud/cmd/cge1_evidence/main.go'
E_OPCLI = 'cloud/cmd/operator_cli/main.go'
E_SUBMIT = 'sdk/grpc_client_go/cmd/submit_plan/main.go'
NEED_EXAMPLES = (E_FEED, E_DENY, E_CGE1, E_OPCLI, E_SUBMIT)


# 여기까지 모은 위반. `die()` 가 이것을 함께 인쇄하는 이유는 N2 에 있다: 인용·소스·예제가
# 트리에서 빠지면 N2 가 먼저 서고 곧이어 유도의 정본이 없어 전제가 무너진다. 전제 실패만
# 인쇄하면 「무엇이 빠졌는지」가 사라져 N2 는 영원히 인쇄되지 않는 칸이 된다.
FAILS = []


def die(msg):
    for code, m in FAILS:
        sys.stdout.write('[FAIL] %s %s\n' % (code, m))
    sys.stdout.write("SPEC-API-SURFACES: prerequisite failure — %s\n" % msg)
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
    rows, out = 0, {}
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
    """마커 뒤 첫 표를 행 목록으로 돌려준다. 머리행·구분행은 뺀다."""
    rows, started = [], False
    for ln in doc[pos:].splitlines():
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


def doc_cols(doc, code, marker, name, cols, fails):
    """표에서 첫 칸 -> (검사할 칸들의 값) 을 읽는다.

    `cols` 는 (칸번호, 종류) 목록. 종류: 'ident'(백틱 식별자) · 'int'(정수)."""
    out = {}
    for row in table_after(doc, marker):
        m = CELL_RE.match(row[0])
        if not m:
            fails.append((code, "The first column of table `%s` is not a backtick identifier: %r"
                          % (name, row[0][:40])))
            continue
        key, vals, bad = m.group(1), [], False
        for idx, kind in cols:
            if len(row) <= idx:
                fails.append((code, "Table `%s`, row `%s` has no column %d" % (name, key, idx)))
                bad = True
                break
            cell = row[idx].strip()
            if kind == 'ident':
                mm = TYPE_CELL_RE.match(cell)
                if not mm:
                    fails.append((code, "Table `%s`, row `%s`, column %d is not a backtick identifier: %r"
                                  % (name, key, idx, cell[:40])))
                    bad = True
                    break
                vals.append(mm.group(1))
            else:
                if not re.match(r'^\d+$', cell):
                    fails.append((code, "Table `%s`, row `%s`, column %d is not an integer: %r"
                                  % (name, key, idx, cell[:40])))
                    bad = True
                    break
                vals.append(int(cell))
        if not bad:
            out[key] = tuple(vals)
    return out


def compare(code, what, doc_map, src_map, fails):
    """어휘와 값을 **양방향**으로 잰다. 한 방향만 재면 반대쪽이 조용히 낡는다."""
    missing = sorted(set(src_map) - set(doc_map))
    phantom = sorted(set(doc_map) - set(src_map))
    if missing:
        fails.append((code, "%s — present in source but absent from documentation: %s" % (what, missing)))
    if phantom:
        fails.append((code, "%s — documented but absent from source: %s" % (what, phantom)))
    for name in sorted(set(doc_map) & set(src_map)):
        if doc_map[name] != src_map[name]:
            fails.append((code, "%s `%s` — documented %s / source %s"
                          % (what, name, doc_map[name], src_map[name])))


# ── 소스 쪽: 어휘 유도 ──────────────────────────────────────────────────────
def _block(src, header, what):
    m = re.search(r'^' + header + r'\s*\{\n(.*?)^\}', src, re.M | re.S)
    if not m:
        die("Cannot find %s; no comparison target" % what)
    return m.group(1)


def proto_fields(src, name):
    body = _block(src, r'message ' + name, '`%s` 메시지 선언' % name)
    out = {}
    for ln in body.splitlines():
        ln = ln.split('//')[0].strip()
        m = re.match(r'^([A-Za-z_][\w.]*)\s+([a-z_]\w*)\s*=\s*\d+;$', ln)
        if m:
            out[m.group(2)] = (m.group(1),)
    if not out:
        die("No fields read from `%s`; an empty scan cannot establish agreement" % name)
    return out


def proto_enum(src, name):
    body = _block(src, r'enum ' + name, '`%s` 열거 선언' % name)
    out = {}
    for ln in body.splitlines():
        ln = ln.split('//')[0].strip()
        m = re.match(r'^([A-Z][\w]*)\s*=\s*(\d+);$', ln)
        if m:
            out[m.group(1)] = (int(m.group(2)),)
    if not out:
        die("No enum values read from `%s`" % name)
    return out


def msg_fields(text, what):
    out = {}
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith('#'):
            continue
        s = s.split('#')[0].strip()
        m = re.match(r'^([A-Za-z_][\w/]*)\s+([a-z_]\w*)$', s)
        if m:
            out[m.group(2)] = (m.group(1),)
    if not out:
        die("No fields read from %s" % what)
    return out


def cpp_enum(src, name):
    m = re.search(r'enum class ' + name + r'\s*\{([^}]*)\}', src)
    if not m:
        die("Cannot find `enum class %s`" % name)
    vals = [v.strip() for v in m.group(1).split(',') if v.strip()]
    if not vals:
        die("No values read from `enum class %s`" % name)
    return {v: () for v in vals}


def safety_parse_table(src):
    """`ParseSafetyLevel` 에서 (철자 -> 레벨) 을 유도한다. else 가지는 `*`."""
    body = re.search(r'ParseSafetyLevel\(const std::string &s\) \{(.*?)\n\}',
                     src, re.S)
    if not body:
        die("Cannot find the `ParseSafetyLevel` body")
    body = body.group(1)
    out = {sp: lv for sp, lv in
           re.findall(r'if \(s == "([^"]+)"\) return SafetyLevel::(\w+);', body)}
    tail = re.findall(r'^\s*return SafetyLevel::(\w+);', body, re.M)
    if not out or not tail:
        die("Cannot derive recognized spellings or the else branch of `ParseSafetyLevel`")
    out['*'] = tail[-1]
    return out


def estop_map(src):
    body = re.search(r'EstopActionFor\(SafetyLevel l\) \{(.*?)\n\}', src, re.S)
    if not body:
        die("Cannot find the `EstopActionFor` body")
    out = dict(re.findall(
        r'case SafetyLevel::(\w+):\s*return EstopAction::(\w+);', body.group(1)))
    if not out:
        die("No branches read from `EstopActionFor`")
    return out


def policy_trust(text):
    """`trust_classes:` 절에서 (등급 -> 랭크, 소스목록) 을 읽는다 (표준 라이브러리만)."""
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.rstrip() == 'trust_classes:')
    except StopIteration:
        die("`policy.yaml` has no `trust_classes:` section")
    out, cur = {}, None
    for raw in lines[start + 1:]:
        if raw.strip() and not raw.startswith((' ', '\t', '#')):
            break
        ln = raw.split('#')[0].rstrip()
        if not ln.strip():
            continue
        m = re.match(r'^\s+-\s+id:\s*(\S+)$', ln)
        if m:
            cur = m.group(1)
            out[cur] = {'rank': None, 'sources': []}
            continue
        if cur is None:
            continue
        m = re.match(r'^\s+rank:\s*(\d+)$', ln)
        if m:
            out[cur]['rank'] = int(m.group(1))
            continue
        m = re.match(r'^\s+sources:\s*\[([^\]]*)\]$', ln)
        if m:
            out[cur]['sources'] = [s.strip() for s in m.group(1).split(',') if s.strip()]
    if not out:
        die("No entries read from `trust_classes:`")
    for cid, v in out.items():
        if v['rank'] is None:
            die("Cannot read the rank of trust class `%s`; unreadable is not verified" % cid)
    return out


def evidence_sources(text):
    """`Evidence.msg` 의 `source` 주석에서 허용 철자를 읽는다."""
    m = re.search(r'^string source\s+#\s*(\S+)\s*$', text, re.M)
    if not m:
        die("Cannot read allowed source spellings from the `Evidence.msg` source comment")
    out = [s for s in m.group(1).split('|') if s]
    if not out:
        die("The `Evidence.msg` source list is empty")
    return out


def main():
    layout, root, doc_path, ko_path, tree_path = locate()
    doc = read(doc_path)
    pmap = public_map(tree_path)
    fails = FAILS

    # --- N1 / N2: 인용과 경로 -------------------------------------------------
    def ship(target, code, what):
        local, shipped = resolve(target, root, pmap)
        if not shipped:
            fails.append((code, "%s — %s is not distributed in the public tree and cannot be checked by recipients" % (target, what)))
            return None
        if local is None or not os.path.exists(local):
            fails.append((code, "%s — %s does not exist in this layout" % (target, what)))
            return None
        return local

    pins = list(PIN_RE.finditer(doc))
    if not pins:
        die("No documentation pins found; zero comparisons cannot establish quote correctness")
    checked = 0
    doc_pins = []  # (공개경로, 인용문) — N11 의 대조 상대
    for m in pins:
        target = m.group(1)
        fence = FENCE_RE.search(doc, m.end())
        if not fence:
            fails.append(('N1', "%s — no quotation block after the pin" % target))
            continue
        doc_pins.append((target, fence.group(1)))
        local = ship(target, 'N2', '인용 대상')
        if local is None:
            continue
        if fence.group(1) not in read(local):
            head = (fence.group(1).splitlines() or [''])[0]
            fails.append(('N1', "%s — quote is not a byte substring (first line: %s)"
                          % (target, head[:70])))
            continue
        checked += 1

    srcs = {}
    for m in SOURCE_RE.finditer(doc):
        local = ship(m.group(1), 'N2', '소스')
        if local is not None:
            srcs[m.group(1)] = local
    for need in NEED_SOURCES:
        if need not in srcs:
            die("%s is not declared as a source or is not distributed; no vocabulary source" % need)

    exs = {}
    for m in EXAMPLE_RE.finditer(doc):
        local = ship(m.group(1), 'N2', '예제')
        if local is not None:
            exs[m.group(1)] = local
    for need in NEED_EXAMPLES:
        if need not in exs:
            die("%s is not declared as an example or is not distributed; no example comparison" % need)

    # --- 소스에서 유도 --------------------------------------------------------
    pail = read(srcs[P_PAIL])
    oper = read(srcs[P_OPER])
    hpp = read(srcs[P_HPP])
    evid_txt = read(srcs[P_EVID])
    pol = read(srcs[P_POL])

    src_msg = {
        'evidence': msg_fields(evid_txt, '`Evidence.msg`'),
        'safety_state': msg_fields(read(srcs[P_SAFE]), '`SafetyState.msg`'),
        'stop_request': msg_fields(read(srcs[P_STOP]), '`StopRequest.msg`'),
    }
    src_pfield = {
        'denial': proto_fields(pail, 'Denial'),
        'unlock': proto_fields(oper, 'UnlockRequest'),
        'revoke': proto_fields(oper, 'RevokeKeyRequest'),
    }
    src_penum = {
        'disposition': proto_enum(pail, 'Disposition'),
        'severity': proto_enum(pail, 'Severity'),
        'context_event_kind': proto_enum(oper, 'ContextEventKind'),
    }
    parse_tab, estop = safety_parse_table(hpp), estop_map(hpp)
    src_safety_level = {sp: (lv, estop.get(lv, '<대응없음>'))
                        for sp, lv in parse_tab.items()}
    src_estop = cpp_enum(hpp, 'EstopAction')
    trust = policy_trust(pol)
    graded = {}
    for cid, v in sorted(trust.items()):
        for s in v['sources']:
            if s in graded:
                fails.append(('N8', "Evidence source `%s` is graded twice (`%s`, `%s`); no unique grade"
                              % (s, graded[s], cid)))
                continue
            graded[s] = cid
    declared = evidence_sources(evid_txt)
    for s in declared:
        if s not in graded:
            fails.append(('N8', "Evidence source `%s` is declared by the message but ungraded by policy; it is unusable" % s))
    for s in sorted(set(graded) - set(declared)):
        fails.append(('N8', "Policy-graded source `%s` is absent from the message declaration" % s))

    # --- 문서의 표를 한 번만 읽는다 -------------------------------------------
    # 같은 표를 검사마다 다시 읽으면 형식 오류 하나가 여러 칸에서 중복 계상되어
    # FAIL 수가 결함 수를 넘는다. 세는 값이 뜻을 잃으면 판정도 잃는다.
    vpos = {m.group(1): m.end() for m in VOCAB_RE.finditer(doc)}
    want = (set(src_msg) | set(src_pfield) | set(src_penum)
            | {'safety_level', 'estop_action', 'evidence_source', 'trust_class'})
    if set(vpos) != want:
        die("Documented vocabulary tables differ from required tables: documented %s / required %s"
            % (sorted(vpos), sorted(want)))

    ident1 = ((1, 'ident'),)
    int1 = ((1, 'int'),)
    doc_tab = {}
    for name in sorted(set(src_msg) | set(src_pfield)):
        doc_tab[name] = doc_cols(doc, 'N3' if name in src_msg else 'N4',
                                 vpos[name], name, ident1, fails)
    for name in sorted(src_penum):
        doc_tab[name] = doc_cols(doc, 'N5', vpos[name], name, int1, fails)
    doc_tab['safety_level'] = doc_cols(doc, 'N6', vpos['safety_level'],
                                       'safety_level', ((1, 'ident'), (2, 'ident')),
                                       fails)
    doc_tab['estop_action'] = doc_cols(doc, 'N7', vpos['estop_action'],
                                       'estop_action', (), fails)
    doc_tab['evidence_source'] = doc_cols(doc, 'N8', vpos['evidence_source'],
                                          'evidence_source', ident1, fails)
    doc_tab['trust_class'] = doc_cols(doc, 'N9', vpos['trust_class'],
                                      'trust_class', int1, fails)

    # --- N3 ~ N9 --------------------------------------------------------------
    for name in sorted(src_msg):
        compare('N3', '`%s` 필드' % name, doc_tab[name], src_msg[name], fails)
    for name in sorted(src_pfield):
        compare('N4', '`%s` 필드' % name, doc_tab[name], src_pfield[name], fails)
    for name in sorted(src_penum):
        compare('N5', '`%s` 값' % name, doc_tab[name], src_penum[name], fails)
    compare('N6', '안전 레벨', doc_tab['safety_level'], src_safety_level, fails)
    compare('N7', 'E-STOP 동작', doc_tab['estop_action'], src_estop, fails)
    compare('N8', '증거 source 등급',
            doc_tab['evidence_source'], {s: (c,) for s, c in graded.items()}, fails)
    compare('N9', '신뢰 등급',
            doc_tab['trust_class'], {c: (v['rank'],) for c, v in trust.items()}, fails)

    # --- N10: 실린 예제 -------------------------------------------------------
    # 예제마다 **바닥**을 둔다. 0건은 "문서에 없는 이름을 안 쓴다" 와 같은 바이트라
    # 유도가 끊긴 날 이 칸이 저절로 초록이 된다.
    def used(path, rx, floor, what):
        got = set(re.findall(rx, read(exs[path])))
        if len(got) < floor:
            fails.append(('N10', "%s: read %s only %d times; minimum %d (derivation failed)"
                          % (path, what, len(got), floor)))
            return set()
        return got

    for name in sorted(used(E_DENY, r'Disposition_(\w+)', 3, 'disposition 사용')
                       - set(doc_tab['disposition'])):
        fails.append(('N10', "%s uses undocumented disposition `%s`" % (E_DENY, name)))
    for name in sorted(used(E_DENY, r'Severity_(\w+)', 3, 'severity 사용')
                       - set(doc_tab['severity'])):
        fails.append(('N10', "%s uses undocumented severity `%s`" % (E_DENY, name)))
    for name in sorted(used(E_CGE1, r'ContextEventKind_(\w+)', 4, 'context event 사용')
                       - set(doc_tab['context_event_kind'])):
        fails.append(('N10', "%s uses undocumented context event `%s`"
                      % (E_CGE1, name)))

    feed = read(exs[E_FEED])
    m = re.search(r'"--evidence-source"\s*,\s*default="([^"]+)"', feed)
    if not m:
        fails.append(('N10', "Cannot read the default evidence source from %s" % E_FEED))
    elif m.group(1) not in doc_tab['evidence_source']:
        fails.append(('N10', "%s has undocumented default source `%s`" % (E_FEED, m.group(1))))
    m = re.search(r'\.level\s*=\s*"([^"]+)"', feed)
    if not m:
        fails.append(('N10', "Cannot read published safety-level strings from %s" % E_FEED))
    elif m.group(1) not in doc_tab['safety_level']:
        fails.append(('N10', "%s publishes level `%s`, absent from documented spellings; unknown is not safe"
                      % (E_FEED, m.group(1))))

    floor = re.search(r'const MinNonceBytes = (\d+)', read(srcs[P_OPGO]))
    if not floor:
        die("Cannot read the minimum nonce length from `operator.go`")
    ns = [int(n) for n in re.findall(r'nonce\s*=\s*make\(\[\]byte,\s*(\d+)\)',
                                     read(exs[E_OPCLI]))]
    if not ns:
        fails.append(('N10', "Cannot read nonce generation length from %s" % E_OPCLI))
    for n in ns:
        if n < int(floor.group(1)):
            fails.append(('N10', "%s generates a %d-byte nonce, below server minimum %s; this example will be rejected"
                          % (E_OPCLI, n, floor.group(1))))
    sub = read(exs[E_SUBMIT])
    for sym in ('GetDenial(', 'GetRetryForbidden('):
        if sym not in sub:
            fails.append(('N10', "%s does not call `%s`; examples must use structured contracts, not arbitrary prose or zero values"
                          % (E_SUBMIT, sym)))

    # --- N11: 한국어판 --------------------------------------------------------
    ko = read(ko_path)
    ko_pos = {m.group(1): m.end() for m in VOCAB_RE.finditer(ko)}
    if set(ko_pos) != set(vpos):
        fails.append(('N11', "Korean vocabulary tables differ from canonical tables: canonical %s / Korean %s"
                      % (sorted(vpos), sorted(ko_pos))))
    else:
        ko_fails = []  # 번역본의 표 형식 오류는 N11 한 칸으로 접는다
        for name in sorted(vpos):
            kv = doc_cols(ko, 'N11', ko_pos[name], name, (), ko_fails)
            if set(kv) != set(doc_tab[name]):
                fails.append(('N11', "Table `%s` identifiers differ: canonical %s / Korean %s"
                              % (name, sorted(doc_tab[name]), sorted(kv))))
        fails.extend(ko_fails)
    ko_pins = []
    for m in PIN_RE.finditer(ko):
        fence = FENCE_RE.search(ko, m.end())
        if fence:
            ko_pins.append((m.group(1), fence.group(1)))
    # 인용은 소스가 아니라 정본과 대조한다 (위 머리말 참조).
    if ko_pins != doc_pins:
        fails.append(('N11', "Korean quotes differ from canonical quotes: canonical %d / Korean %d; first mismatch: %s"
                      % (len(doc_pins), len(ko_pins),
                         next((a[0] for a, b in zip(doc_pins + [(None, None)],
                                                    ko_pins + [(None, None)])
                               if a != b), '?'))))

    sys.stdout.write(
        "layout %s · quotes %d/%d · sources %d · examples %d · vocabulary tables %d · source grades %d\n"
        % (layout, checked, len(pins), len(srcs), len(exs), len(vpos), len(graded)))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-API-SURFACES: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), 0, 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
