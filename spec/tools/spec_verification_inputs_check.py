#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""BT-1b — `spec/VERIFICATION_INPUTS.md` 를 동결 벡터와 방출자 소스에 핀한다.

이 문서가 겨누는 실패는 BT-1a 가 실제로 안고 있던 것이다: **루트를 유도하는 것은
루트를 검증하는 것이 아니다.** 그 결함은 산술이 옳은 채로 산다 — 그래서 조용하다.
규격서가 그 규칙을 적어 두는 것만으로는 부족하고, 규격서 자신이 낡지 않는다는 것을
따로 재야 한다.

AC-1/AC-4 의 세 꼭짓점(문서 == 실린 소스 == 실린 예제)은 여기 그대로 옮겨오지 못한다.
방출자(앵커 서비스)도 소비자(AV-3 하네스)도 **공개 스냅숏에 실리지 않기** 때문에
「실린 소스」 꼭짓점이 아예 없다. 그 자리를 **채집한 와이어 바이트**로 대신한다:

    문서(표)  ==  동결 벡터(실제 응답 바이트)  ==  방출자 소스(내부에서만)

세 번째 항이 내부 전용이라는 것은 숨기지 않고 §9 에 적었고, 이 검사기도 공개 배치에서
그 칸들을 **건너뛰었다고 인쇄한다**. 조용히 없는 검사는 통과한 검사와 구분되지 않는다.

  V1   `pin-internal` 인용 블록은 그 파일의 **바이트 부분문자열**이어야 한다 (내부)
  V2   동결 벡터가 실재하고 `RESPONSES.tsv` 등재 == 디렉터리 실물 (양방향)
  V3   `inclusion_field` 표 == 방출자 `inclusionResponse` 의 json 태그 (내부)
  V4   `consistency_field` 표 == 방출자 `consistencyResponse` 의 json 태그 (내부)
  V5   소비자(AV-3) 가 읽는 이름 ⊆ 방출자가 내보내는 이름 ∪ 에러 본문의 이름 (내부)
  V6   `reason` 표 == 세 방출 지점의 (사유 → http) 집합 (내부)
  V7   `shadowed` 는 배선이 떠받친다 — 증명 라우트가 전부 미들웨어에 감싸여 있다 (내부)
  V8   동결 샘플의 JSON 키 == 문서 필드 표 (양방향)
  V9   `observed` ⟺ 동결 에러 벡터에 실재, http 까지 (양방향)
  V10  체크포인트 관문 1 — 서명 (독립 ed25519)
  V11  체크포인트 관문 2 — origin (대역 외 상수와 대조)
  V12  노트 문면 규칙 — 본문 3행 · 빈 행 · EM DASH 서명행 · 루트 폭 32
  V13  동결 증명 전건 RFC 6962 재유도 — **인증된** 루트에 대해서만
  V14  `proof_key` 두 철자가 각각 자기 표면에 실재한다
  V15  한국어판이 같은 어휘를 가르치고 같은 인용을 싣는다
  V16  이 파일의 RFC 6962 자체에 대한 기지답 — 동결 벡터가 태우지 못하는 두 가지

V10 과 V11 을 가른 것은 장식이 아니라 BT-1a 의 결론이다(H-B9). 서명은 *우리가 신뢰하는
누군가가 썼다* 를, origin 은 *그리고 이 로그에 대해 썼다* 를 말한다. 한 칸에 두면 한쪽을
죽인 변형이 다른 쪽 뒤에 숨는다. 둘은 서로 다른 입력으로 깨진다 — 서명은 노트 바이트로,
origin 은 **대역 외 상수**로. origin 을 노트에서 읽어 오면 관문 2 는 자기 자신과
대조하는 장식이 된다.

V13 은 V10 이 붉으면 **돌지 않고 건너뛰었다고 인쇄한다.** 인증되지 않은 루트로 증명을
재유도하는 것이 정확히 이 문서가 금지하는 행위이므로, 검사기가 그것을 하면 규격서를
어기면서 규격서를 검사하게 된다.

ed25519 와 RFC 6962 는 이 파일이 **직접** 구현한다. 벡터를 만들어 낸 Go 라이브러리를
불러 쓰면 일치는 증거가 아니라 항등식이다(implementation contract 의 canon 사본 규칙과 같다).

rc: 0 = FAIL 0, 1 = FAIL 있음, 2 = 검사기가 자기 전제를 세우지 못함.
"""

import base64
import hashlib
import json
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
     'oss/spec/VERIFICATION_INPUTS.md', 'oss/spec/VERIFICATION_INPUTS.ko.md',
     'oss/PUBLIC_TREE.tsv'),
    ('public', ('spec', 'tools'),
     'spec/VERIFICATION_INPUTS.md', 'spec/VERIFICATION_INPUTS.ko.md', None),
)

# `pin-internal` 은 `pin` 과 일부러 다른 낱말이다. 가리키는 파일이 공개 스냅숏에 실리지
# 않으므로, 받은 사람이 "실렸어야 할 것이 빠졌다"고 읽으면 안 된다.
PIN_RE = re.compile(r'^<!--[ \t]*pin-internal:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
FENCE_RE = re.compile(r'^```[a-zA-Z0-9]*\n(.*?)^```[ \t]*$', re.M | re.S)
SAMPLE_RE = re.compile(r'^<!--[ \t]*sample:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
VOCAB_RE = re.compile(r'^<!--[ \t]*vocab:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)

CELL_RE = re.compile(r'^`([A-Za-z_][A-Za-z0-9_]*)`$')
TYPE_CELL_RE = re.compile(r'^`([A-Za-z_][A-Za-z0-9_\[\]]*)`$')

# 문서가 가리키는 공개 경로 (정본 이름은 여기 한 벌만 산다)
V_DIR = 'spec/proof-vectors'
V_TSV = V_DIR + '/RESPONSES.tsv'
V_NOTE = V_DIR + '/checkpoint.note'
V_VKEY = V_DIR + '/checkpoint.vkey'

# 내부 전용 유도 소스 (공개 스냅숏에 실리지 않는다)
S_PROOFAPI = 'services/anchor_saas/internal/proofapi/proofapi.go'
S_AUTHMW = 'services/anchor_saas/internal/authmw/authmw.go'
S_TENANTREG = 'services/anchor_saas/internal/tenantreg/tenantreg.go'
S_VERDICT = 'services/anchor_saas/internal/verdict/verdict.go'
S_MAIN = 'services/anchor_saas/cmd/anchor_saas/main.go'
S_AV3 = 'asvs/cmd/av3/main.go'

# 대역 외 입력. 검사 중인 노트에서 읽어 오지 않는다 — 그러면 관문 2 가 자기 자신과
# 대조하는 장식이 된다(§2.2).
WANT_ORIGIN = 'glowfly-anchor-log'

DISPOSITIONS = ('observed', 'shadowed', 'auth_only', 'state_only')

# 아래 두 상수는 이 파일의 RFC 6962 구현에 대한 기지답(known-answer)이다.
#
# 왜 필요한가. 이 검사기가 겨누는 벡터(`spec/proof-vectors/`)는 채집된 실선 바이트라
# 트리 크기가 1·2·4 뿐이다 — 전부 2의 거듭제곱. 그래서 `verify_inclusion` 의 경계 접기
# 루프와 `verify_consistency` 의 비-거듭제곱 씨앗 선택은 **한 번도 돌지 않는다**. 둘 중
# 어느 쪽을 지워도 V13 은 전건 초록이었다(2026-08-30 실측). 벡터가 형식을 핀한다고 해서
# 산술까지 핀하는 것은 아니다.
#
# 값의 출처는 `spec/merkle-vectors/` (BT-1c) 의 동결 세트이고, 그쪽은 다른 구현이
# 만들어 CT 레퍼런스로 교차 검증한 것이다. 런타임으로 그 세트를 읽지 않는 이유는
# 소유권이다 — 이 검사기가 다른 규격의 파일에 의존하면 그 파일이 없는 날 여기가
# 붉는다. 대신 상수가 낡지 않는다는 것은 저쪽이 진다
# (`spec_merkle_vectors_check.py` 의 `K13`).
KAT_INCLUSION = {
    "size": 3,
    "index": 2,
    "leaf_hash": "2a6a2cedd03e2d0037b2ab63727611cdbb58ab60aaee9685aa4b3de9179d75e3",
    "proof": [
        "645388217c67cbb482cba29ef06a913f7ad69cb8a12320174137514bea0cffed"
    ],
    "root": "6df12a6a277a1f96aa471f6568822d77ad0deec81f006f1da093c1399a038175"
}
KAT_CONSISTENCY = {
    "size1": 3,
    "size2": 5,
    "proof": [
        "2a6a2cedd03e2d0037b2ab63727611cdbb58ab60aaee9685aa4b3de9179d75e3",
        "809821060e34c816d7488f0c00f80109b0b43bd26b6deeba0d9734bc43305ccc",
        "645388217c67cbb482cba29ef06a913f7ad69cb8a12320174137514bea0cffed",
        "9333a5dd822b95cc8507a7d095c21b5f2df595e11ca8bb5c8eecc13e34bf81fe"
    ],
    "root1": "6df12a6a277a1f96aa471f6568822d77ad0deec81f006f1da093c1399a038175",
    "root2": "9e060c6832f2babb22ea7ad34e718e9fa90b217861d709badd96f6c1c73315b2"
}

# 증명 평면 라우트. V7 은 이 셋이 전부 미들웨어에 감싸여 있는지 본다.
PROOF_ROUTES = ('/v1/checkpoint/', '/v1/proof/inclusion/', '/v1/proof/consistency/')

HTTP_NAME = {
    'OK': 200, 'BadRequest': 400, 'Unauthorized': 401, 'Forbidden': 403,
    'NotFound': 404, 'MethodNotAllowed': 405, 'UnprocessableEntity': 422,
    'ServiceUnavailable': 503,
}

GO_TYPE = {'string': 'string', 'uint64': 'uint64', '[]string': 'string[]'}

# 여기까지 모은 위반. `die()` 가 이것을 함께 인쇄하는 이유는 V2 에 있다: 벡터가
# 트리에서 빠지면 V2 가 먼저 서고 곧이어 유도의 정본이 없어 전제가 무너진다. 전제
# 실패만 인쇄하면 「무엇이 빠졌는지」가 사라져 V2 는 영원히 인쇄되지 않는 칸이 된다.
FAILS = []
SKIPS = []


def die(msg):
    for code, m in FAILS:
        sys.stdout.write('[FAIL] %s %s\n' % (code, m))
    sys.stdout.write("SPEC-VERIFICATION-INPUTS: prerequisite failure — %s\n" % msg)
    raise SystemExit(2)


def read(path, binary=False):
    try:
        with open(path, 'rb' if binary else 'r',
                  **({} if binary else {'encoding': 'utf-8'})) as fh:
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

    `cols` 는 (칸번호, 종류) 목록. 종류: 'ident'(백틱 식별자) · 'int'(정수) ·
    'raw'(칸 전문). 'raw' 는 값이 식별자가 아니라 **식**인 표(`sig_element` 의
    `hint_input` 같은)를 위한 것이다 — 식별자 규격을 억지로 씌우면 표가 규격에
    맞추느라 사람이 읽을 수 없는 값을 싣게 된다."""
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
            elif kind == 'raw':
                if not cell:
                    fails.append((code, "Table `%s`, row `%s`, column %d is empty; missing data cannot establish equality" % (name, key, idx)))
                    bad = True
                    break
                vals.append(cell)
            else:
                if not re.match(r'^\d+$', cell):
                    fails.append((code, "Table `%s`, row `%s`, column %d is not an integer: %r"
                                  % (name, key, idx, cell[:40])))
                    bad = True
                    break
                vals.append(int(cell))
        if not bad:
            out[key] = tuple(vals)
    if not out:
        fails.append((code, "No rows read from table `%s`; an empty comparison cannot establish agreement" % name))
    return out


CONCAT = '‖'       # U+2016 DOUBLE VERTICAL LINE — 표 안에서 `|` 를 쓸 수 없다


def eval_concat(expr, env):
    """`a ‖ "lit" ‖ 0xNN` 꼴의 식을 바이트로 계산한다.

    문서의 식을 **읽어서 계산**하기 위한 것이다. 파이썬 쪽에 정답을 적어 두고
    문자열로 맞춰 보면 그 행은 자기 자신과만 일치한다 — 표를 고치고 여기를 함께
    고치면 둘 다 틀린 채로 초록이 된다(생산기와 검증기를 공유하지 않는 것과 같은
    이유). 해석하지 못한 항은 조용히 건너뛰지 않고 None 을 돌려 붉힌다."""
    out = bytearray()
    for term in [t.strip() for t in expr.split(CONCAT)]:
        if not term:
            return None, 'Empty expression term'
        if len(term) >= 2 and term[0] == '"' and term[-1] == '"':
            out += term[1:-1].encode('utf-8')
        elif re.match(r'^0x[0-9a-fA-F]{2}$', term):
            out.append(int(term, 16))
        elif term in env:
            out += env[term]
        else:
            return None, 'Unknown expression term %r' % term
    return bytes(out), None


def v17_sig_input(doc_sig, note, vkey_text, fails, gate1_ok):
    """§2.4 의 여섯 행을 동결 벡터에 대고 재유도한다.

    `gate1_ok` 는 V10 의 판정이다. 서명이 열리지 않는 노트에서는 `sig_message`
    행을 **잴 수 없다** — 어느 구간으로도 열리지 않는 것은 문서가 구간을 잘못
    지목했다는 뜻이 아니라 서명이 깨졌다는 뜻이고, 그것은 이미 V10 이 말한다.
    그대로 붉히면 한 결함이 두 칸을 붉혀 「혼자 붉는가」가 깨진다(H-B9)."""
    want = {'key_encoding', 'key_algid', 'hint_input', 'hint_width',
            'blob_layout', 'sig_message'}
    got = set(doc_sig)
    if got != want:
        fails.append(('V17', "sig_element rows differ: missing %s / unexpected %s"
                      % (sorted(want - got), sorted(got - want))))
        return
    cell = {k: v[0].strip('`').strip() for k, v in doc_sig.items()}

    # 두 번만 자른다. 구분자 `+` 는 본체의 알파벳(base64)에 **속해** 있어서 정당한
    # 키 넷 중 셋가량이 자기 안에 그것을 품는다 — 전부 자르고 세 조각을 요구하면
    # 대부분의 신뢰근을 재료 부족으로 거부한다.
    parts = vkey_text.strip().split('+', 2)
    if len(parts) != 3:
        fails.append(('V17', "vkey does not contain three components; key format cannot be checked"))
        return
    name, hint_hex, key_b64 = parts
    try:
        keyraw = base64.b64decode(key_b64, validate=True)
    except Exception as exc:
        fails.append(('V17', "vkey base64 decoding failed: %s" % exc))
        return
    if not keyraw:
        fails.append(('V17', "vkey body is empty"))
        return
    algid, pubkey = keyraw[:1], keyraw[1:]

    # key_algid — 문서가 적은 알고리즘 식별자가 실린 키의 첫 바이트인가
    if not re.match(r'^0x[0-9a-fA-F]{2}$', cell['key_algid']):
        fails.append(('V17', "key_algid is not in 0xNN format: %r" % cell['key_algid']))
    elif int(cell['key_algid'], 16) != algid[0]:
        fails.append(('V17', "Documented key_algid is 0x%02x; distributed key begins with 0x%02x"
                      % (int(cell['key_algid'], 16), algid[0])))

    # hint_width — 문서가 적은 폭이 키 파일의 16진수 폭인가
    if not re.match(r'^\d+$', cell['hint_width']):
        fails.append(('V17', "hint_width is not an integer: %r" % cell['hint_width']))
        return
    width = int(cell['hint_width'])
    if width * 2 != len(hint_hex):
        fails.append(('V17', "Documented hint_width is %d, but key file hint is %d bytes"
                      % (width, len(hint_hex) // 2)))

    env = {'name': name.encode('utf-8'), 'algid': algid, 'pubkey': pubkey}

    # hint_input — 문서의 식으로 해시를 다시 계산해 키 파일이 선언한 힌트와 대조
    material, err = eval_concat(cell['hint_input'], env)
    if err:
        fails.append(('V17', "Cannot interpret hint_input: %s; documented derivation must be implementable" % err))
    else:
        derived = hashlib.sha256(material).hexdigest()[:width * 2]
        if derived != hint_hex:
            fails.append(('V17', "Derived hint %s differs from key-file hint %s" % (derived, hint_hex)))
        env['hint'] = bytes.fromhex(hint_hex)

    # blob_layout — 서명행 블롭을 문서가 적은 순서대로 쪼갠다
    cut = note.find(b'\n\n')
    if cut < 0:
        fails.append(('V17', "No blank line separating note body and signature"))
        return
    body = note[:cut + 1]
    siglines = [l for l in note[cut + 2:].decode('utf-8', 'replace').split('\n') if l]
    if not siglines:
        fails.append(('V17', "No signature line"))
        return
    f = siglines[0].split(' ')
    if len(f) < 3:
        fails.append(('V17', "Signature line does not contain three components: %r" % siglines[0][:40]))
        return
    try:
        blob = base64.b64decode(f[2], validate=True)
    except Exception as exc:
        fails.append(('V17', "Signature blob base64 decoding failed: %s" % exc))
        return
    layout = [t.strip() for t in cell['blob_layout'].split(CONCAT)]
    if layout != ['hint', 'signature']:
        fails.append(('V17', "blob_layout is not hint concatenated with signature: %r; unsupported layout" % cell['blob_layout']))
    elif len(blob) != width + 64:
        fails.append(('V17', "blob_layout requires %d bytes, but blob has %d bytes"
                      % (width + 64, len(blob))))
    elif 'hint' in env and blob[:width] != env['hint']:
        fails.append(('V17', "The leading %d blob bytes %s differ from key-file hint %s"
                      % (width, blob[:width].hex(), hint_hex)))

    # sig_message — 문서가 지목한 구간으로 서명이 열리고, **다른 구간으로는 열리지
    # 않는지**. 한 방향만 재면 `note` 라고 적어도 초록이다(본문은 파일의 부분이라
    # 둘 다 통과하는 구현을 쓰면 구분되지 않는다).
    spans = {'body': body, 'note': note}
    named = cell['sig_message']
    if named not in spans:
        fails.append(('V17', "sig_message is %r; checker supports interval %s"
                      % (named, sorted(spans))))
    elif not gate1_ok:
        SKIPS.append(('V17', 'sig_message interval cannot be checked after signature failure; V10 reports that failure'))
    elif len(blob) > width:
        sig = blob[width:]
        ok_named = ed25519_verify(pubkey, spans[named], sig)
        others = sorted(k for k in spans if k != named)
        if not ok_named:
            fails.append(('V17', "sig_message specifies `%s`, but the signature does not verify over that interval" % named))
        for other in others:
            if ed25519_verify(pubkey, spans[other], sig):
                fails.append(('V17', "Signature also verifies over `%s`; sig_message `%s` does not distinguish the intended interval" % (other, named)))

    # key_encoding — 문서의 식으로 키 파일을 다시 조립해 바이트로 대조.
    # 두 매크로는 인자 안에 CONCAT 을 품을 수 있어(`base64(algid ‖ pubkey)`) 항으로
    # 쪼개기 전에 통째로 치환한다 — 먼저 쪼개면 매크로가 두 항으로 잘린다.
    env2 = dict(env)
    enc = cell['key_encoding']
    for i, (macro, val) in enumerate((('hex(hint)', hint_hex.encode('ascii')),
                                      ('base64(algid ' + CONCAT + ' pubkey)',
                                       key_b64.encode('ascii')))):
        slot = '\x00%d\x00' % i
        env2[slot] = val
        enc = enc.replace(macro, slot)
    rebuilt, err = eval_concat(enc, env2)
    if err:
        fails.append(('V17', "Cannot interpret key_encoding: %s" % err))
    elif rebuilt != vkey_text.strip().encode('utf-8'):
        fails.append(('V17', "key_encoding constructs %r, unlike distributed key file %r"
                      % (rebuilt[:60], vkey_text.strip()[:60])))


def compare(code, what, doc_map, src_map, fails):
    """어휘와 값을 **양방향**으로 잰다. 한 방향만 재면 반대쪽이 조용히 낡는다."""
    missing = sorted(set(src_map) - set(doc_map))
    phantom = sorted(set(doc_map) - set(src_map))
    if missing:
        fails.append((code, "%s — observed but undocumented: %s" % (what, missing)))
    if phantom:
        fails.append((code, "%s — documented but not observed: %s" % (what, phantom)))
    for name in sorted(set(doc_map) & set(src_map)):
        if doc_map[name] != src_map[name]:
            fails.append((code, "%s `%s` — documented %s / observed %s"
                          % (what, name, doc_map[name], src_map[name])))


# ── 독립 ed25519 (RFC 8032). 서명 검증만 한다. ─────────────────────────────
_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, (_BX * _BY) % _Q)


def _add(p, q_):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q_
    a = (y1 - x1) * (y2 - x2) % _Q
    b = (y1 + x1) * (y2 + x2) % _Q
    c = t1 * 2 * _D * t2 % _Q
    dd = z1 * 2 * z2 % _Q
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _mul(p, e):
    r = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            r = _add(r, p)
        p = _add(p, p)
        e >>= 1
    return r


def _decode_point(s):
    y = int.from_bytes(s, 'little') & ((1 << 255) - 1)
    if y >= _Q:
        return None
    x = _xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = _Q - x
    if (y * y - x * x - 1 - _D * x * x % _Q * y * y) % _Q != 0:
        return None
    return (x, y, 1, x * y % _Q)


def ed25519_verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    a = _decode_point(pub)
    r = _decode_point(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], 'little')
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), 'little') % _L
    x1, y1, z1, _t = _mul(_B, s)
    x2, y2, z2, _u = _add(r, _mul(a, h))
    return (x1 * z2 - x2 * z1) % _Q == 0 and (y1 * z2 - y2 * z1) % _Q == 0


# ── 독립 RFC 6962 ───────────────────────────────────────────────────────────
def leaf_hash(b):
    return hashlib.sha256(b'\x00' + b).digest()


def _node(l, r):
    return hashlib.sha256(b'\x01' + l + r).digest()


def verify_inclusion(index, size, lh, proof):
    """RFC 6962 §2.1.1. 루트를 **유도만** 한다 — 대조는 부르는 쪽 몫이다."""
    if size == 0 or index >= size:
        return None
    fn, sn, r = index, size - 1, lh
    for p in proof:
        if sn == 0:
            return None
        if (fn & 1) or fn == sn:
            r = _node(p, r)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def _decomp(index, size):
    inner = (index ^ (size - 1)).bit_length()
    return inner, bin(index >> inner).count('1')


def _chain_inner(seed, proof, index):
    for i, h in enumerate(proof):
        seed = _node(h, seed) if (index >> i) & 1 else _node(seed, h)
    return seed


def _chain_inner_right(seed, proof, index):
    for i, h in enumerate(proof):
        if (index >> i) & 1:
            seed = _node(h, seed)
    return seed


def _chain_border_right(seed, proof):
    for h in proof:
        seed = _node(h, seed)
    return seed


def verify_consistency(size1, size2, proof, root1):
    """RFC 6962 §2.1.2. `root1` 은 대조 상대가 아니라 **입력**이다 (§5.2).

    반환 (유도한 root@size1, 유도한 root@size2) — 둘 다 부르는 쪽이 대조한다."""
    if size1 == 0 or size2 < size1:
        return None, None
    if size1 == size2:
        return (root1, root1) if not proof else (None, None)
    if not proof:
        return None, None
    inner, border = _decomp(size1 - 1, size2)
    shift = ((size1 & -size1).bit_length() - 1)
    inner -= shift
    if size1 == (1 << shift):
        seed, start = root1, 0
    else:
        seed, start = proof[0], 1
    if len(proof) != start + inner + border:
        return None, None
    p = proof[start:]
    mask = (size1 - 1) >> shift
    h1 = _chain_border_right(_chain_inner_right(seed, p[:inner], mask), p[inner:])
    h2 = _chain_border_right(_chain_inner(seed, p[:inner], mask), p[inner:])
    return h1, h2


# ── 노트 열기 (두 관문) ─────────────────────────────────────────────────────
def parse_vkey(text):
    """`name+keyhash+base64(alg||pubkey)`. base64 에 `+` 가 들어갈 수 있으므로
    앞의 두 개만 쪼갠다."""
    parts = text.strip().split('+', 2)
    if len(parts) != 3:
        return None, None, 'vkey must have three components'
    name, _kh, b64 = parts
    try:
        raw = base64.b64decode(b64)
    except Exception as exc:
        return None, None, 'vkey base64 decoding failed: %s' % exc
    if len(raw) != 33 or raw[0] != 1:
        return None, None, 'vkey must be Ed25519 (alg=1), 33 bytes; got %d bytes' % len(raw)
    return name, raw[1:], None


def split_note(raw):
    """(본문, 서명행목록, 사유). 본문은 서명이 덮는 바이트 그대로다."""
    text = raw.decode('utf-8', 'replace')
    marker = '\n\n'
    cut = text.find(marker)
    if cut < 0:
        return None, None, 'No blank line between note body and signature'
    body = text[:cut + 1]
    sigs = [l for l in text[cut + 2:].split('\n') if l]
    if not sigs:
        return None, None, 'No signature lines'
    return body, sigs, None


def open_note(raw, vkey_text):
    """관문 1(서명)만 통과시킨다. 관문 2(origin)는 부르는 쪽에서 따로 잰다."""
    name, pub, err = parse_vkey(vkey_text)
    if err:
        return None, err
    body, sigs, err = split_note(raw)
    if err:
        return None, err
    msg = body.encode('utf-8')
    for line in sigs:
        if not line.startswith('— '):
            return None, ('Signature line does not start with U+2014 EM DASH: %r'
                          % line[:12])
        rest = line[2:]
        if ' ' not in rest:
            return None, 'Signature line lacks signer name or base64'
        who, b64 = rest.split(' ', 1)
        if who != name:
            continue
        try:
            blob = base64.b64decode(b64)
        except Exception as exc:
            return None, 'Signature base64 decoding failed: %s' % exc
        if len(blob) != 68:
            return None, 'Signature blob must contain 4+64 bytes; got %d' % len(blob)
        if ed25519_verify(pub, msg, blob[4:]):
            return body, None
        return None, 'Signature does not verify under a trusted key (Ed25519 verification failed)'
    return None, 'No signature line for trusted key (%s)' % name


# ── 소스 쪽: 어휘 유도 (내부 배치 전용) ─────────────────────────────────────
def go_struct_tags(src, name, what):
    m = re.search(r'^type ' + name + r' struct \{\n(.*?)^\}', src, re.M | re.S)
    if not m:
        die("Cannot find %s; no comparison target" % what)
    out = {}
    for ln in m.group(1).splitlines():
        mm = re.match(r'^\s*[A-Z]\w*\s+(\S+)\s+`json:"(\w+)"`', ln)
        if mm:
            gt = GO_TYPE.get(mm.group(1))
            if gt is None:
                die("No documentation-type mapping for %s Go type %r"
                    % (what, mm.group(1)))
            out[mm.group(2)] = (gt,)
    if not out:
        die("No fields read from %s; empty scan cannot establish agreement" % what)
    return out


def err_body_fields(src):
    """`writeErr` 가 굽는 에러 본문의 키를 소스에서 읽는다."""
    m = re.search(r'func writeErr\(.*?\n\}', src, re.S)
    if not m:
        die("Cannot find writeErr body")
    keys = set(re.findall(r'"(\w+)":', m.group(0)))
    if not keys:
        die("No error-body keys read from writeErr")
    return keys


def source_reasons(proofapi, authmw, tenantreg):
    """(사유 -> http) 를 세 방출 지점에서 유도한다. 지점마다 바닥을 둔다."""
    out = {}

    def take(pairs, where):
        if not pairs:
            die("No reasons read from %s; empty comparison cannot establish agreement" % where)
        for status, reason in pairs:
            code = HTTP_NAME.get(status)
            if code is None:
                die("No numeric-code mapping for %s http.Status%s" % (where, status))
            prev = out.get(reason)
            if prev is not None and prev != (code,):
                die("Reason `%s` is emitted with two codes (%s / %s); one documented row cannot represent both" % (reason, prev[0], code))
            out[reason] = (code,)

    take(re.findall(r'writeErr\(w, http\.Status(\w+), "(\w+)"\)', proofapi),
         '`proofapi.writeErr`')
    take(re.findall(r'deny\(w, http\.Status(\w+), "(\w+)"\)', authmw),
         '`authmw.deny`')
    take(re.findall(r'w\.WriteHeader\(http\.Status(\w+)\)[^\n]*\n[^\n]*'
                    r'"reason":\s*"(\w+)"', tenantreg),
         '`tenantreg.GateFor`')
    return out


# ── 벡터 쪽 ─────────────────────────────────────────────────────────────────
def read_tsv(path):
    rows, head = [], None
    for ln in read(path).splitlines():
        if not ln.strip():
            continue
        cells = [c.strip() for c in ln.split('\t')]
        if head is None:
            head = cells
            continue
        rows.append(dict(zip(head, cells)))
    if head is None or not rows:
        die("No rows read from RESPONSES.tsv: %s" % path)
    for need in ('name', 'http', 'content_type', 'file'):
        if need in head:
            continue
        die("RESPONSES.tsv lacks column `%s`" % need)
    return rows


def main():
    layout, root, doc_path, ko_path, tree_path = locate()
    doc = read(doc_path)
    pmap = public_map(tree_path)
    fails = FAILS
    internal = layout == 'internal'

    def skip(code, why):
        SKIPS.append((code, why))

    def ship(target, code, what):
        local, shipped = resolve(target, root, pmap)
        if not shipped:
            fails.append((code, "%s — %s is not distributed in the public tree and cannot be checked by recipients" % (target, what)))
            return None
        if local is None or not os.path.exists(local):
            fails.append((code, "%s — %s does not exist in this layout" % (target, what)))
            return None
        return local

    def inside(rel):
        """내부 전용 유도 소스. 공개 배치에서는 없다."""
        p = os.path.join(root, *rel.split('/'))
        return p if os.path.exists(p) else None

    # --- V16: 이 파일의 RFC 6962 자체에 대한 기지답 ----------------------------
    # 겨누는 벡터가 거듭제곱뿐이라 V13 은 아래 두 가지를 태우지 못한다. 상수의 유래와
    # 신선도 책임은 `KAT_INCLUSION` 선언부에 적어 두었다.
    kat_i = KAT_INCLUSION
    got = verify_inclusion(kat_i['index'], kat_i['size'],
                           bytes.fromhex(kat_i['leaf_hash']),
                           [bytes.fromhex(h) for h in kat_i['proof']])
    if got is None or got.hex() != kat_i['root']:
        fails.append(('V16', "Known-answer inclusion proof (size=%d,index=%d) failed; boundary-fold verifier is incorrect" % (kat_i['size'], kat_i['index'])))
    kat_c = KAT_CONSISTENCY
    h1, h2 = verify_consistency(kat_c['size1'], kat_c['size2'],
                                [bytes.fromhex(h) for h in kat_c['proof']],
                                bytes.fromhex(kat_c['root1']))
    if h1 is None or h1.hex() != kat_c['root1'] or h2.hex() != kat_c['root2']:
        fails.append(('V16', "Known-answer consistency proof (%d->%d) failed; non-power-of-two seed selection is incorrect"
                      % (kat_c['size1'], kat_c['size2'])))

    # --- V1: 인용 (내부 전용) -------------------------------------------------
    pins = list(PIN_RE.finditer(doc))
    if not pins:
        die("Document has no pin-internal markers; zero quotes cannot establish agreement")
    doc_pins = []           # (경로, 인용문) — V15 의 대조 상대
    pinned = 0
    for m in pins:
        target = m.group(1)
        fence = FENCE_RE.search(doc, m.end())
        if not fence:
            fails.append(('V1', "%s — no quotation block after the pin" % target))
            continue
        doc_pins.append((target, fence.group(1)))
        if not internal:
            continue
        local = inside({'anchor-checkpoint-implementation': 'asvs/internal/audit/checkpoint.go'}.get(target, target))
        if local is None:
            fails.append(('V1', "%s — quoted target missing from development source layout" % target))
            continue
        if fence.group(1) not in read(local):
            head = (fence.group(1).splitlines() or [''])[0]
            fails.append(('V1', "%s — quote is not a byte substring (first line: %s)"
                          % (target, head.strip()[:60])))
            continue
        pinned += 1
    if not internal:
        skip('V1', 'Producer/consumer source is not distributed in the public snapshot (section 9)')

    # --- V2: 동결 벡터 --------------------------------------------------------
    tsv_path = ship(V_TSV, 'V2', '동결 벡터 등재부')
    if tsv_path is None:
        die("Frozen vectors missing; no independent derivation inputs")
    vdir = os.path.dirname(tsv_path)
    rows = read_tsv(tsv_path)
    listed = {r['file'] for r in rows}
    actual = {n for n in os.listdir(vdir) if n != 'RESPONSES.tsv'}
    vkey_local = ship(V_VKEY, 'V2', '체크포인트 검증자 키')
    if vkey_local:
        actual.discard(os.path.basename(vkey_local))
    for extra in sorted(actual - listed):
        fails.append(('V2', "%s — file exists but is absent from RESPONSES.tsv; unregistered vector" % extra))
    for missing in sorted(listed - actual):
        fails.append(('V2', "%s — listed in RESPONSES.tsv but absent from directory" % missing))
    for name in sorted(m.group(1) for m in SAMPLE_RE.finditer(doc)):
        if ship(name, 'V2', '문서가 인용한 샘플') is None:
            continue
        if os.path.basename(name) not in listed:
            fails.append(('V2', "%s — quoted by documentation but absent from RESPONSES.tsv" % name))

    bodies = {}
    for r in rows:
        p = os.path.join(vdir, r['file'])
        if os.path.exists(p):
            bodies[r['name']] = (r, read(p, binary=True))
        else:
            fails.append(('V2', "%s — registered vector file is missing" % r['file']))

    # --- V3~V7: 방출자 소스 (내부 전용) --------------------------------------
    vpos = {m.group(1): m.end() for m in VOCAB_RE.finditer(doc)}
    for need in ('checkpoint_line', 'inclusion_field', 'consistency_field',
                 'proof_key', 'reason', 'sig_element'):
        if need not in vpos:
            die("Document lacks vocabulary marker `%s`" % need)

    doc_incl = doc_cols(doc, 'V3', vpos['inclusion_field'], 'inclusion_field',
                        ((1, 'ident'),), fails)
    doc_cons = doc_cols(doc, 'V4', vpos['consistency_field'], 'consistency_field',
                        ((1, 'ident'),), fails)
    doc_reason = doc_cols(doc, 'V6', vpos['reason'], 'reason',
                          ((1, 'int'), (2, 'ident')), fails)
    doc_pkey = doc_cols(doc, 'V14', vpos['proof_key'], 'proof_key',
                        ((1, 'ident'),), fails)
    doc_sig = doc_cols(doc, 'V17', vpos['sig_element'], 'sig_element',
                       ((1, 'raw'),), fails)

    for name, (_h, disp) in sorted(doc_reason.items()):
        if disp not in DISPOSITIONS:
            fails.append(('V6', "`%s` disposition `%s` is not one of the four defined values: %s"
                          % (name, disp, list(DISPOSITIONS))))

    src_reasons = None
    if internal:
        pa = inside(S_PROOFAPI)
        aw = inside(S_AUTHMW)
        tr = inside(S_TENANTREG)
        mn = inside(S_MAIN)
        av = inside(S_AV3)
        vd = inside(S_VERDICT)
        for p, rel in ((pa, S_PROOFAPI), (aw, S_AUTHMW), (tr, S_TENANTREG),
                       (mn, S_MAIN), (av, S_AV3), (vd, S_VERDICT)):
            if p is None:
                die("Development-only derivation source is missing: %s" % rel)
        pa_s, aw_s, tr_s = read(pa), read(aw), read(tr)
        mn_s, av_s, vd_s = read(mn), read(av), read(vd)

        compare('V3', '`inclusion_field`', doc_incl,
                go_struct_tags(pa_s, 'inclusionResponse', '`inclusionResponse`'), fails)
        compare('V4', '`consistency_field`', doc_cons,
                go_struct_tags(pa_s, 'consistencyResponse', '`consistencyResponse`'),
                fails)

        emitted = set(go_struct_tags(pa_s, 'inclusionResponse', '`inclusionResponse`'))
        emitted |= set(go_struct_tags(pa_s, 'consistencyResponse',
                                      '`consistencyResponse`'))
        emitted |= err_body_fields(pa_s)
        consumed = set(go_struct_tags(av_s, 'inclusionResp', '`inclusionResp`'))
        consumed |= set(go_struct_tags(av_s, 'consistencyResp', '`consistencyResp`'))
        stray = sorted(consumed - emitted)
        if stray:
            fails.append(('V5', "Consumer reads names not emitted by producer: %s; zero defaults cannot stand in for missing fields" % stray))

        src_reasons = source_reasons(pa_s, aw_s, tr_s)
        compare('V6', '`reason`',
                {k: (v[0],) for k, v in doc_reason.items()}, src_reasons, fails)

        shadowed = sorted(k for k, v in doc_reason.items() if v[1] == 'shadowed')
        if not shadowed:
            fails.append(('V7', "No reasons declared shadowed; required middleware coverage cannot be established"))
        wrapped = 0
        for route in PROOF_ROUTES:
            m = re.search(r'mux\.HandleFunc\("' + re.escape(route) + r'",\s*([^\n]*)',
                          mn_s)
            if not m:
                fails.append(('V7', "Cannot find route registration %s" % route))
                continue
            if 'WrapTenantFor(' not in m.group(1):
                fails.append(('V7', "%s is no longer wrapped by middleware; documented shadowing of %s is unsupported"
                              % (route, shadowed)))
                continue
            wrapped += 1

        if wrapped and wrapped != len(PROOF_ROUTES):
            fails.append(('V7', "There are %d proof routes but only %d are wrapped; partial wiring does not establish global shadowing"
                          % (len(PROOF_ROUTES), wrapped)))

        for key, (surface,) in sorted(doc_pkey.items()):
            hay = pa_s if surface == 'proof_plane' else vd_s
            if ('json:"%s"' % key) not in hay:
                fails.append(('V14', "`%s` is absent from source for surface `%s`" % (key, surface)))
    else:
        # V14 는 여기 없다 — 그 칸은 동결 벡터만으로도 절반이 돌고, 못 보는 절반은
        # 자기 자리에서 따로 적는다. 여기 넣으면 한 칸이 SKIP 두 줄을 낸다.
        for code, why in (('V3', '`inclusionResponse`'), ('V4', '`consistencyResponse`'),
                          ('V5', 'AV-3 consumer structure'), ('V6', 'reason emission sites'),
                          ('V7', 'route registration')):
            skip(code, '%s — not distributed in the public snapshot (section 9)' % why)

    # --- V8: 동결 샘플의 키 == 문서 표 ---------------------------------------
    def sample_keys(name):
        got = bodies.get(name)
        if got is None:
            return None
        try:
            return set(json.loads(got[1]))
        except ValueError as exc:
            fails.append(('V8', "%s — cannot parse JSON: %s" % (name, exc)))
            return None

    checked_samples = 0
    for name, table, code in (('inclusion_size4_idx0', doc_incl, 'V8'),
                              ('inclusion_size4_idx3', doc_incl, 'V8'),
                              ('inclusion_size2_idx0', doc_incl, 'V8'),
                              ('consistency_2_4', doc_cons, 'V8'),
                              ('consistency_1_4', doc_cons, 'V8')):
        keys = sample_keys(name)
        if keys is None:
            continue
        checked_samples += 1
        missing = sorted(keys - set(table))
        phantom = sorted(set(table) - keys)
        if missing:
            fails.append((code, "%s — present in vectors but absent from documentation table: %s" % (name, missing)))
        if phantom:
            fails.append((code, "%s — documented but absent from vectors: %s" % (name, phantom)))
    if checked_samples == 0:
        fails.append(('V8', "No success samples read; empty comparison cannot establish agreement"))

    # --- V9: observed ⟺ 동결 에러 벡터 ---------------------------------------
    seen = {}
    err_fields = set()
    for name, (row, raw) in sorted(bodies.items()):
        if not name.startswith('err_'):
            continue
        try:
            obj = json.loads(raw)
        except ValueError as exc:
            fails.append(('V9', "%s — cannot parse JSON: %s" % (name, exc)))
            continue
        err_fields |= set(obj)
        reason = obj.get('reason')
        if not reason:
            fails.append(('V9', "%s — error body lacks reason field" % name))
            continue
        try:
            http = int(row['http'])
        except ValueError:
            fails.append(('V9', "%s — RESPONSES.tsv HTTP value is not an integer: %r"
                          % (name, row['http'])))
            continue
        prev = seen.get(reason)
        if prev is not None and prev != http:
            fails.append(('V9', "`%s` appears under two HTTP codes in frozen vectors: %d / %d"
                          % (reason, prev, http)))
        seen[reason] = http
    if not seen:
        fails.append(('V9', "No frozen error vectors read; reason coverage cannot be established"))
    declared = {k: v[0] for k, v in doc_reason.items() if v[1] == 'observed'}
    compare('V9', '`observed` 사유', declared, seen, fails)
    for reason, (http, disp) in sorted(doc_reason.items()):
        if disp != 'observed' and reason in seen:
            fails.append(('V9', "`%s` is declared `%s` but exists in frozen vectors; claimed unobservability is incorrect" % (reason, disp)))

    # --- V10 / V11: 두 관문 ---------------------------------------------------
    note_path = ship(V_NOTE, 'V2', '동결 체크포인트 노트')
    body = None
    if note_path is None or vkey_local is None:
        skip('V10', 'Checkpoint note or verification key is unavailable')
        skip('V11', 'Checkpoint note or verification key is unavailable')
    else:
        raw_note = read(note_path, binary=True)
        body, err = open_note(raw_note, read(vkey_local))
        if err:
            fails.append(('V10', "Gate 1 (signature) — %s" % err))
        if body is None:
            skip('V11', 'Signature gate failed; unauthenticated body bytes are not used')
        else:
            declared_origin = body.split('\n', 1)[0]
            if declared_origin != WANT_ORIGIN:
                fails.append(('V11', "Gate 2 (origin) — note origin %r differs from out-of-band origin %r" % (declared_origin, WANT_ORIGIN)))

    # --- V17: §2.4 서명 입력 — 문서의 식을 해석해 동결 벡터에 대고 재유도 --------
    # 이 칸이 없던 동안 §2 는 관문 1 을 `note.Open` 이라는 **이름**으로만 규정했다.
    # 형태(§2.1~2.3)는 다른 언어로도 재현할 수 있었지만 서명은 재현할 수 없었고,
    # 그때 남는 선택지가 §1 이 첫 문장으로 경고한 그 결함이다. V10 이 서명을 확인하기는
    # 했으나 그것은 **이 파일의 구현**을 잰 것이지 문서의 주장을 잰 것이 아니었다 —
    # 문서가 서명에 대해 아무 주장도 하지 않았으므로 대조할 상대가 없었다.
    if note_path is None or vkey_local is None:
        skip('V17', 'Checkpoint note or verification key is unavailable')
    else:
        v17_sig_input(doc_sig, read(note_path, binary=True), read(vkey_local), fails,
                      body is not None)

    # --- V12: 노트 문면 규칙 --------------------------------------------------
    root_hash, tree_size = None, None
    if note_path is None:
        skip('V12', 'Frozen checkpoint note is unavailable')
    else:
        raw_note = read(note_path, binary=True)
        text = raw_note.decode('utf-8', 'replace')
        cut = text.find('\n\n')
        if cut < 0:
            fails.append(('V12', "No blank line separating note body and signature"))
        else:
            lines = text[:cut].split('\n')
            doc_lines = doc_cols(doc, 'V12', vpos['checkpoint_line'],
                                 'checkpoint_line', ((1, 'int'),), fails)
            if len(lines) != len(doc_lines):
                fails.append(('V12', "Body has %d lines; documentation specifies %d"
                              % (len(lines), len(doc_lines))))
            else:
                for nm, (idx,) in sorted(doc_lines.items()):
                    if idx >= len(lines):
                        fails.append(('V12', "`%s` specifies line %d, absent from the body"
                                      % (nm, idx)))
                if 'size' in doc_lines and doc_lines['size'][0] < len(lines):
                    try:
                        tree_size = int(lines[doc_lines['size'][0]].strip())
                    except ValueError:
                        fails.append(('V12', "Size line is not a decimal integer: %r"
                                      % lines[doc_lines['size'][0]][:20]))
                if 'root_b64' in doc_lines and doc_lines['root_b64'][0] < len(lines):
                    cell = lines[doc_lines['root_b64'][0]].strip()
                    try:
                        cand = base64.b64decode(cell, validate=True)
                    except Exception as exc:
                        fails.append(('V12', "Root line is not base64: %s" % exc))
                    else:
                        if len(cand) != hashlib.sha256().digest_size:
                            fails.append(('V12', "Root is %d bytes; a root must be 32 bytes"
                                          % len(cand)))
                        else:
                            root_hash = cand
            for line in (l for l in text[cut + 2:].split('\n') if l):
                if not line.startswith('— '):
                    fails.append(('V12', "Signature line does not start with U+2014 EM DASH: %r"
                                  % line[:12]))

    # --- V13: 동결 증명 재유도 -----------------------------------------------
    if body is None or root_hash is None or tree_size is None:
        skip('V13', 'No authenticated root; refusing to derive proofs against an unauthenticated root (section 1)')
    else:
        roots = {tree_size: root_hash}
        leaves = {}
        derived = 0
        for nm in ('inclusion_size4_idx0', 'inclusion_size4_idx3',
                   'inclusion_size2_idx0'):
            got = bodies.get(nm)
            if got is None:
                fails.append(('V13', "%s — vector missing" % nm))
                continue
            d = json.loads(got[1])
            try:
                leaf = base64.b64decode(d['leaf_b64'], validate=True)
                proof = [base64.b64decode(x, validate=True) for x in d['proof_b64']]
            except Exception as exc:
                fails.append(('V13', "%s — base64 decoding failed: %s" % (nm, exc)))
                continue
            idx, size = d['leaf_index'], d['tree_size']
            leaves[idx] = leaf
            got_root = verify_inclusion(idx, size, leaf_hash(leaf), proof)
            if got_root is None:
                fails.append(('V13', "%s — invalid RFC 6962 proof structure" % nm))
                continue
            derived += 1
            want = roots.get(size)
            if want is None:
                # §5.1 — 과거 크기에서는 서버가 루트를 되울리지 않는다. 여기서 유도한
                # 값은 아직 **증거가 아니다**. V13 은 뒤의 일관성 증명이 이 값을
                # 인증된 루트에 이어 붙일 때에만 증거로 승격시킨다.
                roots[size] = got_root
                if d['root_b64'] != '':
                    fails.append(('V13', "%s — historical tree size %d must not carry a nonempty root_b64" % (nm, size)))
                continue
            if got_root != want:
                fails.append(('V13', "%s — derived root differs from authenticated root" % nm))
            elif d['root_b64'] and base64.b64decode(d['root_b64']) != want:
                fails.append(('V13', "%s — echoed root_b64 differs from authenticated root" % nm))
        if 0 in leaves:
            roots.setdefault(1, leaf_hash(leaves[0]))

        anchored = 0
        for nm in ('consistency_2_4', 'consistency_1_4'):
            got = bodies.get(nm)
            if got is None:
                fails.append(('V13', "%s — vector missing" % nm))
                continue
            d = json.loads(got[1])
            try:
                proof = [base64.b64decode(x, validate=True) for x in d['proof_b64']]
            except Exception as exc:
                fails.append(('V13', "%s — base64 decoding failed: %s" % (nm, exc)))
                continue
            f_, t_ = d['from'], d['to']
            r1 = roots.get(f_)
            if r1 is None:
                fails.append(('V13', "%s — root@%d could not be obtained" % (nm, f_)))
                continue
            h1, h2 = verify_consistency(f_, t_, proof, r1)
            if h1 is None:
                fails.append(('V13', "%s — invalid RFC 6962 proof structure" % nm))
                continue
            if h1 != r1:
                fails.append(('V13', "%s — derived root@%d differs from input" % (nm, f_)))
                continue
            want2 = roots.get(t_)
            if want2 is None:
                fails.append(('V13', "%s — root@%d is not authenticated" % (nm, t_)))
                continue
            if h2 != want2:
                fails.append(('V13', "%s — derived root@%d differs from authenticated root"
                              % (nm, t_)))
                continue
            derived += 1
            if t_ == tree_size:
                anchored += 1
        if derived < 5:
            fails.append(('V13', "Only %d proofs re-derived; insufficient coverage" % derived))
        if anchored == 0:
            fails.append(('V13', "No consistency proof connects directly to an authenticated root; mutual agreement alone is insufficient"))

    # --- V14: 두 철자 ---------------------------------------------------------
    if 'proof_b64' not in doc_pkey:
        fails.append(('V14', "proof_key table lacks proof_b64 row"))
    else:
        hits = sorted(n for n, (_r, b) in bodies.items() if b'"proof_b64"' in b)
        if not hits:
            fails.append(('V14', "proof_b64 occurs in no frozen vector"))
    if not internal:
        skip('V14', 'proof_base64 verdict-bundle source is not distributed (section 9)')

    # --- V15: 한국어판 --------------------------------------------------------
    ko = read(ko_path)
    ko_pos = {m.group(1): m.end() for m in VOCAB_RE.finditer(ko)}
    if set(ko_pos) != set(vpos):
        fails.append(('V15', "Korean vocabulary tables differ from canonical tables: canonical %s / Korean %s"
                      % (sorted(vpos), sorted(ko_pos))))
    else:
        ko_fails = []   # 번역본의 표 형식 오류는 V15 한 칸으로 접는다
        spec = {'checkpoint_line': ((1, 'int'),), 'inclusion_field': ((1, 'ident'),),
                'consistency_field': ((1, 'ident'),), 'proof_key': ((1, 'ident'),),
                'reason': ((1, 'int'), (2, 'ident')), 'sig_element': ((1, 'raw'),)}
        # 양쪽을 **같은 열 규격**으로 읽는다. 규격을 두 벌 적으면 두 표가 같아도
        # 값이 달라 보이고, 그 붉음은 번역본의 결함으로 읽힌다.
        doc_tab = {'checkpoint_line': doc_cols(doc, 'V15', vpos['checkpoint_line'],
                                               'checkpoint_line',
                                               spec['checkpoint_line'], []),
                   'inclusion_field': doc_incl, 'consistency_field': doc_cons,
                   'proof_key': doc_pkey, 'reason': doc_reason,
                   'sig_element': doc_sig}
        for name in sorted(vpos):
            # `spec`/`doc_tab` 은 문서의 표 목록과 나란히 손으로 유지되는 복사본이다.
            # 정본에 표를 하나 더하고 여기를 안 고치면 예전에는 KeyError 로 죽었다 —
            # 죽는 순간 그때까지 모은 FAIL 이 인쇄되지 않으므로, 표 하나를 더한 것이
            # 다른 칸의 결함을 통째로 가렸다. 붉은 줄로 내려서 나머지가 계속 인쇄되게 한다.
            if name not in spec or name not in doc_tab:
                fails.append(('V15', "Table `%s` has no column specification in checker; added table is not being validated" % name))
                continue
            kv = doc_cols(ko, 'V15', ko_pos[name], name, spec[name], ko_fails)
            if set(kv) != set(doc_tab[name]):
                fails.append(('V15', "Table `%s` identifiers differ: canonical %s / Korean %s"
                              % (name, sorted(doc_tab[name]), sorted(kv))))
            elif kv != doc_tab[name]:
                bad = sorted(k for k in kv if kv[k] != doc_tab[name][k])
                fails.append(('V15', "Table `%s` values differ; mismatching rows: %s"
                              % (name, bad)))
        fails.extend(ko_fails)
    ko_pins = []
    for m in PIN_RE.finditer(ko):
        fence = FENCE_RE.search(ko, m.end())
        if fence:
            ko_pins.append((m.group(1), fence.group(1)))
    # 인용은 소스가 아니라 정본과 대조한다 — 소스와 대조하면 소스가 바뀌는 날 V1 과
    # V15 가 함께 붉어 한 결함이 두 칸으로 세어진다.
    if ko_pins != doc_pins:
        fails.append(('V15', "Korean quotes differ from canonical quotes: canonical %d / Korean %d; first mismatch: %s"
                      % (len(doc_pins), len(ko_pins),
                         next((a[0] for a, b in zip(doc_pins + [(None, None)],
                                                    ko_pins + [(None, None)])
                               if a != b), '?'))))

    sys.stdout.write(
        "layout %s · quotes %d/%d · vectors %d · success samples %d · observed reasons %d/%d · vocabulary tables %d\n"
        % (layout, pinned, len(pins), len(rows), checked_samples,
           len(seen), len(doc_reason), len(vpos)))
    for code, why in SKIPS:
        sys.stdout.write('[SKIP] %s %s\n' % (code, why))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-VERIFICATION-INPUTS: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), len(SKIPS), 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
