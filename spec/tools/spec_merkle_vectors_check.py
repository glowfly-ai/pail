#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""BT-1c — `spec/MERKLE_VECTORS.md` 를 동결된 RFC 6962 기지답 세트에 핀한다.

이 검사기가 겨누는 실패는 BT-1b 가 실제로 안고 있던 것이고, 주장이 아니라 실측이다
(2026-08-30). `spec/proof-vectors/` 의 열여덟 벡터는 전부 트리 크기 1·2·4 에 산다 —
전부 2의 거듭제곱이다. 그래서 포함증명 검증기에서 **경계 접기 루프를 통째로 지워도**,
일관성증명 검증기에서 **비-거듭제곱 씨앗 선택을 무너뜨려도**, 열여덟 칸이 전건 초록이다.
제3자는 비-거듭제곱 트리에서 전부 틀리는 검증기를 만들어 우리가 공개한 모든 것을 통과할
수 있다. 산술이 옳은 채로 사는 결함이 아니라 **산술이 한 번도 돌지 않는** 결함이다.

그래서 이 세트는 크기 0..9 전수다. 루트 10 · 포함증명 45 · 일관성증명 36.

RFC 6962 는 이 파일이 **직접** 구현한다. 벡터를 만들어 낸 쪽(Go 생성기)은 재귀 정의
(MTH/PATH/SUBPROOF)로 조립하고, 여기서는 검증 알고리즘(§2.1.1/§2.1.2)으로 되짚는다.
서로 다른 두 구현이 같은 답을 내는 것은 증거이고, 한 라이브러리가 자기와 같은 답을 내는
것은 항등식이다 (implementation contract 의 canon 사본 규칙과 같다).

  K1   세트가 실재하고 `MANIFEST.sha256` 등재 == 디렉터리 실물 (양방향), 파일별 해시
  K2   `set_sha256` 재계산 == 매니페스트 == 문서
  K3   §2 해시 원시 — 문서가 적은 접두어 바이트로 재유도한 값이 핀·동결 바이트와 같다
  K4   §3 코퍼스 규칙 — `leaves.json` 전건을 문서의 규칙만으로 재유도
  K5   §4 MTH — `roots.json` 전건 재유도, 크기 0..max 빠짐없이
  K6   §5 포함증명 전건 — **자체 유도한** 루트에 대해 검증 (실린 `root` 칸이 아니다)
  K7   §6 일관성증명 전건 — 두 루트를 모두 자체 유도한 루트에 대조
  K8   §8 커버리지 수 == 계측 실측 (어느 가지가 실제로 돌았는가)
  K9   §7 파일·필드 표 == 동결 JSON 의 실제 키와 자료형 (양방향)
  K10  §5/§6 인용 샘플 == 동결 케이스
  K11  §9 경계 — `canon_set_sha256` == 실린 canon 매니페스트, 그리고 두 값이 다르다
  K12  §3 어휘 == 생성기 소스 상수 (내부 전용)
  K13  §11 의 주장 — BT-1b 검사기가 품은 기지답 상수가 이 세트의 동결 바이트와 같다
  K14  한국어판이 같은 어휘를 가르치고 같은 샘플을 싣는다

K6 이 실린 `root` 칸과 대조하지 않는 것은 형식이 아니라 §5 의 규칙이다 — 건네받은 수와
대조하는 것은 검증이 아니다. K8 이 계수를 세는 것도 장식이 아니다. 아무도 재지 않는
커버리지 주장은 시간이 지나면 거짓인 커버리지 주장이 된다.

K13 은 이 문서가 §11 에서 다른 검사기에 대해 하는 주장을 잰다. BT-1b 검사기는 자기
벡터가 거듭제곱뿐이라 자기 산술을 증명할 수 없으므로 이 세트에서 뽑은 기지답을 품는데,
품은 상수는 조용히 낡는다. 두 규격을 런타임으로 엮는 대신 **핀을 이쪽이 진다.**

rc: 0 = FAIL 0, 1 = FAIL 있음, 2 = 검사기가 자기 전제를 세우지 못함.
"""

import ast
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

# (배치 이름, 스크립트 자리 꼬리, 영문 정본, 한국어판, 벡터 뿌리, canon 매니페스트,
#  BT-1b 검사기)
LAYOUTS = (
    ('internal', ('scripts',),
     'oss/spec/MERKLE_VECTORS.md', 'oss/spec/MERKLE_VECTORS.ko.md',
     'oss/spec/vectors/merkle', 'tests/golden/canon/MANIFEST.sha256',
     'scripts/spec_verification_inputs_check.py'),
    ('public', ('spec', 'tools'),
     'spec/MERKLE_VECTORS.md', 'spec/MERKLE_VECTORS.ko.md',
     'spec/merkle-vectors', 'spec/vectors/canon/MANIFEST.sha256',
     'spec/tools/spec_verification_inputs_check.py'),
)

# 생성기. 공개 스냅숏에 실리지 않는다 — K12 는 거기서 건너뛰었다고 인쇄한다.
S_GEN = 'asvs/cmd/genmerklevec/main.go'

FILES = ('leaves.json', 'roots.json', 'inclusion.json', 'consistency.json')
MANIFEST = 'MANIFEST.sha256'

VOCAB_RE = re.compile(r'^<!--[ \t]*vocab:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
SAMPLE_RE = re.compile(r'^<!--[ \t]*sample:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
FENCE_RE = re.compile(r'^```[a-zA-Z0-9]*\n(.*?)^```[ \t]*$', re.M | re.S)
BT_RE = re.compile(r'^`([^`]+)`$')
HEX32_RE = re.compile(r'^[0-9a-f]{64}$')

VOCABS = ('hash', 'corpus', 'file', 'leaf_field', 'root_field',
          'inclusion_field', 'consistency_field', 'coverage', 'claim')
SAMPLES = ('inclusion', 'consistency')

FAILS = []
SKIPS = []


def die(msg):
    # 전제 실패만 인쇄하면 「무엇이 빠졌는지」의 칸이 영원히 안 보인다 (AC-1 의 교훈).
    for code, m in FAILS:
        sys.stdout.write('[FAIL] %s %s\n' % (code, m))
    sys.stdout.write("SPEC-MERKLE-VECTORS: prerequisite failure — %s\n" % msg)
    raise SystemExit(2)


def skip(code, why):
    SKIPS.append((code, why))


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
    for name, tail, doc, ko, vdir, canon, vichk in LAYOUTS:
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            j = lambda p: os.path.join(root, *p.split('/'))
            hit.append((name, root, j(doc), j(ko), j(vdir), j(canon), j(vichk)))
    if len(hit) != 1:
        die("Cannot determine layout (%d matches); script location: %s" % (len(hit), here))
    return hit[0]


# ── 독립 RFC 6962 ───────────────────────────────────────────────────────────
def leaf_hash(data):
    return hashlib.sha256(b'\x00' + data).digest()


def node_hash(left, right):
    return hashlib.sha256(b'\x01' + left + right).digest()


def empty_root():
    return hashlib.sha256(b'').digest()


def k_split(n):
    """RFC 6962 의 k — n 보다 **엄격히** 작은 가장 큰 2의 거듭제곱 (n > 1)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def mth(leaves):
    """MTH(D[n]). 정의 그대로 — 생성기와 별개로 이 파일이 적은 구현이다."""
    n = len(leaves)
    if n == 0:
        return empty_root()
    if n == 1:
        return leaf_hash(leaves[0])
    k = k_split(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def verify_inclusion(index, size, lh, proof, trace):
    """RFC 6962 §2.1.1. 루트를 유도만 한다 — 대조는 부르는 쪽 몫이다 (§5).

    `trace['border']` 는 경계 접기 루프가 **실제로 돌았는지**를 적는다. K8 이 그것을
    센다. 어느 가지가 돌았는지를 재지 않으면 커버리지 주장은 문장일 뿐이다."""
    trace['border'] = False
    if size == 0 or index >= size:
        return None
    fn, sn, r = index, size - 1, lh
    for p in proof:
        if sn == 0:
            return None
        if (fn & 1) or fn == sn:
            r = node_hash(p, r)
            while fn != 0 and (fn & 1) == 0:
                trace['border'] = True
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def _inner_border(index, size):
    inner = (index ^ (size - 1)).bit_length()
    return inner, bin(index >> inner).count('1')


def _chain_inner(seed, proof, index):
    for i, h in enumerate(proof):
        seed = node_hash(h, seed) if (index >> i) & 1 else node_hash(seed, h)
    return seed


def _chain_inner_right(seed, proof, index):
    for i, h in enumerate(proof):
        if (index >> i) & 1:
            seed = node_hash(h, seed)
    return seed


def _chain_border_right(seed, proof):
    for h in proof:
        seed = node_hash(h, seed)
    return seed


def verify_consistency(size1, size2, proof, root1, trace):
    """RFC 6962 §2.1.2. 반환 (유도한 root@size1, 유도한 root@size2).

    둘 다 부르는 쪽이 대조한다 (§6). `trace['seed_from_proof']` 는 씨앗을 `proof[0]`
    에서 가져왔는지 — 즉 비-거듭제곱 가지를 탔는지 — 를 적는다."""
    trace['seed_from_proof'] = False
    if size1 == 0 or size2 < size1:
        return None, None
    if size1 == size2:
        return (root1, root1) if not proof else (None, None)
    if not proof:
        return None, None
    inner, border = _inner_border(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift
    if size1 == (1 << shift):
        seed, start = root1, 0
    else:
        trace['seed_from_proof'] = True
        seed, start = proof[0], 1
    if len(proof) != start + inner + border:
        return None, None
    p = proof[start:]
    mask = (size1 - 1) >> shift
    h1 = _chain_border_right(_chain_inner_right(seed, p[:inner], mask), p[inner:])
    h2 = _chain_border_right(_chain_inner(seed, p[:inner], mask), p[inner:])
    return h1, h2


# ── 문서 쪽: 표 읽기 ────────────────────────────────────────────────────────
def table_after(doc, pos):
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


def backticked(cell):
    m = BT_RE.match(cell.strip())
    return m.group(1) if m else None


def doc_table(doc, code, pos, name, ncols, fails):
    """첫 칸 -> 나머지 칸(백틱 안 문자열) 튜플. 0행은 "전부 일치" 와 같은 바이트다."""
    out = {}
    for row in table_after(doc, pos):
        key = backticked(row[0])
        if key is None:
            fails.append((code, "First column of table `%s` is not a backtick identifier: %r" % (name, row[0][:40])))
            continue
        if len(row) < ncols + 1:
            fails.append((code, "Table `%s`, row `%s` contains only %d columns" % (name, key, len(row))))
            continue
        vals, bad = [], False
        for i in range(1, ncols + 1):
            v = backticked(row[i])
            if v is None:
                fails.append((code, "Table `%s`, row `%s`, column %d is not a backtick identifier: %r"
                              % (name, key, i, row[i][:40])))
                bad = True
                break
            vals.append(v)
        if not bad:
            if key in out:
                fails.append((code, "Table `%s` contains duplicate row `%s`" % (name, key)))
            out[key] = tuple(vals)
    if not out:
        fails.append((code, "No rows read from table `%s`; an empty comparison cannot establish agreement" % name))
    return out


def as_int(code, what, s, fails):
    if not re.match(r'^\d+$', s):
        fails.append((code, "%s is not an integer: %r" % (what, s[:40])))
        return None
    return int(s)


def compare_sets(code, what, doc_keys, real_keys, fails):
    missing = sorted(set(real_keys) - set(doc_keys))
    phantom = sorted(set(doc_keys) - set(real_keys))
    if missing:
        fails.append((code, "%s — observed but undocumented: %s" % (what, missing)))
    if phantom:
        fails.append((code, "%s — documented but not observed: %s" % (what, phantom)))
    return not missing and not phantom


# ── 자료형 ──────────────────────────────────────────────────────────────────
def type_of(v):
    if isinstance(v, bool):
        return 'bool'
    if isinstance(v, int):
        return 'int'
    if isinstance(v, str):
        return 'hex32' if HEX32_RE.match(v) else 'string'
    if isinstance(v, list):
        inner = {type_of(x) for x in v}
        if not inner:
            return 'hex32[]'      # 빈 배열은 원소 자료형을 말하지 않는다 (§5)
        if inner == {'hex32'}:
            return 'hex32[]'
        return '%s[]' % '|'.join(sorted(inner))
    return type(v).__name__


def main():
    layout, root, doc_path, ko_path, vdir, canon_path, vichk_path = locate()
    internal = layout == 'internal'
    fails = FAILS

    doc = read(doc_path)
    vpos = {m.group(1): m.end() for m in VOCAB_RE.finditer(doc)}
    if set(vpos) != set(VOCABS):
        die("Vocabulary tables differ: documented %s / expected %s" % (sorted(vpos), sorted(VOCABS)))

    # --- K1: 세트 실재 + 등재 대조 -------------------------------------------
    man_path = os.path.join(vdir, MANIFEST)
    if not os.path.isdir(vdir):
        fails.append(('K1', "Vector root is missing: %s" % vdir))
        die("No frozen vectors available as independent derivation inputs")
    on_disk = sorted(n for n in os.listdir(vdir) if n != MANIFEST)
    man = read(man_path)
    listed, set_line = {}, None
    for ln in man.splitlines():
        if ln.startswith('#') or not ln.strip():
            continue
        if ln.startswith('set_sha256'):
            set_line = ln.split()[1] if len(ln.split()) > 1 else None
            continue
        parts = ln.split('  ')
        if len(parts) == 2 and HEX32_RE.match(parts[0]):
            listed[parts[1]] = parts[0]
        else:
            fails.append(('K1', "Cannot parse manifest line: %r" % ln[:60]))
    compare_sets('K1', '매니페스트 등재 대 디렉터리 실물', listed, on_disk, fails)
    if sorted(listed) != sorted(FILES):
        fails.append(('K1', "Registered file list differs from expected: %s" % sorted(listed)))
    raw = {}
    for name in sorted(set(listed) & set(on_disk)):
        b = read(os.path.join(vdir, name), binary=True)
        raw[name] = b
        got = hashlib.sha256(b).hexdigest()
        if got != listed[name]:
            fails.append(('K1', "%s — file hash differs from registry (observed %s)" % (name, got[:16])))

    for name in FILES:
        if name not in raw:
            die("Cannot read %s; derivation input unavailable" % name)

    # --- K2: set_sha256 -------------------------------------------------------
    body = ''.join('%s  %s\n' % (listed[n], n) for n in sorted(listed))
    calc = hashlib.sha256(body.encode('utf-8')).hexdigest()
    if set_line is None:
        fails.append(('K2', "Manifest lacks a `set_sha256` line"))
    elif set_line != calc:
        fails.append(('K2', "Manifest set_sha256 differs: distributed %s / recomputed %s"
                      % (set_line[:16], calc[:16])))
    doc_claim = doc_table(doc, 'K2', vpos['claim'], 'claim', 1, fails)
    doc_set = doc_claim.get('merkle_set_sha256', (None,))[0]
    if doc_set != calc:
        fails.append(('K2', "Documented merkle_set_sha256 differs: documented %s / recomputed %s"
                      % (str(doc_set)[:16], calc[:16])))

    data = {n: json.loads(raw[n].decode('utf-8')) for n in FILES}
    leaves_doc = data['leaves.json']
    roots_doc = data['roots.json']
    incl_cases = data['inclusion.json']['cases']
    cons_cases = data['consistency.json']['cases']

    # --- K3: 해시 원시 --------------------------------------------------------
    doc_hash = doc_table(doc, 'K3', vpos['hash'], 'hash', 2, fails)
    doc_corpus = doc_table(doc, 'K3', vpos['corpus'], 'corpus', 1, fails)
    prefix_of = {}
    for name in ('leaf_hash', 'node_hash', 'empty_root'):
        if name not in doc_hash:
            fails.append(('K3', "Hash table lacks row `%s`" % name))
            continue
        pfx, pinned = doc_hash[name]
        if not HEX32_RE.match(pinned):
            fails.append(('K3', "Pinned `%s` value is not 64-character lowercase hex: %r"
                          % (name, pinned[:40])))
            continue
        if name == 'empty_root':
            if pfx != 'none':
                fails.append(('K3', "The empty_root prefix must be none: %r" % pfx))
            got = hashlib.sha256(b'').hexdigest()
        else:
            m = re.match(r'^0x([0-9a-fA-F]{2})$', pfx)
            if not m:
                fails.append(('K3', "Prefix of `%s` is not in 0xNN format: %r" % (name, pfx)))
                continue
            pb = bytes([int(m.group(1), 16)])
            prefix_of[name] = pb
            l0 = doc_corpus.get('leaf_prefix', ('',))[0] + '0'
            l1 = doc_corpus.get('leaf_prefix', ('',))[0] + '1'
            if name == 'leaf_hash':
                got = hashlib.sha256(pb + l0.encode()).hexdigest()
            else:
                a = hashlib.sha256(prefix_of.get('leaf_hash', b'\x00') + l0.encode()).digest()
                b_ = hashlib.sha256(prefix_of.get('leaf_hash', b'\x00') + l1.encode()).digest()
                got = hashlib.sha256(pb + a + b_).hexdigest()
        if got != pinned:
            fails.append(('K3', "`%s` — documented derivation differs from pin (derived %s / pinned %s)" % (name, got[:16], pinned[:16])))
    # 핀 값은 동결 바이트에도 실재해야 한다 — 문서 안에서만 맞으면 세트와 무관해진다.
    frozen_root = {r.get('size'): r.get('root') for r in roots_doc['roots']}
    for name, where in (('leaf_hash', leaves_doc['leaves'][0].get('leaf_hash')),
                        ('node_hash', frozen_root.get(2)),
                        ('empty_root', frozen_root.get(0))):
        if name in doc_hash and doc_hash[name][1] != where:
            fails.append(('K3', "Pinned `%s` value differs from frozen bytes" % name))

    # --- K4: 코퍼스 규칙 ------------------------------------------------------
    lp = doc_corpus.get('leaf_prefix', (None,))[0]
    max_size = as_int('K4', '`max_size`', doc_corpus.get('max_size', ('',))[0], fails)
    if lp is None:
        fails.append(('K4', "Corpus table lacks a leaf_prefix row"))
    if lp != leaves_doc.get('leaf_prefix'):
        fails.append(('K4', "Documented leaf_prefix differs from leaves.json: documented %r / distributed %r"
                      % (lp, leaves_doc.get('leaf_prefix'))))
    corpus = []
    if lp is not None and max_size is not None:
        rows = leaves_doc['leaves']
        if len(rows) != max_size:
            fails.append(('K4', "leaves.json contains %d leaves; max_size is %d"
                          % (len(rows), max_size)))
        derived_leaves = 0
        for i, row in enumerate(rows):
            want_data = '%s%d' % (lp, i)
            if row.get('index') != i:
                fails.append(('K4', "Leaf %d has index %r" % (i, row.get('index'))))
                continue
            if row.get('data') != want_data:
                fails.append(('K4', "Leaf %d — documented rule yields %r, distributed value is %r"
                              % (i, want_data, row.get('data'))))
                continue
            got = leaf_hash(want_data.encode('utf-8')).hex()
            if got != row.get('leaf_hash'):
                fails.append(('K4', "Leaf %d — re-derived leaf_hash differs from distributed value" % i))
                continue
            corpus.append(want_data.encode('utf-8'))
            derived_leaves += 1
        if derived_leaves != len(rows):
            fails.append(('K4', "Re-derived leaves: %d/%d; incomplete derivation cannot establish conformance" % (derived_leaves, len(rows))))

    if max_size is None or len(corpus) != max_size:
        die("Cannot reconstruct corpus from documented rules; further derivations are not meaningful")

    # --- K5: MTH --------------------------------------------------------------
    my_roots = {n: mth(corpus[:n]) for n in range(0, max_size + 1)}
    listed_roots = {}
    for row in roots_doc['roots']:
        n = row.get('size')
        if not isinstance(n, int):
            fails.append(('K5', "roots.json size is not an integer: %r" % (n,)))
            continue
        if n in listed_roots:
            fails.append(('K5', "Duplicate size=%d in roots.json" % n))
        listed_roots[n] = row.get('root')
    compare_sets('K5', '루트 크기 집합', listed_roots, my_roots, fails)
    rederived = 0
    for n in sorted(set(listed_roots) & set(my_roots)):
        if listed_roots[n] != my_roots[n].hex():
            fails.append(('K5', "root@%d — re-derived value differs from distributed value" % n))
        else:
            rederived += 1
    if rederived != max_size + 1:
        fails.append(('K5', "Re-derived roots: %d/%d" % (rederived, max_size + 1)))

    # --- K6: 포함증명 ---------------------------------------------------------
    want_incl = {(n, m) for n in range(1, max_size + 1) for m in range(n)}
    seen_incl, incl_ok, border_hits, empty_proofs = set(), 0, 0, 0
    for c in incl_cases:
        n, m = c.get('size'), c.get('index')
        key = (n, m)
        if key in seen_incl:
            fails.append(('K6', "Duplicate inclusion proof (size=%r,index=%r)" % key))
        seen_incl.add(key)
        try:
            proof = [bytes.fromhex(h) for h in c['proof']]
            lh = bytes.fromhex(c['leaf_hash'])
        except (KeyError, ValueError, TypeError) as exc:
            fails.append(('K6', "(size=%r,index=%r) — cannot decode hex: %s" % (n, m, exc)))
            continue
        if not proof:
            empty_proofs += 1
        if not isinstance(m, int) or not 0 <= m < len(corpus):
            fails.append(('K6', "(size=%r,index=%r) — index outside corpus range" % (n, m)))
            continue
        if lh != leaf_hash(corpus[m]):
            fails.append(('K6', "(size=%r,index=%r) — distributed leaf_hash differs from corpus" % (n, m)))
            continue
        trace = {}
        got = verify_inclusion(m, n, lh, proof, trace)
        if trace.get('border'):
            border_hits += 1
        if got is None:
            fails.append(('K6', "(size=%d,index=%d) — invalid RFC 6962 proof structure" % (n, m)))
            continue
        if n not in my_roots or got != my_roots[n]:
            fails.append(('K6', "(size=%d,index=%d) — derived root differs from independently computed MTH" % (n, m)))
            continue
        if c.get('root') != my_roots[n].hex():
            fails.append(('K6', "(size=%d,index=%d) — distributed root differs from independently computed MTH"
                          % (n, m)))
            continue
        incl_ok += 1
    compare_sets('K6', '포함증명 (size,index) 집합', seen_incl, want_incl, fails)
    if incl_ok != len(incl_cases):
        fails.append(('K6', "Verified inclusion proofs: %d/%d" % (incl_ok, len(incl_cases))))

    # --- K7: 일관성증명 -------------------------------------------------------
    want_cons = {(a, b) for b in range(2, max_size + 1) for a in range(1, b)}
    seen_cons, cons_ok, seed_hits = set(), 0, 0
    for c in cons_cases:
        n1, n2 = c.get('size1'), c.get('size2')
        key = (n1, n2)
        if key in seen_cons:
            fails.append(('K7', "Duplicate consistency proof (%r->%r)" % key))
        seen_cons.add(key)
        try:
            proof = [bytes.fromhex(h) for h in c['proof']]
        except (KeyError, ValueError, TypeError) as exc:
            fails.append(('K7', "(%r->%r) — cannot decode hex: %s" % (n1, n2, exc)))
            continue
        if n1 not in my_roots or n2 not in my_roots:
            fails.append(('K7', "(%r->%r) — size has no independently derived root" % (n1, n2)))
            continue
        trace = {}
        h1, h2 = verify_consistency(n1, n2, proof, my_roots[n1], trace)
        if trace.get('seed_from_proof'):
            seed_hits += 1
        if h1 is None:
            fails.append(('K7', "(%d->%d) — invalid RFC 6962 proof structure" % (n1, n2)))
            continue
        if h1 != my_roots[n1]:
            fails.append(('K7', "(%d->%d) — derived root@%d differs from independently computed MTH" % (n1, n2, n1)))
            continue
        if h2 != my_roots[n2]:
            fails.append(('K7', "(%d->%d) — derived root@%d differs from independently computed MTH" % (n1, n2, n2)))
            continue
        if c.get('root1') != my_roots[n1].hex() or c.get('root2') != my_roots[n2].hex():
            fails.append(('K7', "(%d->%d) — distributed roots differ from independently computed MTH" % (n1, n2)))
            continue
        cons_ok += 1
    compare_sets('K7', '일관성증명 (size1,size2) 집합', seen_cons, want_cons, fails)
    if cons_ok != len(cons_cases):
        fails.append(('K7', "Verified consistency proofs: %d/%d" % (cons_ok, len(cons_cases))))

    # --- K8: 커버리지 ---------------------------------------------------------
    doc_cov = doc_table(doc, 'K8', vpos['coverage'], 'coverage', 1, fails)
    measured = {
        'roots': len(roots_doc['roots']),
        'inclusion_cases': len(incl_cases),
        'consistency_cases': len(cons_cases),
        'border_fold_cases': border_hits,
        'nonpow2_seed_cases': seed_hits,
        'empty_proof_cases': empty_proofs,
    }
    if compare_sets('K8', '커버리지 항목', doc_cov, measured, fails):
        for name in sorted(measured):
            want = as_int('K8', '`%s`' % name, doc_cov[name][0], fails)
            if want is not None and want != measured[name]:
                fails.append(('K8', "`%s` — documented %d / observed %d" % (name, want, measured[name])))
    for name in ('border_fold_cases', 'nonpow2_seed_cases'):
        if measured[name] == 0:
            fails.append(('K8', "`%s` is zero; required coverage was not exercised" % name))

    # --- K9: 파일·필드 표 -----------------------------------------------------
    doc_file = doc_table(doc, 'K9', vpos['file'], 'file', 2, fails)
    real_file = {
        'leaves.json': ('leaves', len(leaves_doc['leaves'])),
        'roots.json': ('roots', len(roots_doc['roots'])),
        'inclusion.json': ('cases', len(incl_cases)),
        'consistency.json': ('cases', len(cons_cases)),
    }
    if compare_sets('K9', '파일 목록', doc_file, real_file, fails):
        for name in sorted(real_file):
            key, rows = doc_file[name]
            if key != real_file[name][0]:
                fails.append(('K9', "`%s` — array key documented `%s` / observed `%s`"
                              % (name, key, real_file[name][0])))
            got = as_int('K9', '`%s` 의 행 수' % name, rows, fails)
            if got is not None and got != real_file[name][1]:
                fails.append(('K9', "`%s` — row count documented %d / observed %d"
                              % (name, got, real_file[name][1])))

    for vocab, rows in (('leaf_field', leaves_doc['leaves']),
                        ('root_field', roots_doc['roots']),
                        ('inclusion_field', incl_cases),
                        ('consistency_field', cons_cases)):
        dt = doc_table(doc, 'K9', vpos[vocab], vocab, 1, fails)
        real = {}
        for row in rows:
            for k, v in row.items():
                t = type_of(v)
                if real.setdefault(k, t) != t:
                    real[k] = 'mixed(%s,%s)' % (real[k], t)
        if compare_sets('K9', '`%s` 필드' % vocab, dt, real, fails):
            for k in sorted(real):
                if dt[k][0] != real[k]:
                    fails.append(('K9', "`%s`.`%s` — documented `%s` / observed `%s`"
                                  % (vocab, k, dt[k][0], real[k])))

    # --- K10: 인용 샘플 -------------------------------------------------------
    spos = {m.group(1): m.end() for m in SAMPLE_RE.finditer(doc)}
    if set(spos) != set(SAMPLES):
        fails.append(('K10', "Quoted sample list differs: documented %s / expected %s"
                      % (sorted(spos), sorted(SAMPLES))))
    doc_samples = {}
    for name in sorted(set(spos) & set(SAMPLES)):
        fence = FENCE_RE.search(doc, spos[name])
        if not fence:
            fails.append(('K10', "No code block after sample `%s`" % name))
            continue
        try:
            obj = json.loads(fence.group(1))
        except ValueError as exc:
            fails.append(('K10', "Sample `%s` is not JSON: %s" % (name, exc)))
            continue
        doc_samples[name] = obj
        pool = incl_cases if name == 'inclusion' else cons_cases
        if obj not in pool:
            fails.append(('K10', "Sample `%s` is absent from the frozen cases" % name))

    # --- K11: 적합성 경계 -----------------------------------------------------
    canon_set = None
    if not os.path.exists(canon_path):
        fails.append(('K11', "Canon manifest is missing: %s" % canon_path))
    else:
        for ln in read(canon_path).splitlines():
            if ln.startswith('set_sha256'):
                parts = ln.split()
                canon_set = parts[1] if len(parts) > 1 else None
    doc_canon = doc_claim.get('canon_set_sha256', (None,))[0]
    if canon_set is None:
        fails.append(('K11', "Cannot read set_sha256 from canon manifest"))
    elif doc_canon != canon_set:
        fails.append(('K11', "Documented canon_set_sha256 differs: documented %s / distributed %s" % (str(doc_canon)[:16], canon_set[:16])))
    if doc_canon is not None and doc_canon == doc_set:
        fails.append(('K11', "The two set hashes are equal; the documented separation of vector sets no longer holds"))

    # --- K12: 생성기 상수 (내부 전용) -----------------------------------------
    if internal:
        gen_path = os.path.join(root, *S_GEN.split('/'))
        if not os.path.exists(gen_path):
            fails.append(('K12', "Generator source is missing: %s" % S_GEN))
        else:
            src = read(gen_path)
            m = re.search(r'const\s+MaxSize\s*=\s*(\d+)', src)
            if not m:
                fails.append(('K12', "Cannot find generator constant MaxSize"))
            elif int(m.group(1)) != max_size:
                fails.append(('K12', "max_size — documented %d / generator %s"
                              % (max_size, m.group(1))))
            m = re.search(r'const\s+LeafPrefix\s*=\s*"([^"]*)"', src)
            if not m:
                fails.append(('K12', "Cannot find generator constant LeafPrefix"))
            elif m.group(1) != lp:
                fails.append(('K12', "leaf_prefix — documented %r / generator %r" % (lp, m.group(1))))
    else:
        skip('K12', 'Vector generator implementation is not distributed in the public snapshot (section 11)')

    # --- K13: BT-1b 검사기의 기지답 상수 --------------------------------------
    if not os.path.exists(vichk_path):
        fails.append(('K13', "Verification-input checker is missing: %s" % vichk_path))
    else:
        kat = {}
        try:
            tree = ast.parse(read(vichk_path))
        except SyntaxError as exc:
            tree = None
            fails.append(('K13', "Cannot parse verification-input checker: %s" % exc))
        for node in (tree.body if tree else []):
            if not isinstance(node, ast.Assign):
                continue
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in ('KAT_INCLUSION', 'KAT_CONSISTENCY'):
                    try:
                        kat[t.id] = ast.literal_eval(node.value)
                    except ValueError:
                        fails.append(('K13', "`%s` is not a literal" % t.id))
        for want in ('KAT_INCLUSION', 'KAT_CONSISTENCY'):
            if want not in kat:
                fails.append(('K13', "Verification-input checker lacks constant `%s`; documented claim is unsupported" % want))
        ki = kat.get('KAT_INCLUSION')
        if isinstance(ki, dict):
            if ki not in incl_cases:
                fails.append(('K13', "KAT_INCLUSION is not a frozen inclusion proof from this set"))
            else:
                n, m = ki['size'], ki['index']
                if n & (n - 1) == 0:
                    fails.append(('K13', "KAT_INCLUSION size=%d is a power of two; required edge-case coverage is missing" % n))
                trace = {}
                verify_inclusion(m, n, bytes.fromhex(ki['leaf_hash']),
                                 [bytes.fromhex(h) for h in ki['proof']], trace)
                if not trace.get('border'):
                    fails.append(('K13', "KAT_INCLUSION does not exercise the boundary-fold branch"))
        elif ki is not None:
            fails.append(('K13', "KAT_INCLUSION is not a dict"))
        kc = kat.get('KAT_CONSISTENCY')
        if isinstance(kc, dict):
            if kc not in cons_cases:
                fails.append(('K13', "KAT_CONSISTENCY is not a frozen consistency proof from this set"))
            else:
                n1 = kc['size1']
                if n1 & (n1 - 1) == 0:
                    fails.append(('K13', "KAT_CONSISTENCY size1=%d is a power of two; the required seed branch is not exercised" % n1))
        elif kc is not None:
            fails.append(('K13', "KAT_CONSISTENCY is not a dict"))

    # --- K14: 한국어판 --------------------------------------------------------
    ko = read(ko_path)
    ko_v = {m.group(1): m.end() for m in VOCAB_RE.finditer(ko)}
    if set(ko_v) != set(vpos):
        fails.append(('K14', "Korean vocabulary tables differ from canonical tables: canonical %s / Korean %s"
                      % (sorted(vpos), sorted(ko_v))))
    else:
        ncols = {'hash': 2, 'corpus': 1, 'file': 2, 'leaf_field': 1, 'root_field': 1,
                 'inclusion_field': 1, 'consistency_field': 1, 'coverage': 1, 'claim': 1}
        ko_fails = []
        for name in sorted(vpos):
            # 양쪽을 **같은 열 규격**으로 읽는다. 규격을 두 벌 적으면 같은 표가 달라 보인다.
            en = doc_table(doc, 'K14', vpos[name], name, ncols[name], [])
            kv = doc_table(ko, 'K14', ko_v[name], name, ncols[name], ko_fails)
            if set(kv) != set(en):
                fails.append(('K14', "Table `%s` identifiers differ: canonical %s / Korean %s"
                              % (name, sorted(en), sorted(kv))))
            elif kv != en:
                bad = sorted(k for k in kv if kv[k] != en[k])
                fails.append(('K14', "Table `%s` values differ; mismatching rows: %s" % (name, bad)))
        fails.extend(ko_fails)
    ko_s = {m.group(1): m.end() for m in SAMPLE_RE.finditer(ko)}
    if set(ko_s) != set(spos):
        fails.append(('K14', "Korean sample list differs: canonical %s / Korean %s"
                      % (sorted(spos), sorted(ko_s))))
    else:
        for name in sorted(ko_s):
            fence = FENCE_RE.search(ko, ko_s[name])
            if not fence:
                fails.append(('K14', "No code block after Korean sample `%s`" % name))
                continue
            try:
                obj = json.loads(fence.group(1))
            except ValueError as exc:
                fails.append(('K14', "Korean sample `%s` is not JSON: %s" % (name, exc)))
                continue
            if name in doc_samples and obj != doc_samples[name]:
                fails.append(('K14', "Korean sample `%s` differs from canonical sample" % name))

    sys.stdout.write(
        "layout %s · roots %d · inclusion proofs %d/%d · consistency proofs %d/%d · boundary folds %d · non-power-of-two seeds %d · vocabulary tables %d\n"
        % (layout, rederived, incl_ok, len(incl_cases), cons_ok, len(cons_cases),
           border_hits, seed_hits, len(vpos)))
    for code, why in SKIPS:
        sys.stdout.write('[SKIP] %s %s\n' % (code, why))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-MERKLE-VECTORS: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), len(SKIPS), 0, layout))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
