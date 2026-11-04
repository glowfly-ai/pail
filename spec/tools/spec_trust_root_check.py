#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""BT-1e — `spec/TRUST_ROOT.md` 와 `spec/trust-roots.tsv` 를 공개 트리 전수에 핀한다.

이 검사기가 겨누는 실패는 실측이다 (2026-08-30). BT-1b 가 실어 보낸
`spec/proof-vectors/checkpoint.vkey` 는 그 자체로 형식에 맞는 신뢰근 한 줄이고,
BT-1d 가 실어 보낸 검증기에 그것을 물리면 `checkpoint OK` 에 rc=0 이 나온다 —
개인 절반이 디스크에 쓰인 적 없는 키에 대고 `verified` 가 나온 것이다. 그것이
신뢰근이 아니라는 경고는 다른 문서의 한 절에만 살았고, **파일은 그것을 설명하는
문서를 데리고 여행하지 않는다.**

그래서 처분은 파일마다 주석을 다는 것이 아니라 **전수 목록**이다: 공개 트리에
나타나는 vkey 꼴 바이트 전부가 등재부에 분류돼 실리고, 없는 것이 실리면 붉는다.
목록은 유도로 만든다 — 오늘 쓴 규칙이 내일 추가될 파일을 덮어야 한다.

  T1   등재부가 파싱된다: 여섯 칸, 아는 `kind`, 형식에 맞는 날짜
  T2   모든 `vkey` 가 자기 키해시와 자기 `key_sha256` 을 재유도한다
  T3   공개 트리의 모든 vkey 꼴 바이트에 행이 있다 (**양방향**)
  T4   어떤 `key_sha256` 도 `anchor` 와 `not-anchor` 에 동시에 등재되지 않는다
  T5   행은 단조다: 등재됐던 행이 사라지지 않았다
  T5r  `T5` 를 잴 수 있었는지 자체를 따로 낸 값
  T6   문서의 인용이 등재부의 바이트 부분문자열이다 (en+ko)
  T7   `VERIFICATION_INPUTS.md` 의 전방 참조가 이 문서를 지목한다 (en+ko)
  T8   `anchor` 수를 인쇄하고, 두 판이 선언한 수가 그것과 같다
  T9   §7 표의 식별자 == 이 파일이 구현한 식별자 (양방향)
  T10  한국어판이 같은 두 표를 가르친다

T2 가 `key_sha256` 을 파일에서 읽지 않고 `vkey` 에서 재유도하는 것은 형식이 아니라
규칙이다 — 자기 칸을 자기 칸으로 대조하는 등재부는 무엇을 적든 자기와 일치한다.

T3 이 양방향인 이유는 `not-anchor` 가 **주장**이기 때문이다. 「이 트리에 실리지만
신뢰근이 아니다」라고 적힌 행의 키가 등재부와 이 두 문서 밖 어디에도 없다면, 그
행은 자기가 분류하던 파일보다 오래 산 것이다. 한 방향만 재면 그 표류가 안 보인다.

T5 는 스냅숏에서 잴 수 없다 — 내보낸 사본에는 리비전 정보가 없다. 볼 수 없는
자리에서 조용히 통과하는 단조성 검사는 없는 것보다 나쁘므로(`H-B2`), 세 값을 내고
`T5r` 이 어느 쪽인지 말한다.

rc: 0 = FAIL 0, 1 = FAIL 있음, 2 = 검사기가 자기 전제를 세우지 못함.
"""

import base64
import hashlib
import os
import re
import subprocess
import sys

# Preserve diagnostic text on legacy consoles without changing checked bytes.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="backslashreplace")

HERE = os.path.dirname(os.path.abspath(__file__))

# (배치 이름, 스크립트 자리 꼬리, 영문 정본, 한국어판, 등재부, VI 정본, VI 한국어판,
#  공개 트리 목록 or None)
LAYOUTS = (
    ('internal', ('scripts',),
     'oss/spec/TRUST_ROOT.md', 'oss/spec/TRUST_ROOT.ko.md',
     'oss/spec/trust-roots.tsv',
     'oss/spec/VERIFICATION_INPUTS.md', 'oss/spec/VERIFICATION_INPUTS.ko.md',
     'oss/PUBLIC_TREE.tsv'),
    ('public', ('spec', 'tools'),
     'spec/TRUST_ROOT.md', 'spec/TRUST_ROOT.ko.md',
     'spec/trust-roots.tsv',
     'spec/VERIFICATION_INPUTS.md', 'spec/VERIFICATION_INPUTS.ko.md',
     None),
)

# 이 파일이 구현한 관측점. T9 가 문서의 §7 표와 양방향으로 대조한다.
IDS = ('T1', 'T2', 'T3', 'T4', 'T5', 'T5r', 'T6', 'T7', 'T8', 'T9', 'T10')

KINDS = ('anchor', 'not-anchor')

# vkey 꼴: `<origin>+<8자리 키해시>+<44자 base64>`.
# 33바이트(알고리즘 바이트 1 + 공개키 32) = 264비트 = 정확히 44 base64 문자다 —
# 나머지 비트가 없으므로 패딩도 없고 마지막 글자에 제약도 없다. 제약을 상상해서
# 붙이면 그 순간 이 스캔은 **아무것도 못 맞추면서 초록**이 된다 (실측 2026-08-30:
# 마지막 글자를 `[AQgw]` 로 좁혀 545개 파일에서 0건을 찾았다).
VKEY_RE = re.compile(
    rb'(?<![A-Za-z0-9+/=._-])'
    rb'([A-Za-z0-9._-]{1,64}\+[0-9a-f]{8}\+[A-Za-z0-9+/]{44})'
    rb'(?![A-Za-z0-9+/=])')

DATE_RE = re.compile(r'^20[0-9]{2}-[0-9]{2}-[0-9]{2}$')
REGISTRY_RE = re.compile(r'^<!--[ \t]*registry:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
VOCAB_RE = re.compile(r'^<!--[ \t]*vocab:[ \t]*(\S+)[ \t]*-->[ \t]*$', re.M)
# 문서가 스스로 주장하는 앵커 수. 인쇄만으로는 「앵커 0건」 이라고 적은 산문이
# 첫 앵커보다 오래 사는 것을 못 막는다 — 인쇄된 수는 그것을 부정하는 문단 옆에서
# 동의로 읽힌다.
ANCHORS_RE = re.compile(r'^<!--[ \t]*anchors:[ \t]*([0-9]+)[ \t]*-->[ \t]*$', re.M)
FENCE_RE = re.compile(r'^```[a-zA-Z0-9]*\n(.*?)^```[ \t]*$', re.M | re.S)
BT_RE = re.compile(r'^`([^`]+)`$')

VOCABS = ('kind', 'observation')

FAILS = []


def die(msg):
    # 전제 실패만 인쇄하면 「무엇이 빠졌는지」의 칸이 영원히 안 보인다 (AC-1 의 교훈).
    for code, m in FAILS:
        sys.stdout.write('[FAIL] %s %s\n' % (code, m))
    sys.stdout.write("SPEC-TRUST-ROOT: prerequisite failure — %s\n" % msg)
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
    for name, tail, doc, ko, reg, vi, vi_ko, tree in LAYOUTS:
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            j = lambda p: os.path.join(root, *p.split('/'))
            hit.append((name, root, j(doc), j(ko), j(reg), j(vi), j(vi_ko),
                        j(tree) if tree else None))
    if len(hit) != 1:
        die("Cannot determine layout (%d matches); script location: %s" % (len(hit), here))
    return hit[0]


# ── vkey 유도 ───────────────────────────────────────────────────────────────
def key_hash(origin, raw33):
    """`sumdb/note` 의 키 해시 — SHA-256(origin ‖ "\\n" ‖ 33바이트) 의 앞 4바이트."""
    return hashlib.sha256(origin.encode('utf-8') + b'\n' + raw33).hexdigest()[:8]


def derive(vkey):
    """vkey 한 줄에서 (origin, 실린 키해시, 재유도 키해시, key_sha256) 을 낸다.

    실패하면 (None, 사유). 여기서 나오는 값 중 파일에서 **읽은** 것은 실린 키해시
    하나뿐이고 나머지는 전부 키 재료에서 다시 만든 것이다."""
    # 두 번만 자른다 — 구분자 `+` 는 본체의 알파벳(base64)에 속해 있어서 정당한 키
    # 넷 중 셋가량이 자기 안에 그것을 품는다. 전부 자르면 그 키들이 형식 불량으로
    # 읽힌다.
    parts = vkey.split('+', 2)
    if len(parts) != 3:
        return None, 'Expected three components separated by +'
    origin, hinted, b64 = parts
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as exc:              # noqa: BLE001 - base64 는 여러 예외를 낸다
        return None, 'Invalid base64 (%s)' % exc
    if len(raw) != 33:
        return None, 'Decoded key must be 33 bytes (got %d)' % len(raw)
    if raw[0] != 1:
        return None, 'Algorithm byte must be 1 (Ed25519), got %d' % raw[0]
    return (origin, hinted, key_hash(origin, raw),
            hashlib.sha256(raw[1:]).hexdigest()), None


# ── 공개 트리 전수 ──────────────────────────────────────────────────────────
def shipped_files(root, tree_path):
    """(공개경로, 실재경로) 목록. 이 검사기가 '공개 트리' 라고 부르는 것의 정본이다.

    내부 배치에서는 `oss/PUBLIC_TREE.tsv` 의 INCLUDE 행이 유일 정본이다 — 내부
    트리를 걸어 다니면 공개되지 않는 파일까지 세게 되고, 그 수는 유도의 바닥으로
    쓸 수 없다. 공개 배치에서는 트리 자신이 답이다."""
    out = []
    if tree_path is None:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d != '.git']
            for fn in sorted(filenames):
                p = os.path.join(dirpath, fn)
                out.append((os.path.relpath(p, root).replace(os.sep, '/'), p))
        return sorted(out)
    for ln in read(tree_path).splitlines():
        if ln.startswith('#') or not ln.strip():
            continue
        cells = ln.split('\t')
        if len(cells) < 3 or cells[0] != 'INCLUDE':
            continue
        internal, public = cells[1].strip(), cells[2].strip()
        out.append((public, os.path.join(root, *internal.split('/'))))
    if not out:
        die("No INCLUDE rows read from public manifest: %s" % tree_path)
    return sorted(out)


# ── 표 파싱 ─────────────────────────────────────────────────────────────────
def doc_table(text, code, pos, name, fails):
    """마커 뒤의 첫 마크다운 표를 {식별자: 나머지 칸} 으로 읽는다.

    표의 끝은 **빈 줄**이다. 「마커에서 N자 안」 같은 창으로 끊으면 정본과
    한국어판이 글자 수만 다를 뿐인데 한쪽만 다음 표까지 삼킨다 — 두 문서에 같은
    규칙을 적용했다고 믿는 채로 서로 다른 것을 재게 된다 (실측 2026-08-30)."""
    rows, seen_sep = {}, False
    for ln in text[pos:].splitlines():
        s = ln.strip()
        if not s:
            if seen_sep:
                break
            continue
        if not s.startswith('|'):
            break
        cells = [c.strip() for c in s.strip('|').split('|')]
        if all(c and set(c) <= set('- :') for c in cells):
            seen_sep = True
            continue
        if not seen_sep:
            continue                      # 헤더 줄
        bt = BT_RE.match(cells[0])
        if not bt:
            fails.append((code, "First column of table `%s` is not a backtick identifier: %s"
                          % (name, cells[0][:40])))
            continue
        rows[bt.group(1)] = tuple(cells[1:])
    if not rows:
        fails.append((code, "Cannot read table `%s` (zero rows)" % name))
    return rows


# ── T5: 단조성 ──────────────────────────────────────────────────────────────
def git(root, *args):
    try:
        p = subprocess.run(('git', '-C', root) + args, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.decode('utf-8', 'replace') if p.returncode == 0 else None


def parse_rows(text, code, fails):
    """등재부 본문 -> [(kind, vkey, key_sha256, listed, retired, label)]."""
    rows = []
    for n, ln in enumerate(text.splitlines(), 1):
        if ln.startswith('#') or not ln.strip():
            continue
        cells = ln.split('\t')
        if len(cells) != 6:
            fails.append((code, "Line %d: expected six columns, got %d" % (n, len(cells))))
            continue
        rows.append(tuple(c.strip() for c in cells))
    return rows


def monotone(root, reg_path, rows, fails):
    """반환 `measured` / `unmeasurable:<사유>`.

    「과거를 못 봤다」와 「과거가 깨끗했다」가 같은 초록으로 도착하면 안 된다."""
    top = git(root, 'rev-parse', '--show-toplevel')
    if top is None:
        return 'unmeasurable:no Git history in this exported snapshot'
    rel = os.path.relpath(reg_path, top.strip()).replace(os.sep, '/')
    log = git(root, 'log', '--format=%H', '--', rel)
    if log is None:
        return 'unmeasurable:cannot read registry Git history'
    revs = [r for r in log.split() if r]
    if not revs:
        return 'unmeasurable:registry has no committed history'
    now = {r[1]: r for r in rows}
    for rev in revs:
        blob = git(root, 'show', '%s:%s' % (rev, rel))
        if blob is None:
            fails.append(('T5', "Cannot read registry %s" % rev[:8]))
            continue
        for past in parse_rows(blob, 'T5', []):
            cur = now.get(past[1])
            if cur is None:
                fails.append(('T5', "A prior row from %s disappeared; registry history must be preserved: %s"
                              % (rev[:8], past[1][:48])))
                continue
            if cur[3] != past[3]:
                fails.append(('T5', "listed date changed (%s: %s -> %s): %s"
                              % (rev[:8], past[3], cur[3], past[1][:48])))
            if past[4] != '-' and cur[4] != past[4]:
                fails.append(('T5', "retired date rewritten (%s: %s -> %s): %s"
                              % (rev[:8], past[4], cur[4], past[1][:48])))
    return 'measured:%d리비전' % len(revs)


def main():
    layout, root, doc_path, ko_path, reg_path, vi_path, vi_ko_path, tree_path = locate()
    doc = read(doc_path)
    reg = read(reg_path)
    fails = FAILS

    # --- T1: 등재부가 파싱된다 ------------------------------------------------
    rows = parse_rows(reg, 'T1', fails)
    if not rows:
        # 0행은 "행이 전부 맞다" 와 같은 바이트다. 등재부가 비면 T2~T5 가 잴 것이 없다.
        die("No entry rows read from registry: %s" % reg_path)
    seen_vkey = set()
    for kind, vkey, ksha, listed, retired, label in rows:
        if kind not in KINDS:
            fails.append(('T1', "Unrecognized kind: %s" % kind))
        if not DATE_RE.match(listed):
            fails.append(('T1', "listed date is not YYYY-MM-DD: %s" % listed))
        if retired != '-' and not DATE_RE.match(retired):
            fails.append(('T1', "retired is neither '-' nor a date: %s" % retired))
        if not label:
            fails.append(('T1', "Empty label: %s" % vkey[:48]))
        if vkey in seen_vkey:
            fails.append(('T1', "Duplicate registered vkey: %s" % vkey[:48]))
        seen_vkey.add(vkey)

    # --- T2: vkey 가 자기 값을 재유도한다 -------------------------------------
    derived = {}
    for kind, vkey, ksha, listed, retired, label in rows:
        got, why = derive(vkey)
        if got is None:
            fails.append(('T2', '%s: %s' % (vkey[:48], why)))
            continue
        origin, hinted, rederived, key_sha = got
        if hinted != rederived:
            fails.append(('T2', "%s: distributed key hash %s != re-derived %s"
                          % (origin, hinted, rederived)))
        if ksha != key_sha:
            fails.append(('T2', "%s: distributed key_sha256 %s… != re-derived %s…"
                          % (origin, ksha[:16], key_sha[:16])))
        derived[vkey] = (kind, key_sha, origin)

    # --- T3: 공개 트리 전수 (양방향) ------------------------------------------
    files = shipped_files(root, tree_path)
    read_ok, found = 0, {}
    doc_public = {'spec/TRUST_ROOT.md', 'spec/TRUST_ROOT.ko.md', 'spec/trust-roots.tsv'}
    for public, local in files:
        try:
            with open(local, 'rb') as fh:
                blob = fh.read()
        except OSError:
            # 공개된다고 등재된 파일을 못 읽는 것은 스캔의 침묵이지 깨끗함이 아니다.
            fails.append(('T3', "Cannot read a file listed for distribution: %s" % public))
            continue
        read_ok += 1
        for m in VKEY_RE.finditer(blob):
            found.setdefault(m.group(1).decode('ascii'), set()).add(public)
    if read_ok == 0:
        die("No files read from public tree; derivation inputs are absent")
    for vkey, where in sorted(found.items()):
        if vkey not in seen_vkey:
            fails.append(('T3', "Distributed vkey is not registered (%s): %s"
                          % (sorted(where)[0], vkey[:48])))
    for vkey, (kind, _ksha, origin) in sorted(derived.items()):
        if kind != 'not-anchor':
            continue
        where = found.get(vkey, set()) - doc_public
        if not where:
            fails.append(('T3', "Registered not-anchor value appears only in registry/documentation, not in distributed content: %s" % origin))

    # --- T4: 한 키가 두 종류일 수 없다 ----------------------------------------
    by_sha = {}
    for vkey, (kind, key_sha, origin) in derived.items():
        by_sha.setdefault(key_sha, set()).add(kind)
    for key_sha, kinds in sorted(by_sha.items()):
        if len(kinds) > 1:
            fails.append(('T4', "%s… is registered simultaneously as %s; contradictory trust classification" % (key_sha[:16], sorted(kinds))))

    # --- T5 / T5r -------------------------------------------------------------
    t5r = monotone(root, reg_path, rows, fails)

    # --- T6: 인용이 부분문자열 ------------------------------------------------
    quoted = 0
    for label, text in (('en', doc), ('ko', read(ko_path))):
        marks = list(REGISTRY_RE.finditer(text))
        if not marks:
            fails.append(('T6', "%s: registry marker missing; zero quotes do not establish agreement" % label))
            continue
        for m in marks:
            fence = FENCE_RE.search(text, m.end())
            if not fence:
                fails.append(('T6', "%s: no quote block after registry marker" % label))
                continue
            if fence.group(1) not in reg:
                head = (fence.group(1).splitlines() or [''])[0]
                fails.append(('T6', "%s: quote is not a byte substring of registry (first line: %s)" % (label, head[:60])))
                continue
            quoted += 1

    # --- T7: 전방 참조 --------------------------------------------------------
    want = os.path.basename(doc_path)
    for label, path in (('en', vi_path), ('ko', vi_ko_path)):
        vi = read(path)
        if want not in vi:
            fails.append(('T7', "%s: VERIFICATION_INPUTS does not reference `%s`; publication claim lacks a target"
                          % (label, want)))
        if os.path.basename(reg_path) not in vi:
            fails.append(('T7', "%s: VERIFICATION_INPUTS does not reference the registry"
                          % label))

    # --- T9: 문서의 관측점 == 구현한 관측점 -----------------------------------
    vpos = {m.group(1): m.end() for m in VOCAB_RE.finditer(doc)}
    if set(vpos) != set(VOCABS):
        fails.append(('T9', "Canonical vocabulary tables differ: observed %s / expected %s"
                      % (sorted(vpos), sorted(VOCABS))))
    obs = doc_table(doc, 'T9', vpos['observation'], 'observation', fails) \
        if 'observation' in vpos else {}
    if obs:
        missing = sorted(set(IDS) - set(obs))
        extra = sorted(set(obs) - set(IDS))
        if missing:
            fails.append(('T9', "Implemented observation point absent from section 7 table: %s" % missing))
        if extra:
            fails.append(('T9', "Observation point advertised in section 7 but not implemented: %s" % extra))
    kinds_doc = doc_table(doc, 'T9', vpos['kind'], 'kind', fails) \
        if 'kind' in vpos else {}
    if kinds_doc and set(kinds_doc) != set(KINDS):
        fails.append(('T9', "Section 3 kind table differs: documented %s / checker %s" % (sorted(kinds_doc), sorted(KINDS))))

    # --- T10: 한국어판 --------------------------------------------------------
    ko = read(ko_path)
    ko_v = {m.group(1): m.end() for m in VOCAB_RE.finditer(ko)}
    if set(ko_v) != set(vpos):
        fails.append(('T10', "Korean vocabulary tables differ from canonical tables: canonical %s / Korean %s" % (sorted(vpos), sorted(ko_v))))
    else:
        ko_fails = []
        for name in sorted(vpos):
            en = doc_table(doc, 'T10', vpos[name], name, [])
            kv = doc_table(ko, 'T10', ko_v[name], name, ko_fails)
            if set(kv) != set(en):
                fails.append(('T10', "Table `%s` identifiers differ: canonical %s / Korean %s"
                              % (name, sorted(en), sorted(kv))))
        fails.extend(ko_fails)

    # --- T8: 세는 값들 + 문서가 선언한 수 --------------------------------------
    anchors = sum(1 for r in rows if r[0] == 'anchor')
    for label, text in (('en', doc), ('ko', ko)):
        decl = ANCHORS_RE.findall(text)
        if len(decl) != 1:
            fails.append(('T8', "%s: anchors declaration occurs %d times; expected a unique checkable count"
                          % (label, len(decl))))
            continue
        if int(decl[0]) != anchors:
            fails.append(('T8', "%s: documented anchor count %s != registered %d"
                          % (label, decl[0], anchors)))
    sys.stdout.write(
        "layout %s · files read %d/%d · vkey values %d · registry rows %d · anchors %d · quotes %d · T5r %s\n"
        % (layout, read_ok, len(files), len(found), len(rows), anchors, quoted, t5r))
    for code, msg in fails:
        sys.stdout.write('[FAIL] %s %s\n' % (code, msg))
    sys.stdout.write('SPEC-TRUST-ROOT: %s failures=%d skipped_groups=%d unmeasurable_groups=%d scope=%s\n' % ('FAIL' if fails else 'PASS', len(fails), 0, int(t5r.startswith("unmeasurable:")), layout))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
