#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""S8 (PAIL-SD2-LLD-v1 §2) — 저장소에 커밋된 개발용 공개키의 지문 목록을 만든다.

  --scan   저장소를 훑어 known_dev_keys.tsv 를 갱신한다 (기존 행과 병합)
  --emit   TSV 로부터 Go/C++ 상수 파일을 생성한다
  --check  생성물이 TSV 와 일치하는지만 확인한다 (rc=1 이면 불일치)
  --check-monotone <기준TSV>
           기준 대비 지문이 하나라도 빠졌는지 본다 (rc=1 이면 소실)

인자가 없으면 --scan --emit 을 순서대로 한다.

목록은 단조다 (PAIL-SD5-LLD-v1 §4). S8 이 묻는 것은 "이 키가 지금 저장소에 있는가"가
아니라 "이 키가 개발용으로 쓰인 적이 있는가"이다. 저장소에서 지운다고 배포된 사본이
회수되지 않으므로, --scan 은 어떤 지문도 목록에서 빼지 않는다.

훑는 대상은 git 이 추적하는 파일뿐이다. 개발자가 로컬에서 만든 키(AS-16 이후의 정상
경로)는 추적되지 않으므로 목록에 들어오지 않는다 — 목록은 커밋된 것의 함수여야지
작업 트리 상태의 함수여서는 안 된다.

지문 정의:
  ed25519  sha256(32바이트 공개키) hex
  spki     sha256(SubjectPublicKeyInfo DER) hex   — 인증서를 재발급해도 키를
           바꾸지 않으면 같은 값이므로, 인증서 파일 해시보다 키에 붙는다.

SROS2 enclave 의 key.pem 은 범위 밖이다(§8). DDS 신원은 미들웨어가 적재하며
검사 지점이 다르다 — AS-16 이 받는다.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# 이 도구는 배치가 다른 두 트리에서 돈다: 내부 저장소와, `oss/PUBLIC_TREE.tsv` 가
# 재배치한 공개 스냅숏이다. 설계서 §2.5 는 공개 CI 의 2층으로 `--check` /
# `--check-monotone` 을 지목하는데, 경로를 내부 배치로 굳혀 두면 공개 트리에서
# 첫날 죽는다(실측: `spec/pail_ws/...` FileNotFoundError — REPO 가 `spec/` 로 잡힌다).
# 그때 오는 수정은 대개 "그 단계를 지우는 것"이고, 그러면 2층이 조용히 사라진다.
#
# 배치는 **스크립트 자신이 놓인 자리**로 정한다. 산출물의 존재로 찾지 않는 이유는
# `--scan` 이 아직 없는 파일을 만드는 쪽이기 때문이다 — SD5-0-4 는 빈 디렉터리만
# 있는 합성 트리에서 이 도구를 돌린다.
LAYOUTS = (
    ('internal', ('scripts',),
     'pail_ws/src/pail_deploy_guard/known_dev_keys.tsv',
     'services/pail_services_go/internal/deploysec/devkeys.go',
     'pail_ws/src/pail_deploy_guard/include/pail_deploy_guard/known_dev_keys.hpp'),
    ('public', ('spec', 'tools'),
     'robot/pail_deploy_guard/known_dev_keys.tsv',
     'cloud/internal/deploysec/devkeys.go',
     'robot/pail_deploy_guard/include/pail_deploy_guard/known_dev_keys.hpp'),
)


def _locate(here=HERE):
    """(배치이름, REPO, TSV, GO_OUT, HPP_OUT).

    일치가 정확히 1건이 아니면 죽는다. 아무 배치나 골라 계속 가면 그 다음에 오는
    것은 "지문 0행"이고, 그것은 '이 저장소에 개발키가 없다'와 같은 바이트다(`H-B2`).
    (오늘 도달 가능한 실패는 0건뿐이다 — 두 꼬리가 겹치지 않는다. 조건을 `!= 1` 로
    두는 것은 배치가 늘 때 겹침이 조용히 통과하지 않게 하려는 것이다.)
    """
    parts = here.replace(os.sep, '/').split('/')
    hit = []
    for name, tail, tsv, go, hpp in LAYOUTS:
        if len(parts) > len(tail) and tuple(parts[-len(tail):]) == tail:
            root = os.path.abspath(os.path.join(here, *(['..'] * len(tail))))
            hit.append((name, root,
                        os.path.join(root, *tsv.split('/')),
                        os.path.join(root, *go.split('/')),
                        os.path.join(root, *hpp.split('/'))))
    if len(hit) != 1:
        raise SystemExit(
            '배치를 정하지 못했다 (일치 %d건) — 이 스크립트의 자리: %s\n'
            '  아는 자리: %s\n'
            '  이 도구는 자기 위치로 저장소 배치를 정한다. 옮겼다면 LAYOUTS 에 더해라.'
            % (len(hit), here, ' · '.join('/'.join(l[1]) for l in LAYOUTS)))
    return hit[0]


LAYOUT, REPO, TSV, GO_OUT, HPP_OUT = _locate()

# 훑을 곳. SROS2 keystore 는 의도적으로 제외한다(§8).
JSON_ROOTS = [
    'config/keys',
    'deploy/config-cloud/keys',
    'deploy/config-robot/keys',
    'asvs/integration',
    'demo-anchor',
    'services/anchor_saas',
    'dist',
]
CERT_ROOTS = [
    'config/grpc_certs',
    'deploy/config-cloud/grpc_certs',
    'deploy/config-robot/grpc_certs',
]

HEADER = """\
# S8 공용 지문 목록 (PAIL-SD2-LLD-v1 §2). scripts/gen_known_dev_keys.py 가 생성한다.
# 손으로 고치지 말 것 — Go/C++ 상수와 이 파일을 대조하는 드리프트 테스트가 깨진다.
#
# 여기 적힌 것은 공개키의 지문이다. 개인키를 저장소에서 지워도(AS-16) 이미 배포된
# 사본이 남으므로 목록은 그대로 유지한다. 키를 옮기거나 이름을 바꿔도 지문은 같다.
#
# 열: fingerprint(sha256 hex)  kind(ed25519|spki)  label
"""


def _rel(p):
    return os.path.relpath(p, REPO)


def _tracked():
    """git 이 추적하는 파일의 저장소 상대 경로 집합. 작업 트리에만 있는 파일은
    목록에 들어오면 안 된다(모듈 주석 참조).

    `-z` 없이는 `core.quotePath` 가 한글 경로를 `"\\355\\225\\234..."` 로 이스케이프해
    이 집합의 원소가 실제 경로와 달라진다. 그러면 생성기와 `S13` 검사기가 **서로 다른
    파일 집합**을 보게 된다(`implementation contract` `DB-4`).
    """
    out = subprocess.run(['git', '-C', REPO, 'ls-files', '-z'],
                         capture_output=True)
    if out.returncode != 0:
        raise SystemExit('git ls-files -z 실패: %s' % out.stderr.decode()[:200].strip())
    text = out.stdout.decode('utf-8', 'surrogateescape')
    return {os.path.normpath(p) for p in text.split('\0') if p}


def _walk(root, suffixes, tracked):
    base = os.path.join(REPO, root)
    if not os.path.isdir(base):
        return
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in ('.git', 'node_modules', 'sros2_keystore')]
        for fn in sorted(filenames):
            if not fn.endswith(suffixes):
                continue
            path = os.path.join(dirpath, fn)
            if os.path.normpath(_rel(path)) in tracked:
                yield path


def _ed25519_from_json(path):
    """(pub_b64, key_id) 쌍을 뽑는다. 키파일(단일)과 keyring(배열) 둘 다 처리."""
    try:
        with open(path, encoding='utf-8') as f:
            doc = json.load(f)
    except (ValueError, OSError):
        return
    if isinstance(doc, dict) and 'ed25519_public_key_base64' in doc:
        yield doc['ed25519_public_key_base64'], doc.get('key_id', '?')
    for entry in (doc.get('keys') or []) if isinstance(doc, dict) else []:
        if isinstance(entry, dict) and entry.get('ed25519_public_key_base64'):
            yield entry['ed25519_public_key_base64'], entry.get('key_id', '?')


def _spki_fingerprint(path):
    out = subprocess.run(
        ['openssl', 'x509', '-in', path, '-pubkey', '-noout'],
        capture_output=True, text=True)
    if out.returncode != 0:
        return None
    der = subprocess.run(
        ['openssl', 'pkey', '-pubin', '-outform', 'DER'],
        input=out.stdout.encode('ascii'), capture_output=True)
    if der.returncode != 0:
        return None
    return hashlib.sha256(der.stdout).hexdigest()


def scan():
    """지문 -> 라벨. 같은 키가 여러 파일에 있으면 라벨을 합친다."""
    # 훑을 자리가 하나도 없으면 결과는 0건이고, 0건은 `merge_retained` 를 지나
    # **모든 행에 '저장소에서 제거됨' 을 붙인 TSV** 로 착지한다. 목록은 그대로
    # 남지만 라벨이 통째로 거짓이 되고, 다음 `--scan` 이 그 위에 다시 쌓인다.
    # 경로 결합을 푼 뒤(위 `_locate`) 공개 배치에서 이 경로가 처음으로 살아났다 —
    # 즉 이 가드는 그 수정이 만든 구멍을 같이 막는 것이다.
    # 공개 스냅숏에서 도는 것은 `--check` / `--check-monotone` 뿐이다(설계서 §2.5).
    present = [r for r in JSON_ROOTS + CERT_ROOTS if os.path.isdir(os.path.join(REPO, r))]
    if not present:
        raise SystemExit(
            '--scan 이 훑을 자리가 이 트리에 하나도 없다 (배치 %s · 루트 %s).\n'
            '  여기서 0건을 적어 내면 "개발키가 없다"로 읽힌다 — 실제로는 훑지 않은 것이다.\n'
            '  공개 배치에서는 --check / --check-monotone 만 돈다 (설계서 §2.5).'
            % (LAYOUT, REPO))
    found = {}
    tracked = _tracked()

    def add(fpr, kind, label):
        cur = found.setdefault(fpr, [kind, []])
        if label not in cur[1]:
            cur[1].append(label)

    for root in JSON_ROOTS:
        for path in _walk(root, ('.json',), tracked):
            for pub_b64, key_id in _ed25519_from_json(path):
                try:
                    raw = base64.b64decode(pub_b64, validate=True)
                except (ValueError, TypeError):
                    continue
                if len(raw) != 32:
                    continue
                add(hashlib.sha256(raw).hexdigest(), 'ed25519',
                    '%s (%s)' % (_rel(path), key_id))

    for root in CERT_ROOTS:
        for path in _walk(root, ('.crt',), tracked):
            fpr = _spki_fingerprint(path)
            if fpr:
                add(fpr, 'spki', _rel(path))

    return found


REMOVED_MARK = '[저장소에서 제거됨 — 배포 사본 유효]'


def merge_retained(found):
    """PAIL-SD5-LLD-v1 §4.1: 목록은 단조다. 트리에서 사라진 지문도 행을 유지하고
    라벨에 이력을 남긴다. 반환값은 유지된 지문 목록(보고용)."""
    if not os.path.exists(TSV):
        return []
    retained = []
    for fpr, kind, label in read_tsv():
        if fpr in found:
            continue
        if REMOVED_MARK not in label:
            label = '%s %s' % (label, REMOVED_MARK)
        found[fpr] = [kind, [label]]
        retained.append(fpr)
    return retained


def write_tsv(found):
    lines = [HEADER]
    for fpr in sorted(found):
        kind, labels = found[fpr]
        lines.append('%s\t%s\t%s\n' % (fpr, kind, ' | '.join(sorted(labels))))
    with open(TSV, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    print('wrote %s (%d fingerprints)' % (_rel(TSV), len(found)))


def read_tsv():
    rows = []
    if not os.path.exists(TSV):
        raise SystemExit(
            '지문 목록이 없다: %s (배치 %s)\n'
            '  배치를 잘못 잡았거나 목록이 트리에서 빠진 것이다. 어느 쪽이든\n'
            '  "지문 0행" 으로 계속 가지 않는다 — 그것은 통과와 같은 바이트다.'
            % (TSV, LAYOUT))
    with open(TSV, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            col = line.split('\t')
            if len(col) != 3:
                raise SystemExit('malformed TSV row: %r' % line)
            if not re.fullmatch(r'[0-9a-f]{64}', col[0]):
                raise SystemExit('bad fingerprint: %r' % col[0])
            if col[1] not in ('ed25519', 'spki'):
                raise SystemExit('bad kind: %r' % col[1])
            rows.append(tuple(col))
    return rows


GO_TMPL = '''\
package deploysec

// S8 (PAIL-SD2-LLD-v1 §2): fingerprints of the key material committed to this
// repository. Generated by scripts/gen_known_dev_keys.py — do not edit.
//
// Compiled in, not read from a file: a check that depends on a file on disk is
// removed by deleting that file. The label is for the operator's error message.

type KnownDevKey struct {
\tFingerprint string // sha256 hex
\tKind        string // "ed25519" (raw public key) | "spki" (SubjectPublicKeyInfo DER)
\tLabel       string
}

var knownDevKeys = []KnownDevKey{
%s}
'''

HPP_TMPL = '''\
#ifndef PAIL_DEPLOY_GUARD__KNOWN_DEV_KEYS_HPP_
#define PAIL_DEPLOY_GUARD__KNOWN_DEV_KEYS_HPP_

// S8 (PAIL-SD2-LLD-v1 §2): fingerprints of the key material committed to this
// repository. Generated by scripts/gen_known_dev_keys.py — do not edit.

#include <cstddef>

namespace pail_deploy_guard {

struct KnownDevKey {
  const char * fingerprint;  // sha256 hex
  const char * kind;         // "ed25519" | "spki"
  const char * label;
};

inline const KnownDevKey * KnownDevKeys(std::size_t * count)
{
  static const KnownDevKey kKeys[] = {
%s  };
  *count = sizeof(kKeys) / sizeof(kKeys[0]);
  return kKeys;
}

}  // namespace pail_deploy_guard

#endif  // PAIL_DEPLOY_GUARD__KNOWN_DEV_KEYS_HPP_
'''


def _go_escape(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')


def emit(rows):
    go_body = ''.join(
        '\t{"%s", "%s", "%s"},\n' % (f, k, _go_escape(l)) for f, k, l in rows)
    with open(GO_OUT, 'w', encoding='utf-8') as f:
        f.write(GO_TMPL % go_body)
    hpp_body = ''.join(
        '    {"%s", "%s", "%s"},\n' % (f, k, _go_escape(l)) for f, k, l in rows)
    with open(HPP_OUT, 'w', encoding='utf-8') as f:
        f.write(HPP_TMPL % hpp_body)
    print('wrote %s and %s (%d fingerprints)' % (_rel(GO_OUT), _rel(HPP_OUT), len(rows)))


def check(rows):
    """생성물이 TSV 와 일치하는지. 드리프트 테스트는 각 언어에서 따로 돌지만,
    이 확인은 CI 없이도 손으로 돌릴 수 있는 최소 안전망이다."""
    bad = 0
    for path in (GO_OUT, HPP_OUT):
        if not os.path.exists(path):
            print('MISSING: %s' % _rel(path))
            bad += 1
            continue
        text = open(path, encoding='utf-8').read()
        for fpr, _kind, _label in rows:
            if fpr not in text:
                print('DRIFT: %s lacks fingerprint %s' % (_rel(path), fpr[:16]))
                bad += 1
        n = len(re.findall(r'[0-9a-f]{64}', text))
        if n != len(rows):
            print('DRIFT: %s has %d fingerprints (TSV %d)' % (_rel(path), n, len(rows)))
            bad += 1
    if bad:
        return 1
    print('OK: %d generated fingerprints match TSV' % len(rows))
    return 0


def check_monotone(baseline_path, rows):
    """기준 TSV 대비 지문 소실이 있는지. 소실은 'S8 이 더는 거부하지 못하는
    배포된 개발키'를 뜻한다 (PAIL-SD5-LLD-v1 §0)."""
    have = {r[0] for r in rows}
    base = []
    with open(baseline_path, encoding='utf-8') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            base.append(line.split('\t')[0])
    lost = [f for f in base if f not in have]
    if lost:
        for fpr in lost:
            print('LOST: %s is in the baseline but absent from the current list' % fpr[:16])
        print('Lost %d fingerprints; S8 coverage would be weakened' % len(lost))
        return 1
    print('OK: no loss from baseline (baseline %d rows / current %d rows)' % (len(base), len(rows)))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--scan', action='store_true')
    ap.add_argument('--emit', action='store_true')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--check-monotone', metavar='BASELINE_TSV')
    args = ap.parse_args()
    if not (args.scan or args.emit or args.check or args.check_monotone):
        args.scan = args.emit = True

    if args.scan:
        found = scan()
        retained = merge_retained(found)
        write_tsv(found)
        for fpr in retained:
            print('  retain: %s (absent from this tree; retained because distributed copies may exist)' % fpr[:16])
    rows = read_tsv()
    if args.emit:
        emit(rows)
    rc = 0
    if args.check:
        rc |= check(rows)
    if args.check_monotone:
        rc |= check_monotone(args.check_monotone, rows)
    return rc


if __name__ == '__main__':
    sys.exit(main())
