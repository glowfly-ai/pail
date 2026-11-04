#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Generate local development Ed25519 keys without third-party dependencies.

Existing private keys are preserved unless --force is explicit. The public keyring
is regenerated from those keys. --check reports missing files without creating keys.
The dev-key-3 issuer is deliberately excluded from the keyring for unknown-key tests.
Issuer, operator, burst and mirror roles remain distinct; mirror verification never
falls back to an issuer/burst identity. Generated material must not be committed.

Public-key derivation follows RFC 8032 and checks its published known-answer vector
before generating random keys. macOS LibreSSL need not support Ed25519.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import stat
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = os.path.join(REPO, 'config', 'keys')

# --- RFC 8032 Ed25519 공개키 유도 -------------------------------------------
_P = 2 ** 255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P


def _recover_x(y, sign):
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if (x * x - xx) % _P != 0:
        raise ValueError('not on curve')
    if x % 2 != sign:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_B = (_recover_x(_BY, 0), _BY)


def _add(p, q):
    x1, y1 = p
    x2, y2 = q
    t = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, _P - 2, _P) % _P
    return (x3, y3)


def _mul(p, e):
    r = (0, 1)
    while e > 0:
        if e & 1:
            r = _add(r, p)
        p = _add(p, p)
        e >>= 1
    return r


def public_from_seed(seed):
    """Derive a 32-byte public key from a 32-byte Ed25519 seed."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    x, y = _mul(_B, a)
    enc = bytearray(y.to_bytes(32, 'little'))
    enc[31] |= (x & 1) << 7
    return bytes(enc)


def selftest():
    """RFC 8032 published known-answer test; not a deployment key."""
    seed = bytes.fromhex(
        '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
    want = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    got = public_from_seed(seed).hex()
    if got != want:
        raise SystemExit('ed25519 self-test FAILED: %s != %s' % (got, want))


# --- 키 묶음 ----------------------------------------------------------------
# (파일명, key_id, keyring 역할 또는 None)
SPEC = [
    ('issuer_ed25519.json',    'dev-key-1',   'issuer'),
    ('issuer_ed25519_v2.json', 'dev-key-2',   'issuer'),
    ('issuer_ed25519_v3.json', 'dev-key-3',   None),
    ('operator_ed25519.json',  'op-key-1',    'operator'),
    ('agent_ed25519.json',     'agent-key-1', 'burst'),
    ('mirror_ed25519.json',    'mirror-key-1', 'mirror'),
]
KEYRING = 'keyring.json'


def _b64(b):
    return base64.b64encode(b).decode('ascii')


def _write_key(path, key_id, force=False):
    seed = os.urandom(32)
    pub = public_from_seed(seed)
    doc = {
        'key_id': key_id,
        # Go ed25519.PrivateKey 와 같은 배치: seed(32) || public(32).
        'ed25519_private_key_base64': _b64(seed + pub),
        'ed25519_public_key_base64': _b64(pub),
    }
    if force:
        fd, temporary = tempfile.mkstemp(prefix='.keygen-', dir=os.path.dirname(path))
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write('\n')
    # `O_CREAT` 의 모드는 파일을 **만들 때만** 쓰인다. 이미 있는 파일을 다시
    # 쓰면 옛 모드가 그대로 남는다 — 한 번 `0644` 로 태어난 키는 이 생성기를
    # 몇 번 다시 돌려도 `0644` 다. §1.3 이 실측한 `config/keys/issuer_ed25519.json`
    # 이 그 자리이고, 런타임 강제는 `S19`.
    if force:
        os.replace(temporary, path)
    os.chmod(path, 0o600)
    return doc


def _read_key(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def key_exists(path):
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(mode):
        raise ValueError('Key path is not a regular file: ' + path)
    return True


def generate(force):
    os.makedirs(KEYS, mode=0o700, exist_ok=True)
    docs = {}
    for fn, key_id, _role in SPEC:
        path = os.path.join(KEYS, fn)
        if key_exists(path) and not force:
            docs[key_id] = _read_key(path)
            print('keep   %s (%s)' % (fn, key_id))
            continue
        docs[key_id] = _write_key(path, key_id, force)
        print('%s %s (%s)' % ('regen ' if force else 'create', fn, key_id))

    entries = []
    for _fn, key_id, role in SPEC:
        if role is None:
            continue
        entries.append({
            'key_id': key_id,
            'ed25519_public_key_base64': docs[key_id]['ed25519_public_key_base64'],
            'role': role,
        })
    path = os.path.join(KEYS, KEYRING)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump({'keys': entries}, f, indent=2, ensure_ascii=False)
        f.write('\n')
    print('write  %s (%d public keys; dev-key-3 intentionally excluded)' % (KEYRING, len(entries)))
    return 0


def check():
    missing = [fn for fn, _k, _r in SPEC if not key_exists(os.path.join(KEYS, fn))]
    if not key_exists(os.path.join(KEYS, KEYRING)):
        missing.append(KEYRING)
    if missing:
        for fn in missing:
            print('MISSING: %s' % os.path.join(KEYS, fn))
        print('Run this generator without --check, using the same --config-dir.')
        return 1
    print('OK: %s contains %d development keys and a keyring' % (KEYS, len(SPEC)))
    return 0


def main():
    global KEYS
    ap = argparse.ArgumentParser()
    ap.add_argument('--force', action='store_true')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--config-dir', default=os.path.join(REPO, 'config'), help='Writable per-run config directory; keys are stored in its keys/ child')
    args = ap.parse_args()
    KEYS = os.path.join(os.path.abspath(args.config_dir), 'keys')
    try:
        selftest()
        if args.check:
            return check()
        return generate(args.force)
    except (OSError, ValueError) as exc:
        print('KEYGEN: REFUSED: '+str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
