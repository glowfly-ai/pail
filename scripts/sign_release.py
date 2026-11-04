#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Sign delivery manifests with the release Ed25519 key (publisher side) or verify signatures (anyone).

What is signed: each artifact's `*.manifest.json` (it binds the artifact's SHA-256, byte size, release id and
every member digest), producing `<manifest>.sig` — the raw 64-byte Ed25519 signature over the manifest bytes.
The private key never enters the repository or a delivery; the public key ships as `RELEASE-SIGNING-KEY.pub`
(PEM, SubjectPublicKeyInfo) in the Core source ZIP and in every evaluation bundle, and its SHA-256 fingerprint
is printed in RELEASE.md so a recipient can compare the key they received with the one the publisher states.

  sign:    sign_release.py --key ~/.pail-release-signing/pail-release-ed25519.pem --sign A.manifest.json B.manifest.json
  verify:  sign_release.py --public-key RELEASE-SIGNING-KEY.pub --verify A.manifest.json   (needs the .sig beside it)

Verification uses the Python `cryptography` package when importable, else OpenSSL 3 (`openssl pkeyutl -verify
-rawin`), else reports that it could not verify (exit 2). Exit 0 verified, 1 bad signature, 2 unable.
"""
import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path


def fingerprint(public_pem):
    """SHA-256 over the raw 32-byte public key (what RELEASE.md prints)."""
    try:
        from cryptography.hazmat.primitives import serialization
        pub = serialization.load_pem_public_key(public_pem)
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except ImportError:
        import base64
        der = base64.b64decode(''.join(l for l in public_pem.decode().splitlines() if not l.startswith('-----')))
        if len(der) != 44 or der[:12] != bytes.fromhex('302a300506032b6570032100'):
            raise ValueError('not an Ed25519 SubjectPublicKeyInfo')
        raw = der[12:]
    return hashlib.sha256(raw).hexdigest()


def sign(key_path, files):
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    for f in files:
        data = Path(f).read_bytes()
        sig = key.sign(data)
        Path(str(f) + '.sig').write_bytes(sig)
        key.public_key().verify(sig, data)
        print('signed', f, '->', Path(f).name + '.sig')
    print('public key fingerprint sha256:', fingerprint(pub))
    return 0


def verify_one(public_key_path, f, expected_fingerprint=None):
    """0 verified, 1 bad signature or a key whose fingerprint is not the expected one, 2 not verified."""
    fp = fingerprint(Path(public_key_path).read_bytes())
    if expected_fingerprint and fp != expected_fingerprint.strip().lower():
        return 1, 'KEY MISMATCH key=' + fp + ' expected=' + expected_fingerprint.strip().lower()
    data = Path(f).read_bytes(); sig_path = Path(str(f) + '.sig')
    if not sig_path.is_file():
        return 2, 'no signature file: ' + sig_path.name
    sig = sig_path.read_bytes()
    tried = []
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
        pub = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
        try:
            pub.verify(sig, data)
            return 0, 'VERIFIED key=' + fp + ' (python cryptography)'
        except InvalidSignature:
            return 1, 'BAD SIGNATURE key=' + fp
    except ImportError:
        tried.append('python cryptography: not importable')
    seen = []
    for exe in (shutil.which('openssl'), '/opt/homebrew/opt/openssl@3/bin/openssl'):
        if not exe or not Path(exe).exists():
            continue
        v = subprocess.run([exe, 'version'], capture_output=True, text=True).stdout
        if not v.startswith('OpenSSL 3') and not v.startswith('OpenSSL 1.1.1'):
            seen.append(exe + ' is ' + (v.strip() or 'unknown'))
            continue
        r = subprocess.run([exe, 'pkeyutl', '-verify', '-pubin', '-inkey', str(public_key_path), '-rawin', '-in', str(f), '-sigfile', str(sig_path)],
                           capture_output=True, text=True)
        if r.returncode == 0 and 'Verified Successfully' in r.stdout:
            return 0, 'VERIFIED key=%s (%s)' % (fp, v.strip())
        if 'Failure' in r.stdout or r.returncode:
            return 1, 'BAD SIGNATURE key=%s (%s)' % (fp, v.strip())
    tried.append('OpenSSL 3: ' + ('; '.join(seen) if seen else 'no openssl on PATH'))
    # The Core ZIP carries the verifier's source: `go run ./cloud/cmd/pail_verify --sig-only` (verify_release.py tries
    # that first when `go` is present); an evaluation bundle carries the built `native/pail_verify-<host>` instead.
    return 2, 'signature present but not verified: no verifier on this host (' + '; '.join(tried) + '); install the python cryptography package or OpenSSL 3, or build cloud/cmd/pail_verify from the Core source'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--key', type=Path, help='private Ed25519 key (PEM, PKCS8) — publisher only')
    ap.add_argument('--public-key', type=Path, help='RELEASE-SIGNING-KEY.pub')
    ap.add_argument('--sign', nargs='+', metavar='MANIFEST'); ap.add_argument('--verify', nargs='+', metavar='MANIFEST')
    ap.add_argument('--fingerprint', action='store_true', help='print the public key fingerprint and exit')
    ap.add_argument('--expected-fingerprint', help='fingerprint obtained outside the archive; --verify refuses a key that differs')
    a = ap.parse_args()
    if a.fingerprint:
        if not a.public_key: ap.error('--fingerprint needs --public-key')
        print(fingerprint(a.public_key.read_bytes())); return 0
    if a.sign:
        if not a.key: ap.error('--sign needs --key')
        return sign(a.key, a.sign)
    if a.verify:
        if not a.public_key: ap.error('--verify needs --public-key')
        print('public key fingerprint sha256:', fingerprint(a.public_key.read_bytes()))
        worst = 0
        for f in a.verify:
            rc, msg = verify_one(a.public_key, f, a.expected_fingerprint); worst = max(worst, rc)
            print('%s: %s' % (Path(f).name, msg))
        return worst
    ap.error('give --sign, --verify or --fingerprint')


if __name__ == '__main__':
    sys.exit(main())
