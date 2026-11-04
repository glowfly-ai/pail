#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Compare a pristine extracted release with its trusted delivery manifest (not a signature)."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
sys.dont_write_bytecode = True
from release_identity import validate_identity


ISSUER_DIR = 'cloud/issuer/'
BUSL_SPDX = 'SPDX-License-Identifier: BUSL-1.1'
PROLOGUE = 8
RE_BUSL_HEADER = re.compile(r'^\s*(?:#|//|/\*|\*|<!--|;|--)\s*SPDX-License-Identifier:\s*BUSL-1\.1\b')


def verify_with_go(root, manifest, public_key, expected_fingerprint=None):
    """(rc, message) from `go run ./cloud/cmd/pail_verify --sig-only` when `go` and the verifier source are present in
    the extracted tree, else (None, reason). The verifier imports only the standard library, so `go run` needs no
    module download. rc 0 verified / 1 bad signature or key mismatch; any other outcome falls back to sign_release."""
    import shutil
    import subprocess
    go = shutil.which('go')
    source = Path(root) / 'cloud/cmd/pail_verify'
    if not go or not source.is_dir():
        return None, 'go toolchain or cloud/cmd/pail_verify not present'
    cmd = [go, 'run', './cloud/cmd/pail_verify', '--sig-only', '--manifest', str(Path(manifest).resolve()), '--public-key', str(Path(public_key).resolve())]
    if expected_fingerprint:
        cmd += ['--expected-fingerprint', expected_fingerprint]
    try:
        r = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, 'go run failed: ' + str(exc)[:160]
    if r.returncode in (0, 1) and r.stdout.startswith('SIGNATURE: '):
        return r.returncode, r.stdout.strip()[len('SIGNATURE: '):] + ' (go run)'
    return None, 'go run failed: ' + (r.stderr or r.stdout).strip()[:160]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate manifest field: ' + key)
        result[key] = value
    return result


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def verify(root, manifest, archive=None, expected_release=None, identity_root=None):
    m = json.loads(manifest.read_text(), object_pairs_hook=unique_object)
    # The PAIL-Issuer overlay carries no release.json of its own; its identity comes
    # from the PAIL-Core (or complete) tree it belongs to.
    identity = validate_identity(identity_root if identity_root is not None else root)
    if m.get('release_id') != identity['release_id'] or m.get('artifact') not in identity['artifacts'].values():
        raise ValueError('Manifest identity disagrees with this source release')
    bundle = m.get('bundle')
    if bundle is not None and identity['artifacts'].get(bundle) != m.get('artifact'):
        raise ValueError('Manifest bundle does not match its artifact name')
    if expected_release is not None and expected_release != identity['release_id']:
        raise ValueError('Requested release differs from actual source/manifest identity')
    expected = m['source_files_sha256']
    if not isinstance(expected, dict) or not expected or m['file_count'] != len(expected):
        raise ValueError('Nonempty file map and file_count must agree')
    for name, value in expected.items():
        rel = PurePosixPath(name)
        if (not name or rel.is_absolute() or '..' in rel.parts or '\\' in name
                or str(rel) != name or not re.fullmatch('[0-9a-f]{64}', value)):
            raise ValueError('Unsafe path or invalid digest: ' + name)
    if not root.is_dir() or root.is_symlink():
        raise ValueError('Root must be a real extracted directory')
    actual = {f.relative_to(root).as_posix(): f for f in root.rglob('*') if f.is_file() or f.is_symlink()}
    bad = []
    for name in sorted(set(actual) - set(expected)):
        bad.append('EXTRA ' + name)
    for name, want in expected.items():
        f = actual.get(name)
        if f is None:
            bad.append('MISSING ' + name)
        elif any(root.joinpath(*PurePosixPath(name).parts[:i]).is_symlink() for i in range(1, len(PurePosixPath(name).parts) + 1)):
            bad.append('SYMLINK ' + name)
        elif digest(f) != want:
            bad.append('MISMATCH ' + name)
    if archive is not None:
        if archive.name != m['artifact'] or archive.stat().st_size != m['bytes'] or digest(archive) != m['sha256']:
            bad.append('ARCHIVE_MISMATCH ' + archive.name)
    bad += check_bundle_map(root, m)
    return bad, len(expected), m.get('signature_status', 'unspecified; no signature verified'), bundle or 'unspecified'


def check_bundle_map(root, m):
    """Is the per-file bundle map self-consistent, and do issuer-bundle-headed files outside the issuer
    directory say so in their own header?

    The map is the answer to "which license covers which file". An external review
    (2026-09-18) found that a recipient had no tool that measured it: the table arrived as an
    assertion. A missing table is reported too — absent is not the same as correct.
    """
    table = m.get('source_files_bundle')
    if table is None:
        return ['BUNDLE_MAP_ABSENT source_files_bundle is missing from the manifest']
    out = []
    if not isinstance(table, dict) or set(table) != set(m['source_files_sha256']):
        return ['BUNDLE_MAP_KEYS source_files_bundle does not cover exactly the file map']
    tally = {}
    for name, member in table.items():
        if member not in ('core', 'issuer'):
            out.append('BUNDLE_MAP_VALUE %s -> %r (want core|issuer)' % (name, member))
            continue
        tally[member] = tally.get(member, 0) + 1
        # Directory rule: everything under cloud/issuer/ is issuer.
        if name.startswith(ISSUER_DIR) and member != 'issuer':
            out.append('BUNDLE_MAP_DIR %s is under %s but labelled %s' % (name, ISSUER_DIR, member))
        # An issuer file outside the directory can only be known by its own header — require it.
        if member == 'issuer' and not name.startswith(ISSUER_DIR):
            f = root / name
            try:
                head = f.read_text(errors='replace').splitlines()[:PROLOGUE]
            except OSError:
                out.append('BUNDLE_MAP_UNREADABLE ' + name)
                continue
            if not any(RE_BUSL_HEADER.match(line) for line in head):
                out.append('BUNDLE_MAP_SPDX %s is bundle issuer outside %s but does not state %s'
                           % (name, ISSUER_DIR, BUSL_SPDX))
    counts = m.get('bundle_file_counts')
    if counts is not None and counts != tally:
        out.append('BUNDLE_MAP_COUNTS bundle_file_counts %r disagrees with the map %r' % (counts, tally))
    # Reverse direction: when a file outside the directory states the issuer-bundle header ITSELF, the map has to
    # label it issuer. An external review (2026-09-18) relabelled WORKLOADS.yaml as core and
    # fixed the counts to match; that table was self-consistent and passed every check above
    # although the file's first line contradicted it. Only a comment line in the prologue
    # counts as a header — a string literal in the body is not one.
    for name, member in table.items():
        if member != 'core' or name.startswith(ISSUER_DIR):
            continue
        try:
            head = (root / name).read_text(errors='replace').splitlines()[:PROLOGUE]
        except OSError:
            continue  # a missing or unreadable file is already reported above (MISSING / MISMATCH)
        if any(RE_BUSL_HEADER.match(line) for line in head):
            out.append('BUNDLE_MAP_SPDX_REVERSE %s states %s in its prologue but the map labels it core'
                       % (name, BUSL_SPDX))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', required=True, type=Path)
    ap.add_argument('--manifest', required=True, type=Path)
    ap.add_argument('--zip', type=Path)
    ap.add_argument('--expected-release', help='Intended release ID, independent of supplied files')
    ap.add_argument('--identity-root', type=Path, help='Tree holding release.json/VERSION/RELEASE.md when --root is the issuer overlay alone')
    ap.add_argument('--public-key', type=Path, help='publisher public key (PEM); default <root>/RELEASE-SIGNING-KEY.pub')
    ap.add_argument('--expected-fingerprint', help='sha256 of the raw public key obtained outside the archive; a key that differs is refused')
    ap.add_argument('--allow-unsigned', action='store_true', help='accept the archive on digests only when no .sig is beside the manifest (the default refuses)')
    a = ap.parse_args()
    try:
        bad, count, signature, bundle = verify(a.root.absolute(), a.manifest, a.zip, a.expected_release,
                                               a.identity_root.absolute() if a.identity_root else None)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('RELEASE_VERIFY: CANNOT_CHECK:', exc)
        return 2
    for finding in bad:
        print(finding)
    print('RELEASE_VERIFY: %s files=%d findings=%d bundle=%s' % ('FAIL' if bad else 'PASS', count, len(bad), bundle))
    print('Manifest signature_status:', signature)
    public_key = a.public_key or (a.root / 'RELEASE-SIGNING-KEY.pub')
    # P22-L1: the manifest says whether a signature is required; a required signature that is absent is a failure,
    # not a quiet fall-back to digests. P22-M1: the key is checked against a fingerprint from outside the archive.
    required = not a.allow_unsigned   # P23-M1: nothing inside the archive can waive the signature
    sig_failed = False
    if Path(str(a.manifest) + '.sig').is_file():
        import importlib.util
        spec = importlib.util.spec_from_file_location('sign_release', Path(__file__).resolve().parent / 'sign_release.py')
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        if public_key.is_file():
            # preview.42: the Core ZIP carries the standalone verifier's source (standard library only), so a host with
            # the Go toolchain the README already requires verifies without python `cryptography` or OpenSSL 3.
            src, msg = verify_with_go(a.root, a.manifest, public_key, a.expected_fingerprint)
            if src is None:
                src, msg = mod.verify_one(public_key, a.manifest, a.expected_fingerprint)
            print('SIGNATURE:', msg)
            sig_failed = src == 1 or (src == 2 and required)
        else:
            print('SIGNATURE: .sig present but no public key at', public_key)
            sig_failed = required
    else:
        print('SIGNATURE: no .sig beside the manifest; digest comparison only, this run did not authenticate the publisher.'
              + ('; a signature is required (pass --allow-unsigned to accept digests only)' if required else ''))
        sig_failed = required
    if sig_failed:
        print('RELEASE_VERIFY: FAIL (signature)')
        return 1
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
