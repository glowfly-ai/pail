#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Prepare only a fresh E2E state's runtime files, or export its stopped journal."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

UID = GID = 10001


def own_tree(root, uid, gid):
    for path in [root] + list(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symlink in managed runtime tree: ' + str(path))
        os.chown(path, uid, gid)
        path.chmod(0o700 if path.is_dir() else 0o600)


def prepare(state):
    dst = state / 'runtime/config'
    if dst.exists():
        raise ValueError('Runtime config already exists; use a new state')
    (state / 'runtime').mkdir(mode=0o755, exist_ok=True)
    state.chmod(0o755)
    (state / 'runtime').chmod(0o755)
    shutil.copytree(state / 'provision/config', dst)
    own_tree(dst, UID, GID)
    for name in ['blackbox', 'anchor']:
        own_tree(state / name, UID, GID)
    print('RUNTIME_FILES: prepared isolated config and writable journal/anchor for uid=10001')


def bundle(state, which):
    source = state / ('provision/config/keys/keyring_bundle.' + which + '.json')
    target = state / 'runtime/config/keys/keyring_bundle.json'
    if source.is_symlink() or target.is_symlink():
        raise ValueError('Bundle paths must not be symlinks')
    temp = target.with_suffix('.next')
    with temp.open('xb') as stream:
        stream.write(source.read_bytes())
        stream.flush()
        os.fsync(stream.fileno())
    os.chown(temp, UID, GID)
    temp.chmod(0o600)
    temp.replace(target)
    print('RUNTIME_FILES: installed ' + which + ' bundle')


def export(state, uid, gid):
    # Called only after this run's containers stop. Never copy provision/ or runtime/keys.
    dest = state / 'viewer-input'
    if dest.exists():
        raise ValueError('Viewer snapshot already exists; refusing to overwrite')
    source = state / 'blackbox'
    for path in source.rglob('*'):
        if path.is_symlink():
            raise ValueError('Refusing journal symlink: ' + str(path))
    shutil.copytree(source, dest)
    hashes = {f.relative_to(dest).as_posix(): hashlib.sha256(f.read_bytes()).hexdigest()
              for f in dest.rglob('*') if f.is_file()}
    own_tree(dest, uid, gid)
    meta = state / 'evidence/viewer-input-manifest.json'
    meta.write_text(json.dumps({'source': 'stopped run blackbox', 'files_sha256': hashes}, indent=2) + '\n')
    os.chown(meta, uid, gid)
    meta.chmod(0o600)
    print('RUNTIME_FILES: exported stopped journal snapshot; files=' + str(len(hashes)))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action', choices=['prepare', 'good', 'forged', 'export'])
    ap.add_argument('--state', type=Path, default=Path('/state'))
    ap.add_argument('--uid', type=int)
    ap.add_argument('--gid', type=int)
    a = ap.parse_args()
    try:
        if a.action == 'prepare': prepare(a.state)
        elif a.action in ['good', 'forged']: bundle(a.state, a.action)
        else:
            if a.uid is None or a.gid is None or min(a.uid, a.gid) < 0:
                raise ValueError('Export needs explicit nonnegative owner uid/gid')
            export(a.state, a.uid, a.gid)
        return 0
    except (OSError, ValueError) as exc:
        print('RUNTIME_FILES: REFUSED:', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
