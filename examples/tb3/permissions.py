#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Executable TB3 access contract: runner, service and shared observation paths."""
import argparse
import json
import hashlib
import shutil
import os
from pathlib import Path
import stat
import sys

DIRECTORIES = {'.': 0o755, 'evidence': 0o755, 'evidence/runtime': 0o755,
               'runtime': 0o755, 'runtime/config': 0o700, 'runtime/scripts': 0o755,
               'runtime/reference': 0o755, 'control': 0o755, 'blackbox': 0o700,
               'keyring-state': 0o700, 'agent-state': 0o700, 'root-keys': 0o700}
SERVICE_OWNED = ['runtime/config', 'blackbox', 'keyring-state', 'agent-state', 'evidence/runtime']
REFERENCE_SOURCES = {name: 'examples/tb3/'+name for name in ('tb3_reference.launch.py','mock_io.py','fastdds_loopback.xml','permissions.py')}
REFERENCE_SOURCES['raw_retention.py'] = 'examples/common/raw_retention.py'
REFERENCE_FILES = list(REFERENCE_SOURCES)


def describe():
    return {'directories': {p: format(m, '04o') for p, m in DIRECTORIES.items()},
            'service_owned': SERVICE_OWNED, 'reference_files': REFERENCE_FILES, 'reference_sources': REFERENCE_SOURCES,
            'shared_log_mode': '0644', 'private_key_mode': '0600',
            'roles': {'runner': 'creates control; reads observations', 'service': 'reads config/reference; writes observations/journal'}}


def stage_reference(state, core, demo=False):
    if core is None:raise ValueError('--core is required for stage')
    reference=state/'runtime/reference'
    sources=dict(REFERENCE_SOURCES)
    if demo:sources['demo_io.py']='examples/tb3/demo_io.py'
    # Check the entire declared dependency set before writing any file.
    for name,relative in sources.items():
        if not (core/relative).is_file():raise ValueError('Missing reference dependency: '+relative)
        if (reference/name).exists() or (reference/name).is_symlink():raise ValueError('Reference already staged: '+name)
    hashes={}
    for name,relative in sources.items():
        target=reference/name
        with (core/relative).open('rb') as source,target.open('xb') as out:
            shutil.copyfileobj(source,out)
        target.chmod(0o644)
        hashes[name]=hashlib.sha256(target.read_bytes()).hexdigest()
    print(json.dumps(dict(sha256=hashes,mode='0644',source_unchanged=True)))


def initialize(state):
    if state.exists() and any(state.iterdir()): raise ValueError('Use a new, empty state')
    for name, mode in DIRECTORIES.items():
        p = state / name
        p.mkdir(parents=True, exist_ok=True)
        p.chmod(mode)


def prepare(state):
    if os.geteuid() != 0: raise ValueError('Ownership preparation requires the scoped root container')
    for name in SERVICE_OWNED:
        root = state / name
        for p in [root] + list(root.rglob('*')):
            if p.is_symlink():
                target=p.resolve()
                if name!='runtime/config' or not target.exists() or root.resolve() not in target.parents:
                    raise ValueError('Symlink leaves the generated config tree: '+str(p))
                os.lchown(p,10001,10001)  # SROS2 links to its own generated CA/governance files.
            else:
                os.chown(p, 10001, 10001)
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'common'))
    from raw_retention import initialize as prepare_raw
    prepare_raw(state/'evidence/runtime',{r:{'uid':10001,'gid':10001} for r in ('planner','base','safety','evidence')})
    # Ownership changes do not set permissions. Apply the declared directory modes explicitly.
    for name, mode in DIRECTORIES.items(): (state / name).chmod(mode)


def runtime_probe(state):
    if os.getuid() != 10001: raise ValueError('Probe must run as service UID 10001')
    for name in REFERENCE_FILES:
        with (state / 'runtime/reference' / name).open('rb') as f: f.read(1)
    with (state / 'control/input.json').open('rb') as f: f.read(1)
    for name in ['issuer_ed25519.json', 'agent_ed25519.json']:
        p = state / 'runtime/config/keys' / name
        if stat.S_IMODE(p.stat().st_mode) != 0o600: raise ValueError('Private key mode must remain 0600')
        with p.open('rb') as f: f.read(1)
    for name in ['blackbox', 'keyring-state']:
        p = state / name / '.write-probe'
        fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd); p.unlink()
    p = state / 'evidence/runtime/access-probe.json'
    fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    os.fchmod(fd, 0o644)
    with os.fdopen(fd, 'w') as f: json.dump({'service_uid': os.getuid(), 'observation_write': True}, f)
    print('ACCESS_CONTRACT: service reads reference/private keys and writes observations/journal')


def host_probe(state):
    p = state / 'evidence/runtime/access-probe.json'
    got = json.loads(p.read_text())
    if got != {'service_uid': 10001, 'observation_write': True}: raise ValueError('Missing or unexpected service observation')
    for name, mode in DIRECTORIES.items():
        if stat.S_IMODE((state / name).stat().st_mode) != mode:
            raise ValueError('Directory mode differs from contract: ' + name)
    if stat.S_IMODE(p.stat().st_mode) != 0o644: raise ValueError('Shared observation mode differs from contract')
    result = {'passed': True, 'runner_uid': os.getuid(), 'service_uid': 10001,
              'runtime_observation_directory_mode': '0755', 'shared_log_mode': '0644',
              'private_keys_checked_by_service': '0600', 'scope': 'actual cross-UID read/write, not chmod success alone'}
    (state / 'evidence/access-contract.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action', choices=['describe', 'init', 'stage', 'prepare', 'runtime', 'host'])
    ap.add_argument('--state', type=Path)
    ap.add_argument('--core', type=Path)
    ap.add_argument('--demo', action='store_true')
    a = ap.parse_args()
    try:
        if a.action == 'describe': print(json.dumps(describe())); return 0
        if a.state is None: raise ValueError('--state is required')
        if a.action == 'stage':stage_reference(a.state,a.core,a.demo);return 0
        {'init': initialize, 'prepare': prepare, 'runtime': runtime_probe, 'host': host_probe}[a.action](a.state)
        return 0
    except (OSError, ValueError) as exc:
        print('ACCESS_CONTRACT: REFUSED: '+str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__': sys.exit(main())
