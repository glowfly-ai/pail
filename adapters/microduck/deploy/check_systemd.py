#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""C6: unchanged staged adapter unit + real distribution target/slice definitions, without booting systemd."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def verify(stage):
    analyzer = shutil.which('systemd-analyze')
    if analyzer is None:
        return {'status': 'NOT_RUN', 'reason': 'systemd_analyze_unavailable'}
    source = next((p for p in [Path('/usr/lib/systemd/system'), Path('/lib/systemd/system')]
                   if (p / 'sysinit.target').is_file() and (p / 'basic.target').is_file()), None)
    if source is None:
        return {'status': 'NOT_RUN', 'reason': 'distribution_unit_definitions_unavailable'}
    unit = stage / 'etc/systemd/system/pail-duckd.service'
    original = unit.read_bytes()
    dest = stage / 'usr/lib/systemd/system'
    for path in [dest, *dest.parents]:
        if path == stage:
            break
        if path.is_symlink():
            raise ValueError('Symlink in validation support path: ' + str(path))
    dest.mkdir(parents=True, exist_ok=True)
    copied = {}
    # These are actual vendor files, not invented targets. Never copy host enablement
    # symlinks/generators or custom services: this is a static adapter-unit check,
    # not a reproduction of a booted board's dependency graph.
    for path in sorted(source.iterdir()):
        if path.suffix not in ('.target', '.slice') or not path.is_file():
            continue
        data = path.read_bytes()
        target = dest / path.name
        if target.is_symlink() or (target.exists() and target.read_bytes() != data):
            raise ValueError('Conflicting verification support file: ' + str(target))
        target.write_bytes(data)
        target.chmod(0o644)
        copied[path.name] = hashlib.sha256(data).hexdigest()
    for name in ['basic.target', 'sysinit.target', 'local-fs.target', 'shutdown.target']:
        if name not in copied:
            raise ValueError('Required distribution definition missing: ' + name)
    cmd = [analyzer, 'verify', '--man=no', '--root=' + str(stage), str(unit)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if unit.read_bytes() != original:
        raise ValueError('Adapter unit changed during verification')
    return {'status': 'PASS' if p.returncode == 0 else 'FAIL', 'exit_code': p.returncode,
            'reason': 'adapter_unit_static_verification', 'command': cmd,
            'systemd_version': subprocess.check_output([analyzer, '--version'], text=True).splitlines()[0],
            'vendor_units_source': str(source.resolve()), 'vendor_units_sha256': copied,
            'adapter_unit_sha256': hashlib.sha256(original).hexdigest(),
            'stdout': p.stdout, 'stderr': p.stderr,
            'not_verified': ['upstream robotd unit and board enablement/generators', 'live systemd startup, restart, drop-in application and update survival']}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--stage', type=Path, required=True)
    ap.add_argument('--report', type=Path, required=True)
    a = ap.parse_args()
    try:
        stage = a.stage.resolve()
        if stage == Path('/') or not stage.is_dir():
            raise ValueError('A populated private staging root is required')
        result = verify(stage)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result = {'status': 'FAIL', 'reason': 'verification_environment_error', 'detail': str(exc)}
    a.report.write_text(json.dumps(result, indent=2) + '\n')
    print('C6_DETAIL=' + json.dumps(result))
    return {'PASS': 0, 'FAIL': 1, 'NOT_RUN': 2}[result['status']]


if __name__ == '__main__':
    sys.exit(main())
