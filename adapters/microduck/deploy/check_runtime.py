#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""C5: run the staged ELF with its staged library; distinguish unsupported hosts from broken delivery."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shlex
import struct
import subprocess
import sys


def check(binary, libdir, unit):
    command = re.sub(r'\\\n[ \t]*', ' ', unit.read_text())
    starts = [s for s in re.findall(r'^ExecStart=(.*)$', command, re.M) if s.strip()]
    if len(starts) != 1:
        raise ValueError('Expected one adapter ExecStart command')
    argv = shlex.split(starts[0])
    required = sorted({s.split('=', 1)[0] for s in argv[1:] if s.startswith('--')})
    if not required:
        raise ValueError('Adapter unit exposes no flags to check')
    with binary.open('rb') as source:
        header = source.read(20)
    if len(header) < 20 or header[:4] != b'\x7fELF' or header[5] not in (1, 2):
        return {'status': 'FAIL', 'reason': 'invalid_elf', 'detail': 'Expected a Linux ELF artifact, not a script or an unrecognized binary'}
    machine = struct.unpack('<H' if header[5] == 1 else '>H', header[18:20])[0]
    host = platform.machine().lower()
    expected = {'aarch64': 183, 'arm64': 183, 'x86_64': 62, 'amd64': 62, 'armv7l': 40, 'riscv64': 243}.get(host)
    meta = {'host_os': platform.system(), 'host_arch': host, 'elf_machine': machine}
    if platform.system() != 'Linux' or expected is None or machine != expected:
        return dict(meta, status='NOT_RUN', reason='unsupported_host_or_arch', detail='Run on a compatible Linux host; this is not a loader-success claim')
    env = dict(os.environ)
    prior = [p for p in env.get('LD_LIBRARY_PATH', '').split(':') if p]
    env['LD_LIBRARY_PATH'] = ':'.join([str(libdir.resolve()), *prior])
    try:
        result = subprocess.run([str(binary), '--help'], env=env, capture_output=True, text=True, timeout=15)
    except OSError as exc:
        return dict(meta, status='FAIL', reason='execution_error', detail=str(exc))
    except subprocess.TimeoutExpired:
        return dict(meta, status='FAIL', reason='help_timeout', detail='Staged --help exceeded 15 seconds')
    meta.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                staged_library_path=str(libdir.resolve()))
    if result.returncode:
        reason = 'loader_dependency' if 'shared libraries' in result.stderr or 'version `' in result.stderr else 'binary_help_failed'
        return dict(meta, status='FAIL', reason=reason)
    text = result.stdout + result.stderr
    missing = [flag for flag in required if not re.search(r'(?<![\w-])' + re.escape(flag) + r'(?![\w-])', text)]
    return dict(meta, status='FAIL' if missing else 'PASS', reason='missing_unit_flags' if missing else 'staged_help_valid', required_flags=required, missing_flags=missing)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', type=Path, required=True)
    ap.add_argument('--libdir', type=Path, required=True)
    ap.add_argument('--unit', type=Path, required=True)
    ap.add_argument('--report', type=Path, required=True)
    a = ap.parse_args()
    try:
        result = check(a.binary, a.libdir, a.unit)
    except (OSError, ValueError) as exc:
        result = {'status': 'FAIL', 'reason': 'unreadable_artifact', 'detail': str(exc)}
    a.report.write_text(json.dumps(result, indent=2) + '\n')
    print('C5_DETAIL=' + json.dumps(result))
    return {'PASS': 0, 'FAIL': 1, 'NOT_RUN': 2}[result['status']]


if __name__ == '__main__':
    sys.exit(main())
