#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Build a native local viewer with Docker; read only the E2E's exported journal snapshot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def port_free(port):
    """True when this process could bind 127.0.0.1:port now. Without SO_REUSEADDR the bind also
    fails when another process listens on the wildcard address (Linux and macOS)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', port))
        return True
    except OSError:
        return False


def answered(child, port, timeout_s=30):
    """The viewer we started answers /healthz, and it is still our process that runs."""
    import time
    import urllib.request
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if child.poll() is not None:
            return False
        try:
            with urllib.request.urlopen('http://127.0.0.1:%d/healthz' % port, timeout=2) as r:
                if r.status == 200 and child.poll() is None:
                    return True
        except OSError:
            pass
        time.sleep(0.2)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--state', required=True, type=Path, help='Completed E2E state directory')
    ap.add_argument('--port', type=int, default=18090)
    ap.add_argument('--check-only', action='store_true', help='Reindex and compare origins, then exit')
    ap.add_argument('--skip-build', action='store_true', help='Reuse this state viewer binary previously built by this tool')
    a = ap.parse_args()
    if platform.system() not in ['Darwin', 'Linux']:
        ap.error('Run in macOS or Linux/WSL2, not native Windows')
    arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64', 'AMD64': 'amd64'}.get(platform.machine())
    if not arch or not 1 <= a.port <= 65535:
        ap.error('Unsupported CPU or invalid port')
    state = a.state.expanduser().resolve()
    journal = state / 'viewer-input'
    registry = state / 'evidence/robot_registry.yaml'
    keyring = state / 'evidence/verification-keyring.json'
    # Ports first (P24-N1, executed form of the bind-first pin): a busy port is refused before the journal is read or
    # anything is built, and the address is printed only once this viewer answers on it (below).
    if not a.check_only and not port_free(a.port):
        print('PORT_CHECK: BUSY %d on 127.0.0.1. Another process (perhaps an earlier viewer) holds it; '
              'choose another with --port.' % a.port, file=sys.stderr, flush=True)
        return 2
    try:
        meta = json.loads((state / 'evidence/viewer-input-manifest.json').read_text())
        expected = meta['files_sha256']
        actual = {f.relative_to(journal).as_posix(): f for f in journal.rglob('*') if f.is_file()}
        if set(actual) != set(expected) or any(hashlib.sha256(actual[n].read_bytes()).hexdigest() != h for n, h in expected.items()):
            raise ValueError('Journal snapshot differs from its export manifest')
        if not expected:
            raise ValueError('Journal snapshot is empty; inspect E2E results before viewing')
        for f in [registry, keyring]:
            with f.open('rb') as stream: stream.read(1)
        out = state / 'viewer'
        out.mkdir(mode=0o700, exist_ok=True)
        binary = out / 'pail_telemetryd'
        if not a.skip_build:
            image = 'pail/viewer-builder:' + (ROOT / 'VERSION').read_text().strip().replace('+', '-')
            print('Building local viewer using Docker; first build can take several minutes.', flush=True)
            subprocess.run(['docker', 'build', '--target', 'builder', '-f', str(ROOT / 'docker/Dockerfile.cloud'), '-t', image, str(ROOT)], check=True)
            subprocess.run(['docker', 'run', '--rm', '--network', 'none', '-u', '0:0',
                            '-v', str(out) + ':/out', '-w', '/repo/cloud', '-e', 'GOCACHE=/tmp/gocache',
                            '-e', 'CGO_ENABLED=0', '-e', 'GOOS=' + ('darwin' if platform.system() == 'Darwin' else 'linux'),
                            '-e', 'GOARCH=' + arch, '--entrypoint', 'sh', image, '-c',
                            'go build -mod=readonly -tags pail_generated -o /out/pail_telemetryd ./cmd/pail_telemetryd && chown \"$1:$2\" /out/pail_telemetryd',
                            'viewer-build', str(os.getuid()), str(os.getgid())], check=True)
        if not binary.is_file():
            raise ValueError('Viewer binary missing; run without --skip-build')
        binary.chmod(0o700)
        args = ['-dir', str(out), '-blackbox-dir', str(journal)]
        subprocess.run([str(binary), '-reindex'] + args, check=True)
        subprocess.run([str(binary), '-index-check'] + args, check=True)
        if a.check_only: return 0
        # Let the OS choose an unused local UDP observation port. This recipe uses a snapshot, not a live feed.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0)); udp = sock.getsockname()[1]
        if os.environ.get('PAIL_TELEMETRY_TOKEN'):
            raise ValueError('This local-only recipe does not provide browser bearer login; unset PAIL_TELEMETRY_TOKEN for this invocation')
        env = dict(os.environ, PAIL_PROFILE='dev', PAIL_KEYRING_MODE='unsigned-dev', PAIL_KEYRING=str(keyring))
        # The address used to be printed before the viewer bound its port, so a
        # port already held by an older viewer showed THAT viewer's journal under this URL.
        # Refuse a busy port (taken since the check above, e.g. during the build), and print the address only once
        # this viewer answers on it.
        if not port_free(a.port):
            print('PORT_CHECK: BUSY %d on 127.0.0.1. Another process (perhaps an earlier viewer) holds it; '
                  'choose another with --port.' % a.port, file=sys.stderr, flush=True)
            return 2
        child = subprocess.Popen([str(binary)] + args + ['-registry', str(registry), '-http', '127.0.0.1:' + str(a.port), '-listen', '127.0.0.1:' + str(udp)], env=env)
        if not answered(child, a.port):
            child.terminate(); child.wait(timeout=10)
            print('VIEWER: REFUSED: the viewer did not start on 127.0.0.1:%d' % a.port, file=sys.stderr, flush=True)
            return 2
        print('Local snapshot viewer: http://127.0.0.1:%d/dashboard/?tab=timeline&preset=6h' % a.port, flush=True)
        print('Not a live journal feed. Stop with Ctrl-C. No private key directory is read.', flush=True)
        try: return child.wait()
        except KeyboardInterrupt:
            child.terminate(); child.wait(timeout=10); return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('VIEWER: REFUSED:', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    # a failure ends with a named refusal line, never a bare traceback (class pin C2)
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        print('VIEWER_REFUSED: ' + str(exc), file=sys.stderr, flush=True)
        sys.exit(2)
