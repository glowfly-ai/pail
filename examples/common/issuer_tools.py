# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Run a tool beside an Issuer container instead of inside it.

The Issuer image holds the Issuer executables and nothing else: no interpreter, no shell. A probe that used to be
run with `docker exec <issuer> python …` runs in a short-lived container of an image that has Python (the
Microduck image) which joins the Issuer container's network namespace, so `127.0.0.1:<port>` is the Issuer exactly
as it was inside it. The namespace is joined at start, so this also works right after the Issuer was restarted;
a long-lived container that shared the namespace would be left on the old one.

The container gets no capability, no new privileges, no pull, and only the mounts it is given. A mount is
read-only unless its target is listed in `writable`.
"""
import subprocess
import uuid


def _mount(mount, writable):
    if isinstance(mount, dict):
        if mount.get('type') != 'volume' or not mount.get('source') or not mount.get('target'):
            raise ValueError('a mapping mount must be a named volume with source and target')
        spec = 'type=volume,source=%s,target=%s' % (mount['source'], mount['target'])
        if mount['target'] not in writable:
            spec += ',readonly'
        if mount.get('subpath'):
            spec += ',volume-subpath=' + mount['subpath']
        return ['--mount', spec]
    parts = str(mount).split(':')
    if len(parts) not in (2, 3) or not parts[0] or not parts[1].startswith('/'):
        raise ValueError('mount must be SOURCE:/TARGET[:ro]: ' + str(mount))
    if parts[1] not in writable and parts[2:] != ['ro']:
        raise ValueError('a tool mount is read-only unless its target is declared writable: ' + str(mount))
    return ['-v', str(mount)]


def command(image, issuer_container, argv, mounts=(), env=None, user=None, name=None, writable=(), workdir=None):
    """The `docker run` argument list of one tool run beside `issuer_container`."""
    if not image or not issuer_container or not argv:
        raise ValueError('image, Issuer container and command are required')
    out = ['docker', 'run', '--rm', '--name', name or ('pail-tool-' + uuid.uuid4().hex[:12]), '--pull', 'never',
           '--network', 'container:' + issuer_container, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
           '--pids-limit', '128', '--memory', '256m']
    if user:
        out += ['--user', str(user)]
    if workdir:
        out += ['--workdir', workdir]
    for mount in mounts:
        out += _mount(mount, tuple(writable))
    for key, value in sorted((env or {}).items()):
        out += ['-e', '%s=%s' % (key, value)]
    return out + [image] + [str(a) for a in argv]


def run(image, issuer_container, argv, timeout=30, **kw):
    """Run the tool and return the CompletedProcess. On a timeout the container is removed and TimeoutExpired is
    raised again: nothing of ours stays on the Issuer's network namespace."""
    name = kw.pop('name', None) or ('pail-tool-' + uuid.uuid4().hex[:12])
    argv = command(image, issuer_container, argv, name=name, **kw)
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)
        raise
