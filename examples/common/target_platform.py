# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Explicit delivery targets; server architecture is not the operator's Mac."""
import struct

ARCHITECTURES = ('arm64', 'amd64')


def architecture(value):
    if value not in ARCHITECTURES:
        raise ValueError('Unsupported target architecture: ' + str(value))
    return value


def build_architecture(build):
    # Legacy receipts were exclusively arm64; never infer amd64 from the host.
    return architecture(build.get('architecture', 'arm64'))


def image_tags(version, arch):
    suffix = '' if architecture(arch) == 'arm64' else '-amd64'
    return {role: 'pail/' + name + ':' + version + suffix for role, name in
            (('issuer', 'issuer-eval'), ('microduck', 'core-microduck'), ('tb3_gate', 'core-tb3-gate'))}


def artifact_names(version, arch):
    platform = 'linux-' + architecture(arch)
    return {'issuer': f'PAIL-Issuer-Eval-{version}-{platform}-image.tar',
            'runtime': f'PAIL-Core-Runtime-{version}-{platform}-images.tar',
            'evaluation': f'PAIL-Evaluation-{version}' + ('' if arch == 'arm64' else '-' + platform) + '.zip',
            'offline': f'PAIL-Evaluation-{version}-{platform}-offline.zip'}


def native_targets(arch):
    return [('darwin', 'arm64'), ('linux', architecture(arch))]


# Every native helper a bundle ships for each target of native_targets(): the host dashboard and, since
# 0.2.0-preview.42, the standalone release verifier (so the mandatory signature verification needs no python
# `cryptography` or OpenSSL 3 on the recipient host). Both are built from the candidate's own staged cloud/ tree.
NATIVE_BINARIES = ('pail_telemetryd', 'pail_verify')


def native_binaries():
    return NATIVE_BINARIES


def native_keys(arch):
    """`<binary>-<os>-<arch>` for every shipped native helper of a bundle architecture."""
    return [name + '-' + host + '-' + host_arch for name in native_binaries() for host, host_arch in native_targets(arch)]


def validate_native(path, os_name, arch):
    """Inspect executable headers, not executable names. Does not execute binaries."""
    architecture(arch)
    with path.open('rb') as stream:
        head = stream.read(64)
    if os_name == 'linux':
        if len(head) < 64 or head[:6] != b'\x7fELF\x02\x01':
            raise ValueError('Expected ELF64 little-endian native helper')
        if struct.unpack_from('<H', head, 18)[0] != {'arm64': 183, 'amd64': 62}[arch]:
            raise ValueError('Native helper architecture mismatch')
    elif os_name == 'darwin':
        if len(head) < 32 or head[:4] != b'\xcf\xfa\xed\xfe' or struct.unpack_from('<I', head, 4)[0] != {'arm64': 0x100000c, 'amd64': 0x1000007}[arch]:
            raise ValueError('Expected matching Mach-O64 native helper')
    else:
        raise ValueError('Unsupported native helper OS')
