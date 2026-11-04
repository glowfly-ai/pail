# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""SD3 (see spec/ARCHITECTURE.md): BG deployment gate S0~S3, evaluated inside
the node process instead of only in the entrypoint script.

Twin of ``include/pail_deploy_guard/deploy_guard.hpp``. The two implementations
are held together by ``test/guard_matrix.tsv``, which both test suites read.

``evaluate`` is pure: resolved inputs in, findings out. ``resolve`` and
``enforce`` are the impure wrappers.
"""

import os
import sys

EXIT_CONFIG = 78  # sysexits.h EX_CONFIG

# `L10` . Byte-identical to the C++ ``kIdentityPrefix`` and to
# Go's ``deploysec.IdentityPrefix``: one deployment emits all three, and a log
# filter that learns one head would silently miss the others.
IDENTITY_PREFIX = 'PAIL PREFLIGHT IDENTITY:'


def emit_process_identity(component):
    """Write the process credentials this component actually runs with.

    It reports, it does not judge. ``uid=0`` is not refused here: whether root is
    acceptable is a deployment decision and ``U-E3`` kept ``L10`` delegated. What
    was missing was not the isolation — the containers already run unprivileged —
    but any line saying so. Without it a unit shipped without ``User=`` looks
    exactly like one shipped with it.

    Real and effective ids are printed separately. Equal is the common case; when
    they differ the process was launched setuid, and folding the two into one
    field would make that indistinguishable from the ordinary case (``H-B2``).
    """
    sys.stderr.write('%s uid=%d euid=%d gid=%d egid=%d component=%s\n'
                     % (IDENTITY_PREFIX, os.getuid(), os.geteuid(),
                        os.getgid(), os.getegid(), component))
    sys.stderr.flush()


class GuardInput:
    def __init__(self, component, profile="", security_enable="", security_strategy="",
                 keystore="", enclave_provisioned=False, effective_enclave="/"):
        self.component = component
        self.profile = profile
        self.security_enable = security_enable
        self.security_strategy = security_strategy
        self.keystore = keystore
        self.enclave_provisioned = enclave_provisioned
        self.effective_enclave = effective_enclave


class GuardResult:
    def __init__(self, profile, fail):
        self.profile = profile
        self.fail = fail  # list of (id, detail)


def expected_enclave(component):
    return '/' + component


def evaluate(inp):
    profile = inp.profile or 'production'
    fail = []

    if profile not in ('production', 'dev'):
        # The profile decides how findings are enforced. If we cannot trust it,
        # reporting the rest would suggest a strictness we cannot deliver.
        fail.append(('S0', 'PAIL_PROFILE=%s (want production|dev)' % inp.profile))
        return GuardResult(profile, fail)

    if inp.security_enable != 'true':
        fail.append(('S1',
                     'ROS_SECURITY_ENABLE=%s (want true) — DDS participant auth and topic '
                     'access control are OFF; any process on the domain can publish the '
                     'drive topic' % (inp.security_enable or '<unset>')))
        return GuardResult(profile, fail)  # strategy/enclave are meaningless while off

    if inp.security_strategy != 'Enforce':
        fail.append(('S2',
                     'ROS_SECURITY_STRATEGY=%s (want Enforce) — unsecured participants '
                     'would be silently permitted' % (inp.security_strategy or '<unset>')))

    if not inp.keystore:
        fail.append(('S3', 'ROS_SECURITY_KEYSTORE unset'))
    elif not inp.enclave_provisioned:
        fail.append(('S3', 'enclave not provisioned: %s/enclaves/%s '
                           '(run scripts/sros2_provision.sh)' % (inp.keystore, inp.component)))

    want = expected_enclave(inp.component)
    if inp.effective_enclave != want:
        fail.append(('S3',
                     'effective enclave %s != %s — the process would load another '
                     "component's credentials (check --enclave and "
                     'ROS_SECURITY_ENCLAVE_OVERRIDE)' % (inp.effective_enclave or '<unset>', want)))

    return GuardResult(profile, fail)


def effective_enclave_from_argv(argv):
    """Last --enclave on the command line, matching rcl's last-wins parsing.

    '/' is rcl's default when the argument is absent.
    """
    enclave = '/'
    for i in range(len(argv) - 1):
        if argv[i] == '--enclave':
            enclave = argv[i + 1]
    return enclave


def effective_enclave(override_env, argv):
    """rcl_get_secure_root(): ROS_SECURITY_ENCLAVE_OVERRIDE, when set, replaces the
    enclave the process loads credentials from — the command line no longer
    decides. Checking argv alone would leave that path open.
    """
    return override_env or effective_enclave_from_argv(argv)


def resolve(component, argv):
    keystore = os.environ.get('ROS_SECURITY_KEYSTORE', '')
    provisioned = False
    if keystore:
        provisioned = os.path.isdir(os.path.join(keystore, 'enclaves', component))
    return GuardInput(
        component=component,
        profile=os.environ.get('PAIL_PROFILE', ''),
        security_enable=os.environ.get('ROS_SECURITY_ENABLE', ''),
        security_strategy=os.environ.get('ROS_SECURITY_STRATEGY', ''),
        keystore=keystore,
        enclave_provisioned=provisioned,
        effective_enclave=effective_enclave(
            os.environ.get('ROS_SECURITY_ENCLAVE_OVERRIDE', ''), argv),
    )


def enforce(component, argv=None):
    """Evaluate, report on stderr, and exit 78 when production has findings.

    Call before rclpy.init so a refused process never joins the DDS domain.
    """
    # `L10` 관측점. 아래 세 갈래는 전부 일찍 빠져나가고(OK 반환 · dev 반환 ·
    # ``sys.exit``), 그중 마지막이 정확히 "잘못 올린 배치"다. 평가 뒤에 두면 가장
    # 알고 싶은 경우에만 줄이 안 나온다.
    emit_process_identity(component)
    if argv is None:
        argv = sys.argv
    inp = resolve(component, argv)
    r = evaluate(inp)
    tail = ' [profile=%s component=%s enclave=%s]' % (r.profile, component, inp.effective_enclave)

    if not r.fail:
        sys.stderr.write('PAIL PREFLIGHT: profile=%s OK (S0,S1,S2,S3) component=%s enclave=%s\n'
                         % (r.profile, component, inp.effective_enclave))
        sys.stderr.flush()
        return

    if r.profile == 'dev':
        ids = ','.join(f[0] for f in r.fail)
        sys.stderr.write('PAIL PREFLIGHT: profile=dev INSECURE(%s) component=%s — NOT FOR PRODUCTION\n'
                         % (ids, component))
        for fid, detail in r.fail:
            sys.stderr.write('PAIL PREFLIGHT:   %s %s\n' % (fid, detail))
        sys.stderr.flush()
        return

    for fid, detail in r.fail:
        sys.stderr.write('PAIL PREFLIGHT FAIL: %s %s%s\n' % (fid, detail, tail))
    sys.stderr.write('PAIL PREFLIGHT FAIL: refusing to start. Set PAIL_PROFILE=dev to run '
                     'without these protections (DEV ONLY).\n')
    sys.stderr.flush()
    sys.exit(EXIT_CONFIG)
