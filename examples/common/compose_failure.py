# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""One reading of a failed `docker compose up` (or `docker run`) for every runner.

A stack that did not come up is not a product verdict: the test could not run. Every runner that starts a
compose project therefore ends such a run as BLOCKED (exit 3), and the top-level line carries the cause and
the next action in one sentence, instead of leaving the raw compose error in a log file that the summary
does not quote (preview.23 evaluation P23-L1: the address-pool explanation lived in one runner while
`test-supersede` reported `RESULT=FAIL 0/8` for the same condition).

    from compose_failure import explain, blocked_line
    cause = explain(text_of_the_compose_output)        # '' when the text matches no known condition
    print(blocked_line('RIG_NOT_READY', cause, log_path))

The table below is matched against the daemon's words. Add a row when a new environmental refusal is seen;
never map a product error (a gate BLOCK, a token refusal) through here — those are verdicts, not blockers.
"""
import re

# (regex over the compose/docker output, code, cause, next action)
CONDITIONS = (
    (r'address pools have been fully subnetted|could not find an available, non-overlapping IPv4 address pool',
     'DOCKER_ADDRESS_POOL_EXHAUSTED',
     'Docker has no free subnet for a new network: stopped PAIL demos keep their networks until cleanup removes them (stop alone does not)',
     'run `evaluation.py cleanup --state <state>` for the states you no longer need (README section 7), then retry'),
    (r'port is already allocated|address already in use|bind: address already in use',
     'PORT_BUSY',
     'a published port is held by another process or container',
     'choose free ports for this run (the launcher prints the busy one) and retry'),
    (r'no space left on device',
     'DISK_FULL',
     'the Docker host has no free disk space for a new layer or volume',
     'free space on the Docker host (unused images: `docker image prune`), then retry'),
    (r'No such image|pull access denied|repository does not exist|manifest unknown',
     'IMAGE_MISSING',
     'a runtime image named by the lock is not in the local Docker store',
     'run `evaluation.py load` (or `load --images-dir`) for this release, then retry'),
    (r'Cannot connect to the Docker daemon|Is the docker daemon running',
     'DOCKER_UNREACHABLE',
     'the Docker daemon did not answer',
     'start Docker and run `evaluation.py doctor`, then retry'),
    (r'permission denied while trying to connect to the Docker daemon socket',
     'DOCKER_ACCESS_DENIED',
     'this user may not use the Docker socket',
     'run as a user in the docker group (README section 2), then retry'),
    (r'exec format error|no matching manifest for linux/|platform .* does not match',
     'ARCH_MISMATCH',
     'the images are built for another CPU architecture than this host',
     'use the bundle built for this architecture, or `--allow-emulation` where the tool offers it'),
)


def explain(text):
    """Return 'CODE — cause — next action' for the first known condition in text, else ''."""
    for pattern, code, cause, action in CONDITIONS:
        if re.search(pattern, text or '', re.I):
            return code + ' — ' + cause + ' — ' + action
    return ''


def explain_file(path, tail=20000):
    try:
        with open(path, 'r', errors='replace') as f:
            text = f.read()
    except OSError:
        return ''
    return explain(text[-tail:])


def blocked_line(code, cause, log):
    """The one line a runner prints when its stack did not come up: never 'FAIL', always the cause or the log."""
    return 'RESULT=BLOCKED ' + code + (' — ' + cause if cause else ' — cause not recognised; see ' + str(log)) + (' (log: ' + str(log) + ')' if cause else '')


def failed_step(label, rc, log, *extra_logs):
    """The message of the exception a launcher raises when one of its compose (or docker run) steps failed.

    The interactive demos (README section 4) are the first path a new developer walks, and they used to end such
    a failure as `DEMO_REFUSED: up rc=1; see .../up.log` while the test runners named the daemon's condition on
    the top line (preview.24 evaluation P24-L1). One builder for every launcher: the step, its exit code, the
    recognised condition with its next action, and the log to read.
    """
    cause = ''
    for path in (log,) + tuple(extra_logs):
        cause = explain_file(path)
        if cause:
            break
    head = 'STACK_NOT_UP: %s rc=%d' % (label, rc)
    return head + (' — ' + cause if cause else ' — cause not recognised') + '; see ' + str(log)
