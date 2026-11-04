# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""One rule for the compose project — and so container — names of the official examples (preview.40 review item
01): `pail-<kind>-<release token>-<12 hex>`. The kind of run, the release it was started from and a value unique
to the run are readable from `docker ps` alone; `evidence/console.json` records the same project beside the release id.

Runs of earlier releases carried no release token (`pail-duck-demo-<hex>`); `PROJECT_PATTERN` accepts both shapes so
that this release's `cleanup` and `stop --orphaned` still reach them. distribution/host_control.py carries the same
pattern string (it cannot import this module from a packaged tree); a contract test keeps the two equal."""
import re
import uuid
from pathlib import Path

KINDS = ('tb3-demo', 'tb3', 'duck-demo', 'duck', 'duck-fleet')
PROJECT_PATTERN = r'pail-(?:duck-(?:demo-|fleet-)?|tb3-(?:demo-)?)(?:[a-z0-9]+(?:-[a-z0-9]+)*-)?[a-f0-9]{10,32}'
_TOKEN_MAX = 24   # keeps the longest project name (`pail-duck-fleet-` + token + 12 hex) within 50 characters


def release_token(release_id):
    """The release id as compose accepts it in a project name: lower case, every run of other characters one `-`."""
    token = re.sub(r'[^a-z0-9]+', '-', str(release_id).lower()).strip('-')
    if not token:
        raise ValueError('RELEASE_ID_EMPTY')
    if len(token) > _TOKEN_MAX:
        raise ValueError('RELEASE_ID_TOO_LONG')
    return token


def release_id(root):
    """The release this tree is: its VERSION file (the same source as the automatic tests' core_version)."""
    return (Path(root) / 'VERSION').read_text().strip()


def project_name(kind, release, run_hex=None):
    if kind not in KINDS:
        raise ValueError('RUN_KIND_UNKNOWN: ' + str(kind))
    run_hex = run_hex or uuid.uuid4().hex[:12]
    if not re.fullmatch(r'[a-f0-9]{12}', run_hex):
        raise ValueError('RUN_ID_SHAPE')
    return 'pail-%s-%s-%s' % (kind, release_token(release), run_hex)


def parse_project(name):
    """(kind, release token or None, run hex) of one of our project names; None for any other string."""
    if not isinstance(name, str) or not re.fullmatch(PROJECT_PATTERN, name):
        return None
    head, _, run = name.rpartition('-')
    for kind in sorted(KINDS, key=len, reverse=True):   # 'duck-demo' before 'duck', 'tb3-demo' before 'tb3'
        prefix = 'pail-' + kind
        if head == prefix:
            return kind, None, run
        if head.startswith(prefix + '-'):
            return kind, head[len(prefix) + 1:], run
    return None
