# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""TC-AU-03 (static half) — logrotate copytruncate regression guard.

`copytruncate` truncates a log file in place while the writer holds it open,
which would zero a blackbox segment mid-write and silently snap the hash-chain.
The blackbox segments must only ever be rotated by the writer's own segment roll,
never by an external logrotate. This asserts no deploy config introduces
copytruncate. The runtime chain-intact half is covered by
`scenarios/audit/au01_cross_segment_chain.yaml` and the cross-segment unit test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]   # PAIL-v2/
PUBLIC = (REPO_ROOT / "cloud" / "go.mod").exists()
DEPLOY = REPO_ROOT if PUBLIC else REPO_ROOT / "deploy"

_CONFIG_GLOBS = ["*.yml", "*.yaml", "*.conf", "*.service", "*logrotate*"]


def _config_files():
    seen = set()
    for pat in _CONFIG_GLOBS:
        candidates = list(DEPLOY.glob(pat)) if PUBLIC else list(DEPLOY.rglob(pat))
        if PUBLIC:
            for directory in [REPO_ROOT / "config", REPO_ROOT / "examples"]:
                candidates.extend(directory.rglob(pat))
        for p in candidates:
            if p.is_file():
                seen.add(p)
    return sorted(seen)


@pytest.mark.unit
def test_no_copytruncate_in_deploy_configs():
    offenders = []
    for p in _config_files():
        text = p.read_text(encoding="utf-8")
        if "copytruncate" in text.lower():
            offenders.append(str(p.relative_to(REPO_ROOT)))
    assert not offenders, (
        "copytruncate found in deploy config(s) — would break the blackbox "
        f"hash-chain: {offenders}")


@pytest.mark.unit
def test_deploy_dir_present():
    # guards the test itself against silently scanning nothing
    assert DEPLOY.is_dir(), f"deploy dir missing at {DEPLOY}"
    assert _config_files(), "no deploy config files found to scan"
