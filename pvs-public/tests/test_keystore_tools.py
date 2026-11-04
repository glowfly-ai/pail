# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Host-tier tests for the SROS2 rig provisioner.

The provisioning itself is live-tier (it needs the `ros2 security` CLI), but the part that
made the Enforcement axis unrunnable on 2026-09-19 is not: the enclaves the rig adds after the
canonical provisioner has finished kept their umask mode, and the SUT refuses to start on a
private key readable beyond its owner. Both scenarios then failed as a liveness timeout — the
containers that named the real reason had already exited. These tests run the narrowing on a
scratch tree and pin that it is followed by a verification.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from keystore_tools import provision

KEY_BODY = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n"


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def _enclave(tmp_path: Path, name: str = "pvs_rig", mode: int = 0o644) -> Path:
    d = tmp_path / "enclaves" / name
    d.mkdir(parents=True)
    key = d / "key.pem"
    key.write_text(KEY_BODY, encoding="utf-8")
    cert = d / "cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n", encoding="utf-8")
    os.chmod(key, mode)
    os.chmod(cert, 0o644)
    return key


def test_a_key_the_ros_cli_left_wide_is_narrowed(tmp_path):
    key = _enclave(tmp_path)
    assert _mode(key) == 0o644, "precondition: the mode the ros2 CLI leaves behind"
    provision.narrow_private_keys(tmp_path)
    assert _mode(key) == 0o600


def test_a_certificate_beside_it_is_left_alone(tmp_path):
    """Private key material is recognised by content — narrowing everything would be a
    different, blunter tool, and the public certificate has to stay readable."""
    key = _enclave(tmp_path)
    provision.narrow_private_keys(tmp_path)
    assert _mode(key.with_name("cert.pem")) == 0o644


def test_the_narrowing_verifies_itself(monkeypatch):
    """A narrowing that quietly did nothing looks exactly like one that worked, so the same
    call must also assert the result. If this wiring is dropped the shell still exits 0."""
    seen = []
    monkeypatch.setattr(provision, "_run", lambda cmd: seen.append(cmd))
    provision.narrow_private_keys(Path("/tmp/does-not-matter"))
    script = seen[0][-1]
    assert "pail_narrow_private_keys" in script
    assert "pail_assert_private_key_modes" in script
    assert script.index("pail_narrow_private_keys") < script.index("pail_assert_private_key_modes")


def test_the_verification_it_relies_on_is_not_vacuous(tmp_path):
    """Pin the shared predicate directly: a 0644 key must make it exit nonzero. Otherwise the
    check above would assert the presence of a guard that lets everything through."""
    _enclave(tmp_path)
    r = subprocess.run(["bash", "-c", '. "$1"; pail_assert_private_key_modes "" "$2"',
                        "_", str(provision.KEYMODE_LIB), str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "readable beyond its owner" in r.stderr


def test_the_wide_key_is_reported_by_path(tmp_path):
    key = _enclave(tmp_path)
    with pytest.raises(subprocess.CalledProcessError):
        # narrowing is skipped here: only the assertion runs, against the wide key
        provision._run(["bash", "-c", '. "$1"; pail_assert_private_key_modes "" "$2"',
                        "_", str(provision.KEYMODE_LIB), str(key.parent)])


def test_the_rig_enclaves_are_narrowed_after_they_are_created(monkeypatch, tmp_path):
    """Ordering is the whole defect: the canonical provisioner narrows what exists when it
    runs, and these enclaves are created after it returns."""
    calls = []
    monkeypatch.setattr(provision, "_run", lambda cmd: calls.append(cmd))
    provision.provision_pvs_enclaves(keystore=tmp_path, policy=provision.PVS_POLICY)
    kinds = ["create_enclave" if "create_enclave" in c else
             "create_permission" if "create_permission" in c else
             "narrow" if any("pail_narrow_private_keys" in x for x in c) else "?" for c in calls]
    assert kinds.count("create_enclave") == len(provision.PVS_ENCLAVES)
    assert kinds[-1] == "narrow", kinds


def test_the_empty_rogue_keystore_is_narrowed_too(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(provision, "_run", lambda cmd: calls.append(cmd))
    provision.make_empty_keystore(tmp_path / "rogue-ks")
    assert any("pail_narrow_private_keys" in x for c in calls for x in c)
