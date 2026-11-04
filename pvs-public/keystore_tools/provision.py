# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""SROS2 keystore provisioning wrapper for the PVS test rig .

LIVE-TIER / BUILD-ONLY on a bare host. This module is import-safe anywhere (it
only shells out to the `ros2 security` CLI at call time, never at import), but
`provision()` only does real work on a ROS2 machine where that CLI exists. It is
*not* exercised by the host test tier; a live bring-up runs it once before the
Enforcement scenarios (see pvs/LIVE_BRINGUP.md).

What it does:
  1. Ensures the SUT keystore + gRPC mTLS certs exist by delegating to the
     canonical `scripts/sros2_provision.sh` (no duplication of the SUT's own
     enclaves/CA — single source of truth).
  2. Adds the two PVS principals from `pvs_policy.xml` INTO the same keystore:
       /pvs_rig   — authorized mock rig (inject + observe /drive_cmd_vel)
       /pvs_rogue — underprivileged attacker (publish /safe_cmd_vel is DENIED)
  3. Optionally mints an EMPTY keystore (`--empty-keystore DIR`) for the other
     Enforcement variant: a rogue with no matching enclave, whose *participant
     creation* is rejected under ROS_SECURITY_STRATEGY=Enforce.

Honesty: on the `insecure` profile none of this applies and the Enforcement axis
SKIPs (never faked). This tool only makes the `sros2` profile provable.
"""

from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PVS = _HERE.parent                       # pvs/
_REPO = _PVS.parent                       # PAIL-v2/

DEFAULT_CONFIG = _REPO / "config"
DEFAULT_KEYSTORE = DEFAULT_CONFIG / "sros2_keystore"
SUT_PROVISION = _REPO / "scripts" / "sros2_provision.sh"
KEYMODE_LIB = _REPO / "scripts" / "_keymode.sh"
PVS_POLICY = _HERE / "pvs_policy.xml"

PVS_ENCLAVES = ("/pvs_rig", "/pvs_rogue")

# implementation contract: the SUT provisioner refuses to run without a robot list —
# per-robot client certs + robot_registry.yaml are co-emitted with issuance.
DEFAULT_ROBOTS = ("robot-1",)


def sros2_cli_available() -> bool:
    """True only where the `ros2 security` CLI is importable/runnable."""
    if shutil.which("ros2") is None:
        return False
    try:
        r = subprocess.run(["ros2", "security", "--help"],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _run(cmd: list[str]) -> None:
    print("+", " ".join(cmd), file=sys.stderr)
    subprocess.run(cmd, check=True)


def ensure_sut_keystore(config_dir: Path = DEFAULT_CONFIG,
                        robots: tuple[str, ...] = DEFAULT_ROBOTS) -> None:
    """Delegate to the canonical SUT provisioner (idempotent)."""
    if not SUT_PROVISION.is_file():
        raise FileNotFoundError(f"SUT provisioner missing: {SUT_PROVISION}")
    if not robots:
        raise ValueError("robot list required — the SUT provisioner refuses "
                         "an empty list by design ")
    _run(["bash", str(SUT_PROVISION), str(config_dir), *robots])


def narrow_private_keys(*dirs: Path) -> None:
    """Narrow every private key under `dirs` to 0600, then verify it from the result.

    `ros2 security create_enclave` writes `key.pem` with the umask (0644 here). The canonical
    provisioner narrows what exists at the moment it runs, and the PVS enclaves are created
    *after* it returns — so nothing narrowed them. The SUT refuses to start on private key
    material readable beyond its owner (S19), which it does not waive in dev: measured
    2026-09-19, both Enforcement scenarios failed as a 60 s liveness timeout while three SUT
    containers had exited 78 naming `pvs_rig/key.pem` and `pvs_rogue/key.pem`.

    The narrowing and the verification are the SUT's own (`scripts/_keymode.sh`), not a second
    implementation of "which files are private keys": one predicate, used by both sides.
    """
    if not KEYMODE_LIB.is_file():
        raise FileNotFoundError(f"key-mode library missing: {KEYMODE_LIB}")
    targets = " ".join(shlex.quote(str(d)) for d in dirs)
    lib = shlex.quote(str(KEYMODE_LIB))
    # Verifying after narrowing is the point: a narrowing that silently did nothing (an
    # unreadable mode, a path that moved) reads exactly like one that worked.
    _run(["bash", "-c", f'set -e; . {lib}; pail_narrow_private_keys {targets}; '
                        f'pail_assert_private_key_modes "" {targets}'])


def provision_pvs_enclaves(keystore: Path = DEFAULT_KEYSTORE,
                           policy: Path = PVS_POLICY) -> None:
    """Add /pvs_rig and /pvs_rogue to an existing keystore (idempotent per the
    ros2 CLI, which no-ops an already-present enclave)."""
    if not policy.is_file():
        raise FileNotFoundError(f"PVS policy missing: {policy}")
    for enclave in PVS_ENCLAVES:
        _run(["ros2", "security", "create_enclave", str(keystore), enclave])
        _run(["ros2", "security", "create_permission", str(keystore), enclave, str(policy)])
        print(f"pvs enclave {enclave} provisioned", file=sys.stderr)
    narrow_private_keys(keystore)


def make_empty_keystore(path: Path) -> None:
    """A keystore with a CA but no matching enclave — a rogue pointed here has
    its participant creation rejected under Enforce (the §5.3 'no keystore' path
    done reproducibly, without deleting the real one)."""
    _run(["ros2", "security", "create_keystore", str(path)])
    narrow_private_keys(path)          # the CA key of this keystore falls out at the umask too


def provision(config_dir: Path = DEFAULT_CONFIG,
              keystore: Path = DEFAULT_KEYSTORE,
              policy: Path = PVS_POLICY,
              robots: tuple[str, ...] = DEFAULT_ROBOTS) -> Path:
    if not sros2_cli_available():
        raise RuntimeError(
            "ros2 security CLI unavailable — provisioning is live-tier only "
            "(run on a ROS2 Humble machine; see pvs/LIVE_BRINGUP.md)")
    ensure_sut_keystore(config_dir, robots)
    provision_pvs_enclaves(keystore, policy)
    print(f"OK: keystore={keystore} (+/pvs_rig +/pvs_rogue)", file=sys.stderr)
    return keystore


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Provision the PVS SROS2 test-rig keystore.")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG,
                    help="SUT config dir holding sros2_keystore/ (default: PAIL-v2/config)")
    ap.add_argument("--keystore", type=Path, default=DEFAULT_KEYSTORE)
    ap.add_argument("--policy", type=Path, default=PVS_POLICY)
    ap.add_argument("--empty-keystore", type=Path, default=None,
                    help="also mint an empty (enclave-less) keystore at this path")
    ap.add_argument("--robots", nargs="+", default=list(DEFAULT_ROBOTS),
                    help="robot ids to issue per-robot client certs for "
                         "(implementation contract; default: robot-1)")
    args = ap.parse_args(argv)

    if not sros2_cli_available():
        print("ros2 security CLI unavailable — nothing to do on this host "
              "(live-tier only).", file=sys.stderr)
        return 2

    provision(args.config, args.keystore, args.policy, tuple(args.robots))
    if args.empty_keystore:
        make_empty_keystore(args.empty_keystore)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
