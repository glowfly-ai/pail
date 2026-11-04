# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Keyring loading helpers (implementation contract, keys per config/keys/*.json).

Field names mirror the SUT: `ed25519_public_key_base64`, `key_id`, `role`.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Dict, Optional


def _b64(s: str) -> bytes:
    return base64.b64decode(s)


def load_keyring(path: Path) -> Dict[str, Dict[str, object]]:
    """Return {key_id: {"pub": bytes32, "role": str}} from keyring.json."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: Dict[str, Dict[str, object]] = {}
    for k in data.get("keys", []):
        out[k["key_id"]] = {
            "pub": _b64(k["ed25519_public_key_base64"]),
            "role": k.get("role", ""),
        }
    return out


def issuer_pub(keyring: Dict[str, Dict[str, object]], key_id: Optional[str] = None) -> bytes:
    """Public key of the issuer. If key_id is None, pick the first role==issuer."""
    if key_id is not None:
        return keyring[key_id]["pub"]  # type: ignore[return-value]
    for kid, v in keyring.items():
        if v.get("role") == "issuer":
            return v["pub"]  # type: ignore[return-value]
    raise KeyError("no issuer key in keyring")


def issuer_pubs(keyring: Dict[str, Dict[str, object]]) -> Dict[str, bytes]:
    """All issuer public keys as {key_id: pub} (D5-b rotation: a keyring may
    trust the current and the next issuer key at the same time)."""
    out = {kid: v["pub"] for kid, v in keyring.items() if v.get("role") == "issuer"}
    if not out:
        raise KeyError("no issuer key in keyring")
    return out  # type: ignore[return-value]


def burst_pub(keyring: Dict[str, Dict[str, object]]) -> bytes:
    """Public key that verifies UDP burst packets.

    D2 key separation: the robot-agent signs bursts with its own key
    (role=="burst", agent-key-1) so the issuer private key never leaves the
    cloud side. Falls back to the issuer key for the pre-split combined
    binary, which signs bursts with the issuer key.
    """
    for kid, v in keyring.items():
        if v.get("role") == "burst":
            return v["pub"]  # type: ignore[return-value]
    return issuer_pub(keyring)


def operator_pub(keyring: Dict[str, Dict[str, object]]) -> bytes:
    for kid, v in keyring.items():
        if v.get("role") == "operator":
            return v["pub"]  # type: ignore[return-value]
    raise KeyError("no operator key in keyring")


def load_issuer_pub_from_json(path: Path) -> bytes:
    """Read issuer_ed25519.json → 32-byte public key."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return _b64(data["ed25519_public_key_base64"])
