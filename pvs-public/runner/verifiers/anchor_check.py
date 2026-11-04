# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Cloud anchor cross-checker (implementation contract, M9).

Ground truth: services/pail_services_go/internal/anchor/anchor.go

AnchorRecord (JSON):
    robot_id, key_id, head_hash_hex, segment_seq, record_count, unix_ms,
    ed25519_sig_base64
Signature canon (Ed25519 over ASCII):
    "pail-anchor:v1:" + head_hash_hex + ":" + segment_seq + ":" +
    record_count + ":" + unix_ms
"""

# PAIL-CANON-COPY : pail-anchor:v1
# 정본 = services/pail_services_go/internal/canon
# 이 파일은 SUT 를 import 하지 않는 의도된 독립 구현이다. 같은 상수를 쓰면
# 대조가 항등식이 되어 드리프트를 못 잡는다. 정본과 함께 고치지 않으면
# §4.3 골든 벡터가 붉어진다(CI 검사 2). 삭제 대상이 아니다.


from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ._crypto import ed25519_verify


@dataclass
class AnchorRecord:
    robot_id: str
    key_id: str
    head_hash_hex: str
    segment_seq: int
    record_count: int
    unix_ms: int
    sig: bytes
    raw: dict

    def canon(self) -> bytes:
        return (f"pail-anchor:v1:{self.head_hash_hex}:{self.segment_seq}:"
                f"{self.record_count}:{self.unix_ms}").encode("ascii")

    def verify_sig(self, issuer_pub: bytes) -> bool:
        return ed25519_verify(issuer_pub, self.canon(), self.sig)


def parse_anchor(obj: dict) -> AnchorRecord:
    return AnchorRecord(
        robot_id=obj["robot_id"],
        key_id=obj["key_id"],
        head_hash_hex=obj["head_hash_hex"],
        segment_seq=int(obj["segment_seq"]),
        record_count=int(obj["record_count"]),
        unix_ms=int(obj["unix_ms"]),
        sig=base64.b64decode(obj["ed25519_sig_base64"]),
        raw=obj,
    )


def load_anchors(anchor_dir) -> List[AnchorRecord]:
    """Load anchor_*.json in upload order (name pattern sorts chronologically)."""
    out: List[AnchorRecord] = []
    for p in sorted(Path(anchor_dir).glob("anchor_*.json")):
        out.append(parse_anchor(json.loads(p.read_text(encoding="utf-8"))))
    return out


@dataclass
class AnchorResult:
    ok: bool
    count: int
    head_matches: Optional[bool]
    latest_head_hex: Optional[str]
    errors: List[str]


def cross_check(anchor_dir, issuer_pub,
                local_head_hash: Optional[bytes] = None) -> AnchorResult:
    """Verify every anchor's signature and (optionally) that the latest
    uploaded head_hash matches the local chain head (TC-AN-01).

    issuer_pub: a single public key (bytes) or {key_id: pub} dict. With a
    dict, each anchor is verified against the key its key_id names (D5-b
    rotation: anchors from before and after a rotation coexist); an unknown
    key_id is an error, not a skip.
    """
    errors: List[str] = []
    anchors = load_anchors(anchor_dir)
    if not anchors:
        return AnchorResult(False, 0, None, None, [f"no anchors in {anchor_dir}"])

    for a in anchors:
        if isinstance(issuer_pub, dict):
            pub = issuer_pub.get(a.key_id)
            if pub is None:
                errors.append(f"anchor seq={a.segment_seq} head={a.head_hash_hex[:16]}: "
                              f"unknown key_id {a.key_id!r}")
                continue
        else:
            pub = issuer_pub
        if not a.verify_sig(pub):
            errors.append(f"anchor seq={a.segment_seq} head={a.head_hash_hex[:16]}: bad signature")

    latest = anchors[-1]
    head_matches: Optional[bool] = None
    if local_head_hash is not None:
        head_matches = (latest.head_hash_hex.lower() == local_head_hash.hex().lower())
        if not head_matches:
            errors.append(f"latest anchor head {latest.head_hash_hex[:16]} != local head "
                          f"{local_head_hash.hex()[:16]}")

    return AnchorResult(
        ok=not errors,
        count=len(anchors),
        head_matches=head_matches,
        latest_head_hex=latest.head_hash_hex,
        errors=errors,
    )
