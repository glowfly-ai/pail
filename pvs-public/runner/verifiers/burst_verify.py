# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Signed UDP burst verifier (implementation contract, M6).

Ground truth: services/pail_services_go/internal/burst/packet_v2.go
120-byte packet, signature target = pkt[0:56], sig = pkt[56:120].

    off  field                                 size
    0    magic 'PAIL'                          4
    4    ver = 2                               1
    5    event                                 1
    6    reason (u16 LE)                       2
    8    unix_ms (u64 LE)                      8
    16   robot_id_hash = sha256(robot_id)[:16] 16
    32   token_hash                            16
    48   burst_seq (u32 LE)                    4
    52   reserved                              4
    56   ed25519_sig = Sign(pkt[0:56])         64
    120  total

[치명 정정] reserved must be 4 bytes so calcsize == 120. A 6-byte reserved
(calcsize 122) made every valid burst fail signature verification.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional

from ._crypto import ed25519_verify

PKT = "<4s B B H Q 16s 16s I 4s 64s"
V2_PACKET_SIZE = 120
V2_SIGNED_PREFIX = 56
assert struct.calcsize(PKT) == V2_PACKET_SIZE, struct.calcsize(PKT)

EVENT_NAMES = {1: "BLOCK", 2: "CHAIN_REVOKED", 3: "ESTOP", 4: "CHECKPOINT", 5: "AUTHORITY_WITHHELD"}

# reverse of internal/util/reason_map.go
REASON_NAMES = {
    0x00: "OK",
    0x10: "ERR_TARGET_MISMATCH",
    0x11: "ERR_GEO_FENCE",
    0x12: "ERR_HUMAN_DETECT",
    0x13: "ERR_SAFETY_UNSAFE",
    0x14: "ERR_WORLD_CHANGED",
    0x19: "ERR_WORLD_INDETERMINATE",
    # `D-L6`: 0x10(ERR_TARGET_MISMATCH)은 미러에 있다. 0x1A 를 빼면 판독기가
    # 이것을 `UNMAPPED` 로 적고, 게이트가 방금 갈라 놓은 「물건이 다르다」와
    # 「증거의 등급이 모자란다」가 **증거 평면에서 다시 합쳐진다** — 이번
    # 조건이 닫으려는 결함 그 자체다(`C-B16` 과 같은 논거).
    # 🚩 인접한 0x15(ERR_NO_EVIDENCE)는 여전히 미러에 없다. 증거 평면에서
    # 「등급 미달」은 읽히는데 「증거 없음」은 UNMAPPED 로 남는다는 뜻이다.
    # 그 비대칭은 이 커밋이 만든 것이 아니라 동결된 격차 22종(U-D4)의
    # 일부이고, 여기서 조용히 메우면 격차의 동결이 사람 모르게 풀린다.
    0x1A: "ERR_EVIDENCE_TRUST_CLASS",
    0x20: "ERR_CHAIN_BROKEN",
    # `C-B16`: 미러에 없으면 판독기가 이것을 `UNMAPPED` 로 적는다 — 그러면
    # 게이트가 애써 갈라 놓은 「폐기」와 「모르는 키」가 **증거 평면에서 다시
    # 합쳐진다.** 0x41 은 아직 미러에 없지만(동결 격차 22종), 그 격차를 이
    # 값까지 늘리면 이번 조건이 닫으려는 것을 이번 커밋이 되돌리는 셈이다.
    0x44: "ERR_REVOKED_KEY_ID",
    0x81: "ERR_IDENTIFIER_FORMAT",
    0x99: "ERR_TAMPERED",
    0xFF: "UNMAPPED",
}


@dataclass
class BurstPacket:
    magic: bytes
    version: int
    event: int
    reason: int
    unix_ms: int
    robot_id_hash: bytes
    token_hash: bytes
    burst_seq: int
    reserved: bytes
    signature: bytes
    raw: bytes
    valid: bool = False  # framing + signature

    @property
    def event_name(self) -> str:
        return EVENT_NAMES.get(self.event, "UNKNOWN")

    @property
    def reason_name(self) -> str:
        return REASON_NAMES.get(self.reason, "UNMAPPED")


def parse_packet(pkt: bytes) -> Optional[BurstPacket]:
    """Structural parse only (no signature). None if wrong length/magic/ver."""
    if len(pkt) != V2_PACKET_SIZE:
        return None
    magic, ver, event, reason, unix_ms, rh, th, seq, reserved, sig = struct.unpack(PKT, pkt)
    if magic != b"PAIL" or ver != 2:
        return None
    return BurstPacket(magic, ver, event, reason, unix_ms, rh, th, seq, reserved, sig, pkt)


def verify_pkt(pkt: bytes, issuer_pub: bytes) -> bool:
    """Framing + Ed25519 signature over pkt[0:56]. Rejects v1/unsigned/forged."""
    if len(pkt) != V2_PACKET_SIZE:
        return False
    if pkt[0:4] != b"PAIL" or pkt[4] != 2:
        return False
    return ed25519_verify(issuer_pub, pkt[0:V2_SIGNED_PREFIX], pkt[56:120])


@dataclass
class BurstResult:
    events: List[BurstPacket]          # deduplicated by burst_seq, valid only
    rejected: List[bytes]              # packets failing framing/signature
    seen_seqs: List[int]

    def has_event(self, event_name: str, reason_name: Optional[str] = None) -> bool:
        for e in self.events:
            if e.event_name == event_name and (reason_name is None or e.reason_name == reason_name):
                return True
        return False


class BurstReceiver:
    """Collects UDP bursts, dedupes by burst_seq, verifies signature.

    A single event is retransmitted 5x with the same burst_seq (sender.go); one
    surviving copy is enough to recover the event (TC-SV-02).
    """

    def __init__(self, issuer_pub: bytes):
        self.issuer_pub = issuer_pub
        self._by_seq: Dict[int, BurstPacket] = {}
        self._rejected: List[bytes] = []

    def reset(self) -> None:
        # §9 isolation: a prior scenario's bursts (and their burst_seq dedup
        # keys) must not survive into the next, or has_event() matches stale
        # events / dedup drops the new ones.
        self._by_seq.clear()
        self._rejected.clear()

    def offer(self, pkt: bytes) -> None:
        p = parse_packet(pkt)
        if p is None or not verify_pkt(pkt, self.issuer_pub):
            self._rejected.append(pkt)  # TC-SV-03: forged/unsigned rejected
            return
        p.valid = True
        # dedupe: keep first-seen for a burst_seq
        self._by_seq.setdefault(p.burst_seq, p)

    def result(self) -> BurstResult:
        events = sorted(self._by_seq.values(), key=lambda p: (p.unix_ms, p.burst_seq))
        return BurstResult(events=events, rejected=list(self._rejected),
                           seen_seqs=sorted(self._by_seq.keys()))
