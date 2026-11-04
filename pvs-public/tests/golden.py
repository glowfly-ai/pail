# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Golden data generators — faithful python reimplementation of the Go writers.

These mirror the exact byte layout of:
  services/pail_services_go/internal/blackbox/writer.go
  services/pail_services_go/internal/burst/packet_v2.go
  services/pail_services_go/internal/anchor/anchor.go

Used to round-trip test the PVS verifiers without the live SUT. When the real
SUT is available, the same verifiers parse real segment/burst/anchor files —
these generators only exist to prove the parser matches the writer bit-for-bit.
"""

# PAIL-CANON-COPY : pail-anchor:v1
# 정본 = services/pail_services_go/internal/canon
# 이 파일은 SUT 를 import 하지 않는 의도된 독립 구현이다. 같은 상수를 쓰면
# 대조가 항등식이 되어 드리프트를 못 잡는다. 정본과 함께 고치지 않으면
# §4.3 골든 벡터가 붉어진다(CI 검사 2). 삭제 대상이 아니다.


from __future__ import annotations

import base64
import hashlib
import json
import struct
from pathlib import Path
from typing import List, Optional, Tuple

from nacl.signing import SigningKey

SEG_MAGIC = b"PBSG"
SEG_VERSION = 2
REC_VERSION = 1
REC_CHECKPOINT = 30
REC_CHECKPOINT_V2 = 31


def new_issuer() -> Tuple[SigningKey, bytes]:
    sk = SigningKey.generate()
    return sk, bytes(sk.verify_key)


# The fixture side of the checkpoint canon. It is written out here rather than
# imported from `segment_chain` on purpose: this module is the producer and that
# one is the verifier under test. Sharing one construction would make every
# "verifier accepts fixture" assertion pass by agreement rather than by canon.
# Both are pinned to the same frozen bytes instead (`test_contract_golden.py`).

def checkpoint_v2_payload(head: bytes, record_count: int, seg_seq: int,
                          sign: SigningKey) -> bytes:
    signed = (b"pail-checkpoint:v2:" + head
              + struct.pack(">Q", record_count) + struct.pack(">Q", seg_seq))
    return (head + struct.pack(">Q", record_count) + struct.pack(">Q", seg_seq)
            + sign.sign(signed).signature)


def checkpoint_v1_payload(head: bytes, record_count: int,
                          sign: SigningKey) -> bytes:
    """Old format (type 30): count is u64 **LE** and sits outside the signature."""
    return head + struct.pack("<Q", record_count) + sign.sign(head).signature


# ---------------- blackbox segment writer ----------------

class SegmentWriter:
    def __init__(self, dir_: Path, sign_key: SigningKey, start_seq: int = 0):
        self.dir = Path(dir_)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.sign = sign_key
        self.seg_seq = start_seq
        self.prev_hash = b"\x00" * 32
        self.seg_records = 0
        self.f = None
        self._start_segment(b"\x00" * 32)

    def _seg_name(self, seq: int) -> str:
        return f"pail_blackbox.{seq:08d}.seg"

    def _build_header(self, seq: int, prev_tail: bytes, created_ms: int) -> bytes:
        return struct.pack("<4s I Q 32s Q", SEG_MAGIC, SEG_VERSION, seq, prev_tail, created_ms)

    def _start_segment(self, prev_tail: bytes, created_ms: int = 1_700_000_000_000):
        if self.f is not None:
            self.f.close()
        self.seg_seq += 1
        hdr = self._build_header(self.seg_seq, prev_tail, created_ms)
        path = self.dir / self._seg_name(self.seg_seq)
        self.f = open(path, "wb")
        self.f.write(hdr)
        self.prev_hash = hashlib.sha256(hdr).digest()  # header seeds the chain
        self.seg_records = 0

    def rotate(self):
        self._start_segment(self.prev_hash)

    def append(self, rec_type: int, unix_ms: int, payload: bytes):
        hdr = struct.pack("<I I Q", REC_VERSION, rec_type, unix_ms)  # 16B, hashed
        this_hash = hashlib.sha256(hdr + payload + self.prev_hash).digest()
        self.f.write(hdr)
        self.f.write(struct.pack("<I", len(payload)))  # payload_len, not hashed
        self.f.write(payload)
        self.f.write(self.prev_hash)
        self.f.write(this_hash)
        self.prev_hash = this_hash
        self.seg_records += 1

    def checkpoint(self, unix_ms: int, version: int = 2):
        """v2 by default (`E-C3`); `version=1` still writes the old record.

        v1 has to stay producible in tests — `F8` promises the parser survives
        forever, and a parser nobody feeds is a parser nobody knows is broken.
        """
        if version == 2:
            payload = checkpoint_v2_payload(
                self.prev_hash, self.seg_records, self.seg_seq, self.sign)
            self.append(REC_CHECKPOINT_V2, unix_ms, payload)
        else:
            payload = checkpoint_v1_payload(
                self.prev_hash, self.seg_records, self.sign)
            self.append(REC_CHECKPOINT, unix_ms, payload)

    def close(self):
        if self.f is not None:
            self.f.close()
            self.f = None

    def head_hash(self) -> bytes:
        return self.prev_hash


# ---------------- UDP burst packet ----------------

def build_burst(sign_key: Optional[SigningKey], event: int, reason: int, unix_ms: int,
                robot_id: str, token_id: str, burst_seq: int,
                version: int = 2, forge_key: Optional[SigningKey] = None) -> bytes:
    pkt = bytearray(120)
    pkt[0:4] = b"PAIL"
    pkt[4] = version
    pkt[5] = event
    struct.pack_into("<H", pkt, 6, reason)
    struct.pack_into("<Q", pkt, 8, unix_ms)
    pkt[16:32] = hashlib.sha256(robot_id.encode()).digest()[:16]
    pkt[32:48] = hashlib.sha256(token_id.encode()).digest()[:16]
    struct.pack_into("<I", pkt, 48, burst_seq)
    # pkt[52:56] reserved = 0
    signer = forge_key or sign_key
    if signer is not None:
        sig = signer.sign(bytes(pkt[0:56])).signature
        pkt[56:120] = sig
    return bytes(pkt)


def build_burst_v1_unsigned(robot_id: str) -> bytes:
    """A legacy 32B unsigned packet (ver=1) — must be rejected by v2 receiver."""
    pkt = bytearray(32)
    pkt[0:4] = b"PAIL"
    pkt[4] = 1
    return bytes(pkt)


# ---------------- anchor record ----------------

def build_anchor(sign_key: SigningKey, robot_id: str, key_id: str,
                 head_hash_hex: str, segment_seq: int, record_count: int,
                 unix_ms: int) -> dict:
    canon = f"pail-anchor:v1:{head_hash_hex}:{segment_seq}:{record_count}:{unix_ms}".encode()
    sig = sign_key.sign(canon).signature
    return {
        "robot_id": robot_id,
        "key_id": key_id,
        "head_hash_hex": head_hash_hex,
        "segment_seq": segment_seq,
        "record_count": record_count,
        "unix_ms": unix_ms,
        "ed25519_sig_base64": base64.b64encode(sig).decode(),
    }


def write_anchor(anchor_dir: Path, rec: dict):
    Path(anchor_dir).mkdir(parents=True, exist_ok=True)
    name = f"anchor_{rec['unix_ms']:013d}_{0:06d}_{rec['segment_seq']:08d}_{rec['record_count']:08d}.json"
    (Path(anchor_dir) / name).write_text(json.dumps(rec))
