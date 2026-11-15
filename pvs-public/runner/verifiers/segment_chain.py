# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Blackbox segment-chain verifier (implementation contract, M5).

Ground truth: services/pail_services_go/internal/blackbox/{writer,records}.go

Segment header (56B):
    off  field                    size
    0    magic 'PBSG'             4
    4    version (u32 LE) = 2     4
    8    segment_seq (u64 LE)     8
    16   prev_segment_tail_hash   32
    48   created_unix_ms (u64 LE) 8

Record on disk:
    version(u32) | type(u32) | unix_ms(u64) | payload_len(u32)
    | payload | prev_hash(32) | this_hash(32)

    this_hash = sha256( version|type|unix_ms (16B) || payload || prev_hash )
    (payload_len is NOT covered by the hash)

First record of a segment chains to sha256(segment_header).
CHECKPOINT (type=30) payload = head_hash(32) | record_count(u64 LE) | sig(64),
    sig = Ed25519.Sign(issuer, head_hash).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ._crypto import ed25519_verify

SEG_MAGIC = b"PBSG"
SEG_VERSION = 2
SEG_HDR = "<4s I Q 32s Q"
SEG_HDR_SIZE = struct.calcsize(SEG_HDR)  # 56
REC_VERSION = 1
REC_FIXED = "<I I Q I"                    # version|type|unix_ms|payload_len (on disk)
REC_FIXED_SIZE = struct.calcsize(REC_FIXED)  # 20
HASH_INPUT_HDR = 16                       # version|type|unix_ms covered by hash

# record types (records.go)
REC_TOKEN_ISSUED = 10
REC_PLAN_ACCEPTED = 11
REC_GATE_DECISION = 20
REC_CHAIN_REVOKED = 21
REC_CHECKPOINT = 30
REC_CHECKPOINT_V2 = 31
REC_SAFE_STOP = 40
REC_OPERATOR_EVENT = 41
# OR2 (implementation contract B2-3). 50 stays outside the mirror — the pre-existing gap
# is frozen by RT-04 on purpose, and closing it is not this milestone's business.
REC_CONTEXT_PROVENANCE = 51

assert SEG_HDR_SIZE == 56, SEG_HDR_SIZE


@dataclass
class Record:
    seg_seq: int
    index: int          # record index within the segment
    version: int
    type: int
    unix_ms: int
    payload: bytes
    prev_hash: bytes
    this_hash: bytes


CHECKPOINT_V2_PREFIX = b"pail-checkpoint:v2:"
CHECKPOINT_V1_LEN = 32 + 8 + 64       # head | count(u64LE) | sig
CHECKPOINT_V2_LEN = 32 + 8 + 8 + 64   # head | count(u64BE) | seg_seq(u64BE) | sig


def checkpoint_v2_signed_input(head: bytes, record_count: int, segment_seq: int) -> bytes:
    """`tests/golden/canon/checkpoint_v2.vec` (OR1 동결, `implementation contract`).

    "pail-checkpoint:v2:" ‖ head(32B) ‖ record_count(u64BE) ‖ segment_seq(u64BE)
    """
    return (CHECKPOINT_V2_PREFIX + head
            + struct.pack(">Q", record_count) + struct.pack(">Q", segment_seq))


@dataclass
class CheckpointInfo:
    """What one CHECKPOINT record actually established — not just that it passed.

    `checkpoints_verified` counted; it could not say *what* was attested nor *by
    whom*, so a v1 checkpoint and a v2 checkpoint left the same trace (`F-PR-20`).
    The three booleans below are the difference, and they are separate on purpose:
    a signature can be valid while the count it sits next to is unattested.
    """

    seg_seq: int
    index: int
    version: int                       # 1 (type 30) or 2 (type 31)
    head: bytes
    record_count: int
    signature_verified: bool           # False when the caller supplied no keys
    count_attested: bool               # v2 only — count/seg_seq are signed (NF4)
    key_id: Optional[str]
    key_id_known: bool


@dataclass
class Result:
    ok: bool
    segments: int = 0
    records: int = 0
    checkpoints_verified: int = 0
    # SEC-H07: what the signatures cover. A hash chain can be recomputed by
    # anyone who can write the files, so `ok` alone says "consistent", not
    # "written by the issuer". `attested_records` counts the records up to and
    # including the last checkpoint whose signature was verified;
    # `unattested_tail` is what comes after it. Both stay 0/records when no key
    # was supplied, because then nothing was verified.
    attested_records: int = 0
    unattested_tail: int = 0
    head_hash: Optional[bytes] = None      # this_hash of last record overall
    errors: List[str] = field(default_factory=list)
    all_records: List[Record] = field(default_factory=list)
    checkpoints: List[CheckpointInfo] = field(default_factory=list)
    # E-Q1 (G-ANC-C10, 2026-08-25): 빈/부재 디렉터리를 표현할 필드. 4-상태
    # 소비자는 verdict.go 정본과 같은 순서로 이 필드를 ok 보다 먼저 본다
    # (NoFiles → NO_RECORDS). ok 는 False 로 남는다 — find(strict=True) 의
    # "could not verify" 의미(E-C2)는 그대로다.
    no_files: bool = False

    def fail(self, msg: str) -> "Result":
        self.ok = False
        self.errors.append(msg)
        return self


class ChainNotVerified(Exception):
    """`find(strict=True)` on a chain that did not verify (implementation contract `E-C2`).

    Carries the `Result` so the caller can print *why* — "could not verify" and
    "verified, nothing matched" must not arrive as the same bytes (`H-B2`).
    """

    def __init__(self, result: "Result"):
        super().__init__("; ".join(result.errors) or "chain not verified")
        self.result = result


@dataclass
class FindResult:
    """What `find()` returns. Deliberately **not** list-like.

    `strict=False` stays (diagnosing a broken journal is real work, and removing
    it makes people parse segments by hand instead) — but then the answer is
    only as trustworthy as the chain it came from, and that fact has to travel
    with the answer. A bare `List[Record]` cannot carry it: the caller iterates
    and never learns. So the value is a struct with `verified` on it, and it has
    no `__iter__`/`__len__`/`__getitem__` on purpose — a caller written against
    the old list signature fails loudly instead of silently walking unverified
    records. Enumeration can be bypassed by doing nothing; a type cannot.
    """

    records: List[Record]
    verified: bool
    result: "Result"


def _segment_files(seg_dir: Path) -> List[Path]:
    files = sorted(seg_dir.glob("pail_blackbox.*.seg"))
    return files


def _parse_segment(path: Path, res: Result, issuer_pub: Optional[List[bytes]],
                   prev_seg_tail: Optional[bytes]) -> Optional[bytes]:
    """Verify one segment; return its tail this_hash (or None on failure)."""
    data = path.read_bytes()
    if len(data) < SEG_HDR_SIZE:
        res.fail(f"{path.name}: truncated header ({len(data)}B)")
        return None
    magic, ver, seg_seq, prev_tail, created_ms = struct.unpack(SEG_HDR, data[:SEG_HDR_SIZE])
    if magic != SEG_MAGIC:
        res.fail(f"{path.name}: bad magic {magic!r}")
        return None
    if ver != SEG_VERSION:
        res.fail(f"{path.name}: unsupported version {ver}")
        return None

    # cross-segment continuity (writer.go: new segment inherits prior tail)
    if prev_seg_tail is not None and prev_tail != prev_seg_tail:
        res.fail(f"{path.name}: prev_segment_tail_hash mismatch "
                 f"(hdr={prev_tail.hex()[:16]} expected={prev_seg_tail.hex()[:16]})")
        return None

    prev_hash = hashlib.sha256(data[:SEG_HDR_SIZE]).digest()  # header seeds the chain
    off = SEG_HDR_SIZE
    idx = 0
    seg_tail = prev_tail  # empty-segment fallback inherits its prev tail
    while off < len(data):
        if off + REC_FIXED_SIZE > len(data):
            res.fail(f"{path.name}[rec {idx}]: truncated record header at off={off}")
            return None
        rver, rtype, unix_ms, plen = struct.unpack(REC_FIXED, data[off:off + REC_FIXED_SIZE])
        if rver != REC_VERSION:
            res.fail(f"{path.name}[rec {idx}]: unsupported record version {rver}")
            return None
        body = off + REC_FIXED_SIZE
        end = body + plen + 32 + 32
        if end > len(data):
            res.fail(f"{path.name}[rec {idx}]: truncated record body at off={off}")
            return None
        payload = data[body:body + plen]
        rec_prev = data[body + plen:body + plen + 32]
        this_hash = data[body + plen + 32:end]

        # recompute the hash exactly as writer.go appendRecord
        h = hashlib.sha256()
        h.update(data[off:off + HASH_INPUT_HDR])  # version|type|unix_ms
        h.update(payload)
        h.update(prev_hash)
        want = h.digest()

        if rec_prev != prev_hash:
            res.fail(f"{path.name}[rec {idx}]: prev_hash break "
                     f"(stored={rec_prev.hex()[:16]} chain={prev_hash.hex()[:16]})")
            return None
        if this_hash != want:
            res.fail(f"{path.name}[rec {idx}]: this_hash tamper "
                     f"(stored={this_hash.hex()[:16]} recomputed={want.hex()[:16]})")
            return None

        covers = False
        if rtype in (REC_CHECKPOINT, REC_CHECKPOINT_V2):
            if not _verify_checkpoint(path, idx, rtype, payload, prev_hash,
                                      seg_seq, issuer_pub, res):
                return None
            covers = res.checkpoints[-1].signature_verified

        res.all_records.append(Record(seg_seq, idx, rver, rtype, unix_ms,
                                      payload, rec_prev, this_hash))
        res.records += 1
        if covers:
            # The signed head is bound to every earlier record, across segments
            # (the header carries the inherited tail, checked above).
            res.attested_records = res.records
        prev_hash = this_hash
        seg_tail = this_hash
        off = end
        idx += 1

    return seg_tail


def _verify_checkpoint(path: Path, idx: int, rtype: int, payload: bytes,
                       chain_prev: bytes, seg_seq: int,
                       ring: Optional["_Ring"], res: Result) -> bool:
    """Verify one CHECKPOINT record and record *what* it established (`E-C3`).

    v1 (type 30) stays readable forever (`F8`) — deleting the parser would
    destroy past evidence with our own hands. But it is read with two facts
    attached that v2 does not need: its `record_count` is outside the signature
    (`X13a`/`NF4`), and its signature covers a bare 32-byte hash with no domain
    separation (`X13b`), so a matching ring key proves "this key signed these
    bytes" — not "this key attested this checkpoint". Naming a `key_id` for v1
    would be the over-claim; `key_id_known=False` is the honest value.
    """
    version = 2 if rtype == REC_CHECKPOINT_V2 else 1
    want_len = CHECKPOINT_V2_LEN if version == 2 else CHECKPOINT_V1_LEN
    if len(payload) != want_len:
        res.fail(f"{path.name}[rec {idx}]: CHECKPOINT v{version} payload len "
                 f"{len(payload)} != {want_len}")
        return False

    head = payload[0:32]
    # head_hash is this_hash of the preceding record == the chain prev at this point
    if head != chain_prev:
        res.fail(f"{path.name}[rec {idx}]: CHECKPOINT head_hash != chain head "
                 f"({head.hex()[:16]} vs {chain_prev.hex()[:16]})")
        return False

    if version == 2:
        count = struct.unpack(">Q", payload[32:40])[0]
        seq_field = struct.unpack(">Q", payload[40:48])[0]
        sig = payload[48:112]
        signed = checkpoint_v2_signed_input(head, count, seq_field)
        if seq_field != seg_seq:
            res.fail(f"{path.name}[rec {idx}]: CHECKPOINT v2 segment_seq {seq_field} "
                     f"!= segment {seg_seq} (checkpoint moved between segments)")
            return False
    else:
        count = struct.unpack("<Q", payload[32:40])[0]
        sig = payload[40:104]
        signed = head

    key_id: Optional[str] = None
    verified = False
    if ring is not None:
        matched = ring.match(signed, sig)
        if matched is None:
            res.fail(f"{path.name}[rec {idx}]: CHECKPOINT v{version} signature invalid "
                     f"(against {len(ring.pubs)} trusted issuer key(s))")
            return False
        verified = True
        res.checkpoints_verified += 1
        if version == 2:
            key_id = ring.ids[matched] if ring.ids else None

    res.checkpoints.append(CheckpointInfo(
        seg_seq=seg_seq, index=idx, version=version, head=head, record_count=count,
        signature_verified=verified, count_attested=(version == 2 and verified),
        key_id=key_id, key_id_known=key_id is not None))
    return True


class _Ring:
    """The trusted issuer keys, with their names when the caller knew them.

    A bare list of public keys can answer "did any of these sign it" and nothing
    else. That is the whole of `F-PR-20`: a revoked key sitting in the ring keeps
    passing and leaves no trace of having been the one. `ids` is None when the
    caller passed an unnamed list — and then `key_id_known` stays False rather
    than inventing an index-shaped name.
    """

    def __init__(self, pubs: List[bytes], ids: Optional[List[str]]):
        self.pubs = pubs
        self.ids = ids

    def match(self, signed: bytes, sig: bytes) -> Optional[int]:
        for i, pub in enumerate(self.pubs):
            if ed25519_verify(pub, signed, sig):
                return i
        return None


def _normalize_pubs(issuer_pub) -> Optional["_Ring"]:
    """Accepts one key, an iterable of keys, or a `key_id -> pub` mapping."""
    if issuer_pub is None:
        return None
    if isinstance(issuer_pub, dict):
        items = list(issuer_pub.items())
        return _Ring([bytes(v) for _, v in items], [str(k) for k, _ in items])
    if isinstance(issuer_pub, (bytes, bytearray)):
        return _Ring([bytes(issuer_pub)], None)
    return _Ring([bytes(p) for p in issuer_pub], None)


def verify(seg_dir, issuer_pub=None, *, require_attested: bool = False) -> Result:
    """Verify the full segment chain across a blackbox directory.

    require_attested (SEC-H07): also fail when the journal has records but no
    checkpoint with a verified signature, or when records trail after the last
    one. The default keeps the earlier meaning of `ok` (chain consistent, and
    every checkpoint that IS present verifies); the coverage is reported in
    `attested_records` / `unattested_tail` either way. A journal cut exactly at
    a signed checkpoint is a valid signed prefix and passes both modes — that is
    what the anchor cross-check is for.

    issuer_pub: if provided, CHECKPOINT signatures are verified (M5 attestation).
    Accepts a single 32-byte public key, an iterable of them (D5-b rotation), or
    a `key_id -> pub` mapping. Only the mapping lets a v2 checkpoint report which
    key attested it (`E-C3`); the other two forms leave `key_id_known=False`.
    """
    issuer_pub = _normalize_pubs(issuer_pub)
    seg_dir = Path(seg_dir)
    res = Result(ok=True)
    files = _segment_files(seg_dir)
    if not files:
        res.no_files = True
        return res.fail(f"no segment files in {seg_dir}")

    prev_seg_tail: Optional[bytes] = None
    expected_seq: Optional[int] = None
    for path in files:
        # segment_seq continuity
        seg_seq = struct.unpack(SEG_HDR, path.read_bytes()[:SEG_HDR_SIZE])[2]
        if expected_seq is not None and seg_seq != expected_seq:
            res.fail(f"{path.name}: segment_seq gap (got {seg_seq} expected {expected_seq})")
            return res
        tail = _parse_segment(path, res, issuer_pub, prev_seg_tail)
        if tail is None:
            return res
        prev_seg_tail = tail
        expected_seq = seg_seq + 1
        res.segments += 1
        res.head_hash = tail

    res.unattested_tail = res.records - res.attested_records
    if require_attested:
        if res.records > 0 and res.attested_records == 0:
            res.fail("no signed checkpoint: nothing in this journal is attested "
                     "by an issuer key")
        elif res.unattested_tail > 0:
            res.fail(f"unattested tail: {res.unattested_tail} record(s) after the "
                     f"last signed checkpoint")
    return res


def find(seg_dir, needle: bytes, *, issuer_pubs=None,
         strict: bool = True) -> FindResult:
    """Scan all segments for records whose payload contains `needle`
    (e.g. a token_id hash). Used by --find (LLD §7.1).

    Fail-closed by default (`E-C2`). Before this, `find()` called `verify()`
    without keys and threw the result away: a tampered journal answered `[]`
    with rc=1 — byte-identical to "verified, not present" — while the record it
    was asked about was sitting in the file. Tampering that destroys evidence
    was reported as absence of evidence.

    `issuer_pubs` is passed through so CHECKPOINT signatures are attested; with
    it left None nothing is attested (crypto360 `FINDINGS_S5_HARNESS` §1) and
    `verified=True` means only "the hash chain is intact".
    """
    res = verify(seg_dir, issuer_pubs)
    if strict and not res.ok:
        raise ChainNotVerified(res)
    return FindResult(records=[r for r in res.all_records if needle in r.payload],
                      verified=res.ok, result=res)


if __name__ == "__main__":
    import argparse
    import base64
    import json

    ap = argparse.ArgumentParser(description="PAIL blackbox segment-chain verifier")
    ap.add_argument("seg_dir")
    ap.add_argument("--keyring", help="config/keys/keyring.json for CHECKPOINT sig check")
    ap.add_argument("--issuer-key-id", default=None)
    ap.add_argument("--find", help="hex token hash to locate")
    args = ap.parse_args()

    pub = None
    if args.keyring:
        from .keys import load_keyring, issuer_pub as _ip, issuer_pubs as _ips
        kr = load_keyring(Path(args.keyring))
        # No explicit key id => trust every role==issuer key (D5-b rotation).
        # Named ring, not a bare list: a v2 checkpoint can then say WHICH key
        # attested it, which is the whole of `F-PR-20` (`E-C3`).
        pub = ({args.issuer_key_id: _ip(kr, args.issuer_key_id)}
               if args.issuer_key_id else _ips(kr))

    if args.find:
        # rc is the whole point of this branch (`E-C2`): 0 found+verified /
        # 1 not found+verified / 2 could not verify. `2` used to be folded into
        # `1`, so a wrapper script could not tell "not in the journal" from
        # "the journal cannot be trusted" — and the second is the case that
        # matters. `strict=True` is fixed here; --find is not a diagnostic mode.
        try:
            fr = find(args.seg_dir, bytes.fromhex(args.find), issuer_pubs=pub)
        except ChainNotVerified as e:
            print(json.dumps({"verified": False, "records": [],
                              "errors": e.result.errors}))
            raise SystemExit(2)
        print(json.dumps({"verified": fr.verified,
                          "records": [{"seg": r.seg_seq, "idx": r.index,
                                       "type": r.type} for r in fr.records]}))
        raise SystemExit(0 if fr.records else 1)

    r = verify(args.seg_dir, pub)
    print(f"chain={'PASS' if r.ok else 'FAIL'} segments={r.segments} records={r.records} "
          f"checkpoints_verified={r.checkpoints_verified} "
          f"attested={r.attested_records} unattested_tail={r.unattested_tail} "
          f"head={None if r.head_hash is None else r.head_hash.hex()[:16]}")
    for c in r.checkpoints:
        # "몇 개가 통과했다"만 찍으면 v1 과 v2 가 같은 줄로 도착한다 — 무엇이
        # 서명 안에 있었는지와 누구였는지가 여기서 갈린다 (`E-C3`).
        print(f"  ckpt seg={c.seg_seq} idx={c.index} v{c.version} "
              f"count={c.record_count} count_attested={c.count_attested} "
              f"key_id={c.key_id if c.key_id_known else 'unknown'}")
    for e in r.errors:
        print(f"  ERR: {e}")
    raise SystemExit(0 if r.ok else 1)
