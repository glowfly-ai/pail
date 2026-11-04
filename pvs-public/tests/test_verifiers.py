# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Verifier round-trip + tamper tests (host-runnable, no ROS2/docker).

Proves the pure-python parsers match the Go writers bit-for-bit and that
tamper/forgery is detected at the exact record — the Audit and Survivability
axis machinery, verified with real execution.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner.verifiers import burst_verify, segment_chain, anchor_check  # noqa: E402
from tests import golden  # noqa: E402


# ---------------- burst (M6 / TC-SV) ----------------

def test_burst_valid_roundtrip():
    sk, pub = golden.new_issuer()
    pkt = golden.build_burst(sk, event=1, reason=0x10, unix_ms=1700, robot_id="robot-1",
                             token_id="tok-1", burst_seq=7)
    assert burst_verify.verify_pkt(pkt, pub)
    p = burst_verify.parse_packet(pkt)
    assert p.event_name == "BLOCK"
    assert p.reason_name == "ERR_TARGET_MISMATCH"
    assert p.burst_seq == 7


def test_burst_signed_prefix_tamper_fails():
    sk, pub = golden.new_issuer()
    pkt = bytearray(golden.build_burst(sk, 1, 0x10, 1700, "robot-1", "tok-1", 7))
    pkt[6] ^= 0xFF  # flip reason inside signed prefix
    assert not burst_verify.verify_pkt(bytes(pkt), pub)


def test_burst_forged_key_rejected():
    sk, pub = golden.new_issuer()
    forger, _ = golden.new_issuer()
    pkt = golden.build_burst(sk, 1, 0x10, 1700, "robot-1", "tok-1", 7, forge_key=forger)
    assert not burst_verify.verify_pkt(pkt, pub)  # TC-SV-03


def test_burst_v1_unsigned_rejected():
    sk, pub = golden.new_issuer()
    rx = burst_verify.BurstReceiver(pub)
    rx.offer(golden.build_burst_v1_unsigned("robot-1"))
    res = rx.result()
    assert res.events == []
    assert len(res.rejected) == 1


def test_burst_dedup_recovers_single_event():
    # 5 retransmissions same burst_seq, only #3 delivered (TC-SV-02)
    sk, pub = golden.new_issuer()
    rx = burst_verify.BurstReceiver(pub)
    pkt = golden.build_burst(sk, 3, 0x13, 1700, "robot-1", "tok-9", burst_seq=42)
    rx.offer(pkt)  # a single surviving copy
    res = rx.result()
    assert len(res.events) == 1
    assert res.has_event("ESTOP", "ERR_SAFETY_UNSAFE")
    # feeding duplicates does not multiply the event
    rx.offer(pkt)
    rx.offer(pkt)
    assert len(rx.result().events) == 1


# ---------------- segment chain (M5 / TC-AU) ----------------

def _make_chain(tmp_path, sk):
    w = golden.SegmentWriter(tmp_path, sk)
    w.append(segment_chain.REC_TOKEN_ISSUED, 1700, b"tok-issued-payload")
    w.append(segment_chain.REC_GATE_DECISION, 1701, b"gate-permit-payload")
    w.checkpoint(1702)
    w.rotate()  # cross-segment boundary (TC-AU-01)
    w.append(segment_chain.REC_GATE_DECISION, 1703, b"gate-block-payload")
    w.checkpoint(1704)
    w.close()
    return w


def test_segment_chain_pass_cross_segment(tmp_path):
    sk, pub = golden.new_issuer()
    _make_chain(tmp_path, sk)
    res = segment_chain.verify(tmp_path, pub)
    assert res.ok, res.errors
    assert res.segments == 2
    assert res.checkpoints_verified == 2


def test_segment_tamper_detected_at_record(tmp_path):
    sk, pub = golden.new_issuer()
    _make_chain(tmp_path, sk)
    seg = sorted(Path(tmp_path).glob("*.seg"))[0]
    data = bytearray(seg.read_bytes())
    # flip a byte inside the first record's payload (after the 56B header + 20B rec hdr)
    data[56 + 20 + 2] ^= 0xFF
    seg.write_bytes(data)
    res = segment_chain.verify(tmp_path, pub)
    assert not res.ok
    assert any("rec 0" in e for e in res.errors), res.errors


def test_checkpoint_forged_signature_detected(tmp_path):
    sk, pub = golden.new_issuer()
    other, _ = golden.new_issuer()
    _make_chain(tmp_path, sk)
    # verifying with a DIFFERENT issuer key must fail on the checkpoint sig
    res = segment_chain.verify(tmp_path, bytes(other.verify_key))
    assert not res.ok
    assert any("signature invalid" in e for e in res.errors), res.errors


# ---------------- checkpoint v1/v2 (E-C3) ----------------

def _forge_in_checkpoint(seg_dir, offset: int, raw: bytes):
    """Rewrite bytes inside every CHECKPOINT payload and repair the chain.

    No key material is used — that is the whole of `X13a`: `this_hash` is a bare
    sha256, so an attacker recomputes it for free. Only a signature that covers
    the forged bytes can object.
    """
    import hashlib
    import struct

    seg = sorted(Path(seg_dir).glob("*.seg"))[0]
    data = bytearray(seg.read_bytes())
    prev = hashlib.sha256(bytes(data[:56])).digest()
    off = 56
    while off + 20 <= len(data):
        rtype = struct.unpack("<I", bytes(data[off + 4:off + 8]))[0]
        plen = struct.unpack("<I", bytes(data[off + 16:off + 20]))[0]
        p0, p1 = off + 20, off + 20 + plen
        if rtype in (segment_chain.REC_CHECKPOINT, segment_chain.REC_CHECKPOINT_V2):
            data[p0 + offset:p0 + offset + len(raw)] = raw
        this = hashlib.sha256(bytes(data[off:off + 16]) + bytes(data[p0:p1]) + prev).digest()
        data[p1:p1 + 32] = prev
        data[p1 + 32:p1 + 64] = this
        prev = this
        off = p1 + 64
    seg.write_bytes(bytes(data))


def _v1_chain(tmp_path, sk):
    w = golden.SegmentWriter(tmp_path, sk)
    w.append(segment_chain.REC_TOKEN_ISSUED, 1700, b"tok-issued-payload")
    w.checkpoint(1702, version=1)
    w.close()


def test_checkpoint_v2_names_the_key_that_attested_it(tmp_path):
    """`E2-C5` — a v2 checkpoint verified against a NAMED ring reports which key.

    Before this, the answer was `checkpoints_verified += 1` and nothing else:
    a revoked key still in the ring kept passing and left no trace of having
    been the one (`F-PR-20`).
    """
    sk, pub = golden.new_issuer()
    _make_chain(tmp_path, sk)
    res = segment_chain.verify(tmp_path, {"dev-key-1": pub})
    assert res.ok, res.errors
    assert len(res.checkpoints) == 2
    for c in res.checkpoints:
        assert c.version == 2
        assert c.key_id == "dev-key-1"
        assert c.key_id_known is True
        assert c.count_attested is True


def test_unnamed_ring_leaves_key_id_unknown(tmp_path):
    """A bare list of keys cannot name the signer — and must not pretend to."""
    sk, pub = golden.new_issuer()
    _make_chain(tmp_path, sk)
    res = segment_chain.verify(tmp_path, [pub])
    assert res.ok, res.errors
    assert all(c.key_id is None and c.key_id_known is False for c in res.checkpoints)
    assert all(c.count_attested is True for c in res.checkpoints)


def test_checkpoint_v2_forged_record_count_rejected(tmp_path):
    """`E2-C5` — the v1 forgery of `X13a`, replayed against v2.

    `record_count` is inside the signed input now, so recomputing the hashes is
    not enough. This is the case that used to pass with a forged count reported
    as verified.
    """
    import struct as _s
    sk, pub = golden.new_issuer()
    _make_chain(tmp_path, sk)
    _forge_in_checkpoint(tmp_path, 32, _s.pack(">Q", 999))
    res = segment_chain.verify(tmp_path, {"dev-key-1": pub})
    assert not res.ok
    assert any("signature invalid" in e for e in res.errors), res.errors


def test_checkpoint_v2_segment_seq_pinned(tmp_path):
    """`CP2-03` — a checkpoint may not be replayed into another segment."""
    import struct as _s
    sk, pub = golden.new_issuer()
    _make_chain(tmp_path, sk)
    _forge_in_checkpoint(tmp_path, 40, _s.pack(">Q", 8))
    res = segment_chain.verify(tmp_path, {"dev-key-1": pub})
    assert not res.ok
    assert any("segment_seq" in e or "signature invalid" in e for e in res.errors), res.errors


def test_checkpoint_v1_stays_readable(tmp_path):
    """`F8` — the old record verifies forever. Deleting the parser would destroy
    past evidence with our own hands."""
    sk, pub = golden.new_issuer()
    _v1_chain(tmp_path, sk)
    res = segment_chain.verify(tmp_path, {"dev-key-1": pub})
    assert res.ok, res.errors
    assert len(res.checkpoints) == 1
    assert res.checkpoints[0].version == 1
    assert res.checkpoints[0].signature_verified is True


def test_checkpoint_v1_count_is_not_attested(tmp_path):
    """`E2-C5` step 5 — v1 verifies, and says what it could not vouch for.

    The forged count is still accepted (it is outside the signature and always
    will be), but it no longer arrives looking like an attested number. "I
    verified this" and "I cannot vouch for this field" must not be the same
    struct.
    """
    import struct as _s
    sk, pub = golden.new_issuer()
    _v1_chain(tmp_path, sk)
    _forge_in_checkpoint(tmp_path, 32, _s.pack("<Q", 999))
    res = segment_chain.verify(tmp_path, {"dev-key-1": pub})
    assert res.ok, res.errors
    c = res.checkpoints[0]
    assert c.record_count == 999          # the forgery still lands
    assert c.count_attested is False      # and the report says so
    assert c.signature_verified is True


def test_checkpoint_v1_never_names_a_key(tmp_path):
    """v1 signs a bare 32-byte hash with no domain separation (`X13b`).

    A matching ring key therefore proves "this key signed these bytes", not
    "this key attested this checkpoint". Naming a `key_id` here would be the
    over-claim, so `key_id_known` stays False even with a fully named ring.
    """
    sk, pub = golden.new_issuer()
    _v1_chain(tmp_path, sk)
    res = segment_chain.verify(tmp_path, {"dev-key-1": pub})
    assert res.checkpoints[0].key_id is None
    assert res.checkpoints[0].key_id_known is False


def test_find_locates_record(tmp_path):
    sk, pub = golden.new_issuer()
    _make_chain(tmp_path, sk)
    fr = segment_chain.find(tmp_path, b"gate-block-payload", issuer_pubs=[pub])
    assert fr.verified is True
    assert fr.result.checkpoints_verified == 2
    assert len(fr.records) == 1
    assert fr.records[0].type == segment_chain.REC_GATE_DECISION


def _tamper_first_record(tmp_path):
    seg = sorted(Path(tmp_path).glob("*.seg"))[0]
    data = bytearray(seg.read_bytes())
    data[56 + 20 + 2] ^= 0xFF
    seg.write_bytes(data)


def test_find_strict_refuses_broken_chain(tmp_path):
    """`E2-C3`/`E2-C4` — the record IS there and `find` must still refuse.

    This is the whole defect: before `E-C2` the tampered chain answered `[]`,
    which is byte-identical to "verified, not present". Tampering that destroys
    evidence was reported as absence of evidence.
    """
    sk, _ = golden.new_issuer()
    _make_chain(tmp_path, sk)
    _tamper_first_record(tmp_path)
    with pytest.raises(segment_chain.ChainNotVerified) as ei:
        segment_chain.find(tmp_path, b"tok-issued-payload")
    assert any("rec 0" in e for e in ei.value.result.errors), ei.value.result.errors


def test_find_nonstrict_carries_verified_false(tmp_path):
    """`E2-C4` — `strict=False` survives, but the answer says it is untrusted."""
    sk, _ = golden.new_issuer()
    _make_chain(tmp_path, sk)
    _tamper_first_record(tmp_path)
    fr = segment_chain.find(tmp_path, b"tok-issued-payload", strict=False)
    assert fr.verified is False
    assert fr.result.errors


def test_find_result_is_not_list_like(tmp_path):
    """A caller written against the old `List[Record]` must fail loudly.

    If `FindResult` were iterable, every existing `for r in find(...)` would
    keep working and would keep never learning about `verified` — the fix would
    be a comment. Enumeration can be bypassed by doing nothing; a type cannot.
    """
    sk, _ = golden.new_issuer()
    _make_chain(tmp_path, sk)
    fr = segment_chain.find(tmp_path, b"gate-block-payload")
    with pytest.raises(TypeError):
        len(fr)
    with pytest.raises(TypeError):
        iter(fr)


# ---------------- anchor (M9 / TC-AN) ----------------

def test_anchor_cross_check_head_matches(tmp_path):
    sk, pub = golden.new_issuer()
    w = _make_chain(tmp_path / "seg", sk)
    head = w.head_hash()
    rec = golden.build_anchor(sk, "robot-1", "dev-key-1", head.hex(),
                              segment_seq=2, record_count=2, unix_ms=1704)
    golden.write_anchor(tmp_path / "anchor", rec)
    res = anchor_check.cross_check(tmp_path / "anchor", pub, local_head_hash=head)
    assert res.ok, res.errors
    assert res.head_matches is True


def test_anchor_bad_signature_detected(tmp_path):
    sk, pub = golden.new_issuer()
    forger, _ = golden.new_issuer()
    rec = golden.build_anchor(forger, "robot-1", "dev-key-1", "ab" * 32,
                              segment_seq=1, record_count=1, unix_ms=1700)
    golden.write_anchor(tmp_path / "anchor", rec)
    res = anchor_check.cross_check(tmp_path / "anchor", pub)
    assert not res.ok
    assert any("bad signature" in e for e in res.errors)
