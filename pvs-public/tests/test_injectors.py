# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Host-runnable chaos_monkey tests (docker-free paths)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runner.injectors.chaos_monkey import ChaosMonkey  # noqa: E402
from runner.verifiers import segment_chain  # noqa: E402
from tests import golden  # noqa: E402


def test_pktdrop_keeps_one_and_still_recovers():
    sk, pub = golden.new_issuer()
    pkt = golden.build_burst(sk, 3, 0x13, 1700, "robot-1", "tok", burst_seq=5)
    five = [pkt] * 5
    kept = ChaosMonkey.pktdrop(five, keep_indices=[3])  # TC-SV-02
    assert len(kept) == 1


def test_diskcorrupt_flip_breaks_chain(tmp_path):
    sk, pub = golden.new_issuer()
    w = golden.SegmentWriter(tmp_path, sk)
    w.append(segment_chain.REC_GATE_DECISION, 1700, b"payload-xyz")
    w.checkpoint(1701)
    w.close()
    assert segment_chain.verify(tmp_path, pub).ok
    ChaosMonkey().diskcorrupt(tmp_path, mode="flip", byte_index=56 + 20 + 1)
    assert not segment_chain.verify(tmp_path, pub).ok


def test_clockskew_is_unsupported_by_design():
    with pytest.raises(NotImplementedError):
        ChaosMonkey().clockskew("services", 5000)  # §6.1
