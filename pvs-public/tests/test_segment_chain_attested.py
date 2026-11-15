# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""SEC-H07 (R7): the Python verifier reports what the signatures cover.

A recomputable hash chain attests nothing by itself; only signed checkpoints do.
`verify()` therefore reports how many records sit under a verified checkpoint
and how many trail after the last one, and offers a strict mode that refuses a
journal with no signed coverage or with an uncovered tail. The default call
keeps its meaning, so existing callers do not change verdict silently.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner.verifiers import segment_chain  # noqa: E402
from tests import golden  # noqa: E402


def _journal(tmp_path, sk, bodies_then_ckpt):
    """bodies_then_ckpt: list of (n_bodies, write_checkpoint) groups."""
    w = golden.SegmentWriter(tmp_path, sk)
    t = 1700
    for n, ckpt in bodies_then_ckpt:
        for _ in range(n):
            w.append(segment_chain.REC_GATE_DECISION, t, b"h07-body-%d" % t)
            t += 1
        if ckpt:
            w.checkpoint(t)
            t += 1
    w.close()
    return tmp_path


def test_t14a_fully_covered_journal_reports_full_coverage(tmp_path):
    sk, pub = golden.new_issuer()
    d = _journal(tmp_path, sk, [(2, True), (3, True)])
    r = segment_chain.verify(d, pub)
    assert r.ok
    assert r.records == 7
    assert r.attested_records == 7
    assert r.unattested_tail == 0
    strict = segment_chain.verify(d, pub, require_attested=True)
    assert strict.ok, strict.errors


def test_t14b_default_call_keeps_its_verdict_but_reports_no_coverage(tmp_path):
    sk, pub = golden.new_issuer()
    d = _journal(tmp_path, sk, [(4, False)])
    r = segment_chain.verify(d, pub)
    assert r.ok                      # unchanged meaning: the chain is consistent
    assert r.attested_records == 0
    assert r.unattested_tail == 4


def test_t14c_strict_mode_refuses_a_journal_with_no_signed_checkpoint(tmp_path):
    sk, pub = golden.new_issuer()
    d = _journal(tmp_path, sk, [(4, False)])
    r = segment_chain.verify(d, pub, require_attested=True)
    assert not r.ok
    assert any("no signed checkpoint" in e for e in r.errors), r.errors


def test_t14d_strict_mode_refuses_an_uncovered_tail(tmp_path):
    sk, pub = golden.new_issuer()
    d = _journal(tmp_path, sk, [(3, True), (2, False)])
    r = segment_chain.verify(d, pub)
    assert r.ok
    assert r.attested_records == 4
    assert r.unattested_tail == 2
    strict = segment_chain.verify(d, pub, require_attested=True)
    assert not strict.ok
    assert any("unattested tail" in e for e in strict.errors), strict.errors


def test_t14e_strict_mode_without_a_key_cannot_pass(tmp_path):
    sk, _pub = golden.new_issuer()
    d = _journal(tmp_path, sk, [(2, True)])
    r = segment_chain.verify(d, None, require_attested=True)
    assert not r.ok
    assert r.attested_records == 0
