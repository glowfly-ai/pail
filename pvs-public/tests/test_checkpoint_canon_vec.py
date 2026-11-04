# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

# E-C3  — checkpoint canon 의 Python 축.
#
# tests/golden/canon/checkpoint_v2.vec 는 OR1 에서 동결됐는데 **읽는 코드가
# 없었다**. 서명 입력을 재구현한 곳이 다섯이었고 전부 주석으로만 이 파일을
# 인용했다 — 인용은 대조가 아니다(F7/NF6).
#
# 여기서 고정하는 둘은 역할이 다르다:
#   - runner/verifiers/segment_chain.py = 검증자 (증거를 읽는 쪽)
#   - tests/golden.py                   = 생산자 (픽스처를 만드는 쪽)
# 둘을 서로 대조하면 "생산자가 만든 것을 검증자가 받는다"는 항등식이 되어
# 함께 표류해도 초록이다(golden.py 머리주석의 독립성 규약). 그래서 둘 다
# **동결 바이트**에 각각 묶는다.
#
# 방향: 벡터가 고정된 쪽이다. 여기서는 재동결하지 않는다.

from __future__ import annotations

import struct

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from runner.verifiers import segment_chain  # noqa: E402
from tests import golden as golden_py  # noqa: E402
from tests.test_contract_golden import GOLDEN, read_vec_records  # noqa: E402

VEC = GOLDEN / "canon" / "checkpoint_v2.vec"

# MKVEC-CANON.md §고정 시드: 0x01×32 의 ed25519. 비밀이 아니라 테스트 전용
# 값이고, 아래 첫 단언이 이 키가 정말 벡터를 서명한 키인지 먼저 확인한다.
VEC_SEED = b"\x01" * 32


def records() -> dict[str, dict[str, str]]:
    return {r["id"]: r for r in read_vec_records(VEC)}


def rec(rid: str) -> dict[str, str]:
    r = records().get(rid)
    assert r is not None, f"동결 벡터에 레코드 {rid} 없음"
    return r


def vec_signing_key(rid: str) -> SigningKey:
    """문서화된 시드로 키를 세우고, 그 공개키가 벡터의 것과 같은지 먼저 본다.

    이 확인이 없으면 다른 키로 만든 바이트를 "재현했다"고 비교하게 되고,
    불일치는 코드 표류가 아니라 키 불일치를 뜻하게 된다.
    """
    sk = SigningKey(VEC_SEED)
    assert bytes(sk.verify_key).hex() == rec(rid)["pubkey"], (
        "MKVEC-CANON.md 의 고정 시드가 벡터의 pubkey 를 만들지 않는다")
    return sk


# ---------------------------------------------------------------- 검증자 축

def test_cpv_signed_input_matches_frozen():
    """CP2-01: 검증자의 서명 입력 조립이 동결 바이트를 재현하는가."""
    r = rec("CP2-01")
    got = segment_chain.checkpoint_v2_signed_input(
        bytes.fromhex(r["head_hash_hex"]), int(r["record_count"]), int(r["segment_seq"]))
    assert got.hex() == r["signed_input_hex"], "서명 입력이 동결 벡터에서 표류했다"
    # 동결 서명이 그 바이트를 실제로 덮는지까지 — 조립이 옳아도 서명이 다른
    # 것을 덮고 있으면 벡터가 자기모순이다.
    VerifyKey(bytes.fromhex(r["pubkey"])).verify(got, bytes.fromhex(r["sig"]))
    assert r["expect_verify"] == "1"


def test_cpv_lengths_match_frozen():
    """길이 상수의 정본은 벡터의 payload_len 이다. 상수가 틀리면 잘린
    페이로드가 '정상'으로 읽힌다."""
    assert segment_chain.CHECKPOINT_V2_LEN == int(rec("CP2-01")["payload_len"])
    assert segment_chain.CHECKPOINT_V1_LEN == int(rec("CP1-90")["payload_len"])


@pytest.mark.parametrize("rid", ["CP2-02", "CP2-03"])
def test_cpv_forgery_rejected(rid: str):
    """CP2-02(count 위조) / CP2-03(segment_seq 재사용): 검증자가 하는 그대로
    **페이로드가 실은 값**으로 서명 입력을 다시 세우면 서명이 깨진다.
    v1 에서는 이 두 바이트가 서명 밖이라 통과했다 — 그것이 X13a·NF4 다."""
    r = rec(rid)
    payload = bytes.fromhex(r["payload_hex"])
    assert len(payload) == segment_chain.CHECKPOINT_V2_LEN
    head = payload[0:32]
    count = struct.unpack(">Q", payload[32:40])[0]
    seq = struct.unpack(">Q", payload[40:48])[0]
    # 페이로드에서 읽은 값이 벡터가 선언한 위조값과 같아야 한다 — 다르면 이
    # 테스트는 위조를 재지 않고 다른 것을 재고 있다.
    assert (count, seq) == (int(r["record_count"]), int(r["segment_seq"]))
    signed = segment_chain.checkpoint_v2_signed_input(head, count, seq)
    assert r["expect_verify"] == "0"
    with pytest.raises(BadSignatureError):
        VerifyKey(bytes.fromhex(r["pubkey"])).verify(signed, payload[48:112])


def test_cpv1_stays_verifiable():
    """CP1-90 (F8): 구판은 영원히 검증 가능해야 하고, 그 검증이 말하지 **않는**
    것도 벡터에 적혀 있다 — count 는 u64 LE 로 서명 밖에 있다."""
    r = rec("CP1-90")
    assert r["count_endian"] == "le"
    payload = bytes.fromhex(r["payload_hex"])
    assert len(payload) == segment_chain.CHECKPOINT_V1_LEN
    head = payload[0:32]
    assert head.hex() == r["signed_input_hex"], "v1 서명 입력은 head 그대로다"
    assert struct.unpack("<Q", payload[32:40])[0] == int(r["record_count"])
    VerifyKey(bytes.fromhex(r["pubkey"])).verify(head, payload[40:104])
    assert r["expect_verify"] == "1"


# ---------------------------------------------------------------- 생산자 축

def test_cpv_producer_reproduces_frozen_payload():
    """golden.py 의 v2 생산자가 동결 페이로드를 바이트로 재현하는가.

    ed25519 는 결정적이므로 이것은 재서명이 아니라 비교다 — 기대값은 여전히
    동결 파일 쪽에 있고, 움직인 것이 있다면 구현이다."""
    r = rec("CP2-01")
    got = golden_py.checkpoint_v2_payload(
        bytes.fromhex(r["head_hash_hex"]), int(r["record_count"]),
        int(r["segment_seq"]), vec_signing_key("CP2-01"))
    assert got.hex() == r["payload_hex"], "생산자의 v2 페이로드가 표류했다"


def test_cpv1_producer_reproduces_frozen_payload():
    """v1 생산자도 남아야 한다(F8) — 아무도 먹이지 않는 파서는 고장 난 줄
    아무도 모르는 파서다."""
    r = rec("CP1-90")
    got = golden_py.checkpoint_v1_payload(
        bytes.fromhex(r["head_hash_hex"]), int(r["record_count"]),
        vec_signing_key("CP1-90"))
    assert got.hex() == r["payload_hex"], "생산자의 v1 페이로드가 표류했다"
