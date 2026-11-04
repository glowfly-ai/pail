# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

# TB-3 (implementation contract/§3.5) — 계약 골든의 Python 소비자 축.
#
# 3언어 역할(§2.3): Go = 사전 보유자, C++ = 사유 생산자, Python = 증거 소비자.
# 여기서는 Python 미러들이 커밋된 골든(tests/golden/)과 어긋나지 않는지를 검사한다.
# 골든의 신선도는 Go 쪽이 보증한다(RD-01/RT-02, internal/contract) — 이 파일은
# 낡은 미러·유령 항목·격차 확대를 잡는 소비자 검사다.
#
# RD-05 는 처음부터 붉다(xfail strict): §1.5 실측 결함 D-F2 를 그대로 드러낸다.
# 그것은 RED 증명이 아니라 발견이며, 수정은 별건이다(설계 §5, P6 밖).

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from runner.verifiers import burst_verify, segment_chain  # noqa: E402
from tests import golden as golden_py  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = (REPO_ROOT / "spec" / "vectors") if (REPO_ROOT / "cloud" / "go.mod").exists() else (REPO_ROOT / "tests" / "golden")


# ---------------------------------------------------------------- vec readers

def read_flat_vec(path: Path) -> list[list[str]]:
    """평면 TSV 골든 (proto_schema/reason_dict/record_types/ros_msgs)."""
    rows = []
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        rows.append(line.split("\t"))
    assert rows, f"{path}: 행 0건"
    return rows


def read_vec_records(path: Path) -> list[dict[str, str]]:
    """§2.1 id-레코드형 (tokens.vec/canon.vec). 중복 key = 오류(마지막 승 금지)."""
    recs: list[dict[str, str]] = []
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        key, _, val = line.partition("\t")
        if key == "id":
            recs.append({"id": val})
            continue
        assert recs, f"{path}:{line_no}: 첫 id 이전에 key {key!r}"
        assert key not in recs[-1], (
            f"{path}:{line_no}: 레코드 {recs[-1]['id']} 안 key {key!r} 중복")
        recs[-1][key] = val
    assert recs, f"{path}: 레코드 0건"
    return recs


def reason_dump() -> dict[int, dict[str, str]]:
    """reason_dict.vec → {value: {code, plane}}."""
    out: dict[int, dict[str, str]] = {}
    for cols in read_flat_vec(GOLDEN / "contract" / "reason_dict.vec"):
        assert cols[0] == "reason" and len(cols) == 4, cols
        value = int(cols[2], 16)
        assert value not in out, f"덤프 값 중복: {cols}"
        out[value] = {"code": cols[1], "plane": cols[3]}
    # 2026-08-22 `D-L6`(POLCLASS): `ERR_EVIDENCE_TRUST_CLASS`(0x1A) 등재로 66 → 67.
    # 🚩 이 줄은 "다섯 자리 동시 갱신"이 세는 다섯 밖의 **여섯째 자리**였다.
    # 앞의 다섯을 다 고치고도 여기서 붉었다 — 계수 자리를 세는 목록 자체가
    # 낡아 있었던 것이고, 그 낡음은 사전을 늘릴 때만 드러난다(`H-B2`).
    # 2026-09-04 `AL-2`: 요청자·통로 거부 코드 4건(0x83~0x86) 등재로 67 → 71.
    # 2026-09-04 `AL-3`: 행동 클래스·대상 거부 코드 3건(0x87~0x89)으로 71 → 74.
    # 2026-09-14 `SKL v2.1`: 한도 초과 요청 거부 코드(0x8A, NB)로 74 → 75.
    # 2026-10-01 `OI-01`: ERR_REPORT_GAP (0x5A, LOCAL) — the robot agent's report queue overflow summary; 75 → 76.
    # 2026-10-18 P19-M1: ERR_BUNDLE_CLOCK/LIFETIME/POLICY (0x8B-0x8D, LOCAL) registered; 76 → 79.
    assert len(out) == 79, f"덤프 {len(out)}항목 — 79여야 한다"
    return out


def record_dump() -> dict[str, int]:
    """record_types.vec → {GoName: number}."""
    out: dict[str, int] = {}
    for cols in read_flat_vec(GOLDEN / "contract" / "record_types.vec"):
        assert cols[0] == "record" and len(cols) == 3, cols
        out[cols[1]] = int(cols[2])
    # §1.6 실측 정정으로 15종이었고, OR2(implementation contract B2-2)의 51 로 16종이 됐다.
    # 2026-08-12 OB3(C2-C6)의 90 RecordIdentityRefused 로 17종 — 벡터 헤더는
    # 그날 갱신됐으나 이 가드가 남았다(2026-08-13 C-B8 검증 중 발견·정정).
    # 2026-08-14 OB6(E-C3)의 31 RecordCheckpointV2 로 18종.
    # 2026-08-23 implementation contract(§4 DUR-L3)의 32 RecordRecoveryTruncate 로 19종.
    # 2026-09-04 AL-2(implementation contract D5)의 12 RecordContextSealed · 13 RecordPlanRejected 로 21종.
    # 2026-10-24 core-comm (PAIL-CORE-COMM-LLD-001 E/I): 100 RecordCoreOperation and 101 RecordCoreReport make 23.
    # The vector header was updated that day; this guard was not (found and corrected in the preview.35 presweep, 2026-10-25).
    assert len(out) == 23, f"golden has {len(out)} record types; expected 23 (21 + core-comm 100/101)"
    return out


# ------------------------------------------------------- RD: 사유 사전 미러

# 0xFF 는 사전 항목이 아니라 미등록 센티널(reason.Unregistered)이다 —
# 덤프에 없는 것이 옳고, 그 이름 문제는 RD-05 가 따로 본다.
UNREGISTERED = 0xFF


def test_rd02_mirror_names_match_dump():
    """RD-02: REASON_NAMES 의 모든 (값, 이름)이 덤프와 일치 — 잘못된 이름 탐지."""
    dump = reason_dump()
    checked = 0
    for value, name in burst_verify.REASON_NAMES.items():
        if value == UNREGISTERED:
            continue
        assert value in dump, f"0x{value:02x}: 미러에 있으나 덤프에 없음 (RD-03 소관이나 여기서도 사실)"
        assert dump[value]["code"] == name, (
            f"0x{value:02x}: 미러 {name!r} vs 사전 {dump[value]['code']!r}")
        checked += 1
    # 2026-08-13 C-B8: 0x19 미러 동반 등재로 8 → 9.
    # 2026-08-14 E-W5: 0x81 미러 동반 등재로 9 → 10.
    # 2026-08-16 C-B16: 0x44 미러 동반 등재로 10 → 11.
    # 2026-08-22 D-L6: 0x1A 미러 동반 등재로 11 → 12.
    assert checked == 12, f"미러 실항목 {checked} — 12여야 한다 (§1.5 실측)"
    print(f"GOLDEN-REASONS py mirror={checked} ok=True")


def test_rd03_no_ghost_entries():
    """RD-03: 미러에 덤프에 없는 값이 없다 — 유령 항목 탐지."""
    dump = reason_dump()
    ghosts = [v for v in burst_verify.REASON_NAMES
              if v != UNREGISTERED and v not in dump]
    assert ghosts == [], f"사전에 없는 유령 항목: {[hex(v) for v in ghosts]}"


# §1.5 기계 계수: 버스트 평면(BURST∪BOTH) 32종 대비 미러 누락 22종.
# (2026-08-13 C-B8: ERR_WORLD_INDETERMINATE 0x19 등재 — 미러에 같이 넣었으므로
#  동결 격차는 22종 그대로다. 신규 사유는 격차를 늘리지 않고 미러와 함께 온다.
#  2026-08-14 E-W5: ERR_IDENTIFIER_FORMAT 0x81(BOTH) 등재 — 같은 규율으로
#  미러에 동반 등재했으므로 31 → 32 는 늘고 격차 22 는 그대로다.
#  2026-08-16 C-B16: ERR_REVOKED_KEY_ID 0x44(BURST) 등재 — 32 → 33, 격차 22.
#  이 값을 미러에 넣는 것은 관례 이상이다: 미러가 모르면 판독기가 이것을
#  `UNMAPPED` 로 적고, 게이트가 갈라 놓은 「폐기」와 「모르는 키」가 증거
#  평면에서 다시 합쳐진다 — 이번 조건이 닫으려는 결함 그 자체다.
#  2026-08-22 D-L6: ERR_EVIDENCE_TRUST_CLASS 0x1A(BURST) 등재 — 33 → 34, 격차 22.
#  같은 논거다: 미러가 모르면 「물건이 다르다」(0x10, 미러에 있음)와 「증거의
#  등급이 모자란다」가 증거 평면에서 다시 하나가 된다.)
# 격차의 동결이지 승인이 아니다 — 채우는 것은 프로덕션 파이썬 수정(P6 밖, U-D4).
# 이 목록에 없는 새 누락이 생기면 아래가 FAIL 한다.
RD04_MISSING_ALLOWED = [
    0x15, 0x16, 0x17,                    # ERR_NO_EVIDENCE, SAFETY_STALE, CONSTRAINT
    0x21, 0x22, 0x23, 0x24, 0x25,        # 0x2X 체인 계열 (0x20 은 미러에 있음)
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,  # 토큰 유효성 전부
    0x40, 0x41, 0x42, 0x43,              # 0x4X 암호 검증 (0x44 는 미러에 있음)
    0x51,                                # ERR_GRPC_DISABLED
]


def test_rd04_missing_mirror_frozen():
    """RD-04: 버스트 평면 대비 미러 누락이 허용 목록 22종과 정확히 일치."""
    dump = reason_dump()
    burst_visible = {v for v, e in dump.items() if e["plane"] in ("BURST", "BOTH")}
    assert len(burst_visible) == 34, f"버스트 평면 {len(burst_visible)}종 — 34여야 한다 (§1.5)"
    missing = sorted(burst_visible - set(burst_verify.REASON_NAMES))
    assert missing == RD04_MISSING_ALLOWED, (
        f"미러 누락이 동결 목록과 다름:\n 신규 누락={[hex(v) for v in sorted(set(missing) - set(RD04_MISSING_ALLOWED))]}"
        f"\n 해소됨={[hex(v) for v in sorted(set(RD04_MISSING_ALLOWED) - set(missing))]}"
        "\n(해소했다면 목록을 줄여라 — 침묵 금지)")
    print(f"GOLDEN-REASONS py missing={len(missing)} frozen=True")


@pytest.mark.xfail(strict=True, reason="D-F2 (§1.5): .get 기본값이 0xFF 정식 이름과 충돌 — 수정은 별건(설계 §5)")
def test_rd05_unknown_label_distinct_from_0xff():
    """RD-05: '미러가 모른다'와 '미등록(0xFF)'은 다른 사실 — 라벨이 달라야 한다.

    처음부터 붉다. burst_verify.py:73 의 .get(self.reason, "UNMAPPED") 기본값이
    0xFF 의 정식 이름과 같아, 판독기 출력의 UNMAPPED 가 판독기 결함(미러 누락
    22종)과 시스템 사건(진짜 미등록)을 한 단어로 뭉갠다.
    """
    def named(reason: int) -> str:
        pkt = burst_verify.BurstPacket(
            magic=b"PBST", version=2, event=1, reason=reason, unix_ms=0,
            robot_id_hash=b"\x00" * 16, token_hash=b"\x00" * 16,
            burst_seq=0, reserved=b"\x00" * 4, signature=b"\x00" * 64,
            raw=b"")
        return pkt.reason_name

    # 0x15 는 사전 등재 사유인데 미러가 모른다. 0xEE 는 사전에도 없다.
    # 둘 다 0xFF 의 이름과 달라야 하는데, 현재는 셋 다 "UNMAPPED"다.
    assert named(0x15) != named(UNREGISTERED)
    assert named(0xEE) != named(UNREGISTERED)


# ------------------------------------------------- RT: 레코드 타입 미러

# segment_chain.py 미러 9종 ↔ Go 이름 (record_types.vec 의 키).
# 51 은 OR2(implementation contract B2-3)가, 31 은 OB6(implementation contract E-C3)이 추가했다.
RT_MIRROR = {
    "RecordTokenIssued": segment_chain.REC_TOKEN_ISSUED,
    "RecordPlanAccepted": segment_chain.REC_PLAN_ACCEPTED,
    "RecordGateDecision": segment_chain.REC_GATE_DECISION,
    "RecordChainRevoked": segment_chain.REC_CHAIN_REVOKED,
    "RecordCheckpoint": segment_chain.REC_CHECKPOINT,
    "RecordCheckpointV2": segment_chain.REC_CHECKPOINT_V2,
    "RecordSafeStop": segment_chain.REC_SAFE_STOP,
    "RecordOperatorEvent": segment_chain.REC_OPERATOR_EVENT,
    "RecordContextProvenance": segment_chain.REC_CONTEXT_PROVENANCE,
}

# 미러 누락 8종의 동결 (설계서 "9종"은 16종 오기의 파생 — 실측 당시 15-7=8).
# OR2 에서 정본이 16종이 되고 미러가 8종이 되었으므로 누락 수는 8로 유지된다 —
# 51 을 미러에 넣었을 뿐, 기존 격차 8건은 하나도 해소하지 않았다.
# 2026-08-12 OB3(C2-C6)의 90 은 미러가 받지 않아 누락 9종 (벡터 헤더에 그날
# 명시된 결정 — PVS 는 거부 레코드를 파싱할 소비자가 아직 없다).
# 2026-08-23 implementation contract(§4 DUR-L3)의 32 도 미러가 받지 않아 누락 10종. 이 격차는
# 조용하지 않다: 미러가 32 를 모르면 PVS 는 "복구가 일어났다"를 **레코드 0건**으로
# 읽고, 그것은 "복구가 없었다"와 같은 바이트다(H-B2). 미러가 이 레코드를 소비해야
# 하는 날은 PVS 가 기동 복구를 판정 대상으로 삼는 날이며, 그때까지는 여기 적힌
# 격차가 그 사실을 대신 말한다. 목록은 dump 의 번호 오름차순이라 32 가 맨 앞이다.
RT04_MISSING_ALLOWED = [
    # 2026-09-04 AL-2: 12·13 은 PVS 가 요청자 거부를 판정 대상으로 삼는 날 미러에 받는다.
    "RecordContextSealed", "RecordPlanRejected",
    "RecordRecoveryTruncate",
    "RecordGraphMutation", "RecordAttestation", "RecordConfigSealed",
    "RecordLeaseGranted", "RecordLeaseReconciled", "RecordFleetCensus",
    "RecordLeaseRetracted", "RecordHaMembership", "RecordIdentityRefused",
    # 2026-10-24 core-comm receipts (100/101 = CORE_OPERATION / CORE_REPORT since preview.38): the mirror may omit them
    # only until PVS judges receipt payloads; this allowance is a deferral of the PVS judgement, not a verdict on the mirror.
    "RecordCoreOperation", "RecordCoreReport",
]


def test_rt03_segment_chain_subset():
    """RT-03: segment_chain.py 9종이 골든의 부분집합이며 값 일치 — 사본 오류 탐지."""
    dump = record_dump()
    for name, value in RT_MIRROR.items():
        assert name in dump, f"{name}: 미러에 있으나 골든에 없음"
        assert dump[name] == value, f"{name}: 미러 {value} vs 골든 {dump[name]}"
    print(f"GOLDEN-RECORDS py mirror={len(RT_MIRROR)} ok=True")


def test_rt04_missing_mirror_frozen():
    """RT-04: 미러 누락 12종이 명시적 허용 목록과 일치 — 격차 동결."""
    dump = record_dump()
    missing = sorted(set(dump) - set(RT_MIRROR), key=lambda n: dump[n])
    assert missing == RT04_MISSING_ALLOWED, (
        f"누락이 동결 목록과 다름: {missing} (해소했다면 목록을 줄여라)")


def test_rt05_python_internal_double_declaration():
    """RT-05: golden.py 의 REC_CHECKPOINT 재선언 ≡ segment_chain.py.

    golden.py 는 스스로 "faithful python reimplementation"이라 선언하며 같은
    숫자를 독립 재선언한다(§1.6) — 한쪽만 고치는 것을 이 검사만이 막는다.
    """
    assert golden_py.REC_CHECKPOINT == segment_chain.REC_CHECKPOINT == 30
    # E-C3: golden.py 가 v2 도 독립 재선언한다. 여기에 얹지 않으면 v2 쪽만
    # 한쪽에서 어긋나도 이 검사는 30 을 보고 통과한다.
    assert golden_py.REC_CHECKPOINT_V2 == segment_chain.REC_CHECKPOINT_V2 == 31


# ------------------------------------------------- G-CTR-06: canon Python 축

def test_gctr06_canon_assembly_python_axis():
    """G-CTR-06 Python 축 (§3.5): backend_live.py:401 f-string 관용구로 canon 을
    조립해 canon.vec 와 대조한다. Go 축(TestGCTR06)과 같은 골든이 기준점이다.

    backend_live 모듈은 rclpy/grpc 를 요구하므로 임포트하지 않는다 — 대신
    같은 관용구를 여기서 실행하고, 원문 스캔으로 조립 지점이 그 관용구
    그대로임을 못 박는다.
    """
    recs = read_vec_records(GOLDEN / "token" / "canon.vec")
    assert len(recs) == 5, f"canon.vec {len(recs)}건 — 5건이어야 한다 (CV-01~05)"

    checked = 0
    for r in recs:
        nonce = bytes.fromhex(r["nonce"])
        b64 = base64.b64encode(nonce).decode()
        if r["func"] == "unlock":
            got = f"pail-unlock:v1:{r['arg_id']}:{r['unix_ms']}:{b64}"
        elif r["func"] == "revoke":
            got = f"pail-revoke-issuer:v1:{r['arg_id']}:{r['unix_ms']}:{b64}"
        else:
            pytest.fail(f"{r['id']}: 미지 func {r['func']!r}")
        assert got == r["canon"], (
            f"{r['id']}: canon 불일치\n got={got!r}\nwant={r['canon']!r}")
        print(f"GOLDEN-CANON py {r['id']} ok=True")
        checked += 1
    assert checked == 5


def test_gctr06_canon_source_pinned():
    """조립 지점 고정: backend_live.py 의 unlock canon f-string 이 정확히 1곳,
    revoke 조립기는 0곳(Go 전용 — 생기면 골든 편입이 먼저다).

    OB1 커밋4(9e4ba05, A2-5)가 조립기를 v2 로 올렸는데 이 핀은 v1 을 세고
    있었다 — 2026-08-08 이후 이 테스트는 붉은 채였고 아무도 못 봤다(OB3 에서
    발견, 2026-08-12). v1 계수 0 도 함께 고정한다: v1 조립기가 되돌아오는
    것은 회귀다."""
    src = (Path(__file__).resolve().parents[1] / "runner" / "live" / "backend_live.py").read_text()
    assert src.count('f"pail-unlock:v2:') == 1, (
        "unlock canon(v2) 조립 지점이 1곳이 아님 — 골든 축과의 대응이 흐려진다")
    assert src.count('f"pail-unlock:v1:') == 0, (
        "구판(v1) 조립기가 되돌아왔다 — A2-5 이후 라이브 경로는 v2 다")
    assert src.count('f"pail-revoke-issuer:') == 0, (
        "Python 에 revoke canon 조립기가 생겼다 — canon.vec 대조를 이 파일에 추가하라")
