// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// DC-10  — 단조 기준선 대비 벽시계 드리프트.
//
// 판정의 모든 시간 검사(만료, 증거 창, 안전 신선도)는 now_ms 를 읽고,
// now_ms 는 설정 가능한 시계에서 온다. date -s / NTP 스텝 하나가 그 검사
// 전부를 동시에 움직인다. 그래서 드리프트 규칙은 경로 스위치보다 앞에
// 선다 — 오염된 시계로는 어떤 경로의 판정도 하지 않는다.
//
// 허용치는 기존 clock_skew_ms 를 재사용한다: 발급자와 N ms 이상 어긋나면
// 못 믿는 시계가 자기 자신과는 그보다 크게 어긋나도 된다는 것은 말이 안
// 된다. 미측정(clock_drift_known=false)도 거부다 — 측정하지 않은 시계는
// 건강한 시계가 아니다 (H-B2, X26 과 같은 기본값 규율).
//
// 실행: ctest -R "^clock_drift$" --output-on-failure

#include <cstdio>
#include <string>

#include "pail_gate/gate_core.hpp"
#include "pail_gate/wall_clock.hpp"

using pail_pep_gate::GateDecision;
using pail_pep_gate::GateInputs;
using pail_pep_gate::GatePath;
using pail_pep_gate::decide;

namespace {

int g_failures = 0;

void Row(const char *name, bool cond, const char *detail) {
  if (cond) {
    std::printf("PASS: %s — %s\n", name, detail);
  } else {
    std::printf("FAIL: %s — %s\n", name, detail);
    ++g_failures;
  }
}

constexpr int64_t kNow = 1000000;

// PERMIT 에 도달하는 깨끗한 grpc 명령 — 각 행은 여기서 드리프트 하나만
// 바꾼다 (H-B9: 정확히 한 속성만 위반).
GateInputs BaseGrpc() {
  GateInputs in;
  in.path = GatePath::Command;
  in.now_ms = kNow;
  in.clock_drift_known = true;

  in.token_view.ok = true;
  in.token_view.chain_id = "chain-1";
  in.token_view.token_id = "tok-1";
  in.token_view.status = "OK";

  in.verify_ok = true;
  in.token_consumed = false;

  in.token_info.target_object_id = "pallet-7";
  in.token_info.action_type = pail_pep_gate::kActionMove;
  in.token_info.max_linear_speed_mps = 1.0;
  in.token_info.max_angular_speed_rps = 1.0;
  in.token_info.not_after_unix_ms = kNow + 30000;

  // C-B8 : empty world hashes now BLOCK (indeterminate) — a
  // passing baseline states both sides.
  in.token_info.subgraph_snapshot_hash = "wh-1";
  in.token_view.current_subgraph_hash = "wh-1";

  in.evidence.object_id = "pallet-7";
  in.evidence.confidence = 0.97;
  in.evidence.received_ms = kNow - 500;
  // D-L7 §6.4 (O-3): stated, not inherited. The default is false because a
  // gate that was never asked must not read as one that answered — so a
  // baseline carrying evidence has to say it carries evidence.
  in.evidence.ever_received = true;

  in.safety.enabled = true;
  in.safety.level = "OK";
  in.safety.ever_received = true;
  in.safety.observed_ms = kNow - 200;

  in.command.linear_norm = 0.5;
  in.command.angular_norm = 0.2;

  in.supplier.provider_mode = "grpc";
  in.supplier.grpc_built = true;
  in.supplier.permit_grace_n = 3;

  in.limits.clock_skew_ms = 500;
  in.limits.evidence_window_ms = 2000;
  in.limits.evidence_conf_threshold = 0.90;
  in.limits.safety_stale_ms = 1000;
  return in;
}

}  // namespace

int main() {
  {
    // 대조군: 드리프트 0 인 기준 입력은 그대로 PERMIT.
    const GateDecision d = decide(BaseGrpc());
    Row("DriftControl", d.state == "PERMIT" && d.reason == "OK" && d.forward,
        "드리프트 0 은 정상 경로를 막지 않는다");
  }
  {
    // 전진 점프: 허용치(500) 초과.
    GateInputs in = BaseGrpc();
    in.clock_drift_ms = 501;
    const GateDecision d = decide(in);
    Row("DriftForward", d.state == "BLOCK" && d.reason == "ERR_CLOCK_DRIFT",
        "skew 초과 전진 드리프트는 BLOCK");
    Row("DriftForward", d.stop_permit && !d.forward,
        "드리프트 BLOCK 은 하트비트를 멈추고 전달하지 않는다");
  }
  {
    // 되감기: 부호만 다르고 같은 판정 — |드리프트| 로 잰다.
    GateInputs in = BaseGrpc();
    in.clock_drift_ms = -501;
    const GateDecision d = decide(in);
    Row("DriftRewind", d.state == "BLOCK" && d.reason == "ERR_CLOCK_DRIFT",
        "되감긴 시계도 같은 이유로 거부된다");
  }
  {
    // 경계: 정확히 허용치는 통과 (초과만 드리프트다 — held_expired 의
    // 부등호 규율과 같은 방향).
    GateInputs in = BaseGrpc();
    in.clock_drift_ms = 500;
    const GateDecision d = decide(in);
    Row("DriftBoundary", d.state == "PERMIT" && d.reason == "OK",
        "드리프트 == skew 는 허용 (strict > 만 거부)");
  }
  {
    // H-B2: 미측정은 드리프트 0 과 같은 답을 받으면 안 된다.
    GateInputs in = BaseGrpc();
    in.clock_drift_known = false;
    in.clock_drift_ms = 0;
    const GateDecision d = decide(in);
    Row("DriftUnknown", d.state == "BLOCK" && d.reason == "ERR_CLOCK_DRIFT",
        "측정하지 않은 시계는 거부된다 (미확인 != 확인했고 정상)");
  }
  {
    // 드리프트는 Recheck 경로도 선점한다 — hold.active 가드보다 앞.
    GateInputs in = BaseGrpc();
    in.path = GatePath::Recheck;
    in.hold.active = false;  // 평소라면 무발행으로 끝나는 입력
    in.clock_drift_ms = 501;
    const GateDecision d = decide(in);
    Row("DriftRecheck", d.state == "BLOCK" && d.reason == "ERR_CLOCK_DRIFT",
        "드리프트는 경로를 가리지 않는다 (100ms 마다 시끄럽게 — 의도)");
  }
  {
    // Grace 경로도 같다.
    GateInputs in = BaseGrpc();
    in.path = GatePath::Grace;
    in.clock_drift_ms = 501;
    const GateDecision d = decide(in);
    Row("DriftGrace", d.state == "BLOCK" && d.reason == "ERR_CLOCK_DRIFT",
        "grace 는 발급자 왕복만 건너뛰지 시계 검사는 못 건너뛴다");
  }
  {
    // 측정 헬퍼 자체의 끝-끝 동작: 방금 잡은 기준선의 드리프트는 작아야
    // 한다. (시계를 조작하지 않는 호스트에서의 정상성 확인 — 조작 실측은
    // 컨테이너 안 라이브 단계 C3-C6 의 몫.)
    const pail_pep_gate::ClockBaseline b = pail_pep_gate::CaptureBaseline();
    const int64_t drift = pail_pep_gate::DriftMs(b);
    const int64_t abs_drift = drift >= 0 ? drift : -drift;
    Row("BaselineSanity", abs_drift < 500,
        "직후 측정한 드리프트는 허용치 미만이어야 한다");
    Row("BaselineSanity", b.wall_ms0 > 0 && b.steady_ns0 >= 0,
        "기준선 쌍은 실제 시계 값이어야 한다");
  }

  if (g_failures) {
    std::printf("test_clock_drift: %d row(s) FAILED\n", g_failures);
    return 1;
  }
  return 0;
}
