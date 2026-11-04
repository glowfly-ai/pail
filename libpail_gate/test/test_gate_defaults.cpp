// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// implementation contract (X26 + 그 쌍둥이) — 안전하지 않은 기본값.
//
// GateInputs 는 값 초기화만으로 "검증되었고(verify_ok=true) 소비되지 않았다
// (token_consumed=false)"고 말한다. 두 필드 모두 호출자가 채워야 하는 값인데,
// 채워지지 않은 상태의 기본값이 통과 쪽이다. 새 경로가 하나 늘어날 때마다
// 그 경로는 명시적으로 안전하게 만들어야만 안전하고, 잊으면 열린다.
//
// 이 배터리는 판정 코어를 상대로 그것을 직접 실증한다: 부분 초기화된
// GateInputs — 즉 검증을 한 번도 수행하지 않은 입력 — 가 PERMIT 을 받는가.
//
// RED(수정 전): 받는다.  GREEN(수정 후): 기본값이 verify_ok=false /
// token_consumed=true 이므로 ERR_TAMPERED 로 막힌다.
//
// 실행: ctest -R "^gate_defaults$" --output-on-failure

#include <cstdio>
#include <string>

#include "pail_gate/gate_core.hpp"

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

// 호출자가 "잊은" 입력. 토큰 뷰와 세계·안전 입력은 채우되, 검증 결과와
// 소비 조회 결과는 건드리지 않는다 — 새 경로가 실제로 저지르는 누락이다.
GateInputs PartiallyInitialized() {
  GateInputs in;
  in.path = GatePath::Command;
  in.now_ms = kNow;
  // DC-10: 드리프트는 측정된 것으로 채운다 — 이 배터리의 주제는 verify_ok/
  // token_consumed 기본값이고, 드리프트 기본값(미측정=거부)은 test_clock_drift
  // 가 같은 원리로 따로 실증한다.
  in.clock_drift_known = true;

  in.token_view.ok = true;
  in.token_view.chain_id = "chain-1";
  in.token_view.token_id = "tok-1";
  in.token_view.status = "OK";

  // in.verify_ok        — 채우지 않음 (X26)
  // in.token_consumed   — 채우지 않음 (쌍둥이)

  in.token_info.target_object_id = "pallet-7";
  in.token_info.action_type = pail_pep_gate::kActionMove;
  in.token_info.max_linear_speed_mps = 1.0;
  in.token_info.max_angular_speed_rps = 1.0;
  in.token_info.not_after_unix_ms = kNow + 30000;

  // C-B8 : empty world hashes now BLOCK (indeterminate). This
  // battery's subject is the verify_ok/token_consumed defaults — the world
  // comparison (3c, before 3d) must not preempt the twin row, so both sides
  // are stated here.
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

// PAIL-CASE: UnsafeDefaultsX26
int main() {
  {
    const GateInputs in = PartiallyInitialized();
    const GateDecision d = decide(in);
    Row("UnsafeDefaultsX26", d.state != "PERMIT" && !d.forward,
        "부분 초기화 입력(검증 미수행)이 PERMIT/forward 를 받아서는 안 된다");
    Row("UnsafeDefaultsX26", d.reason == "ERR_TAMPERED",
        "미채움 verify_ok 는 검증 실패와 같은 이유로 거부되어야 한다");
  }
  {
    // 쌍둥이 축: 검증은 채웠으나 소비 조회를 잊은 경우.
    GateInputs in = PartiallyInitialized();
    in.verify_ok = true;
    const GateDecision d = decide(in);
    Row("UnsafeDefaultsTwin", d.state != "PERMIT" && !d.forward,
        "소비 조회를 잊은 입력이 PERMIT 을 받아서는 안 된다 (기본값 = 소비됨)");
    Row("UnsafeDefaultsTwin", d.reason == "ERR_TOKEN_CONSUMED",
        "미채움 token_consumed 는 소비된 것으로 판정되어야 한다");
  }
  {
    // 대조군: 두 값을 명시적으로 채우면 정상 PERMIT. 기본값 반전이
    // 게이트를 잠가 버리는 것이 아님을 같은 배터리 안에서 보인다.
    GateInputs in = PartiallyInitialized();
    in.verify_ok = true;
    in.token_consumed = false;
    const GateDecision d = decide(in);
    Row("UnsafeDefaultsControl", d.state == "PERMIT" && d.reason == "OK" && d.forward,
        "명시적으로 채운 입력은 그대로 PERMIT (반전이 정상 경로를 막지 않는다)");
  }

  if (g_failures) {
    std::printf("test_gate_defaults: %d row(s) FAILED\n", g_failures);
    return 1;
  }
  return 0;
}
