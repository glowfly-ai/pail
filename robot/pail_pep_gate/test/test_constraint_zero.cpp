// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// test_constraint_zero — implementation contract (C-B5): `0 = 무제한` 의미론 제거.
//
// 두 절반을 한 곳에서 잰다 (§9 관측점 B — "발급 거부 3필드 + 집행 1건"):
//   1. ConstraintZeroReason 진리표 — 속도 2필드·not_after 의 0 은 발급값이
//      아니다(ERR_BAD_TOKEN). max_duration_sec 0 은 인자조차 아니다 — 그 집행은
//      명령 경로 소관이라 이 함수가 물을 일이 없다.
//   2. step_overrun 집행 — decide() 가 명령 경로에서 스스로 묻는다. 타이머가
//      멈춰도(fail-open 부품) 초과 스텝은 BLOCK "ERR_CONSTRAINT".
//
// std-only: sodium / protobuf / rclcpp 불요 — L1 티어.

#include <cstdio>
#include <cstring>
#include <string>

#include "pail_gate/gate_core.hpp"
#include "pail_gate/strict_verify.hpp"

namespace {

int g_failures = 0;

void Row(const char *name, bool ok, const char *note) {
  if (!ok) {
    std::fprintf(stderr, "  FAIL [%s] %s\n", name, note);
    ++g_failures;
  } else {
    std::printf("  ok   [%s] %s\n", name, note);
  }
}

constexpr int64_t kNow = 1700000000000;

// D §3.2 집행 확인용 최소 유효 입력 (test_gate_core BaseGrpc 축약본).
pail_pep_gate::GateInputs PermitBase() {
  pail_pep_gate::GateInputs in;
  in.path = pail_pep_gate::GatePath::Command;
  in.now_ms = kNow;
  in.clock_drift_known = true;
  in.token_view.ok = true;
  in.token_view.token_id = "tok-1";
  in.token_view.chain_id = "chain-1";
  in.token_view.status = "OK";
  in.verify_ok = true;
  in.token_consumed = false;
  in.token_info.target_object_id = "pallet-7";
  in.token_info.action_type = pail_pep_gate::kActionMove;
  in.token_info.max_linear_speed_mps = 1.0;
  in.token_info.max_angular_speed_rps = 1.0;
  in.token_info.not_after_unix_ms = kNow + 30000;
  in.token_info.token_id = "tok-1";
  in.token_info.chain_id = "chain-1";
  in.token_info.consumption_key = "ck-tok-1";
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
  in.limits.clock_skew_ms = 500;
  in.limits.evidence_window_ms = 2000;
  in.limits.evidence_conf_threshold = 0.90;
  in.limits.safety_stale_ms = 1000;
  return in;
}

}  // namespace

int main() {
  using pail_pep_gate::ConstraintZeroReason;

  // ---- 1. 발급 거부 진리표 (D §3.1) — 위반은 정확히 한 필드씩 (H-B9) ----
  struct TableRow {
    const char *name;
    bool has_constraints;
    double lin, ang;
    int64_t not_after;
    const char *want;  // nullptr = 정형
  };
  const int64_t kFuture = kNow + 30000;
  const TableRow rows[] = {
      {"well-formed", true, 0.5, 0.5, kFuture, nullptr},
      {"zero linear", true, 0.0, 0.5, kFuture, "ERR_BAD_TOKEN"},
      {"zero angular", true, 0.5, 0.0, kFuture, "ERR_BAD_TOKEN"},
      {"zero not_after (permanent)", true, 0.5, 0.5, 0, "ERR_BAD_TOKEN"},
      {"negative not_after", true, 0.5, 0.5, -1, "ERR_BAD_TOKEN"},
      {"constraints absent", false, 0.0, 0.0, kFuture, "ERR_BAD_TOKEN"},
      // proto3: 부재와 전부-0 은 같은 와이어 바이트 — 판정도 같아야 한다.
      {"constraints all-zero", true, 0.0, 0.0, kFuture, "ERR_BAD_TOKEN"},
      {"negative linear", true, -0.1, 0.5, kFuture, "ERR_BAD_TOKEN"},
  };
  for (const auto &r : rows) {
    const char *got =
        ConstraintZeroReason(r.has_constraints, r.lin, r.ang, r.not_after);
    const bool ok = (r.want == nullptr)
                        ? (got == nullptr)
                        : (got != nullptr && std::strcmp(got, r.want) == 0);
    Row("D5-C1", ok, r.name);
  }

  // ---- 2. 집행 1건 (D §3.2) — 타이머 없이 명령 경로가 스스로 막는다 ----
  {
    pail_pep_gate::GateInputs in = PermitBase();
    in.step_active = true;
    in.step_deadline_ms = kNow - 1;
    const pail_pep_gate::GateDecision d = pail_pep_gate::decide(in);
    Row("D5-C2", d.state == "BLOCK" && d.reason == "ERR_CONSTRAINT" && d.report,
        "overrun step: BLOCK ERR_CONSTRAINT, reported");
  }
  {
    // 대조군: 초과 전이면 통과 — 항상 붉은 게이트는 게이트가 아니라 벽이다.
    pail_pep_gate::GateInputs in = PermitBase();
    in.step_active = true;
    in.step_deadline_ms = kNow + 5000;
    const pail_pep_gate::GateDecision d = pail_pep_gate::decide(in);
    Row("D5-C2", d.state == "PERMIT" && d.reason == "OK",
        "control: within deadline, PERMIT");
  }

  if (g_failures == 0) {
    std::printf("test_constraint_zero: all rows PASS\n");
    return 0;
  }
  std::fprintf(stderr, "test_constraint_zero: %d FAILURES\n", g_failures);
  return 1;
}
