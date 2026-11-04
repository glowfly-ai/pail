// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// test_safety_level — implementation contract (C-B7): 모르는 안전 상태는 UNSAFE.
//
// 세 절반을 한 곳에서 잰다 (§8 D7-C1/C2/C3):
//   1. D7-C1 — 4값 파싱 + 5입력("OK"/"WARN"/"UNSAFE"/"warn"/"") × 새 허가 차단.
//      차단 값이 "WARN" 하나였던 옛 형태에서는 오타·빈 문자열·미래 레벨이
//      전부 통과했다.
//   2. D7-C2 — E-STOP 해제 표 전수: kOk 만 푼다. 옛 형태는 else 라
//      "UNSAFE 아님" 전부가 유일한 해제 지점을 풀었다.
//   3. D7-C3 — NaN 4지점: NaN 은 모든 비교에서 거짓이라 `> max` 도
//      `< threshold` 도 통과다. 각 케이스는 PERMIT 베이스라인에서 정확히
//      한 필드만 NaN 으로 뒤집는다 (H-B9).
//
// std-only: sodium / protobuf / rclcpp 불요 — L1 티어.

#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>

#include "pail_gate/gate_core.hpp"
#include "pail_gate/safety_level.hpp"

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
const double kNaN = std::numeric_limits<double>::quiet_NaN();

// 명령 경로 PERMIT 베이스라인 (test_constraint_zero PermitBase 와 동형).
pail_pep_gate::GateInputs CommandBase() {
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

// grace 경로 PERMIT 베이스라인 — 발급자 무응답 중 보류 허가로 전진.
pail_pep_gate::GateInputs GraceBase() {
  pail_pep_gate::GateInputs in = CommandBase();
  in.path = pail_pep_gate::GatePath::Grace;
  in.token_view.ok = false;
  in.token_view.status = "UNREACHABLE";
  in.supplier.permit_grace_n = 3;
  in.hold.active = true;
  in.hold.token_id = "tok-1";
  in.hold.not_after_ms = kNow + 30000;
  in.hold.max_linear = 1.0;
  in.hold.max_angular = 1.0;
  in.hold.target = "pallet-7";
  in.hold.consumption_key = "ck-tok-1";
  return in;
}

void CheckDecision(const char *gid, const char *note,
                   const pail_pep_gate::GateInputs &in,
                   const char *want_state, const char *want_reason) {
  const pail_pep_gate::GateDecision d = pail_pep_gate::decide(in);
  Row(gid, d.state == want_state && d.reason == want_reason, note);
}

}  // namespace

int main() {
  using pail_pep_gate::EstopAction;
  using pail_pep_gate::EstopActionFor;
  using pail_pep_gate::ParseSafetyLevel;
  using pail_pep_gate::SafetyLevel;

  // ---- 1. D7-C1: 파싱 4값 + 5입력 × 새 허가 차단 ----
  {
    struct ParseRow { const char *raw; SafetyLevel want; };
    const ParseRow rows[] = {
        {"OK", SafetyLevel::kOk},
        {"WARN", SafetyLevel::kWarn},
        {"UNSAFE", SafetyLevel::kUnsafe},
        {"warn", SafetyLevel::kUnknown},   // 오타는 새 레벨이 아니라 모름이다
        {"", SafetyLevel::kUnknown},
        {"CRITICAL", SafetyLevel::kUnknown},  // 미래 레벨도 지금은 모름이다
    };
    for (const auto &r : rows) {
      char note[64];
      std::snprintf(note, sizeof note, "parse \"%s\"", r.raw);
      Row("D7-C1", ParseSafetyLevel(r.raw) == r.want, note);
    }
  }
  {
    // 차단: 베이스라인에서 level 만 바꾼다 (H-B9). "OK" 만 PERMIT.
    const char *blocked[] = {"WARN", "UNSAFE", "warn", ""};
    for (const char *lv : blocked) {
      pail_pep_gate::GateInputs in = CommandBase();
      in.safety.level = lv;
      char note[80];
      std::snprintf(note, sizeof note,
                    "level \"%s\" blocks new permit (ERR_SAFETY_STALE)", lv);
      CheckDecision("D7-C1", note, in, "BLOCK", "ERR_SAFETY_STALE");
    }
    CheckDecision("D7-C1", "control: level \"OK\" permits", CommandBase(),
                  "PERMIT", "OK");
  }

  // ---- 2. D7-C2: E-STOP 해제 표 전수 — kOk 만 푼다 ----
  {
    Row("D7-C2", EstopActionFor(SafetyLevel::kUnsafe) == EstopAction::kTrigger,
        "kUnsafe -> trigger");
    Row("D7-C2", EstopActionFor(SafetyLevel::kOk) == EstopAction::kRelease,
        "kOk -> release (the only release path)");
    Row("D7-C2", EstopActionFor(SafetyLevel::kWarn) == EstopAction::kHold,
        "kWarn -> hold");
    Row("D7-C2", EstopActionFor(SafetyLevel::kUnknown) == EstopAction::kHold,
        "kUnknown -> hold (a typo must not disarm the stop)");
    // 원시 문자열 5입력 전수 — 해제에 도달하는 것은 "OK" 하나뿐이어야 한다.
    const char *raws[] = {"OK", "WARN", "UNSAFE", "warn", ""};
    int releases = 0;
    for (const char *raw : raws) {
      if (EstopActionFor(ParseSafetyLevel(raw)) == EstopAction::kRelease) ++releases;
    }
    Row("D7-C2", releases == 1, "of 5 raw inputs exactly one releases");
  }

  // ---- 3. D7-C3: NaN 4지점 — 비교 전에 막는다 ----
  {  // 지점 1: 명령 경로 3f 제약 (token_info 한계와의 비교)
    pail_pep_gate::GateInputs in = CommandBase();
    in.command.linear_norm = kNaN;
    CheckDecision("D7-C3", "cmd constraint: NaN linear_norm blocks", in,
                  "BLOCK", "ERR_CONSTRAINT");
    in = CommandBase();
    in.token_info.max_linear_speed_mps = kNaN;
    CheckDecision("D7-C3", "cmd constraint: NaN limit blocks", in,
                  "BLOCK", "ERR_CONSTRAINT");
  }
  {  // 지점 2: 명령 경로 신뢰도 (threshold 비교)
    pail_pep_gate::GateInputs in = CommandBase();
    in.evidence.confidence = kNaN;
    CheckDecision("D7-C3", "cmd evidence: NaN confidence blocks", in,
                  "BLOCK", "ERR_TARGET_MISMATCH");
    in = CommandBase();
    in.limits.evidence_conf_threshold = kNaN;
    CheckDecision("D7-C3", "cmd evidence: NaN threshold blocks", in,
                  "BLOCK", "ERR_TARGET_MISMATCH");
  }
  {  // 지점 3: grace 경로 held 제한 (감사 정정 4 — 목록에 없던 그 지점)
    CheckDecision("D7-C3", "control: grace baseline permits", GraceBase(),
                  "PERMIT", "OK");
    pail_pep_gate::GateInputs in = GraceBase();
    in.command.angular_norm = kNaN;
    CheckDecision("D7-C3", "grace constraint: NaN angular_norm blocks", in,
                  "BLOCK", "ERR_CONSTRAINT");
    in = GraceBase();
    in.hold.max_linear = kNaN;
    CheckDecision("D7-C3", "grace constraint: NaN held limit blocks", in,
                  "BLOCK", "ERR_CONSTRAINT");
  }
  {  // 지점 4: grace 경로 신뢰도
    pail_pep_gate::GateInputs in = GraceBase();
    in.evidence.confidence = kNaN;
    CheckDecision("D7-C3", "grace evidence: NaN confidence blocks", in,
                  "BLOCK", "ERR_TARGET_MISMATCH");
  }

  if (g_failures == 0) {
    std::printf("test_safety_level: all rows PASS\n");
    return 0;
  }
  std::fprintf(stderr, "test_safety_level: %d FAILURES\n", g_failures);
  return 1;
}
