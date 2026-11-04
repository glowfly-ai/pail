// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// C-B8 (implementation contract, D8-C1): "could not compare" is a third value, not a
// synonym for "compared and equal". This battery pins (a) the three-valued
// predicate itself, (b) the command-path verdicts for each value, and (c) the
// recheck-path verdict where crypto360 F-PR-1 measured the old bool tipping
// toward GRANT when the envelope emptied current_subgraph_hash.
//
// Plain executable, no gtest. `// PAIL-CASE:` comments are canonical (CG-B).

#include <cstdio>
#include <string>

#include "pail_gate/gate_core.hpp"

using pail_pep_gate::GateDecision;
using pail_pep_gate::GateInputs;
using pail_pep_gate::GatePath;
using pail_pep_gate::WorldMatch;
using pail_pep_gate::decide;
using pail_pep_gate::world_match;

namespace {

constexpr int64_t kNow = 1000000;

int g_failures = 0;

// 지금 재고 있는 §8 조건. 통과한 줄도 이 이름을 찍는다 — 실패했을 때만 이름을
// 부르는 검사는 초록인 날 출력에 자기 이름이 없고, 그러면 "지켜졌다"와 "테스트가
// 지워졌다"가 같은 침묵으로 도착한다(`H-B2`). `ob4_closure.py` 가 이 대괄호
// 표식으로 §8 칸의 결속을 잰다.
const char *g_cond = "UNSCOPED";

struct Cond {
  const char *prev;
  explicit Cond(const char *id) : prev(g_cond) { g_cond = id; }
  ~Cond() { g_cond = prev; }
};

void CheckMatch(const char *note, const std::string &issued,
                const std::string &current, WorldMatch want) {
  const WorldMatch got = world_match(issued, current);
  if (got != want) {
    std::fprintf(stderr, "  FAIL [%s] WM-1 %s: got %d want %d\n", g_cond, note,
                 static_cast<int>(got), static_cast<int>(want));
    ++g_failures;
  } else {
    std::printf("  ok   [%s] WM-1 %s\n", g_cond, note);
  }
}

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
  in.supplier.permit_grace_n = 0;
  in.limits.clock_skew_ms = 500;
  in.limits.evidence_window_ms = 2000;
  in.limits.evidence_conf_threshold = 0.90;
  in.limits.safety_stale_ms = 1000;
  return in;
}

void CheckVerdict(const char *gid, const char *note, const GateInputs &in,
                  const char *state, const char *reason, bool fatal) {
  const GateDecision d = decide(in);
  if (d.state != state || d.reason != reason || d.fatal != fatal || !d.report) {
    std::fprintf(stderr,
                 "  FAIL [%s] %s %s\n"
                 "       got  state=%s reason=%s report=%d fatal=%d fwd=%d\n"
                 "       want state=%s reason=%s report=1 fatal=%d fwd=0\n",
                 g_cond, gid, note, d.state.c_str(), d.reason.c_str(), d.report,
                 d.fatal, d.forward, state, reason, fatal);
    ++g_failures;
  }
  if (d.state == "BLOCK" && d.forward) {
    std::fprintf(stderr, "  FAIL [%s] %s %s: BLOCK must never forward\n", g_cond,
                 gid, note);
    ++g_failures;
  }
  std::printf("  ok   [%s] %s %s\n", g_cond, gid, note);
}

// PAIL-CASE: WorldMatchThreeValues
// D8-C1(a): the predicate itself. Every empty side is indeterminate — never
// folded into match, never into mismatch.
void CaseThreeValues() {
  Cond c("D8-C1");  // (a) 술어 자체 — 빈 쪽은 언제나 kIndeterminate
  CheckMatch("A/A match", "A", "A", WorldMatch::kMatch);
  CheckMatch("A/B mismatch", "A", "B", WorldMatch::kMismatch);
  CheckMatch("A/empty indeterminate", "A", "", WorldMatch::kIndeterminate);
  CheckMatch("empty/B indeterminate", "", "B", WorldMatch::kIndeterminate);
  CheckMatch("empty/empty indeterminate — the old bool read this as MATCH",
             "", "", WorldMatch::kIndeterminate);
}

// PAIL-CASE: WorldMatchCommandPath
// D8-C1(b): command path 3c. Mismatch is fatal (world-change evidence revokes
// the chain); indeterminate blocks WITHOUT fatal (infrastructure failure is
// not evidence, revoking would turn an issuer glitch into a self-DoS).
void CaseCommandPath() {
  Cond c("D8-C1");  // (b) command 경로 3c
  GateInputs in = BaseGrpc();
  in.token_info.subgraph_snapshot_hash = "A";
  in.token_view.current_subgraph_hash = "B";
  CheckVerdict("WM-2", "mismatch: fatal block", in, "BLOCK", "ERR_WORLD_CHANGED", true);

  in = BaseGrpc();
  in.token_info.subgraph_snapshot_hash = "A";
  in.token_view.current_subgraph_hash = "";
  CheckVerdict("WM-2", "current empty: indeterminate block, non-fatal", in,
               "BLOCK", "ERR_WORLD_INDETERMINATE", false);

  in = BaseGrpc();
  in.token_info.subgraph_snapshot_hash = "";
  in.token_view.current_subgraph_hash = "";
  CheckVerdict("WM-2", "both empty: indeterminate block (was PERMIT)", in,
               "BLOCK", "ERR_WORLD_INDETERMINATE", false);

  in = BaseGrpc();
  in.token_info.subgraph_snapshot_hash = "A";
  in.token_view.current_subgraph_hash = "A";
  const GateDecision d = decide(in);
  if (d.state != "PERMIT" || d.reason != "OK") {
    std::fprintf(stderr, "  FAIL [WM-2] match must still PERMIT: %s/%s\n",
                 d.state.c_str(), d.reason.c_str());
    ++g_failures;
  }
}

// PAIL-CASE: WorldMatchRecheckPath
// D8-C1(c): recheck step 5 — the F-PR-1 seat. Emptying the served hash used
// to buy a GRANT (permit survived); it now stops the permit. Grace must not
// defer either verdict (grace covers only an UNANSWERED issuer).
void CaseRecheckPath() {
  Cond c("D8-C1");  // (c) recheck 5단계 — F-PR-1 자리
  GateInputs in = BaseGrpc();
  in.path = GatePath::Recheck;
  in.hold.active = true;
  in.hold.token_id = "tok-1";
  in.hold.not_after_ms = kNow + 30000;
  in.hold.issued_hash = "A";
  in.token_view.current_subgraph_hash = "";
  in.supplier.permit_grace_n = 3;
  CheckVerdict("WM-3", "recheck, served hash emptied: indeterminate stops the permit",
               in, "BLOCK", "ERR_WORLD_INDETERMINATE", false);

  in.token_view.current_subgraph_hash = "B";
  CheckVerdict("WM-3", "recheck divergence still fatal", in, "BLOCK",
               "ERR_WORLD_CHANGED", true);
}

}  // namespace

int main() {
  CaseThreeValues();
  CaseCommandPath();
  CaseRecheckPath();
  if (g_failures) {
    std::fprintf(stderr, "test_world_match: %d row(s) FAILED\n", g_failures);
    return 1;
  }
  std::printf("test_world_match: all rows passed\n");
  return 0;
}
