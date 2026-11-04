// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Session lifecycle regression: wall injection uses the existing C++ input seam;
// elapsed time is real. No host clock changes and no test-only production clock.
#include "pail_gate/gate_session.hpp"
#include <chrono>
#include <cstdio>
#include <thread>
using namespace pail_pep_gate;
namespace {
int failures = 0;
void check(const char *name, bool ok) {
  std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  if (!ok) ++failures;
}
struct Rig {
  GateSession s{SessionConfig{}, SessionPolicy{}, Keyring{}};
  int64_t wall = WallNowMs();
  void begin(double duration = .15, int64_t at = 0) {
    auto in = s.PrepareInputs(GatePath::Command, nullptr, at ? at : wall);
    // This battery starts at the verified decision→state seam. Signature/wire
    // acceptance is exercised independently by gate_two_doors (real Ed25519).
    in.verify_ok = true;
    in.token_info.chain_id = "clock-chain";
    in.token_info.token_id = "clock-token";
    in.token_info.consumption_key = "clock-key";
    in.token_info.max_duration_sec = duration;
    in.token_info.not_after_unix_ms = wall + 10000;
    GateDecision d;
    d.state = "PERMIT"; d.reason = "OK";
    d.enter_permit = true; d.begin_step = true;
    s.ApplyDecision(d, in);
  }
};
void wait_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }
}
int main() {
  {
    Rig r; r.begin();
    check("forward_wall_does_not_complete_early", !r.s.OnStepTimer(r.wall + 400).fired);
  }
  {
    Rig r; r.begin(); wait_ms(220);
    const auto o = r.s.OnStepTimer(r.wall - 180);
    check("backward_wall_does_not_extend_step", o.fired && !o.permit_active && !o.step_active);
    check("timer_consumes_once", r.s.consumed_contains("clock-key") && !r.s.OnStepTimer(r.wall + 10000).fired);
  }
  {
    Rig r; r.begin(); wait_ms(90); r.begin(.15, r.wall + 90); wait_ms(130);
    check("same_key_does_not_reset_elapsed_deadline", r.s.OnStepTimer(r.wall).fired);
  }
  {
    GateInputs in; in.clock_drift_known=true; in.clock_drift_ms=-625;
    in.limits.clock_skew_ms=500;
    auto d=decide(in);
    check("drift_diagnostic", d.reason=="ERR_CLOCK_DRIFT" &&
          d.detail.find("drift_ms=-625")!=std::string::npos &&
          d.detail.find("limit_ms=500")!=std::string::npos);
  }
  std::printf("step_clock failures=%d\n", failures);
  return failures ? 1 : 0;
}
