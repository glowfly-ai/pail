// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// safety_level.hpp — implementation contract (C-B7): the safety-level domain, frozen.
//
// std-only (L1 tier): the refusal must not hide behind rclcpp or grpc linkage.
// Both the gate core (blocking) and the node (E-STOP latch) parse through this
// one table, so the two judgments cannot drift apart again — the defect this
// replaces was exactly that drift (header comment said one domain, code
// enforced another, and the mismatch passed).

#ifndef PAIL_PEP_GATE_SAFETY_LEVEL_HPP_
#define PAIL_PEP_GATE_SAFETY_LEVEL_HPP_

#include <string>

namespace pail_pep_gate {

// An empty string, a typo and a future level all land on kUnknown — same
// disposition as kUnsafe (blocks new permits, holds the E-STOP latch) but a
// distinct value (H-B2): the journal must be able to separate "the feed went
// silent" from "the feed started speaking a level we do not know".
enum class SafetyLevel { kOk, kWarn, kUnsafe, kUnknown };

inline SafetyLevel ParseSafetyLevel(const std::string &s) {
  if (s == "OK") return SafetyLevel::kOk;
  if (s == "WARN") return SafetyLevel::kWarn;
  if (s == "UNSAFE") return SafetyLevel::kUnsafe;
  return SafetyLevel::kUnknown;  // 빈 문자열·오타·미래 레벨 전부 여기 (§4.1)
}

inline const char *SafetyLevelName(SafetyLevel l) {
  switch (l) {
    case SafetyLevel::kOk:      return "OK";
    case SafetyLevel::kWarn:    return "WARN";
    case SafetyLevel::kUnsafe:  return "UNSAFE";
    case SafetyLevel::kUnknown: return "UNKNOWN";
  }
  return "UNKNOWN";  // unreachable; fail closed if it ever isn't
}

// D §4.2: what one safety-state message does to the E-STOP latch. kOk is the
// ONLY release path. The previous shape (`else { estop_active_ = false; }`)
// released on every value that was not "UNSAFE" — a publisher changing one
// level string disarmed the emergency stop. No `default` label anywhere in
// this header: a new SafetyLevel value must fail the build, not get silently
// absorbed into one branch (silent absorption IS the defect this replaces).
enum class EstopAction { kTrigger, kRelease, kHold };

inline EstopAction EstopActionFor(SafetyLevel l) {
  switch (l) {
    case SafetyLevel::kUnsafe:  return EstopAction::kTrigger;
    case SafetyLevel::kOk:      return EstopAction::kRelease;
    case SafetyLevel::kWarn:    return EstopAction::kHold;
    case SafetyLevel::kUnknown: return EstopAction::kHold;
  }
  return EstopAction::kHold;  // unreachable; fail closed if it ever isn't
}

}  // namespace pail_pep_gate

#endif  // PAIL_PEP_GATE_SAFETY_LEVEL_HPP_
