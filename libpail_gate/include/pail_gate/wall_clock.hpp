// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// DC-8 : the absolute judgment clock. One implementation, hoisted
// from strict_verify.cpp — §1.6 measured three clocks in one node, with the
// gate's now_unix_ms() on RCL_ROS_TIME: under use_sim_time a frozen /clock
// makes held tokens never expire and kills half the deadman, silently
// (redundancy loss, no log). The fix is unification, so adding a *third*
// implementation here would preserve the defect's shape — the verifier, the
// gate and the bridge must all call this one function.
//
// ROS stamps (msg.stamp = now()) are deliberately NOT covered: publication
// stamps exist for rosbag correlation and are not judgment inputs (DC-9).

#pragma once

#include <chrono>
#include <cstdint>
#include <cmath>
#include <limits>
#include <fstream>
#include <string>
#if defined(__linux__)
#include <time.h>
#elif defined(__APPLE__)
#include <mach/mach_time.h>
#endif

namespace pail_pep_gate {

inline int64_t WallNowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// GC-TIME-1: local duration clock, independent of wall adjustments. Suspend
// counts against the budget; never silently fall back to wall/ROS time.
inline int64_t ElapsedNowMs() {
#if defined(__linux__)
  timespec ts{};
  if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0 || ts.tv_sec < 0 ||
      ts.tv_sec > (std::numeric_limits<int64_t>::max() - 999) / 1000) return -1;
  return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
#elif defined(__APPLE__)
  mach_timebase_info_data_t info{};
  if (mach_timebase_info(&info) != KERN_SUCCESS || info.denom == 0) return -1;
  const long double ms = static_cast<long double>(mach_continuous_time()) *
                         info.numer / info.denom / 1000000.0L;
  if (ms >= static_cast<long double>(std::numeric_limits<int64_t>::max())) return -1;
  return static_cast<int64_t>(ms);
#else
  return -1;  // unsupported duration clock is not a measured zero
#endif
}

// Advisory same-kernel clock identity for the ROS demo planner. It is not
// authority and is not interchangeable with a MONOTONIC timestamp.
inline std::string ElapsedClockIdentity() {
#if defined(__linux__)
  std::ifstream bootfile("/proc/sys/kernel/random/boot_id"), offsets("/proc/self/timens_offsets");
  std::string boot, clock; long long sec, nsec;
  if (!(bootfile >> boot) || boot.empty()) return "unavailable";
  while (offsets >> clock >> sec >> nsec) {
    if (clock == "boottime") return "linux-boottime:" + boot + ":" + std::to_string(sec) + ":" + std::to_string(nsec);
  }
#endif
  return "unavailable";
}

// Floor fractional milliseconds: rounding up would enlarge the signed budget.
// Bound BEFORE integer conversion/addition (NaN/Inf and overflow fail closed).
inline bool DurationDeadlineMs(int64_t start, double seconds, int64_t *deadline) {
  if (start < 0 || !std::isfinite(seconds) || seconds < 0.0) return false;
  const long double ms = static_cast<long double>(seconds) * 1000.0L;
  const int64_t room = std::numeric_limits<int64_t>::max() - start;
  if (ms >= static_cast<long double>(room)) return false;
  *deadline = start + static_cast<int64_t>(ms);
  return true;
}

// DC-10 : monotonic baseline. The wall clock is a judgment
// input (expiry, evidence window, safety staleness) but it is also settable —
// date -s / NTP step can move every one of those judgments at once. steady_clock
// cannot be set, so the pair captured at startup predicts what the wall clock
// SHOULD read; the difference is drift. Measurement lives here next to
// WallNowMs() so the two clocks being compared are the same two clocks the
// judgments use — a third clock would reproduce the §1.6 defect shape.
struct ClockBaseline {
  int64_t steady_ns0{0};
  int64_t wall_ms0{0};
};

inline ClockBaseline CaptureBaseline() {
  using namespace std::chrono;
  ClockBaseline b;
  b.steady_ns0 = duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
  b.wall_ms0 = WallNowMs();
  return b;
}

// Signed: forward jumps and rewinds are both drift, and the sign is worth
// keeping for the log line even though the judgment takes |drift|.
inline int64_t DriftMs(const ClockBaseline &b) {
  using namespace std::chrono;
  const int64_t steady_now =
      duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
  const int64_t expected_wall = b.wall_ms0 + (steady_now - b.steady_ns0) / 1000000;
  return WallNowMs() - expected_wall;
}

}  // namespace pail_pep_gate
