// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// C3-C9 : held_expired keeps its direction at the extremes.
// The three named cases are exactly where the old additive form
// (`now > not_after + skew`) breaks: INT64_MAX-adjacent not_after overflows
// (UB — a wrap flips "never expires" into "expired long ago"), a giant skew
// overflows the same sum, and a negative skew silently *advances* expiry.
//
// Expectations are literal . The old implementation fails the
// negative-skew row deterministically and the overflow rows by UB — this
// battery is DF-C10's observation point.

#include <cstdint>
#include <cstdio>
#include <limits>

#include "pail_gate/gate_core.hpp"

using pail_pep_gate::held_expired;

namespace {

int failures = 0;

void check(bool got, bool want, const char *what) {
  if (got != want) {
    std::fprintf(stderr, "FAIL: %s — got %d want %d\n", what, got ? 1 : 0, want ? 1 : 0);
    ++failures;
  }
}

constexpr int64_t kMax = std::numeric_limits<int64_t>::max();

}  // namespace

int main() {
  // PAIL-CASE: HeldExtremeNotAfterMax
  // additive form: kMax + 1 is UB; wrap would read as "expired since forever"
  check(held_expired(1000, kMax, 1), false, "not_after=INT64_MAX never expired");
  check(held_expired(kMax - 1, kMax, 0), false, "now just below INT64_MAX not_after");

  // PAIL-CASE: HeldExtremeSkewMax
  // additive form: not_after + kMax is UB; subtraction stays in range because
  // now_ms is a real clock reading (>= 0)
  check(held_expired(1000, 500, kMax), false, "skew=INT64_MAX widens grace, never flips");

  // PAIL-CASE: HeldExtremeSkewNegative
  // additive form: skew=-1 shrinks the window — expiry arrives *early*
  // (fail-open in the deployer's hands). strict_verify.cpp:126 already
  // neutralizes negative skew; the gate must match it.
  check(held_expired(1000, 1000, -1), false, "negative skew neutralized (boundary)");
  check(held_expired(1000, 999, -1), true, "negative skew does not disable expiry");

  // Base semantics pinned so the rewrite cannot drift them:
  check(held_expired(1000, 0, 0), false, "not_after=0 means no expiry (C-B5 is D's)");
  check(held_expired(1000, 0, -5), false, "not_after=0 unaffected by skew");
  check(held_expired(1001, 1000, 0), true, "plain expiry direction");
  check(held_expired(1000, 1000, 0), false, "boundary is not expired (strict >)");
  check(held_expired(1400, 1000, 500), false, "inside skew grace");
  check(held_expired(1501, 1000, 500), true, "past skew grace");

  if (failures == 0) {
    std::printf("test_time_strict: all cases passed\n");
    return 0;
  }
  std::fprintf(stderr, "test_time_strict: %d failure(s)\n", failures);
  return 1;
}
