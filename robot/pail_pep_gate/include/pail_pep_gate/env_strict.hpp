// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// DC-13 : strict env parsing. atoi folds every parse failure
// into 0 and says nothing — "abc" ran as a silent 5ms deadline and "600000"
// would hold the ROS callback thread 3000x past the 200ms silence window.
// Failure is not a default: parse failure = startup refusal (ERR_BAD_ENV),
// same shape as the deploy-mode preflight (pep_gate_node.cpp exit 78).
//
// Two layers on purpose: ParseEnvInt is pure and unit-testable (the §3.6
// five-input table), EnvIntStrict is the refusing wrapper. Testing only the
// parser would leave the refusal a claim — test_env_strict.cpp forks and
// measures the exit code.

#pragma once

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace pail_pep_gate {

struct EnvIntParse {
  bool ok = false;
  int value = 0;
  std::string err;  // human-readable cause when !ok (bounds shown for the operator)
};

// Pure. `text` may be nullptr (unset). Unset/empty -> def (the only tolerated
// absence — an *absent* knob is a chosen default, a *malformed* knob is a typo
// about to run a robot).
inline EnvIntParse ParseEnvInt(const char *text, int def, int lo, int hi) {
  EnvIntParse r;
  if (text == nullptr || text[0] == '\0') {
    r.ok = true;
    r.value = def;
    return r;
  }
  errno = 0;
  char *end = nullptr;
  const long v = std::strtol(text, &end, 10);
  if (end == text) {
    r.err = "not a number";
    return r;
  }
  if (*end != '\0') {
    r.err = "trailing garbage";  // "50x" is not 50 — it is a typo (§3.6)
    return r;
  }
  if (errno == ERANGE || v < static_cast<long>(lo) || v > static_cast<long>(hi)) {
    // Below-floor is refused, not silently raised: silently fixing "3" to 5 is
    // the same defect class as silently reading "abc" as 0 (§3.6 row 5).
    r.err = "out of bounds [" + std::to_string(lo) + ".." + std::to_string(hi) + "]";
    return r;
  }
  r.ok = true;
  r.value = static_cast<int>(v);
  return r;
}

// Refusing wrapper. Bounds are derived from measurement, not invented
// (§3.6): hi(PAIL_RPC_DEADLINE_MS)=200 = 2 x permit_deadline_ms silence
// window (motion_bridge_node.cpp:27,:100). Call sites pass them literally so
// the derivation stays greppable at the point of use.
inline int EnvIntStrict(const char *key, int def, int lo, int hi) {
  const char *text = std::getenv(key);
  const EnvIntParse r = ParseEnvInt(text, def, lo, hi);
  if (!r.ok) {
    // "ERR_BAD_ENV" stands alone so the reason drift scan (drift_test.go
    // errLiteral) sees it — a code embedded mid-format-string is invisible to
    // the quote-anchored regex, and invisible codes escape dict enforcement.
    std::fprintf(stderr, "PAIL PREFLIGHT FAIL: %s %s=\"%s\" (%s)\n",
                 "ERR_BAD_ENV", key, text ? text : "", r.err.c_str());
    std::fprintf(stderr,
                 "PAIL PREFLIGHT FAIL: refusing to start. Unset %s to use the "
                 "default (%d) or set an integer in [%d..%d].\n",
                 key, def, lo, hi);
    std::fflush(stderr);
    std::exit(78);
  }
  return r.value;
}

}  // namespace pail_pep_gate
