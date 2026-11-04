// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// C3-C8 : the five-input table of §3.6, measured — plus the
// refusal itself. Testing only ParseEnvInt would leave "startup refusal" a
// claim about a wrapper nobody exercised (the guardrail that can be satisfied
// but never fired); the fork cases run EnvIntStrict for real and read the
// exit code and the ERR_BAD_ENV line off a pipe.
//
// Plain executable, no gtest : returns 0 only if every row holds.
// Expectations are literal — deriving them from ParseEnvInt would be
// tautological.

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "pail_pep_gate/env_strict.hpp"

using pail_pep_gate::EnvIntParse;
using pail_pep_gate::EnvIntStrict;
using pail_pep_gate::ParseEnvInt;

namespace {

int failures = 0;

void check(bool ok, const char *what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
  }
}

// PAIL-CASE: EnvStrictTable
// §3.6 table, RPC bounds (def=50, lo=5, hi=200). Every "변경 후" cell.
void table_cases() {
  // row 1: unset / empty -> def (the only tolerated absence)
  EnvIntParse r = ParseEnvInt(nullptr, 50, 5, 200);
  check(r.ok && r.value == 50, "unset -> def 50");
  r = ParseEnvInt("", 50, 5, 200);
  check(r.ok && r.value == 50, "empty -> def 50");

  // row 2: "abc" — atoi read this as 0 and the floor made it a silent 5
  r = ParseEnvInt("abc", 50, 5, 200);
  check(!r.ok, "abc refused");

  // row 3: "50x" — trailing garbage is a typo, not 50
  r = ParseEnvInt("50x", 50, 5, 200);
  check(!r.ok, "50x refused");

  // row 4: "600000" — 3000x the 200ms silence window
  r = ParseEnvInt("600000", 50, 5, 200);
  check(!r.ok, "600000 refused (above hi)");

  // row 5: "3" — silently raising to the floor is the same defect class
  r = ParseEnvInt("3", 50, 5, 200);
  check(!r.ok, "3 refused (below lo)");

  // positive controls — a table that only ever refuses proves a wall, not a
  // gate (만족 시 위반 0을 함께 검증).
  r = ParseEnvInt("50", 50, 5, 200);
  check(r.ok && r.value == 50, "50 accepted");
  r = ParseEnvInt("5", 50, 5, 200);
  check(r.ok && r.value == 5, "lo boundary 5 accepted");
  r = ParseEnvInt("200", 50, 5, 200);
  check(r.ok && r.value == 200, "hi boundary 200 accepted");
  r = ParseEnvInt("201", 50, 5, 200);
  check(!r.ok, "201 refused (hi+1)");

  // attest bounds spot-check (def=2000, lo=5, hi=30000)
  r = ParseEnvInt("30000", 2000, 5, 30000);
  check(r.ok && r.value == 30000, "attest hi 30000 accepted");
  r = ParseEnvInt("30001", 2000, 5, 30000);
  check(!r.ok, "attest 30001 refused");
}

// PAIL-CASE: EnvStrictRefusal
// The wrapper must actually exit 78 and name ERR_BAD_ENV on stderr.
void refusal_case(const char *bad_value) {
  int fds[2];
  if (pipe(fds) != 0) {
    check(false, "pipe() failed");
    return;
  }
  const pid_t pid = fork();
  if (pid < 0) {
    check(false, "fork() failed");
    return;
  }
  if (pid == 0) {
    // child: bad env must refuse before returning a value
    close(fds[0]);
    dup2(fds[1], 2);
    setenv("PAIL_TEST_ENV_STRICT", bad_value, 1);
    const int v = EnvIntStrict("PAIL_TEST_ENV_STRICT", 50, 5, 200);
    // reaching here is the defect being tested for
    std::fprintf(stdout, "unexpected value %d\n", v);
    _exit(0);
  }
  close(fds[1]);
  std::string err;
  char buf[512];
  ssize_t n;
  while ((n = read(fds[0], buf, sizeof buf)) > 0) err.append(buf, static_cast<size_t>(n));
  close(fds[0]);
  int status = 0;
  waitpid(pid, &status, 0);

  std::string what = std::string("refusal(") + bad_value + ")";
  check(WIFEXITED(status) && WEXITSTATUS(status) == 78, (what + " exit 78").c_str());
  check(err.find("ERR_BAD_ENV") != std::string::npos, (what + " names ERR_BAD_ENV").c_str());
  check(err.find("PAIL PREFLIGHT FAIL") != std::string::npos,
        (what + " greppable preflight prefix").c_str());
}

// PAIL-CASE: EnvStrictGoodValue
// Good env returns the value in-process (no refusal on the happy path).
void good_case() {
  setenv("PAIL_TEST_ENV_STRICT_OK", "120", 1);
  check(EnvIntStrict("PAIL_TEST_ENV_STRICT_OK", 50, 5, 200) == 120, "good env 120 returned");
  unsetenv("PAIL_TEST_ENV_STRICT_OK");
  check(EnvIntStrict("PAIL_TEST_ENV_STRICT_OK", 50, 5, 200) == 50, "unset env -> def 50");
}

}  // namespace

int main() {
  table_cases();
  refusal_case("abc");
  refusal_case("50x");
  refusal_case("600000");
  refusal_case("3");
  good_case();

  if (failures == 0) {
    std::printf("test_env_strict: all cases passed\n");
    return 0;
  }
  std::fprintf(stderr, "test_env_strict: %d failure(s)\n", failures);
  return 1;
}
