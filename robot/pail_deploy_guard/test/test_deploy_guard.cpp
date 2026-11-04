// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// SD3-1: EvaluateDeployGuard against the shared truth table
// (see spec/ARCHITECTURE.md). Plain executable, no gtest: exit 0 only if
// every row matches. The Python twin reads the same file.

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "pail_deploy_guard/deploy_guard.hpp"

using pail_deploy_guard::EvaluateDeployGuard;
using pail_deploy_guard::GuardInput;

namespace {

std::vector<std::string> Split(const std::string & s, char sep)
{
  std::vector<std::string> out;
  std::string cur;
  std::istringstream is(s);
  while (std::getline(is, cur, sep)) {
    out.push_back(cur);
  }
  return out;
}

std::string Unsentinel(const std::string & s)
{
  return s == "<empty>" ? std::string() : s;
}

int argc_enclave_probe()
{
  // EffectiveEnclaveFromArgv is exercised separately from the table: it reads a
  // command line, not the guard inputs.
  const char * a[] = {"node", "--ros-args", "-p", "x:=1"};
  const char * b[] = {"node", "--ros-args", "--enclave", "/pep_gate"};
  const char * c[] = {"node", "--enclave", "/a", "--enclave", "/b"};
  const char * d[] = {"node", "--enclave"};  // dangling: no value follows
  struct { const char * const * v; int n; const char * want; } rows[] = {
    {a, 4, "/"}, {b, 4, "/pep_gate"}, {c, 5, "/b"}, {d, 2, "/"},
  };
  int bad = 0;
  for (const auto & r : rows) {
    const std::string got = pail_deploy_guard::EffectiveEnclaveFromArgv(r.n, r.v);
    if (got != r.want) {
      std::printf("FAIL argv: got=%s want=%s\n", got.c_str(), r.want);
      ++bad;
    }
  }

  // ROS_SECURITY_ENCLAVE_OVERRIDE outranks the command line (rcl_get_secure_root).
  if (pail_deploy_guard::EffectiveEnclave("", 4, b) != "/pep_gate") {
    std::printf("FAIL override: empty override must fall back to argv\n");
    ++bad;
  }
  if (pail_deploy_guard::EffectiveEnclave("/oem_planner", 4, b) != "/oem_planner") {
    std::printf("FAIL override: override must win over --enclave\n");
    ++bad;
  }
  return bad;
}

}  // namespace

int main(int argc, char ** argv)
{
  if (argc < 2) {
    std::printf("usage: %s <guard_matrix.tsv>\n", argv[0]);
    return 2;
  }
  std::ifstream f(argv[1]);
  if (!f) {
    std::printf("cannot open %s\n", argv[1]);
    return 2;
  }

  int rows = 0, bad = 0;
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') { continue; }
    const auto col = Split(line, '\t');
    if (col.size() != 8) {
      std::printf("FAIL malformed row (%zu cols): %s\n", col.size(), line.c_str());
      ++bad;
      continue;
    }
    ++rows;

    GuardInput in;
    in.component = col[0];
    in.profile = Unsentinel(col[1]);
    in.security_enable = Unsentinel(col[2]);
    in.security_strategy = Unsentinel(col[3]);
    in.keystore = Unsentinel(col[4]);
    in.enclave_provisioned = (col[5] == "1");
    in.effective_enclave = Unsentinel(col[6]);

    std::vector<std::string> want;
    if (col[7] != "-") { want = Split(col[7], ','); }

    const auto r = EvaluateDeployGuard(in);
    std::vector<std::string> got;
    for (const auto & fi : r.fail) { got.push_back(fi.id); }

    if (got != want) {
      std::string g, w;
      for (const auto & s : got) { g += s + " "; }
      for (const auto & s : want) { w += s + " "; }
      std::printf("FAIL [%s profile=%s enable=%s strategy=%s ks=%s prov=%s enclave=%s]\n"
                  "       got=[%s] want=[%s]\n",
                  col[0].c_str(), col[1].c_str(), col[2].c_str(), col[3].c_str(),
                  col[4].c_str(), col[5].c_str(), col[6].c_str(), g.c_str(), w.c_str());
      ++bad;
      continue;
    }
    // Every finding must carry a non-empty explanation — an ID alone does not
    // tell an operator what to change.
    for (const auto & fi : r.fail) {
      if (fi.detail.empty()) {
        std::printf("FAIL [%s] finding %s has empty detail\n", col[0].c_str(), fi.id.c_str());
        ++bad;
      }
    }
  }

  bad += argc_enclave_probe();

  std::printf("test_deploy_guard: rows=%d failures=%d\n", rows, bad);
  if (rows < 20) {
    std::printf("FAIL: truth table shrank (rows=%d) — expected at least 20\n", rows);
    return 1;
  }
  return bad == 0 ? 0 : 1;
}
