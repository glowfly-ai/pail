// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// S10 (PAIL-SD2-LLD-v1 §4.1): every row of threshold_matrix.tsv, both ways.
//
// The "ok" rows carry the weight here. A rule that refuses the disabling values
// is only worth something if a range of ordinary site settings still starts.

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "pail_deploy_guard/thresholds.hpp"

namespace
{

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

}  // namespace

int main(int argc, char ** argv)
{
  if (argc < 2) {
    std::printf("usage: %s <threshold_matrix.tsv>\n", argv[0]);
    return 2;
  }
  std::ifstream f(argv[1]);
  if (!f) {
    std::printf("FAIL: cannot open %s\n", argv[1]);
    return 1;
  }

  std::string line;
  int bad = 0, ok_rows = 0, fail_rows = 0;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    const auto col = Split(line, '\t');
    if (col.size() < 7) {
      std::printf("FAIL: malformed row: %s\n", line.c_str());
      return 1;
    }
    pail_deploy_guard::ThresholdInput in;
    in.evidence_conf_threshold = std::atof(col[0].c_str());
    in.evidence_window_ms = std::atoi(col[1].c_str());
    in.safety_stale_ms = std::atoi(col[2].c_str());
    in.clock_skew_ms = std::atoi(col[3].c_str());
    in.permit_grace_n = std::atoi(col[4].c_str());
    in.permit_recheck_ms = std::atoi(col[5].c_str());
    const bool want_fail = (col[6] == "fail");
    const std::string note = col.size() > 7 ? col[7] : std::string();

    const auto got = pail_deploy_guard::EvaluateThresholds(in);
    if (got.empty() == want_fail) {
      std::printf("FAIL [%s]: want %s, got %zu finding(s)\n",
        note.c_str(), want_fail ? "refusal" : "acceptance", got.size());
      for (const auto & g : got) {
        std::printf("  %s %s\n", g.id.c_str(), g.detail.c_str());
      }
      ++bad;
      continue;
    }
    for (const auto & g : got) {
      if (g.id != "S10") {
        std::printf("FAIL [%s]: finding id=%s (want S10)\n", note.c_str(), g.id.c_str());
        ++bad;
      }
    }
    want_fail ? ++fail_rows : ++ok_rows;
  }

  // A table with no accepted rows would let "refuse everything" pass.
  if (ok_rows == 0 || fail_rows == 0) {
    std::printf("FAIL: the table must exercise both verdicts (ok=%d fail=%d)\n", ok_rows, fail_rows);
    return 1;
  }
  if (bad) {
    std::printf("FAILURES: %d\n", bad);
    return 1;
  }
  std::printf("OK: thresholds %d accepted, %d refused\n", ok_rows, fail_rows);
  return 0;
}
