// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// SD2-1 drift test (PAIL-SD2-LLD-v1 §2.2): the compiled fingerprint list must
// equal known_dev_keys.tsv, which the Go side reads too. Regenerate both with
// scripts/gen_known_dev_keys.py — do not hand-edit either.
//
// Plain executable, no gtest: exit 0 only if every row matches.

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "pail_deploy_guard/key_fingerprint.hpp"

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

int CheckTable(const char * tsv)
{
  std::ifstream f(tsv);
  if (!f) {
    std::printf("FAIL: cannot open %s\n", tsv);
    return 1;
  }
  std::size_t n = 0;
  const pail_deploy_guard::KnownDevKey * keys = pail_deploy_guard::KnownDevKeys(&n);

  std::string line;
  std::size_t row = 0;
  int bad = 0;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    const auto col = Split(line, '\t');
    if (col.size() != 3) {
      std::printf("FAIL: malformed row: %s\n", line.c_str());
      return 1;
    }
    if (row >= n) {
      std::printf("FAIL: tsv has more rows than the compiled list (%zu)\n", n);
      return 1;
    }
    if (col[0] != keys[row].fingerprint || col[1] != keys[row].kind ||
      col[2] != keys[row].label)
    {
      std::printf("FAIL row %zu:\n tsv=%s|%s|%s\n cpp=%s|%s|%s\n", row,
        col[0].c_str(), col[1].c_str(), col[2].c_str(),
        keys[row].fingerprint, keys[row].kind, keys[row].label);
      ++bad;
    }
    ++row;
  }
  if (row != n) {
    std::printf("FAIL: tsv rows=%zu compiled=%zu — run scripts/gen_known_dev_keys.py\n", row, n);
    return 1;
  }
  if (n == 0) {
    std::printf("FAIL: empty list — S8 would accept every key\n");
    return 1;
  }
  return bad;
}

// The rule must also let a key through, or "refuses everything" would pass as
// "refuses the committed keys".
int CheckVerdict()
{
  std::size_t n = 0;
  const pail_deploy_guard::KnownDevKey * keys = pail_deploy_guard::KnownDevKeys(&n);

  std::vector<pail_deploy_guard::KeyMaterialItem> committed{
    {"keyring entry [loaded key_id=prod-issuer-2026]", keys[0].fingerprint}};
  const auto found = pail_deploy_guard::EvaluateKeyMaterial(committed);
  if (found.size() != 1 || found[0].id != "S8") {
    std::printf("FAIL: a committed key was not reported (renaming it must not help)\n");
    return 1;
  }

  std::vector<pail_deploy_guard::KeyMaterialItem> fresh{
    {"keyring entry [loaded key_id=prod-issuer-2026]",
      "0000000000000000000000000000000000000000000000000000000000000000"}};
  if (!pail_deploy_guard::EvaluateKeyMaterial(fresh).empty()) {
    std::printf("FAIL: a key that is not in the repository was reported as committed\n");
    return 1;
  }
  return 0;
}

}  // namespace

// PAIL-CASE: KnownDevKeyRefused
int main(int argc, char ** argv)
{
  if (argc < 2) {
    std::printf("usage: %s <known_dev_keys.tsv>\n", argv[0]);
    return 2;
  }
  const int bad = CheckTable(argv[1]) + CheckVerdict();
  if (bad) {
    std::printf("FAILURES: %d\n", bad);
    return 1;
  }
  std::printf("OK: known_dev_keys drift + verdict\n");
  return 0;
}
