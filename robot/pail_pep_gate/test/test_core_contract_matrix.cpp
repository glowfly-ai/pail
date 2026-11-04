// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//
// One communication contract (0.2.0-preview.40): the gate accepts no PAIL_CORE_COMM_CONTRACT value at all — only an
// absent variable passes; a present one (the removed `legacy`, the former `v1`, garbage, and since 0.2.0-preview.41
// the empty value too, P40-L2) refuses by name before any subscription.
#include <cstdio>
#include <string>

#include "pail_pep_gate/core_contract.hpp"

using pail_pep_gate::EvaluateCoreCommSetting;

namespace {
struct Row {
  const char *env;
  bool expect_refuse;
};
const Row kRows[] = {
  {nullptr, false},
  {"", true},
  {"v1", true},
  {"legacy", true},
  {"legacy ", true},
  {" v1", true},
  {"V1", true},
  {"v2", true},
  {"true", true},
  {"garbage", true},
};
}  // namespace

int main()
{
  int failures = 0;
  const std::string want_id = "CORE_COMM_CONTRACT_SETTING_REMOVED";
  const std::string want_detail =
      "PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); unset it";
  for (const Row &r : kRows) {
    const auto p = EvaluateCoreCommSetting(r.env);
    const bool ok = (p.refuse == r.expect_refuse) && (!r.expect_refuse || (p.id == want_id && p.detail == want_detail)) &&
                    (r.expect_refuse || (p.id.empty() && p.detail.empty()));
    std::printf("%s env=%s -> refuse=%d id=%s\n", ok ? "PASS" : "FAIL", r.env ? r.env : "(unset)", p.refuse ? 1 : 0,
                p.id.c_str());
    if (!ok) ++failures;
  }
  std::printf("%s core contract setting rows=%zu failures=%d\n", failures ? "FAIL" : "PASS", sizeof(kRows) / sizeof(kRows[0]), failures);
  return failures ? 1 : 0;
}
