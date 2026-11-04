// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#ifndef PAIL_PEP_GATE__CORE_CONTRACT_HPP_
#define PAIL_PEP_GATE__CORE_CONTRACT_HPP_

// Basic communication contract (spec/CORE_COMM.md) on the gate. Since 0.2.0-preview.40 there is one contract and no
// setting that selects it: PAIL_CORE_COMM_CONTRACT (once `legacy` | `v1`) has no meaning, and the variable being set at
// all — any value, an empty one included (0.2.0-preview.41, P40-L2) — refuses node construction by name rather than
// being read as anything. The real gRPC token provider always reports
// decisions in the C1 receipt form; the static and no-token providers never send a report (test providers). The
// wire keeps its version numbers (receipt contract version 1) — a protocol version, not a mode. Header-only and
// rclcpp-free so the rule is unit tested on every build flavour.

#include <string>

namespace pail_pep_gate {

struct ContractPolicy {
  bool refuse;
  std::string id;      // "" | "CORE_COMM_CONTRACT_SETTING_REMOVED"
  std::string detail;
};

// The same wording as internal/corecomm (Go), examples/common/core_operation_wire.py and the hardware scripts;
// source: spec/CORE_COMM.md.
inline ContractPolicy EvaluateCoreCommSetting(const char *env)
{
  // getenv() returns nullptr only when the variable is absent; "" is a present variable and refuses too.
  if (env != nullptr) {
    return {true, "CORE_COMM_CONTRACT_SETTING_REMOVED",
            "PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); "
            "unset it"};
  }
  return {false, "", ""};
}

}  // namespace pail_pep_gate

#endif  // PAIL_PEP_GATE__CORE_CONTRACT_HPP_
