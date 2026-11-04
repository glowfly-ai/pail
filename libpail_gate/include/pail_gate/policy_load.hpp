// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#pragma once

// AD-1 (see spec/ARCHITECTURE.md): the policy.yaml → decision-threshold
// mapping, as a LIBRARY function. The node (`pep_gate_node.cpp`) walks the same file with
// three loaders that `std::exit(78)` on refusal; a library cannot exit its host, so this one
// returns the refusal as a string and the caller decides what exit 78 means for it.
//
// The RULES are the node's rules (implementation contract D-L1/D-L2/D-L3/D-L5, implementation contract D-S4), restated
// here rather than shared, because sharing would mean editing the node in AD-1 and the
// contract says the node is untouched until AD-4. The two-doors test (`test_gate_two_doors`)
// pins this loader to the node's fixture expectations so the restatement cannot drift quietly.

#include <cstdint>
#include <string>
#include <unordered_map>

namespace pail_pep_gate {

struct SessionPolicy {
  std::string gate_mode{"enforce"};          // enforce | observe (D-S4: absent key = enforce)
  bool human_safety_enabled{true};           // human_safety.enabled (absent = true, fail-closed)
  double evidence_conf_threshold{0.0};       // evidence.confidence_threshold ∈ (0, 1]
  int min_trust_rank{0};                     // rank of evidence.min_trust_class
  std::unordered_map<std::string, int> trust_rank_by_source;  // trust_classes[].sources → rank
  int64_t safety_stale_ms{0};                // preconditions[safety_feed].freshness_ms
  int64_t evidence_window_ms{0};             // preconditions[evidence_claim].freshness_ms
  bool safety_exempt_in_progress_step{false};// preconditions[safety_feed].exempt_in_progress_step
};

// Returns true and fills `out` when the file is a policy this gate can enforce. Returns false
// with `error` naming the first refusal (the node prints the same facts before exit 78).
bool LoadSessionPolicy(const std::string &path, SessionPolicy *out, std::string *error);

}  // namespace pail_pep_gate
