// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_gate/policy_load.hpp"

#include <fstream>

#include <yaml-cpp/yaml.h>

namespace pail_pep_gate {
namespace {

// Same probe discipline as the node's PolicyKey: a missing key must come back as an
// Undefined node (falsy), never as a Null node (truthy), and a const walk so the probe
// cannot grow the tree it is probing.
YAML::Node KeyWalk(const YAML::Node &cur, const std::string &path, std::size_t pos) {
  if (!cur.IsDefined() || !cur.IsMap()) return YAML::Node(YAML::NodeType::Undefined);
  const std::size_t dot = path.find('.', pos);
  const std::string seg =
      path.substr(pos, dot == std::string::npos ? std::string::npos : dot - pos);
  const YAML::Node next = static_cast<const YAML::Node &>(cur)[seg];
  if (dot == std::string::npos) return next;
  return KeyWalk(next, path, dot + 1);
}

YAML::Node Key(const YAML::Node &node, const char *dotted) {
  std::string path(dotted);
  const std::size_t seq = path.rfind("[].");
  if (seq != std::string::npos) path = path.substr(seq + 3);
  return KeyWalk(node, path, 0);
}

bool Fail(std::string *error, const std::string &msg) {
  if (error) *error = msg;
  return false;
}

}  // namespace

bool LoadSessionPolicy(const std::string &path, SessionPolicy *out, std::string *error) {
  if (!out) return Fail(error, "internal: null output");
  SessionPolicy p;

  {
    std::ifstream probe(path, std::ios::binary);
    if (!probe) return Fail(error, "POLICY_ABSENT " + path + " — the gate's decision thresholds have no source (implementation contract D-L2)");
  }
  YAML::Node root;
  try {
    root = YAML::LoadFile(path);
  } catch (const std::exception &e) {
    return Fail(error, "POLICY_UNREADABLE " + path + " (" + e.what() + ")");
  }

  // ---- gate_mode (implementation contract D-S4) --------------------------------------------------------
  const YAML::Node rules = Key(root, "rules");
  if (rules && rules.IsSequence()) {
    for (const auto &rule : rules) {
      if (rule.IsMap() && Key(rule, "rules[].mode")) {
        return Fail(error, "SHADOW_MODE policy uses rules[].mode — reserved , not implemented");
      }
    }
  }
  const YAML::Node gate_mode = Key(root, "gate_mode");
  if (gate_mode) {
    std::string mode;
    try {
      mode = gate_mode.as<std::string>();
    } catch (const std::exception &) {
      mode.clear();
    }
    if (mode != "enforce" && mode != "observe") {
      return Fail(error, "SHADOW_MODE gate_mode=\"" + mode + "\" is outside {enforce, observe} (D-S4)");
    }
    p.gate_mode = mode;
  }

  // ---- human_safety.enabled (absent = true, fail-closed; the node warns, does not refuse) --
  {
    const YAML::Node n = Key(root, "human_safety.enabled");
    if (n) {
      try {
        p.human_safety_enabled = n.as<bool>();
      } catch (const std::exception &) {
        p.human_safety_enabled = true;
      }
    }
  }

  // ---- evidence.confidence_threshold (D-L1/D-L2) -------------------------------------------
  {
    const YAML::Node n = Key(root, "evidence.confidence_threshold");
    if (!n) return Fail(error, "POLICY_INCOMPLETE evidence.confidence_threshold missing (D-L2)");
    double t = 0.0;
    try {
      t = n.as<double>();
    } catch (const std::exception &) {
      return Fail(error, "POLICY_INCOMPLETE evidence.confidence_threshold is not a number (D-L2)");
    }
    if (!(t > 0.0) || t > 1.0) return Fail(error, "POLICY_RANGE evidence.confidence_threshold must be in (0, 1] (D-L1)");
    p.evidence_conf_threshold = t;
  }

  // ---- trust_classes[] → source → rank (D-L5) ----------------------------------------------
  const YAML::Node classes = Key(root, "trust_classes");
  if (!classes || !classes.IsSequence() || classes.size() == 0) {
    return Fail(error, "POLICY_INCOMPLETE trust_classes missing or empty (D-L3)");
  }
  std::unordered_map<std::string, int> id_rank;
  for (const YAML::Node &cls : classes) {
    if (!cls.IsMap()) return Fail(error, "POLICY_INCOMPLETE trust_classes[] element is not a map");
    const YAML::Node id = Key(cls, "trust_classes[].id");
    const YAML::Node rank = Key(cls, "trust_classes[].rank");
    const YAML::Node sources = Key(cls, "trust_classes[].sources");
    if (!id || !rank || !sources || !sources.IsSequence()) {
      return Fail(error, "POLICY_INCOMPLETE trust_classes[] element missing id / rank / sources");
    }
    int rank_value = 0;
    std::string id_value;
    try {
      id_value = id.as<std::string>();
      rank_value = rank.as<int>();
    } catch (const std::exception &) {
      return Fail(error, "POLICY_INCOMPLETE trust_classes[] id is not a string or rank is not an integer");
    }
    if (rank_value < 1) return Fail(error, "POLICY_INCOMPLETE trust_classes[].rank must be >= 1 (0 means unmapped)");
    id_rank[id_value] = rank_value;
    for (const YAML::Node &src : sources) {
      std::string s;
      try {
        s = src.as<std::string>();
      } catch (const std::exception &) {
        return Fail(error, "POLICY_INCOMPLETE trust_classes[].sources element is not a string");
      }
      p.trust_rank_by_source[s] = rank_value;
    }
  }
  {
    const YAML::Node floor_node = Key(root, "evidence.min_trust_class");
    if (!floor_node) return Fail(error, "POLICY_INCOMPLETE evidence.min_trust_class missing");
    std::string floor_id;
    try {
      floor_id = floor_node.as<std::string>();
    } catch (const std::exception &) {
      return Fail(error, "POLICY_INCOMPLETE evidence.min_trust_class is not a string");
    }
    const auto found = id_rank.find(floor_id);
    if (found == id_rank.end()) {
      return Fail(error, "POLICY_INCOMPLETE evidence.min_trust_class=\"" + floor_id + "\" names no class in trust_classes (D-L5)");
    }
    p.min_trust_rank = found->second;
  }

  // ---- preconditions[] freshness + safety exemption (D-L3) ---------------------------------
  const YAML::Node preconditions = Key(root, "preconditions");
  if (!preconditions || !preconditions.IsSequence()) return Fail(error, "POLICY_INCOMPLETE preconditions missing");
  bool safety_seen = false, evidence_seen = false;
  for (const YAML::Node &pc : preconditions) {
    if (!pc.IsMap()) return Fail(error, "POLICY_INCOMPLETE preconditions[] element is not a map");
    const YAML::Node id = Key(pc, "preconditions[].id");
    if (!id) return Fail(error, "POLICY_INCOMPLETE preconditions[].id missing");
    std::string id_value;
    try {
      id_value = id.as<std::string>();
    } catch (const std::exception &) {
      return Fail(error, "POLICY_INCOMPLETE preconditions[].id is not a string");
    }
    const YAML::Node exempt = Key(pc, "preconditions[].exempt_in_progress_step");
    const YAML::Node fresh = Key(pc, "preconditions[].freshness_ms");
    auto read_fresh = [&](int64_t *dst, const char *what) -> bool {
      if (!fresh) return Fail(error, std::string("POLICY_INCOMPLETE ") + what + " freshness_ms missing or not a number");
      try {
        *dst = fresh.as<int>();
      } catch (const std::exception &) {
        return Fail(error, std::string("POLICY_INCOMPLETE ") + what + " freshness_ms missing or not a number");
      }
      return true;
    };
    if (id_value == "safety_feed") {
      if (!exempt) return Fail(error, "POLICY_INCOMPLETE preconditions[safety_feed].exempt_in_progress_step missing");
      try {
        p.safety_exempt_in_progress_step = exempt.as<bool>();
      } catch (const std::exception &) {
        return Fail(error, "POLICY_INCOMPLETE preconditions[safety_feed].exempt_in_progress_step is not a boolean");
      }
      if (!read_fresh(&p.safety_stale_ms, "preconditions[safety_feed]")) return false;
      safety_seen = true;
    } else if (id_value == "evidence_claim") {
      if (!read_fresh(&p.evidence_window_ms, "preconditions[evidence_claim]")) return false;
      evidence_seen = true;
      bool ev = false;
      if (exempt) {
        try {
          ev = exempt.as<bool>();
        } catch (const std::exception &) {
          return Fail(error, "POLICY_INCOMPLETE preconditions[evidence_claim].exempt_in_progress_step is not a boolean");
        }
      }
      if (ev) return Fail(error, "POLICY_INCOMPLETE preconditions[evidence_claim].exempt_in_progress_step=true is not implementable");
    }
  }
  if (!safety_seen) return Fail(error, "POLICY_INCOMPLETE preconditions has no entry with id: safety_feed");
  if (!evidence_seen) return Fail(error, "POLICY_INCOMPLETE preconditions has no entry with id: evidence_claim");

  *out = p;
  if (error) error->clear();
  return true;
}

}  // namespace pail_pep_gate
