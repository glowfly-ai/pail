// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
#include "pail_gate/skills_load.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <set>
#include <sstream>

#include <yaml-cpp/yaml.h>
#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
#include <sodium.h>
#endif

namespace pail_pep_gate {
namespace {

bool Fail(std::string *error, const std::string &msg) {
  if (error) *error = msg;
  return false;
}

// The digest is the seal's input (SK-4). A build without the gRPC/seal path has no
// libsodium and no seal to feed; it returns "" and the caller records "not computed"
// — never a digest of nothing (H-B2).
std::string Sha256Hex(const std::string &bytes) {
#if !(defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1))
  (void)bytes;
  return "";
#else
  unsigned char out[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(out, reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size());
  static const char *hexd = "0123456789abcdef";
  std::string hex;
  hex.reserve(sizeof out * 2);
  for (unsigned char b : out) {
    hex.push_back(hexd[b >> 4]);
    hex.push_back(hexd[b & 0x0f]);
  }
  return hex;
#endif
}

// The keys the issuer's parser (internal/skills, deny-unknown) accepts. The gate refuses
// the same set so a file one side reads and the other refuses cannot exist.
const std::set<std::string> kTopKeys = {"version", "robot_class", "skills"};
const std::set<std::string> kRowKeys = {"name", "classes", "evidence", "envelope", "feeds",
                                        "complete", "safe_state", "slot", "params_schema"};
const std::set<std::string> kCompleteSignals = {"duration", "robot_report", "robot_report+evidence"};
const std::set<std::string> kEvidenceWhens = {"none", "before", "at_complete"};

bool OnlyKeys(const YAML::Node &map, const std::set<std::string> &allowed, std::string *offender) {
  for (const auto &kv : map) {
    const std::string k = kv.first.as<std::string>();
    if (!allowed.count(k)) {
      *offender = k;
      return false;
    }
  }
  return true;
}

}  // namespace

std::vector<std::string> SplitMeasures(const std::string &csv) {
  std::vector<std::string> out;
  std::stringstream ss(csv);
  std::string item;
  while (std::getline(ss, item, ',')) {
    const auto b = item.find_first_not_of(" \t");
    const auto e = item.find_last_not_of(" \t");
    if (b == std::string::npos) continue;
    out.push_back(item.substr(b, e - b + 1));
  }
  return out;
}

bool LoadSkillRegistry(const std::string &path, const std::string &want_robot_class,
                       SkillRegistryView *out, std::string *error) {
  if (!out) return Fail(error, "internal: null output");
  std::string bytes;
  {
    std::ifstream f(path, std::ios::binary);
    if (!f) return Fail(error, "SKILLS_ABSENT " + path + " — no skill registry to check the adapter's measures against (SK-2 S33)");
    bytes.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
  }
  YAML::Node root;
  try {
    root = YAML::Load(bytes);
  } catch (const std::exception &e) {
    return Fail(error, "SKILLS_UNREADABLE " + path + " (" + e.what() + ")");
  }
  if (!root.IsMap()) return Fail(error, "SKILLS_INCOMPLETE " + path + ": top level is not a map");
  std::string offender;
  if (!OnlyKeys(root, kTopKeys, &offender)) return Fail(error, "SKILLS_INCOMPLETE " + path + ": unknown key " + offender);
  if (!root["version"] || !root["version"].IsScalar() || root["version"].as<int>(0) != 1) {
    return Fail(error, "SKILLS_INCOMPLETE " + path + ": version must be 1");
  }
  if (!root["robot_class"] || !root["robot_class"].IsScalar() || root["robot_class"].as<std::string>().empty()) {
    return Fail(error, "SKILLS_INCOMPLETE " + path + ": robot_class is required");
  }
  SkillRegistryView v;
  v.robot_class = root["robot_class"].as<std::string>();
  if (!want_robot_class.empty() && v.robot_class != want_robot_class) {
    return Fail(error, "SKILLS_INCOMPLETE " + path + ": declares robot_class " + v.robot_class +
                           " but this gate serves " + want_robot_class);
  }
  const YAML::Node skills = root["skills"];
  if (!skills || !skills.IsSequence() || skills.size() == 0) {
    return Fail(error, "SKILLS_INCOMPLETE " + path + ": skills is missing or empty — an empty registry authorizes nothing");
  }
  std::set<std::string> uni, feed_uni, safe_uni;
  for (std::size_t i = 0; i < skills.size(); ++i) {
    const YAML::Node row = skills[i];
    const std::string at = path + ": skills[" + std::to_string(i) + "]";
    if (!row.IsMap()) return Fail(error, "SKILLS_INCOMPLETE " + at + " is not a map");
    if (!OnlyKeys(row, kRowKeys, &offender)) return Fail(error, "SKILLS_INCOMPLETE " + at + ": unknown key " + offender);
    if (!row["name"] || !row["name"].IsScalar()) return Fail(error, "SKILLS_INCOMPLETE " + at + ": name is required");
    const std::string name = row["name"].as<std::string>();
    if (name.empty() || name == "*") return Fail(error, "SKILLS_INCOMPLETE " + at + ": name " + name + " is not a skill");
    if (v.envelope_by_skill.count(name)) return Fail(error, "SKILLS_INCOMPLETE " + at + ": duplicate name " + name);
    for (const char *req : {"classes", "evidence", "envelope", "feeds", "complete", "safe_state"}) {
      if (!row[req]) return Fail(error, "SKILLS_INCOMPLETE " + at + " (" + name + "): " + req + " is required");
    }
    const YAML::Node env = row["envelope"];
    if (!env.IsSequence()) return Fail(error, "SKILLS_INCOMPLETE " + at + " (" + name + "): envelope must be a list (write [] for none)");
    std::vector<std::string> names;
    for (const auto &n : env) {
      if (!n.IsScalar() || n.as<std::string>().empty()) return Fail(error, "SKILLS_INCOMPLETE " + at + " (" + name + "): empty envelope name");
      names.push_back(n.as<std::string>());
      uni.insert(n.as<std::string>());
    }
    v.envelope_by_skill[name] = names;
    // SK-3: the completion signal and the evidence timing are what the session enforces.
    const YAML::Node cpl = row["complete"];
    if (!cpl.IsMap() || !cpl["signal"] || !cpl["signal"].IsScalar() ||
        !kCompleteSignals.count(cpl["signal"].as<std::string>())) {
      return Fail(error, "SKILLS_INCOMPLETE " + at + " (" + name + "): complete.signal must be one of duration|robot_report|robot_report+evidence");
    }
    const YAML::Node ev = row["evidence"];
    if (!ev.IsMap() || !ev["when"] || !ev["when"].IsScalar() || !kEvidenceWhens.count(ev["when"].as<std::string>())) {
      return Fail(error, "SKILLS_INCOMPLETE " + at + " (" + name + "): evidence.when must be one of none|before|at_complete");
    }
    v.complete_by_skill[name] = cpl["signal"].as<std::string>();
    v.evidence_when_by_skill[name] = ev["when"].as<std::string>();
    // SK-5: feeds and the safe state are what the session and the adapter enforce.
    const YAML::Node feeds = row["feeds"];
    if (!feeds.IsSequence()) return Fail(error, "SKILLS_INCOMPLETE " + at + " (" + name + "): feeds must be a list (write [] for none)");
    std::vector<std::string> fids;
    for (const auto &f : feeds) {
      if (!f.IsScalar() || f.as<std::string>().empty()) return Fail(error, "SKILLS_INCOMPLETE " + at + " (" + name + "): empty feed id");
      fids.push_back(f.as<std::string>());
      feed_uni.insert(f.as<std::string>());
    }
    v.feeds_by_skill[name] = fids;
    const YAML::Node ss = row["safe_state"];
    if (!ss.IsScalar() || ss.as<std::string>().empty()) return Fail(error, "SKILLS_INCOMPLETE " + at + " (" + name + "): safe_state must be a non-empty name");
    v.safe_state_by_skill[name] = ss.as<std::string>();
    safe_uni.insert(ss.as<std::string>());
    ++v.rows;
  }
  v.envelope_union.assign(uni.begin(), uni.end());
  v.feeds_union.assign(feed_uni.begin(), feed_uni.end());
  v.safe_state_union.assign(safe_uni.begin(), safe_uni.end());
  v.sha256_hex = Sha256Hex(bytes);
  *out = v;
  return true;
}

std::vector<std::string> UnobservedFeeds(const SkillRegistryView &reg,
                                         const std::vector<std::string> &observed) {
  std::set<std::string> have(observed.begin(), observed.end());
  std::vector<std::string> out;
  for (const auto &f : reg.feeds_union) {
    if (!have.count(f)) out.push_back(f);
  }
  return out;
}

std::vector<std::string> UnsupportedSafeStates(const SkillRegistryView &reg,
                                               const std::vector<std::string> &executable) {
  std::set<std::string> have(executable.begin(), executable.end());
  std::vector<std::string> out;
  for (const auto &s : reg.safe_state_union) {
    if (!have.count(s)) out.push_back(s);
  }
  return out;
}

bool SkillNeedsFeed(const SkillRegistryView &reg, const std::string &skill, const std::string &feed) {
  const auto it = reg.feeds_by_skill.find(skill);
  if (it == reg.feeds_by_skill.end()) return false;
  for (const auto &f : it->second) if (f == feed) return true;
  return false;
}

std::vector<std::string> UnmeasuredNames(const SkillRegistryView &reg,
                                         const std::vector<std::string> &measures) {
  std::set<std::string> have(measures.begin(), measures.end());
  std::vector<std::string> out;
  for (const auto &n : reg.envelope_union) {
    if (!have.count(n)) out.push_back(n);
  }
  return out;
}

}  // namespace pail_pep_gate
