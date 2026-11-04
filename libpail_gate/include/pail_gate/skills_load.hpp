// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//
// SK-2 (implementation contract, S33): the gate's read of the skill registry
// (`config/skills.<robot_class>.yaml`, spec/SKILLS.md). The gate does not judge
// skills by this file — the issuer does (SK-1) — it reads it for two reasons:
//   1. S33: every name a registry row may put on a token (`envelope[]`) must be
//      a name this adapter measures. A bound nobody measures blocks every
//      command as unmeasured (gate_core, ERR_BAD_TOKEN), so the mismatch is
//      refused at start, where it can be read, not at the first command.
//   2. SK-4: the file's digest enters the configuration seal (skills_file_sha256).
// The parser is strict on the shape the gate needs and ignores what the
// issuer judges (classes, evidence, feeds, …) — those keys are read to exist,
// not interpreted, and unknown keys are refused as the issuer refuses them.
#pragma once
#include <map>
#include <string>
#include <vector>

namespace pail_pep_gate {

struct SkillRegistryView {
  std::string robot_class;
  std::string sha256_hex;  // of the file bytes, as read
  std::map<std::string, std::vector<std::string>> envelope_by_skill;
  std::vector<std::string> envelope_union;  // sorted, unique
  // SK-3 : what consumes a step of this skill, and when target
  // evidence is required. Closed vocabularies, refused otherwise:
  //   complete.signal  duration | robot_report | robot_report+evidence
  //   evidence.when    none | before | at_complete
  std::map<std::string, std::string> complete_by_skill;
  std::map<std::string, std::string> evidence_when_by_skill;
  // SK-5 : the state feeds a skill needs fresh while it holds a
  // permit (policy `preconditions[].id`), and the safe state the adapter must
  // execute when the permit is revoked (`ADAPTERS.tsv` safe_state).
  std::map<std::string, std::vector<std::string>> feeds_by_skill;
  std::vector<std::string> feeds_union;  // sorted, unique
  std::map<std::string, std::string> safe_state_by_skill;
  std::vector<std::string> safe_state_union;  // sorted, unique
  std::size_t rows{0};
};

// Loads and validates. On failure *error names it (SKILLS_ABSENT / SKILLS_UNREADABLE /
// SKILLS_INCOMPLETE <detail>). `want_robot_class` empty = do not compare.
bool LoadSkillRegistry(const std::string &path, const std::string &want_robot_class,
                       SkillRegistryView *out, std::string *error);

// S33: names the registry may put on a token that the adapter does not measure.
// Empty = every envelope name is measured. `measures` is the adapter's declaration.
std::vector<std::string> UnmeasuredNames(const SkillRegistryView &reg,
                                         const std::vector<std::string> &measures);

// "a,b, c" → {"a","b","c"} (trimmed, empty dropped).
std::vector<std::string> SplitMeasures(const std::string &csv);

// SK-5: feed ids the registry needs that this gate does not observe. Empty =
// every feed a row names is one the gate reads (safety_feed, evidence_claim, …).
std::vector<std::string> UnobservedFeeds(const SkillRegistryView &reg,
                                         const std::vector<std::string> &observed);

// SK-5: safe states the registry names that the adapter did not declare it can
// execute. Empty = every row's safe_state is one the adapter executes.
std::vector<std::string> UnsupportedSafeStates(const SkillRegistryView &reg,
                                               const std::vector<std::string> &executable);

// SK-5: does `skill`'s row list `feed`? False for an unknown skill.
bool SkillNeedsFeed(const SkillRegistryView &reg, const std::string &skill, const std::string &feed);

}  // namespace pail_pep_gate
