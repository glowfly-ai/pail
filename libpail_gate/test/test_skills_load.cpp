// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
//
// SK-2 : the gate's read of the skill registry and the S33 question.
// Owner of G-ADP-12 (registry envelope ⊆ adapter measures, refused at start).
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#include "pail_gate/skills_load.hpp"

using pail_pep_gate::LoadSkillRegistry;
using pail_pep_gate::SkillRegistryView;
using pail_pep_gate::SplitMeasures;
using pail_pep_gate::UnmeasuredNames;

namespace {
int g_failures = 0;

std::string Write(const char *name, const std::string &text) {
  std::string path = std::string("/tmp/pail_skills_") + name + ".yaml";
  std::ofstream f(path, std::ios::binary);
  f << text;
  return path;
}

void Expect(bool cond, const char *note) {
  if (!cond) {
    std::fprintf(stderr, "  FAIL %s\n", note);
    ++g_failures;
  }
}

const char *kGood =
    "version: 1\n"
    "robot_class: diff_drive_amr\n"
    "skills:\n"
    "  - name: twist\n"
    "    classes: [MOVE]\n"
    "    evidence: {when: before, trust: identity_bearing}\n"
    "    envelope: [sls.linear_mps, sls.angular_rps, step.max_duration_s]\n"
    "    feeds: [safety_feed]\n"
    "    complete: {signal: duration}\n"
    "    safe_state: stop_zero_twist\n"
    "  - name: pick\n"
    "    classes: [MANIPULATE]\n"
    "    evidence: {when: none}\n"
    "    envelope: [step.max_duration_s, sfc.contact_n]\n"
    "    feeds: []\n"
    "    complete: {signal: robot_report}\n"
    "    safe_state: stop_zero_twist\n";

// PAIL-CASE: skills_load_good
int CaseGood() {
  const int before = g_failures;
  SkillRegistryView v;
  std::string err;
  Expect(LoadSkillRegistry(Write("good", kGood), "diff_drive_amr", &v, &err), ("good registry loads: " + err).c_str());
  Expect(v.rows == 2 && v.robot_class == "diff_drive_amr", "rows and class");
  Expect(v.envelope_union.size() == 4, "union has the four names");
  Expect(v.sha256_hex.size() == 64, "digest is sha256 hex");
  Expect(v.envelope_by_skill["pick"].size() == 2, "pick envelope");
  return g_failures - before;
}

// PAIL-CASE: skills_s33_unmeasured
// G-ADP-12: a registry name the adapter does not measure is named, not silently
// accepted; the ROS default measures cover the primitives and nothing else.
int CaseS33() {
  const int before = g_failures;
  SkillRegistryView v;
  std::string err;
  LoadSkillRegistry(Write("s33", kGood), "", &v, &err);
  const auto ros = SplitMeasures("sls.linear_mps, sls.angular_rps,step.max_duration_s");
  Expect(ros.size() == 3, "csv split trims and counts");
  const auto missing = UnmeasuredNames(v, ros);
  Expect(missing.size() == 1 && missing[0] == "sfc.contact_n", "the contact force is the unmeasured name");
  const auto all = UnmeasuredNames(v, SplitMeasures("sls.linear_mps,sls.angular_rps,step.max_duration_s,sfc.contact_n"));
  Expect(all.empty(), "declaring it clears S33");
  const auto none = UnmeasuredNames(v, {});
  Expect(none.size() == 4, "an adapter that measures nothing is unmeasured on every name — not silently fine");
  return g_failures - before;
}

// PAIL-CASE: skills_feeds_safe_state
// SK-5 (G-ADP-18): feeds and safe states are read per row; a feed this gate does
// not observe and a safe state the adapter does not execute are named at start.
int CaseFeedsSafeState() {
  const int before = g_failures;
  const std::string text = std::string(kGood) +
      "  - name: inspect\n"
      "    classes: [NONE]\n"
      "    evidence: {when: none}\n"
      "    envelope: []\n"
      "    feeds: [safety_feed, evidence_claim, fleet_feed]\n"
      "    complete: {signal: duration}\n"
      "    safe_state: hold_position\n";
  SkillRegistryView v;
  std::string err;
  Expect(LoadSkillRegistry(Write("feeds", text), "", &v, &err), ("feeds registry loads: " + err).c_str());
  Expect(v.feeds_by_skill["twist"].size() == 1 && v.feeds_by_skill["pick"].empty() && v.feeds_by_skill["inspect"].size() == 3, "feeds per row");
  Expect(v.feeds_union.size() == 3, "feed union");
  Expect(SkillNeedsFeed(v, "inspect", "evidence_claim") && !SkillNeedsFeed(v, "twist", "evidence_claim") && !SkillNeedsFeed(v, "ghost", "safety_feed"),
         "SkillNeedsFeed answers per row and false for an unknown skill");
  const auto unobs = UnobservedFeeds(v, {"safety_feed", "evidence_claim"});
  Expect(unobs.size() == 1 && unobs[0] == "fleet_feed", "the fleet feed is the unobserved one");
  Expect(UnobservedFeeds(v, {}).size() == 3, "a gate observing nothing is unobserved on every feed");
  const auto unsup = UnsupportedSafeStates(v, SplitMeasures("stop_zero_twist"));
  Expect(unsup.size() == 1 && unsup[0] == "hold_position", "hold_position is the unsupported safe state");
  Expect(UnsupportedSafeStates(v, SplitMeasures("stop_zero_twist,hold_position")).empty(), "declaring it clears the check");
  SkillRegistryView r;
  Expect(!LoadSkillRegistry(Write("feeds_bad", "version: 1\nrobot_class: x\nskills:\n  - name: a\n    classes: [MOVE]\n    evidence: {when: none}\n    envelope: []\n    feeds: safety_feed\n    complete: {signal: duration}\n    safe_state: s\n"), "", &r, &err) &&
             err.find("feeds must be a list") != std::string::npos, ("feeds not a list is refused (" + err + ")").c_str());
  Expect(!LoadSkillRegistry(Write("safe_bad", "version: 1\nrobot_class: x\nskills:\n  - name: a\n    classes: [MOVE]\n    evidence: {when: none}\n    envelope: []\n    feeds: []\n    complete: {signal: duration}\n    safe_state: \"\"\n"), "", &r, &err) &&
             err.find("safe_state must be") != std::string::npos, ("empty safe_state is refused (" + err + ")").c_str());
  return g_failures - before;
}

// PAIL-CASE: skills_load_refusals
int CaseRefusals() {
  const int before = g_failures;
  struct Row { const char *note; std::string text; const char *want_class; const char *needle; };
  const Row rows[] = {
      {"absent file", "", "", "SKILLS_ABSENT"},
      {"unknown top key", std::string(kGood) + "bogus: 1\n", "", "unknown key bogus"},
      {"unknown row key", std::string(kGood) + "    slott: main\n", "", "unknown key slott"},
      {"wildcard", std::string("version: 1\nrobot_class: x\nskills:\n  - name: \"*\"\n    classes: [MOVE]\n    evidence: {when: none}\n    envelope: []\n    feeds: []\n    complete: {signal: duration}\n    safe_state: s\n"), "", "is not a skill"},
      {"class mismatch", kGood, "humanoid", "but this gate serves humanoid"},
      {"empty skills", "version: 1\nrobot_class: x\nskills: []\n", "", "missing or empty"},
      {"envelope not list", std::string("version: 1\nrobot_class: x\nskills:\n  - name: a\n    classes: [MOVE]\n    evidence: {when: none}\n    envelope: sls.linear_mps\n    feeds: []\n    complete: {signal: duration}\n    safe_state: s\n"), "", "envelope must be a list"},
      {"version 2", std::string("version: 2\n") + (kGood + 11), "", "version must be 1"},
  };
  int i = 0;
  for (const auto &r : rows) {
    SkillRegistryView v;
    std::string err;
    const std::string path = r.text.empty() ? "/tmp/pail_skills_does_not_exist.yaml"
                                            : Write(("refuse" + std::to_string(i)).c_str(), r.text);
    ++i;
    const bool ok = LoadSkillRegistry(path, r.want_class, &v, &err);
    Expect(!ok, r.note);
    Expect(err.find(r.needle) != std::string::npos, (std::string(r.note) + ": error names it (" + err + ")").c_str());
  }
  return g_failures - before;
}
}  // namespace

int main() {
  struct { const char *name; int (*fn)(); } cases[] = {
      {"Good", CaseGood}, {"S33", CaseS33}, {"FeedsSafeState", CaseFeedsSafeState}, {"Refusals", CaseRefusals},
  };
  int failed = 0;
  for (const auto &c : cases) {
    const int rc = c.fn();
    std::printf("%-24s %s\n", c.name, rc == 0 ? "PASS" : "FAIL");
    if (rc != 0) ++failed;
  }
  std::printf("---- %d case(s), %d failed\n", (int)(sizeof(cases) / sizeof(cases[0])), failed);
  return failed == 0 ? 0 : 1;
}
