// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// SD4-1 (see spec/ARCHITECTURE.md): the canonical form must be
// deterministic, and it must separate configurations that the journal could not
// separate before (integration/sd4/EVIDENCE_RUN_SD4_0.txt).
//
// There is no second implementation of this canonicalizer — the issuer receives
// the text and hashes it rather than rebuilding it — so this test carries the
// whole contract alone.

#include <clocale>
#include <cstddef>
#include <cstdio>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "pail_deploy_guard/config_seal.hpp"

namespace
{

int g_bad = 0;

void Check(bool cond, const std::string & what)
{
  if (!cond) {
    std::printf("FAIL: %s\n", what.c_str());
    ++g_bad;
  }
}

// The configuration a hardened production gate runs under.
pail_deploy_guard::SealInput Normal()
{
  pail_deploy_guard::SealInput in;
  in.component = "pep_gate";
  in.robot_id = "robot-1";
  in.profile = "production";
  in.security_enable = "true";
  in.security_strategy = "Enforce";
  in.keystore = "/etc/pail/keystore";
  in.enclave_provisioned = true;
  in.effective_enclave = "/pep_gate";
  in.token_provider_mode = "grpc";
  in.grpc_built = true;
  in.token_service_addr = "127.0.0.1:50051";
  in.keyring_mode = "bundle";
  in.trusted_key_fingerprints = {
    "0000000000000000000000000000000000000000000000000000000000000001"};
  in.permit_rate_hz = 20;
  in.permit_deadline_ms = 100;
  in.policy_file = "/etc/pail/policy.yaml";
  in.human_safety_enabled = true;

  // v2. A hardened gate is one that also MEASURED these — the defaults say
  // "nobody looked", which is a degraded state and must not be the baseline
  // the rest of this file compares against.
  in.use_sim_time = "0";
  in.control_transport = "mtls";
  in.control_trust_anchors = {
    "0000000000000000000000000000000000000000000000000000000000000002"};
  in.motion_deadman_ms = "200";
  in.policy_file_sha256 =
    "0000000000000000000000000000000000000000000000000000000000000003";
  in.skills_file_sha256 =
    "0000000000000000000000000000000000000000000000000000000000000005";  // v3: the registry was read
  return in;
}

bool HasAxis(const pail_deploy_guard::SealInput & in, const std::string & id)
{
  const auto axes = pail_deploy_guard::DegradedAxes(pail_deploy_guard::EvaluateSeal(in));
  for (const auto & a : axes) {
    if (a == id) {
      return true;
    }
  }
  return false;
}

// Canon asserts acceptance and hands back the text. R-CS1 made assembly
// fallible, and a helper that quietly returned "" on rejection would let a
// refused input and an empty canon share bytes in every assertion below.
std::string Canon(const pail_deploy_guard::SealInput & in, const std::string & what)
{
  const auto r = pail_deploy_guard::CanonicalizeSeal(in);
  Check(r.ok, "assembly must accept: " + what);
  return r.text;
}

std::string CanonV1(const pail_deploy_guard::SealInput & in, const std::string & what)
{
  const auto r = pail_deploy_guard::CanonicalizeSealV1(in);
  Check(r.ok, "v1 assembly must accept: " + what);
  return r.text;
}

std::string CanonV2(const pail_deploy_guard::SealInput & in, const std::string & what)
{
  const auto r = pail_deploy_guard::CanonicalizeSealV2(in);
  Check(r.ok, "v2 assembly must accept: " + what);
  return r.text;
}

std::size_t BodyKeyCount(const std::string & canon)
{
  std::size_t n = 0;
  for (char ch : canon) {
    if (ch == '\n') { ++n; }
  }
  return n - 1;  // the version line is not a key
}

// The zero-based body position of a key, or npos. A key present at the wrong
// index is a different canon from the frozen table even though every grep for
// the key name still finds it.
std::size_t KeyIndex(const std::string & canon, const std::string & key)
{
  std::size_t idx = 0;
  std::size_t pos = canon.find('\n');  // skip the version line
  if (pos == std::string::npos) {
    return std::string::npos;
  }
  ++pos;
  while (pos < canon.size()) {
    const std::size_t eol = canon.find('\n', pos);
    if (eol == std::string::npos) {
      return std::string::npos;
    }
    const std::size_t eq = canon.find('=', pos);
    if (eq != std::string::npos && eq < eol && canon.compare(pos, eq - pos, key) == 0) {
      return idx;
    }
    ++idx;
    pos = eol + 1;
  }
  return std::string::npos;
}

}  // namespace

// PAIL-CASE: ConfigSealV3
// SK-4 : v3 adds skills_file_sha256; the v2 edition is frozen the
// same way v1 is (OB1-FREEZE-2026-08-17) — config_seal_v2.vec links
// CanonicalizeSealV2, and v2 bytes must not move when v3 gains its key.
void CaseConfigSealV3(const pail_deploy_guard::SealInput & normal, const std::string & c_normal)
{
  {
    const std::string v2 = CanonV2(normal, "normal");
    Check(v2.rfind("pail-config-seal:v2\n", 0) == 0, "v2 must still emit a v2 banner");
    Check(BodyKeyCount(v2) == 31, "v2 must remain 31 keys");
    Check(KeyIndex(v2, "skills_file_sha256") == std::string::npos,
      "a v3 key must not appear in v2: skills_file_sha256");
    auto shaken = Normal();
    shaken.skills_file_sha256 = "unknown";  // the one v3-only input, at its loud value
    Check(CanonV2(shaken, "shaken") == v2, "v3-only input must not reach the v2 canon");
    Check(pail_deploy_guard::EvaluateSealV2(shaken).empty(),
      "v3-only degradation must not add axes to a v2 record");
    // …and in v3 the same input is both a value and an axis (H-B2).
    const std::string c_shaken = Canon(shaken, "shaken v3");
    Check(c_shaken != c_normal, "an unread registry must change the v3 canon");
    Check(HasAxis(shaken, pail_deploy_guard::kSealUnobservedAxis),
      "an unread registry must show as S21 in v3");
    auto none = Normal();
    none.skills_file_sha256 = "";  // no registry configured — a fact, not a silence
    Check(Canon(none, "no registry") != c_normal, "absent registry must differ from a hashed one");
    Check(!HasAxis(none, pail_deploy_guard::kSealUnobservedAxis),
      "no registry configured is not an unobserved value");
    auto other = Normal();
    other.skills_file_sha256 = "00000000000000000000000000000000000000000000000000000000000000ee";
    Check(Canon(other, "other registry") != c_normal, "another registry must change the digest (RA-9)");
    auto word = Normal();
    word.skills_file_sha256 = "unreadable";
    const auto r = pail_deploy_guard::CanonicalizeSeal(word);
    Check(!r.ok && r.text.empty() && r.reject_reason == pail_deploy_guard::kRejectSkillsShaVocabulary,
      "a fourth spelling of skills_file_sha256 has no canonical form (R-A)");
  }

}

// PAIL-CASE: ConfigSealS36
// SK-5 : an undeclared vendor safety controller under production is
// a degraded axis (S36), never a canon key. Unmeasured is silent (the frozen v3
// vectors), declared is quiet, dev is quiet — only measured-and-empty-and-
// production speaks.
void CaseConfigSealS36(const pail_deploy_guard::SealInput & normal, const std::string & c_normal)
{
  auto measured_empty = normal;
  measured_empty.safety_controller_measured = true;
  measured_empty.safety_controller = "";
  Check(HasAxis(measured_empty, pail_deploy_guard::kSafetyControllerAxis),
    "production with an empty safety_controller must show S36");
  Check(Canon(measured_empty, "s36") != c_normal, "S36 must reach the sealed degraded list");

  auto declared = normal;
  declared.safety_controller_measured = true;
  declared.safety_controller = "acme:safeguard-x:2.1:" + std::string(64, 'a');
  Check(!HasAxis(declared, pail_deploy_guard::kSafetyControllerAxis),
    "a declared safety_controller is not S36");
  Check(Canon(declared, "declared") == c_normal,
    "the declaration itself is not a canon key — only the axis reaches the seal");

  auto dev = measured_empty;
  dev.profile = "dev";
  Check(!HasAxis(dev, pail_deploy_guard::kSafetyControllerAxis), "dev is not asked for a safety controller");

  auto unmeasured = normal;  // the default — what the frozen vectors were built with
  Check(!unmeasured.safety_controller_measured && !HasAxis(unmeasured, pail_deploy_guard::kSafetyControllerAxis),
    "unmeasured is silent (frozen v3 vectors carry no S36)");
}

// PAIL-CASE: ConfigSealCanon
int main()
{
  const auto normal = Normal();
  const std::string c_normal = Canon(normal, "normal");

  // 1. Deterministic.
  Check(c_normal == Canon(normal, "normal"), "same input must give the same bytes");
  Check(c_normal.rfind("pail-config-seal:v3\n", 0) == 0, "canonical text must be versioned");
  Check(c_normal.back() == '\n', "canonical text must end with a newline");

  // R-CS2: the version in the first line is the version the constant claims.
  // Two places state the edition, and a canon whose banner disagrees with the
  // constant would be read back under the wrong key table.
  Check(c_normal.rfind(
      "pail-config-seal:v" + std::to_string(pail_deploy_guard::kConfigSealVersion) + "\n", 0) == 0,
    "the banner must carry kConfigSealVersion, not a literal");

  // v3 is 32 keys (implementation contract: v2's 31 + skills_file_sha256). Counting them
  // is what catches a key added without the table being amended — the
  // direction the freeze is supposed to make hard.
  Check(BodyKeyCount(c_normal) == 32, "v3 must seal exactly 32 keys");
  Check(KeyIndex(c_normal, "skills_file_sha256") == KeyIndex(c_normal, "policy_file_sha256") + 1,
    "skills_file_sha256 sits right after policy_file_sha256 (inserted, not appended)");

  // 2. A hardened configuration has nothing to report.
  Check(pail_deploy_guard::EvaluateSeal(normal).empty(),
    "the hardened configuration must produce no findings");
  Check(c_normal.find("degraded=\n") != std::string::npos,
    "the hardened configuration must seal an empty degraded list");
  Check(c_normal.find("verifies_authorization=1\n") != std::string::npos,
    "grpc on a grpc build must seal verifies_authorization=1");

  // 3. ARM B of the RED harness: thresholds turned off. This is the case the
  //    journal could not distinguish from ARM A.
  auto relaxed = Normal();
  relaxed.thresholds.evidence_conf_threshold = 0.0;
  relaxed.thresholds.safety_stale_ms = 60000;
  relaxed.thresholds.clock_skew_ms = 30000;
  const std::string c_relaxed = Canon(relaxed, "relaxed");
  Check(c_relaxed != c_normal, "a relaxed run must not canonicalize like a normal one");
  Check(HasAxis(relaxed, "S10"), "disabled thresholds must show as S10");
  Check(c_relaxed.find("degraded=S10\n") != std::string::npos,
    "the relaxed run must seal S10 in its degraded list");

  // 4. ARM C: static. The mode that verifies nothing must be visible in the
  //    seal itself, not only in the absence of records.
  auto bypass = Normal();
  bypass.profile = "dev";
  bypass.token_provider_mode = "static";
  const std::string c_bypass = Canon(bypass, "bypass");
  Check(c_bypass != c_normal && c_bypass != c_relaxed,
    "a static run must not canonicalize like either grpc run");
  Check(HasAxis(bypass, "S7"), "static must show as S7");
  Check(c_bypass.find("verifies_authorization=0\n") != std::string::npos,
    "static must seal verifies_authorization=0");

  // grpc requested on a build with no grpc linked is the same failure by
  // another road, and must not be mistaken for a working gate.
  auto nogrpc = Normal();
  nogrpc.grpc_built = false;
  Check(HasAxis(nogrpc, "S7"), "grpc mode on a non-grpc build must show as S7");
  Check(Canon(nogrpc, "nogrpc").find("verifies_authorization=0\n") != std::string::npos,
    "grpc mode on a non-grpc build must seal verifies_authorization=0");

  // 5. Each remaining axis moves the digest input on its own.
  auto s1 = Normal();
  s1.security_enable = "false";
  Check(HasAxis(s1, "S1"), "ROS_SECURITY_ENABLE=false must show as S1");
  Check(Canon(s1, "s1") != c_normal, "S1 must change the canonical text");

  auto s3 = Normal();
  s3.effective_enclave = "/motion_bridge";
  Check(HasAxis(s3, "S3"), "another component's enclave must show as S3");
  Check(Canon(s3, "s3") != c_normal, "S3 must change the canonical text");

  auto s8 = Normal();
  s8.keyring_mode = "unsigned-dev";
  Check(HasAxis(s8, "S8"), "an unsigned keyring must show as S8");

  // A trust anchor committed to this repository is the S8 case that matters:
  // the key is public, so anyone with the source can sign for this robot.
  std::size_t n = 0;
  const auto * known = pail_deploy_guard::KnownDevKeys(&n);
  Check(n > 0, "the known dev key list must not be empty");
  if (n > 0) {
    auto s8k = Normal();
    s8k.trusted_key_fingerprints = {known[0].fingerprint};
    Check(HasAxis(s8k, "S8"), "a committed dev key must show as S8");
  }

  // 6. Anchor ordering must not leak into the digest — the same trust set read
  //    back in another order is the same trust set.
  auto order_a = Normal();
  order_a.trusted_key_fingerprints = {"aa", "bb"};
  auto order_b = Normal();
  order_b.trusted_key_fingerprints = {"bb", "aa", "bb"};
  Check(Canon(order_a, "order_a") == Canon(order_b, "order_b"),
    "anchor order and duplicates must not change the seal");

  // 7. A value carrying a newline must not be able to forge a line. Without
  //    escaping, this policy_file would inject its own token_provider_mode.
  auto inject = Normal();
  inject.policy_file = "/etc/pail/policy.yaml\ntoken_provider_mode=grpc";
  const std::string c_inject = Canon(inject, "inject");
  Check(c_inject != c_normal, "an injected value must still change the seal");
  Check(c_inject.find("\ntoken_provider_mode=grpc\n") == std::string::npos ||
        c_inject.find("policy_file=/etc/pail/policy.yaml\\ntoken_provider_mode=grpc\n") !=
          std::string::npos,
    "a newline in a value must be escaped, not emitted as a line break");
  {
    std::size_t lines = 0;
    for (char ch : c_inject) {
      if (ch == '\n') { ++lines; }
    }
    std::size_t base = 0;
    for (char ch : c_normal) {
      if (ch == '\n') { ++base; }
    }
    Check(lines == base, "escaping must keep the line count fixed");
  }

  // 8. Locale must not reach the digest. A decimal comma would otherwise give
  //    the same configuration two different hashes on two hosts. The guarantee
  //    is structural — the only fractional input is carried as a scaled integer
  //    — so it is asserted on the text rather than by switching locales, which
  //    would silently pass wherever the other locale is not installed.
  Check(c_normal.find("evidence_conf_threshold_x1e6=900000\n") != std::string::npos,
    "the confidence threshold must be sealed as a scaled integer");
  {
    auto finer = Normal();
    finer.thresholds.evidence_conf_threshold = 0.900001;
    Check(Canon(finer, "finer") != c_normal,
      "the scaled integer must still resolve a 1e-6 change in the threshold");
  }
  {
    const std::string before = Canon(normal, "locale-before");
    if (std::setlocale(LC_ALL, "de_DE.UTF-8")) {
      const std::string after = Canon(normal, "locale-after");
      std::setlocale(LC_ALL, "C");
      Check(before == after, "the canonical text must not depend on the locale");
    }
  }

  // 9. R-CS1 : a list element carrying the separator folds two
  //    different trust sets onto one line. Frozen vector CS1-06 states the
  //    requirement; this is its execution.
  {
    const std::string a = "00000000000000000000000000000000000000000000000000000000000000aa";
    const std::string b = "00000000000000000000000000000000000000000000000000000000000000bb";

    auto two = Normal();
    two.trusted_key_fingerprints = {a, b};
    auto one = Normal();
    one.trusted_key_fingerprints = {a + "," + b};

    const auto r_two = pail_deploy_guard::CanonicalizeSeal(two);
    const auto r_one = pail_deploy_guard::CanonicalizeSeal(one);
    Check(r_two.ok, "two distinct anchors must still assemble");
    Check(!r_one.ok, "a list element containing ',' must be refused (R-CS1)");
    Check(r_one.reject_reason == pail_deploy_guard::kRejectListSeparator,
      "the refusal must name the rule, not fail silently");
    // A refusal carries no canonical text: an empty canon and a refused canon
    // must not be the same bytes on the wire.
    Check(r_one.text.empty(), "a refused assembly must not hand back a canonical text");
  }

  // 10. v2 key placement . The five new keys were inserted at
  //     their logical positions, not appended, so their index is part of the
  //     frozen table. A key that moved is a different canon even though every
  //     search for its name still finds it.
  {
    const std::pair<const char *, std::size_t> placed[] = {
      {"component", 0},
      {"robot_id", 1},
      {"profile", 2},
      {"use_sim_time", 3},
      {"ros_security_enable", 4},
      {"keyring_mode", 14},
      {"control_transport", 15},
      {"control_trust_anchors", 16},
      {"trusted_key_fingerprints", 17},
      {"permit_deadline_ms", 25},
      {"motion_deadman_ms", 26},
      {"policy_file", 27},
      {"policy_file_sha256", 28},
      {"skills_file_sha256", 29},  // v3 (SK-4): inserted, so the two below moved by one
      {"human_safety_enabled", 30},
      {"degraded", 31},
    };
    for (const auto & p : placed) {
      Check(KeyIndex(c_normal, p.first) == p.second,
        std::string("key must sit at its frozen position: ") + p.first);
    }
  }

  // 11. The v1 edition is frozen, not merely old. config_seal_v1.vec is a PROC
  //     vector whose preservation procedure links CanonicalizeSealV1 directly,
  //     so this asserts the property that procedure depends on: v1 bytes do not
  //     move when v2 gains keys.
  {
    const std::string v1 = CanonV1(normal, "normal");
    Check(v1.rfind("pail-config-seal:v1\n", 0) == 0, "v1 must still emit a v1 banner");
    Check(BodyKeyCount(v1) == 26, "v1 must remain 26 keys");
    for (const char * k : {"use_sim_time", "control_transport", "control_trust_anchors",
        "motion_deadman_ms", "policy_file_sha256"})
    {
      Check(KeyIndex(v1, k) == std::string::npos,
        std::string("a v2 key must not appear in v1: ") + k);
    }

    // Moving every v2-only input at once must leave v1 byte-identical. If v1
    // ever shares an assembler with v2, this is the assertion that fails.
    auto shaken = Normal();
    shaken.use_sim_time = "1";
    shaken.control_transport = "plaintext";
    shaken.control_trust_anchors = {
      "00000000000000000000000000000000000000000000000000000000000000ff"};
    shaken.motion_deadman_ms = "999";
    shaken.policy_file_sha256 = "unknown";
    Check(CanonV1(shaken, "shaken") == v1, "v2-only inputs must not reach the v1 canon");
    Check(pail_deploy_guard::EvaluateSealV1(shaken).empty(),
      "v2-only degradation must not add axes to a v1 record");
  }

  CaseConfigSealV3(normal, c_normal);
  CaseConfigSealS36(normal, c_normal);

  // 12. Each new key changes the digest on its own (H-B8) — a posture the seal
  //     records but cannot distinguish is not recorded.
  {
    auto plain = Normal();
    plain.control_transport = "plaintext";
    const std::string c_plain = Canon(plain, "plaintext");
    Check(c_plain != c_normal, "plaintext and mtls must not hash alike");
    Check(!HasAxis(plain, pail_deploy_guard::kSealUnobservedAxis),
      "plaintext is a measured posture, not an unmeasured one");

    auto sim = Normal();
    sim.use_sim_time = "1";
    Check(Canon(sim, "sim") != c_normal, "use_sim_time must change the canonical text");

    auto dead = Normal();
    dead.motion_deadman_ms = "999";
    Check(Canon(dead, "deadman") != c_normal, "motion_deadman_ms must change the canonical text");

    auto pol = Normal();
    pol.policy_file_sha256 =
      "00000000000000000000000000000000000000000000000000000000000000ff";
    Check(Canon(pol, "policy-sha") != c_normal,
      "policy_file_sha256 must change the canonical text");

    // The same policy path with different contents was one digest before v2.
    auto same_path = Normal();
    same_path.policy_file_sha256 =
      "00000000000000000000000000000000000000000000000000000000000000ee";
    Check(Canon(same_path, "same-path") != Canon(pol, "policy-sha"),
      "two contents behind one policy path must not seal alike");

    auto anch = Normal();
    anch.control_trust_anchors = {};
    Check(Canon(anch, "no-anchors") != c_normal, "an empty trust set must be visible");

    // Anchor order must not leak here either.
    auto o1 = Normal();
    o1.control_trust_anchors = {"aa", "bb"};
    auto o2 = Normal();
    o2.control_trust_anchors = {"bb", "aa", "aa"};
    Check(Canon(o1, "anchor-order-a") == Canon(o2, "anchor-order-b"),
      "control anchor order and duplicates must not change the seal");
  }

  // 13. Not having looked is a state of its own (H-B2). The default values say
  //     "nobody measured this", and they must be distinguishable from a measured
  //     benign value in the axis list, which is what a reader diffs first.
  {
    const std::string axis = pail_deploy_guard::kSealUnobservedAxis;

    auto blind_clock = Normal();
    blind_clock.use_sim_time = "unknown";
    Check(HasAxis(blind_clock, axis), "an unread use_sim_time must raise the observation axis");
    Check(Canon(blind_clock, "blind-clock").find("degraded=" + axis + "\n") != std::string::npos,
      "the observation axis must reach the sealed degraded list");

    auto blind_tp = Normal();
    blind_tp.control_transport.clear();
    Check(HasAxis(blind_tp, axis), "an unset control_transport must raise the observation axis");

    auto blind_dead = Normal();
    blind_dead.motion_deadman_ms = "unknown";
    Check(HasAxis(blind_dead, axis), "an unread motion_deadman_ms must raise the observation axis");

    auto blind_pol = Normal();
    blind_pol.policy_file_sha256 = "unknown";
    Check(HasAxis(blind_pol, axis), "an unreadable policy file must raise the observation axis");

    // "no policy file configured" is a measurement, not a gap: the empty string
    // is a third word in the vocabulary and must not be read as "unknown".
    auto no_policy = Normal();
    no_policy.policy_file.clear();
    no_policy.policy_file_sha256.clear();
    Check(!HasAxis(no_policy, axis), "an absent policy file must not raise the observation axis");
    Check(Canon(no_policy, "no-policy").find("policy_file_sha256=\n") != std::string::npos,
      "an absent policy digest must seal as the empty value");

    // A default-constructed input is the shape the wiring produces before it is
    // taught to measure — it must be loud, not silent.
    pail_deploy_guard::SealInput bare;
    Check(HasAxis(bare, axis), "an unwired gate must declare that it measured nothing");
  }

  // 14. R-A on policy_file_sha256 (§3.1.6): a value outside the three-word
  //     vocabulary has no canonical form, so it does not get one.
  {
    auto bad = Normal();
    bad.policy_file_sha256 =
      "00000000000000000000000000000000000000000000000000000000000000FF";  // uppercase
    const auto r = pail_deploy_guard::CanonicalizeSeal(bad);
    Check(!r.ok, "uppercase hex must be refused, not silently sealed");
    Check(r.reject_reason == pail_deploy_guard::kRejectPolicyShaVocabulary,
      "the refusal must name the vocabulary rule");
    Check(r.text.empty(), "a refused assembly must not hand back a canonical text");

    auto shortish = Normal();
    shortish.policy_file_sha256 = "abc";
    Check(!pail_deploy_guard::CanonicalizeSeal(shortish).ok,
      "a truncated digest must be refused");

    auto word = Normal();
    word.policy_file_sha256 = "unreadable";
    Check(!pail_deploy_guard::CanonicalizeSeal(word).ok,
      "a fourth spelling of \"unknown\" must be refused");
  }

  // 15. R-CS1 covers the new list too. C13 was not the only list field after v2,
  //     and a rule applied to one of two lists is a rule with a hole in it.
  {
    auto folded = Normal();
    folded.control_trust_anchors = {
      "00000000000000000000000000000000000000000000000000000000000000aa,"
      "00000000000000000000000000000000000000000000000000000000000000bb"};
    const auto r = pail_deploy_guard::CanonicalizeSeal(folded);
    Check(!r.ok, "a control anchor containing ',' must be refused (R-CS1)");
    Check(r.reject_reason == pail_deploy_guard::kRejectListSeparator,
      "the control anchor refusal must name R-CS1");
    Check(r.text.empty(), "a refused assembly must not hand back a canonical text");
  }

  // 16. Baseline L3. Whether the deployment has one trust root or three is not
  //     a value the seal has a key for — it is a relation between values. The
  //     anchor list is the only canon field that can carry it, because its
  //     sorted-and-de-duplicated form loses cardinality exactly when the roots
  //     merge into one file.
  {
    const std::string axis = pail_deploy_guard::kSealUnobservedAxis;
    const std::string grpc_ca =
      "0000000000000000000000000000000000000000000000000000000000000011";
    const std::string identity_ca =
      "0000000000000000000000000000000000000000000000000000000000000012";
    const std::string permissions_ca =
      "0000000000000000000000000000000000000000000000000000000000000013";

    auto separated = Normal();
    separated.control_trust_anchors = {grpc_ca, identity_ca, permissions_ca};
    separated.control_trust_roots_expected = 3;
    const std::string c_separated = Canon(separated, "separated-roots");
    Check(!HasAxis(separated, axis),
      "three distinct roots must not raise the observation axis");

    // The tree our own provisioning script produced until L3 was fixed: one
    // ca.cert.pem behind all three slots. Three reads, one digest.
    auto collapsed = Normal();
    collapsed.control_trust_anchors = {grpc_ca, grpc_ca, grpc_ca};
    collapsed.control_trust_roots_expected = 3;
    Check(HasAxis(collapsed, axis),
      "roots that collapse into one file must raise the observation axis");
    Check(Canon(collapsed, "collapsed-roots") != c_separated,
      "a collapsed trust tree must not seal like a separated one");

    // Partial collapse — identity and permissions share a CA while the control
    // plane keeps its own. Two of three is still fewer than three, and a rule
    // that only caught total collapse would call this deployment separated.
    auto partial = Normal();
    partial.control_trust_anchors = {grpc_ca, identity_ca, identity_ca};
    partial.control_trust_roots_expected = 3;
    Check(HasAxis(partial, axis), "two roots behind three slots must be visible");
    Check(Canon(partial, "partial-collapse") != c_separated,
      "a partly collapsed trust tree must not seal like a separated one");

    // "one was not read" lands in the same place as "two are one file" on
    // purpose: the seal knows the count is short, not which of the two it is,
    // and saying more than that would be a claim it cannot support (H-B2).
    auto unread = Normal();
    unread.control_trust_anchors = {};
    unread.control_trust_roots_expected = 3;
    Check(HasAxis(unread, axis), "roots that were never read must be visible as unread");

    // The count is not a canon key. F2 makes adding one a version bump and
    // A2-R4 closed the intake window, so it rides outside the sealed text and
    // must move nothing but the axis list.
    auto counted = Normal();
    counted.control_trust_roots_expected = 1;
    Check(Canon(counted, "counted") == c_normal,
      "the expected-root count must not appear in the canonical text");

    // Default 0 is deliberately silent. CS2-01, CS2-02a, CS2-04 and CS2-09 are
    // frozen mtls records whose anchor lists are shorter than the roots they
    // describe and carry no S21; an axis that fired on posture alone would
    // rewrite those bytes. The silence is closed by RED-E17 and DF-E27, which
    // measure that the gate sets the count — not by remembering to set it.
    auto unmeasured = collapsed;
    unmeasured.control_trust_roots_expected = 0;
    Check(!HasAxis(unmeasured, axis),
      "an unmeasured root count must not invent an observation");
  }

  if (g_bad) {
    std::printf("FAILURES: %d\n", g_bad);
    return 1;
  }
  std::printf("OK: config seal canonical form (v%d)\n", pail_deploy_guard::kConfigSealVersion);
  return 0;
}
