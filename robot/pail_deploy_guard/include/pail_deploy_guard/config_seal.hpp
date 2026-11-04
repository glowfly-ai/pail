// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#ifndef PAIL_DEPLOY_GUARD__CONFIG_SEAL_HPP_
#define PAIL_DEPLOY_GUARD__CONFIG_SEAL_HPP_

// SD4 (see spec/ARCHITECTURE.md): the effective security configuration,
// normalized into one deterministic text so it can be hashed and journalled.
//
// Why this exists. SD1~SD3 refuse a bad configuration at startup, but only in
// the production profile — anyone who can set PAIL_PROFILE=dev still starts a
// gate that verifies nothing. SD4 does not close that door (the operator is
// allowed to run a dev rig); it makes the door leave a mark. The measured
// defect (integration/sd4/EVIDENCE_RUN_SD4_0.txt): three gates permitted ~72
// frames of motion each — normal, thresholds-disabled, and static — and the
// journal could not tell the first two apart and did not record that the third
// existed at all.
//
// This is P0's snapshot-hash principle (도면부호 215) on the configuration
// plane: the decision is bound to a hash of the state it was decided under.
//
// Scope, honestly. This is a declaration by the gate about itself, so a gate
// that is lying or simply silent is not caught here — exactly like AS-2
// attestation. What it buys is that an honest deployment leaves a positive,
// hash-chained record, so "no seal" and "degraded seal" become visible facts
// after the event instead of unanswerable questions.
//
// Header-only, rclcpp-free and libsodium-free by design (SD3): the caller,
// which already links sodium, hashes the canonical text. The judgement stays
// here next to the other deployment rules and stays testable without crypto.

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <string>
#include <vector>

#include "pail_deploy_guard/deploy_guard.hpp"
#include "pail_deploy_guard/key_fingerprint.hpp"
#include "pail_deploy_guard/thresholds.hpp"

namespace pail_deploy_guard
{

// Bumped whenever the canonical form changes. Two gates on different versions
// produce different digests for the same configuration, which is correct: the
// digest is only comparable within a version, and the version is in the text.
constexpr int kConfigSealVersion = 3;

// v2 stays here as a frozen edition (OB1-FREEZE-2026-08-17), for the same two
// reasons v1 does below: config_seal_v2.vec links CanonicalizeSealV2, and a
// v2 record may need re-deriving. SK-4  added one key to v3.
constexpr int kConfigSealVersionV2 = 2;

// v1 stays here as a frozen edition, not as history. F8 keeps old editions
// parseable forever; the generating side needs the same guarantee for a
// different reason — config_seal_v1.vec is a PROC vector whose preservation
// procedure links this header directly (MKVEC-CANON.md, F7). If bumping the
// version above silently re-pointed that procedure at v2, the frozen vector
// would still be on disk while the thing that reproduces it no longer exists,
// and 검사 4 asks whether the procedure still runs — not whether it once did.
constexpr int kConfigSealVersionV1 = 1;

struct SealInput
{
  std::string component;   // "pep_gate"
  std::string robot_id;

  // v2 key 4 — rclcpp declares use_sim_time implicitly, so it appears nowhere in
  // pail_ws/src and neither the preflight nor the seal used to see it. One
  // parameter turns the clock defence off; the default says nobody looked.
  std::string use_sim_time = "unknown";  // "1" | "0" | "unknown"

  // S0~S3 — the same inputs deploy_guard.hpp judges.
  std::string profile;             // raw PAIL_PROFILE ("" = production)
  std::string security_enable;     // raw ROS_SECURITY_ENABLE
  std::string security_strategy;   // raw ROS_SECURITY_STRATEGY
  std::string keystore;            // raw ROS_SECURITY_KEYSTORE
  bool enclave_provisioned = false;
  std::string effective_enclave;

  // S7 — does this process verify authorization at all.
  std::string token_provider_mode;  // "grpc" | "static" | "notoken"
  bool use_token_service = false;
  bool grpc_built = false;
  std::string token_service_addr;

  // v2 keys 16~17 — the control plane's posture. Three postures exist
  // (grpc_channel.cpp:33-54) and none of them reached the seal, so a plaintext
  // gate and an mTLS gate hashed to the same digest. Anchors are the sha256 of
  // the bytes actually read, never the path they came from: two deployments can
  // share a path and not a file. A file that could not be read is simply absent
  // from the list — an empty list means no trust material was loaded at all.
  std::string control_transport;                       // "uds" | "mtls" | "plaintext"
  std::vector<std::string> control_trust_anchors;      // lowercase sha256 hex

  // Baseline L3. The deployment has three trust roots — DDS identity, DDS
  // permissions, and the control plane's CA — and what matters is not any one
  // of their values but whether the three are distinct. `ros2 security
  // create_keystore` makes identity_ca and permissions_ca symlinks to one file
  // (one inode, three names), so the collapse is our tooling's default rather
  // than an integrator's choice.
  //
  // This count is NOT a canon key. The seal's key set is frozen (implementation contract
  // §3.1, 31 keys) and `F2` makes adding one a version bump, which `A2-R4`
  // forbids after the 2026-08-08 intake deadline. So the relation rides in a
  // key that already exists: all three fingerprints go into
  // control_trust_anchors, which canonicalizes sorted-and-deduplicated — two
  // roots that are one file collapse to one entry and the digest moves. The
  // count is what turns that shorter list from a number into a claim; without
  // it a reader cannot tell "two roots, both read" from "three roots, one
  // unreadable".
  //
  // Default 0 means nobody measured, and it is deliberately silent: the frozen
  // v2 vectors carry mtls records with a single anchor and no S21 (CS2-01,
  // CS2-02a, CS2-04, CS2-09), so an axis that fired on an unmeasured count
  // would rewrite bytes a freeze exists to hold still. Silence-by-default is
  // safe here only because the gate is the sole producer and always sets it —
  // and that "always" is not left to discipline: RED-E17 reads the assignment
  // out of pep_gate_node.cpp and DF-E27 deletes it to prove the case can see.
  int control_trust_roots_expected = 0;

  // S8 — the trust anchors actually loaded, not the path they came from.
  std::string keyring_mode;                           // "bundle" | "unsigned-dev" | "none"
  std::vector<std::string> trusted_key_fingerprints;  // lowercase sha256 hex

  // S10 — the numbers that decide whether a check is still a check.
  ThresholdInput thresholds;
  int permit_rate_hz = 20;
  int permit_deadline_ms = 100;

  // v2 key 27 — the motion bridge declares its own permit_deadline_ms and holds
  // motion for twice it (motion_bridge_node.cpp:27,100). The gate's parameter,
  // which key 26 carries, is a different number with the same name. Carrying it
  // as text rather than an int is what makes "unknown" expressible: an int
  // would have to invent a sentinel, and 100 would read as a measurement.
  std::string motion_deadman_ms = "unknown";  // decimal integer | "unknown"

  // Policy plane. The path answers "which file", the digest answers "which
  // contents" — dropping either loses an answer nobody else gives.
  std::string policy_file;
  std::string policy_file_sha256 = "unknown";  // 64 hex | "unknown" | "" (no path)
  bool human_safety_enabled = false;

  // v3 key 30 (SK-4, implementation contract): the skill registry this gate read
  // (config/skills.<robot_class>.yaml), by content. Same vocabulary as the
  // policy digest: 64 hex = read and hashed, "unknown" = a registry was named
  // (robot_class set) but could not be read or hashed, "" = no registry
  // configured (no robot_class). The issuer compares it with its own copy —
  // two registries that differ are two authorities, and the journal must show
  // which bytes each side judged by (S38).
  std::string skills_file_sha256;

  // SK-5 (implementation contract, S36): the vendor safety controller this gate runs beside
  // (`<vendor>:<product>:<version>:<cfg_sha256>`), declared by the operator.
  // NOT a canon key (the v3 table is frozen); it reaches the seal only as the
  // S36 axis when measured and empty under production. `measured` defaults to
  // false and is silent, like control_trust_roots_expected — the frozen v3
  // vectors carry no S36, and the gate always sets it (a deform proves that).
  std::string safety_controller;
  bool safety_controller_measured = false;
};

// The one derived fact the whole seal turns on. SD1's policy (which decides
// refuse-vs-warn) reads the same two values; this is that predicate, not a
// second copy of that policy — there is no verdict here to drift from.
inline bool SealVerifiesAuthorization(const SealInput & in)
{
  const bool grpc_mode = (in.token_provider_mode == "grpc" || in.use_token_service);
  return grpc_mode && in.grpc_built;
}

// EvaluateSealV1 is pure: every way this configuration is weaker than a hardened
// one, in the vocabulary the operator already reads in the preflight output.
// Frozen with the v1 canon — the axes it can produce are the axes a v1 record
// could ever carry, and a v1 record must not gain axes retroactively.
inline std::vector<GuardFinding> EvaluateSealV1(const SealInput & in)
{
  std::vector<GuardFinding> out;

  GuardInput g;
  g.component = in.component;
  g.profile = in.profile;
  g.security_enable = in.security_enable;
  g.security_strategy = in.security_strategy;
  g.keystore = in.keystore;
  g.enclave_provisioned = in.enclave_provisioned;
  g.effective_enclave = in.effective_enclave;
  const GuardResult gr = EvaluateDeployGuard(g);
  out.insert(out.end(), gr.fail.begin(), gr.fail.end());

  if (!SealVerifiesAuthorization(in)) {
    const bool grpc_mode = (in.token_provider_mode == "grpc" || in.use_token_service);
    out.push_back({"S7",
      grpc_mode
        ? "token_provider_mode=grpc on a PAIL_ENABLE_GRPC=0 build — no token "
          "verification code is linked"
        : "token_provider_mode=" + in.token_provider_mode +
          " — no issued token is verified for this motion"});
  }

  std::vector<KeyMaterialItem> items;
  for (const auto & f : in.trusted_key_fingerprints) {
    items.push_back({"keyring entry", f});
  }
  const auto km = EvaluateKeyMaterial(items);
  out.insert(out.end(), km.begin(), km.end());

  if (in.keyring_mode == "unsigned-dev") {
    out.push_back({"S8", "keyring_mode=unsigned-dev — the trust anchors came from an "
                         "unsigned keyring.json"});
  }

  const auto th = EvaluateThresholds(in.thresholds);
  out.insert(out.end(), th.begin(), th.end());

  return out;
}

// Value vocabularies for the v2 keys. Written as predicates rather than as an
// enum because the canon carries text and the seal must be able to write down a
// value it does not recognize — refusing to record it would turn a measurement
// problem into a missing record.
inline bool IsSealInteger(const std::string & v)
{
  std::size_t i = (!v.empty() && v[0] == '-') ? 1 : 0;
  if (i >= v.size()) {
    return false;
  }
  for (; i < v.size(); ++i) {
    if (v[i] < '0' || v[i] > '9') {
      return false;
    }
  }
  return true;
}

inline bool IsLowerHex64(const std::string & v)
{
  if (v.size() != 64) {
    return false;
  }
  for (char c : v) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      return false;
    }
  }
  return true;
}

inline bool IsSealTransport(const std::string & v)
{
  return v == "uds" || v == "mtls" || v == "plaintext";
}

inline bool IsSealPolicySha(const std::string & v)
{
  return v.empty() || v == "unknown" || IsLowerHex64(v);
}

// Sorted, de-duplicated: the same trust set read back in another order is the
// same trust set, so ordering must not reach the digest. It sits above the
// observation rules because one of them counts what survives this — sharing the
// function is the point, since a second copy would let the count and the canon
// disagree about what "distinct" means.
inline std::vector<std::string> NormalizeList(const std::vector<std::string> & v)
{
  std::vector<std::string> out = v;
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

// The axis for "the seal could not measure this". S0~S20 are taken by the
// existing check vocabulary (S0~S10 here and in deploysec, S11~S20 in the OSS
// and OSSB designs), so this is the next free number. §3.1.3 requires an axis
// for an unobserved motion_deadman_ms and does not name one (→ U-D3).
//
// One axis for four keys, deliberately. `degraded` is a list of axes, not of
// findings — S10 already stands for six different threshold defects — and the
// per-key sentence stays in the findings the gate logs. What must not happen is
// silence, and one axis is enough to break silence.
constexpr const char * kSealUnobservedAxis = "S21";

// EvaluateSealObservation is the v2 addition: the seal declaring what it failed
// to look at. A value the gate never read must not canonicalize like a value it
// read and found benign (H-B2) — so "unknown" is carried in the value AND the
// fact of not knowing is carried as an axis, because a reader diffing two seals
// reads the axis list first.
inline std::vector<GuardFinding> EvaluateSealObservation(const SealInput & in)
{
  std::vector<GuardFinding> out;

  if (in.use_sim_time != "1" && in.use_sim_time != "0") {
    out.push_back({kSealUnobservedAxis,
      "use_sim_time=" + in.use_sim_time +
      " — the parameter that decides whether this gate's clock is the wall "
      "clock was not read, so token freshness is unproven"});
  }

  if (!IsSealTransport(in.control_transport)) {
    out.push_back({kSealUnobservedAxis,
      "control_transport=" +
      (in.control_transport.empty() ? std::string("<unset>") : in.control_transport) +
      " — the seal cannot say whether the control channel was authenticated"});
  }

  if (!IsSealInteger(in.motion_deadman_ms)) {
    out.push_back({kSealUnobservedAxis,
      "motion_deadman_ms=" + in.motion_deadman_ms +
      " — the bridge's deadman window was not observed; permit_deadline_ms is "
      "this gate's own parameter and is a different number"});
  }

  if (in.policy_file_sha256 == "unknown") {
    out.push_back({kSealUnobservedAxis,
      "policy_file_sha256=unknown — the seal names a policy path whose contents "
      "it could not read"});
  }

  // Baseline L3. Collapse is not a property of any one root, so no single value
  // can carry it: the seal must say how many distinct roots survived against how
  // many the deployment has. One condition covers both ways the answer can be
  // wrong, because to a reader they are the same sentence — the seal cannot say
  // the roots are distinct. Two roots that are one symlinked file dedup to one
  // entry; a root the gate could not read never enters the list at all.
  //
  // The count going unset is its own silence, and it is not made loud here: the
  // frozen v2 vectors would move (see the field's comment). What keeps that
  // silence from being a hole is that the gate always sets it, measured by
  // RED-E17 rather than asserted.
  if (in.control_trust_roots_expected > 0) {
    const auto distinct = NormalizeList(in.control_trust_anchors).size();
    if (distinct < static_cast<std::size_t>(in.control_trust_roots_expected)) {
      out.push_back({kSealUnobservedAxis,
        "control_trust_anchors carries " + std::to_string(distinct) +
        " distinct roots where the deployment has " +
        std::to_string(in.control_trust_roots_expected) +
        " — either two roots are one file or one was not read, and the seal "
        "cannot tell you which"});
    }
  }

  return out;
}

// EvaluateSealV2 is the v2 verdict: the v1 axes plus the observation axis.
// Frozen with the v2 canon — v3 adds its own observation below rather than
// widening this one, so a v2 record cannot gain an axis retroactively.
inline std::vector<GuardFinding> EvaluateSealV2(const SealInput & in)
{
  std::vector<GuardFinding> out = EvaluateSealV1(in);
  const auto obs = EvaluateSealObservation(in);
  out.insert(out.end(), obs.begin(), obs.end());
  return out;
}

// v3 observation (SK-4): a registry that was named but not read is the same
// silence policy_file_sha256=unknown breaks — the value says "unknown" and the
// axis says nobody looked.
// SK-5 (implementation contract, S36): production with no declared vendor safety controller.
// PAIL never replaces the safety function (ISO 13482/10218 stay with the
// vendor); a gate that cannot name the one it runs beside is degraded, not
// refused — first edition WARN + axis, so the record shows it.
constexpr const char * kSafetyControllerAxis = "S36";

inline std::vector<GuardFinding> EvaluateSealObservationV3(const SealInput & in)
{
  std::vector<GuardFinding> out;
  if (in.skills_file_sha256 == "unknown") {
    out.push_back({kSealUnobservedAxis,
      "skills_file_sha256=unknown — the seal names a skill registry whose contents "
      "it could not read or hash"});
  }
  const bool production = in.profile.empty() || in.profile == "production";
  if (in.safety_controller_measured && production && in.safety_controller.empty()) {
    out.push_back({kSafetyControllerAxis,
      "safety_controller is empty under production — the vendor safety function "
      "this gate runs beside is undeclared (implementation contract, S36)"});
  }
  return out;
}

// EvaluateSeal is the current (v3) verdict: v2 plus the registry observation.
inline std::vector<GuardFinding> EvaluateSeal(const SealInput & in)
{
  std::vector<GuardFinding> out = EvaluateSealV2(in);
  const auto obs = EvaluateSealObservationV3(in);
  out.insert(out.end(), obs.begin(), obs.end());
  return out;
}

// The distinct check ids, sorted — the short form that goes into the record and
// onto the wire. The details stay in the gate's own log; what an auditor needs
// months later is which axes were weakened, and that must be diffable.
inline std::vector<std::string> DegradedAxes(const std::vector<GuardFinding> & findings)
{
  std::vector<std::string> ids;
  for (const auto & f : findings) {
    if (std::find(ids.begin(), ids.end(), f.id) == ids.end()) {
      ids.push_back(f.id);
    }
  }
  std::sort(ids.begin(), ids.end());
  return ids;
}

inline std::string JoinAxes(const std::vector<std::string> & v)
{
  std::string s;
  for (const auto & e : v) {
    if (!s.empty()) {
      s += ",";
    }
    s += e;
  }
  return s;
}

// Rule R-CS1 (implementation contract ④; inherited by the OB1 window, implementation contract).
// A list field is joined with ',' and the elements are not escaped, so an
// element carrying ',' folds two different inputs onto one line: {"aa","bb"} and
// {"aa,bb"} canonicalize to the same bytes and therefore to the same digest.
// That is R-A's collision on the list plane, and like R-A the defense belongs at
// the assembly point — a check at the network boundary protects only the paths
// that happen to run through it.
//
// The reason for rejecting rather than escaping: R-C (escaping) is an exception
// granted to this canon for line integrity only. Extending it to the element
// separator would give one canon two escaping layers whose interaction nobody
// has frozen.
constexpr const char * kRejectListSeparator =
  "list element contains the separator ',' (R-A analogue for C13)";

// Rule R-A applied to policy_file_sha256 . The three words
// are three different facts — measured, unreadable, no path configured — and a
// fourth spelling would be a fact this canon has not defined. Refusing is the
// same judgement as R-A on identifiers: a value outside the vocabulary has no
// canonical form, so it does not get one.
constexpr const char * kRejectPolicyShaVocabulary =
  "policy_file_sha256 outside its vocabulary (64 lowercase hex | \"unknown\" | empty)";

// v3: the same rule for the registry digest — three facts, no fourth spelling.
constexpr const char * kRejectSkillsShaVocabulary =
  "skills_file_sha256 outside its vocabulary (64 lowercase hex | \"unknown\" | empty)";

inline bool ListHasSeparator(const std::vector<std::string> & v)
{
  for (const auto & e : v) {
    if (e.find(',') != std::string::npos) {
      return true;
    }
  }
  return false;
}

// The result of assembly. Rejection is a value, not an exception nor an empty
// string: an empty canon and a refused canon must not share bytes (H-B2).
struct SealCanon
{
  bool ok = false;
  std::string text;           // meaningful only when ok
  std::string reject_reason;  // meaningful only when !ok
};

namespace detail
{

// The canonical text is line-oriented, so a value carrying a newline could
// forge a line. Escaping is what keeps two different configurations from
// canonicalizing to the same string.
inline std::string Esc(const std::string & v)
{
  std::string o;
  o.reserve(v.size());
  for (char c : v) {
    if (c == '\\') { o += "\\\\"; } else if (c == '\n') { o += "\\n"; } else if (c == '\r') {
      o += "\\r";
    } else { o += c; }
  }
  return o;
}

inline void Line(std::string & s, const std::string & k, const std::string & v)
{
  s += k;
  s += "=";
  s += Esc(v);
  s += "\n";
}

inline void Line(std::string & s, const std::string & k, int v)
{
  Line(s, k, std::to_string(v));
}

inline void Line(std::string & s, const std::string & k, bool v)
{
  Line(s, k, std::string(v ? "1" : "0"));
}

}  // namespace detail

// CanonicalizeSealV1 is the frozen v1 assembler (OR1-FREEZE-2026-08-06). It is
// no longer what the gate emits — CanonicalizeSeal below is — and it is kept for
// two things that would otherwise silently break: the preservation procedure
// behind config_seal_v1.vec, and any future need to re-derive a v1 record.
//
// It writes its own 26 lines rather than sharing a helper with v2. Sharing is
// what a freeze cannot survive: the next key added to the shared writer would
// walk into v1 without anyone editing v1.
inline SealCanon CanonicalizeSealV1(const SealInput & in)
{
  if (ListHasSeparator(in.trusted_key_fingerprints)) {
    return SealCanon{false, std::string(), kRejectListSeparator};
  }

  const auto axes = DegradedAxes(EvaluateSealV1(in));
  if (ListHasSeparator(axes)) {
    return SealCanon{false, std::string(), kRejectListSeparator};
  }

  const auto fprs = NormalizeList(in.trusted_key_fingerprints);

  std::string s = "pail-config-seal:v" + std::to_string(kConfigSealVersionV1) + "\n";
  detail::Line(s, "component", in.component);
  detail::Line(s, "robot_id", in.robot_id);
  detail::Line(s, "profile", in.profile.empty() ? std::string("production") : in.profile);
  detail::Line(s, "ros_security_enable", in.security_enable);
  detail::Line(s, "ros_security_strategy", in.security_strategy);
  detail::Line(s, "ros_security_keystore", in.keystore);
  detail::Line(s, "enclave_provisioned", in.enclave_provisioned);
  detail::Line(s, "effective_enclave", in.effective_enclave);
  detail::Line(s, "token_provider_mode", in.token_provider_mode);
  detail::Line(s, "use_token_service", in.use_token_service);
  detail::Line(s, "grpc_built", in.grpc_built);
  detail::Line(s, "verifies_authorization", SealVerifiesAuthorization(in));
  detail::Line(s, "token_service_addr", in.token_service_addr);
  detail::Line(s, "keyring_mode", in.keyring_mode);
  detail::Line(s, "trusted_key_fingerprints", JoinAxes(fprs));
  detail::Line(s, "evidence_conf_threshold_x1e6",
    static_cast<int>(std::llround(in.thresholds.evidence_conf_threshold * 1000000.0)));
  detail::Line(s, "evidence_window_ms", in.thresholds.evidence_window_ms);
  detail::Line(s, "safety_stale_ms", in.thresholds.safety_stale_ms);
  detail::Line(s, "clock_skew_ms", in.thresholds.clock_skew_ms);
  detail::Line(s, "permit_grace_n", in.thresholds.permit_grace_n);
  detail::Line(s, "permit_recheck_ms", in.thresholds.permit_recheck_ms);
  detail::Line(s, "permit_rate_hz", in.permit_rate_hz);
  detail::Line(s, "permit_deadline_ms", in.permit_deadline_ms);
  detail::Line(s, "policy_file", in.policy_file);
  detail::Line(s, "human_safety_enabled", in.human_safety_enabled);
  detail::Line(s, "degraded", JoinAxes(axes));
  return SealCanon{true, s, std::string()};
}

// CanonicalizeSealV2 is the frozen v2 assembler (OB1-FREEZE-2026-08-17). Kept
// whole, like V1 above: config_seal_v2.vec links it, and sharing a writer with
// v3 would let the next key walk into v2 unedited.
//
// CanonicalizeSealV2 is pure and deterministic: same input, same bytes, on any
// host and under any locale. The double is carried as a scaled integer for that
// reason — "%f" formatting follows the process locale, and a decimal comma
// would silently change the digest of an identical configuration.
//
// v2 : 31 keys. The five new ones are inserted at their
// logical positions rather than appended. Appending buys a smaller diff once;
// a table that has lost its logical order costs forever.
inline SealCanon CanonicalizeSealV2(const SealInput & in)
{
  // R-CS1 is checked before anything is assembled: a rejected input has no
  // canonical form, so producing one and then discarding it would leave a
  // window in which the folded bytes exist.
  if (ListHasSeparator(in.trusted_key_fingerprints) ||
    ListHasSeparator(in.control_trust_anchors))
  {
    return SealCanon{false, std::string(), kRejectListSeparator};
  }

  if (!IsSealPolicySha(in.policy_file_sha256)) {
    return SealCanon{false, std::string(), kRejectPolicyShaVocabulary};
  }

  const auto findings = EvaluateSealV2(in);
  const auto axes = DegradedAxes(findings);
  if (ListHasSeparator(axes)) {
    return SealCanon{false, std::string(), kRejectListSeparator};
  }

  const auto fprs = NormalizeList(in.trusted_key_fingerprints);
  const auto anchors = NormalizeList(in.control_trust_anchors);

  std::string s = "pail-config-seal:v" + std::to_string(kConfigSealVersionV2) + "\n";
  detail::Line(s, "component", in.component);
  detail::Line(s, "robot_id", in.robot_id);
  detail::Line(s, "profile", in.profile.empty() ? std::string("production") : in.profile);
  detail::Line(s, "use_sim_time", in.use_sim_time);
  detail::Line(s, "ros_security_enable", in.security_enable);
  detail::Line(s, "ros_security_strategy", in.security_strategy);
  detail::Line(s, "ros_security_keystore", in.keystore);
  detail::Line(s, "enclave_provisioned", in.enclave_provisioned);
  detail::Line(s, "effective_enclave", in.effective_enclave);
  detail::Line(s, "token_provider_mode", in.token_provider_mode);
  detail::Line(s, "use_token_service", in.use_token_service);
  detail::Line(s, "grpc_built", in.grpc_built);
  detail::Line(s, "verifies_authorization", SealVerifiesAuthorization(in));
  detail::Line(s, "token_service_addr", in.token_service_addr);
  detail::Line(s, "keyring_mode", in.keyring_mode);
  detail::Line(s, "control_transport", in.control_transport);
  detail::Line(s, "control_trust_anchors", JoinAxes(anchors));
  detail::Line(s, "trusted_key_fingerprints", JoinAxes(fprs));
  detail::Line(s, "evidence_conf_threshold_x1e6",
    static_cast<int>(std::llround(in.thresholds.evidence_conf_threshold * 1000000.0)));
  detail::Line(s, "evidence_window_ms", in.thresholds.evidence_window_ms);
  detail::Line(s, "safety_stale_ms", in.thresholds.safety_stale_ms);
  detail::Line(s, "clock_skew_ms", in.thresholds.clock_skew_ms);
  detail::Line(s, "permit_grace_n", in.thresholds.permit_grace_n);
  detail::Line(s, "permit_recheck_ms", in.thresholds.permit_recheck_ms);
  detail::Line(s, "permit_rate_hz", in.permit_rate_hz);
  detail::Line(s, "permit_deadline_ms", in.permit_deadline_ms);
  detail::Line(s, "motion_deadman_ms", in.motion_deadman_ms);
  detail::Line(s, "policy_file", in.policy_file);
  detail::Line(s, "policy_file_sha256", in.policy_file_sha256);
  detail::Line(s, "human_safety_enabled", in.human_safety_enabled);
  detail::Line(s, "degraded", JoinAxes(axes));
  return SealCanon{true, s, std::string()};
}


// CanonicalizeSeal (v3, SK-4 implementation contract): v2 plus `skills_file_sha256` after
// `policy_file_sha256` — 32 keys. Inserted at its logical position (next to the
// other content digest), not appended.
//
// CanonicalizeSeal is pure and deterministic: same input, same bytes, on any
// host and under any locale. The double is carried as a scaled integer for that
// reason — "%f" formatting follows the process locale, and a decimal comma
// would silently change the digest of an identical configuration.
//
// v2 : 31 keys. The five new ones are inserted at their
// logical positions rather than appended. Appending buys a smaller diff once;
// a table that has lost its logical order costs forever.
inline SealCanon CanonicalizeSeal(const SealInput & in)
{
  // R-CS1 is checked before anything is assembled: a rejected input has no
  // canonical form, so producing one and then discarding it would leave a
  // window in which the folded bytes exist.
  if (ListHasSeparator(in.trusted_key_fingerprints) ||
    ListHasSeparator(in.control_trust_anchors))
  {
    return SealCanon{false, std::string(), kRejectListSeparator};
  }

  if (!IsSealPolicySha(in.policy_file_sha256)) {
    return SealCanon{false, std::string(), kRejectPolicyShaVocabulary};
  }
  if (!IsSealPolicySha(in.skills_file_sha256)) {
    return SealCanon{false, std::string(), kRejectSkillsShaVocabulary};
  }

  const auto findings = EvaluateSeal(in);
  const auto axes = DegradedAxes(findings);
  if (ListHasSeparator(axes)) {
    return SealCanon{false, std::string(), kRejectListSeparator};
  }

  const auto fprs = NormalizeList(in.trusted_key_fingerprints);
  const auto anchors = NormalizeList(in.control_trust_anchors);

  std::string s = "pail-config-seal:v" + std::to_string(kConfigSealVersion) + "\n";
  detail::Line(s, "component", in.component);
  detail::Line(s, "robot_id", in.robot_id);
  detail::Line(s, "profile", in.profile.empty() ? std::string("production") : in.profile);
  detail::Line(s, "use_sim_time", in.use_sim_time);
  detail::Line(s, "ros_security_enable", in.security_enable);
  detail::Line(s, "ros_security_strategy", in.security_strategy);
  detail::Line(s, "ros_security_keystore", in.keystore);
  detail::Line(s, "enclave_provisioned", in.enclave_provisioned);
  detail::Line(s, "effective_enclave", in.effective_enclave);
  detail::Line(s, "token_provider_mode", in.token_provider_mode);
  detail::Line(s, "use_token_service", in.use_token_service);
  detail::Line(s, "grpc_built", in.grpc_built);
  detail::Line(s, "verifies_authorization", SealVerifiesAuthorization(in));
  detail::Line(s, "token_service_addr", in.token_service_addr);
  detail::Line(s, "keyring_mode", in.keyring_mode);
  detail::Line(s, "control_transport", in.control_transport);
  detail::Line(s, "control_trust_anchors", JoinAxes(anchors));
  detail::Line(s, "trusted_key_fingerprints", JoinAxes(fprs));
  detail::Line(s, "evidence_conf_threshold_x1e6",
    static_cast<int>(std::llround(in.thresholds.evidence_conf_threshold * 1000000.0)));
  detail::Line(s, "evidence_window_ms", in.thresholds.evidence_window_ms);
  detail::Line(s, "safety_stale_ms", in.thresholds.safety_stale_ms);
  detail::Line(s, "clock_skew_ms", in.thresholds.clock_skew_ms);
  detail::Line(s, "permit_grace_n", in.thresholds.permit_grace_n);
  detail::Line(s, "permit_recheck_ms", in.thresholds.permit_recheck_ms);
  detail::Line(s, "permit_rate_hz", in.permit_rate_hz);
  detail::Line(s, "permit_deadline_ms", in.permit_deadline_ms);
  detail::Line(s, "motion_deadman_ms", in.motion_deadman_ms);
  detail::Line(s, "policy_file", in.policy_file);
  detail::Line(s, "policy_file_sha256", in.policy_file_sha256);
  detail::Line(s, "skills_file_sha256", in.skills_file_sha256);
  detail::Line(s, "human_safety_enabled", in.human_safety_enabled);
  detail::Line(s, "degraded", JoinAxes(axes));
  return SealCanon{true, s, std::string()};
}

}  // namespace pail_deploy_guard

#endif  // PAIL_DEPLOY_GUARD__CONFIG_SEAL_HPP_
