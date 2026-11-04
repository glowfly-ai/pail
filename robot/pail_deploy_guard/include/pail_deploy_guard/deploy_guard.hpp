// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#ifndef PAIL_DEPLOY_GUARD__DEPLOY_GUARD_HPP_
#define PAIL_DEPLOY_GUARD__DEPLOY_GUARD_HPP_

// SD3 (see spec/ARCHITECTURE.md): the BG deployment gate S0~S3, evaluated
// inside the node process instead of only in the entrypoint script.
//
// Header-only and rclcpp-free. EvaluateDeployGuard is pure: it takes resolved
// inputs and never touches the environment, the filesystem or the process.
// ResolveDeployGuard and EnforceDeployGuard are the impure wrappers.

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace pail_deploy_guard {

constexpr int kExitConfig = 78;  // sysexits.h EX_CONFIG

// ConfigRefused carries a configuration refusal raised while a ROS node is being
// constructed up to main(), which turns it into exit kExitConfig after
// rclcpp::shutdown(). std::exit() from inside a node constructor tears rclcpp down
// underneath live objects (segmentation fault observed on the TB3 rig, 2026-09-23).
struct ConfigRefused : std::runtime_error {
  using std::runtime_error::runtime_error;
};

// The greppable head of the `L10` line. Must stay byte-identical to Go's
// deploysec.IdentityPrefix: one deployment emits both, and an operator (or a
// log filter) that learns one head would silently miss the other half.
constexpr char kIdentityPrefix[] = "PAIL PREFLIGHT IDENTITY:";

// Writes the process credentials this component actually runs with (`L10`,
// implementation contract). Mirrors deploysec.EmitProcessIdentity exactly.
//
// It reports, it does not judge. uid=0 is not refused here: whether root is
// acceptable is a deployment decision and `U-E3` kept `L10` delegated. What was
// missing was not the isolation — the containers already run unprivileged —
// but any line saying so. Without it a unit shipped without `User=` looks
// exactly like one shipped with it.
//
// Real and effective ids are printed separately. Equal is the common case; when
// they differ the process was launched setuid, and folding the two into one
// field would make that indistinguishable from the ordinary case (`H-B2`).
inline void EmitProcessIdentity(const std::string & component)
{
  std::fprintf(stderr, "%s uid=%d euid=%d gid=%d egid=%d component=%s\n",
               kIdentityPrefix,
               static_cast<int>(::getuid()), static_cast<int>(::geteuid()),
               static_cast<int>(::getgid()), static_cast<int>(::getegid()),
               component.c_str());
  std::fflush(stderr);
}

struct GuardInput {
  std::string component;           // "pep_gate" | "motion_bridge" | "perception"
  std::string profile;             // raw PAIL_PROFILE ("" = production)
  std::string security_enable;     // raw ROS_SECURITY_ENABLE
  std::string security_strategy;   // raw ROS_SECURITY_STRATEGY
  std::string keystore;            // raw ROS_SECURITY_KEYSTORE
  bool enclave_provisioned = false;  // <keystore>/enclaves/<component> is a directory
  std::string effective_enclave;   // enclave this process will actually init with
};

struct GuardFinding {
  std::string id;
  std::string detail;
};

struct GuardResult {
  std::string profile;  // normalized: "production" | "dev" | raw (when S0 fails)
  std::vector<GuardFinding> fail;
};

inline std::string ExpectedEnclave(const std::string & component)
{
  return "/" + component;
}

inline GuardResult EvaluateDeployGuard(const GuardInput & in)
{
  GuardResult r;
  r.profile = in.profile.empty() ? "production" : in.profile;

  if (r.profile != "production" && r.profile != "dev") {
    // The profile decides how findings are enforced. If we cannot trust it,
    // reporting the rest would suggest a strictness we cannot deliver.
    r.fail.push_back({"S0", "PAIL_PROFILE=" + in.profile + " (want production|dev)"});
    return r;
  }

  if (in.security_enable != "true") {
    r.fail.push_back({"S1",
      "ROS_SECURITY_ENABLE=" + (in.security_enable.empty() ? "<unset>" : in.security_enable) +
      " (want true) — DDS participant auth and topic access control are OFF; "
      "any process on the domain can publish the drive topic"});
    return r;  // strategy and enclave are meaningless while security is off
  }

  if (in.security_strategy != "Enforce") {
    r.fail.push_back({"S2",
      "ROS_SECURITY_STRATEGY=" +
      (in.security_strategy.empty() ? "<unset>" : in.security_strategy) +
      " (want Enforce) — unsecured participants would be silently permitted"});
  }

  if (in.keystore.empty()) {
    r.fail.push_back({"S3", "ROS_SECURITY_KEYSTORE unset"});
  } else if (!in.enclave_provisioned) {
    r.fail.push_back({"S3",
      "enclave not provisioned: " + in.keystore + "/enclaves/" + in.component +
      " (run scripts/sros2_provision.sh)"});
  }

  const std::string want = ExpectedEnclave(in.component);
  if (in.effective_enclave != want) {
    r.fail.push_back({"S3",
      "effective enclave " +
      (in.effective_enclave.empty() ? "<unset>" : in.effective_enclave) +
      " != " + want + " — the process would load another component's credentials "
      "(check --enclave and ROS_SECURITY_ENCLAVE_OVERRIDE)"});
  }

  return r;
}

// Last --enclave on the command line, matching rcl's own last-wins parsing.
// "/" is rcl's default when the argument is absent.
inline std::string EffectiveEnclaveFromArgv(int argc, char const * const * argv)
{
  std::string enclave = "/";
  for (int i = 0; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == "--enclave") {
      enclave = argv[i + 1];
    }
  }
  return enclave;
}

// rcl_get_secure_root(): ROS_SECURITY_ENCLAVE_OVERRIDE, when set, replaces the
// enclave the process loads credentials from — the command line no longer
// decides. Checking argv alone would leave that path open.
inline std::string EffectiveEnclave(const std::string & override_env,
                                    int argc, char const * const * argv)
{
  return override_env.empty() ? EffectiveEnclaveFromArgv(argc, argv) : override_env;
}

inline GuardInput ResolveDeployGuard(const std::string & component,
                                     int argc, char const * const * argv)
{
  auto env = [](const char * k) -> std::string {
    const char * v = std::getenv(k);
    return v ? std::string(v) : std::string();
  };

  GuardInput in;
  in.component = component;
  in.profile = env("PAIL_PROFILE");
  in.security_enable = env("ROS_SECURITY_ENABLE");
  in.security_strategy = env("ROS_SECURITY_STRATEGY");
  in.keystore = env("ROS_SECURITY_KEYSTORE");
  in.effective_enclave =
    EffectiveEnclave(env("ROS_SECURITY_ENCLAVE_OVERRIDE"), argc, argv);

  if (!in.keystore.empty()) {
    struct stat st {};
    const std::string p = in.keystore + "/enclaves/" + component;
    in.enclave_provisioned = (::stat(p.c_str(), &st) == 0) && S_ISDIR(st.st_mode);
  }
  return in;
}

// Evaluates, reports on stderr, and exits 78 when the production profile has
// findings. Call before rclcpp::init so a refused process never joins the
// DDS domain.
inline void EnforceDeployGuard(const std::string & component,
                               int argc, char const * const * argv)
{
  // `L10` 관측점 (`U-E3`, implementation contract). Go 쪽 `deploysec.Preflight` 와 같은
  // 자리 · 같은 형식이다. 평가보다 앞에 서는 이유도 같다 — 아래 세 갈래가 전부
  // 일찍 빠져나가고 마지막이 `exit(78)` 이며, 그것이 정확히 잘못 올린 배치다.
  EmitProcessIdentity(component);
  const GuardInput in = ResolveDeployGuard(component, argc, argv);
  const GuardResult r = EvaluateDeployGuard(in);
  const std::string tail =
    " [profile=" + r.profile + " component=" + component +
    " enclave=" + in.effective_enclave + "]";

  if (r.fail.empty()) {
    std::fprintf(stderr, "PAIL PREFLIGHT: profile=%s OK (S0,S1,S2,S3) component=%s enclave=%s\n",
                 r.profile.c_str(), component.c_str(), in.effective_enclave.c_str());
    std::fflush(stderr);
    return;
  }

  if (r.profile == "dev") {
    std::string ids;
    for (const auto & f : r.fail) {
      if (!ids.empty()) { ids += ","; }
      ids += f.id;
    }
    std::fprintf(stderr, "PAIL PREFLIGHT: profile=dev INSECURE(%s) component=%s — NOT FOR PRODUCTION\n",
                 ids.c_str(), component.c_str());
    for (const auto & f : r.fail) {
      std::fprintf(stderr, "PAIL PREFLIGHT:   %s %s\n", f.id.c_str(), f.detail.c_str());
    }
    std::fflush(stderr);
    return;
  }

  for (const auto & f : r.fail) {
    std::fprintf(stderr, "PAIL PREFLIGHT FAIL: %s %s%s\n",
                 f.id.c_str(), f.detail.c_str(), tail.c_str());
  }
  std::fprintf(stderr,
               "PAIL PREFLIGHT FAIL: refusing to start. Set PAIL_PROFILE=dev to run "
               "without these protections (DEV ONLY).\n");
  std::fflush(stderr);
  std::exit(kExitConfig);
}

}  // namespace pail_deploy_guard

#endif  // PAIL_DEPLOY_GUARD__DEPLOY_GUARD_HPP_
