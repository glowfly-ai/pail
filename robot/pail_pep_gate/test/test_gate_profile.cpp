// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// TB-7  + TB-11 잔여 (§6.4, 미결 4): node-wiring battery —
// config digest exposure (G-DEP-04) + seal-in-every-provider-mode (G-DEP-05).
// Plain executable, no gtest : returns 0 only if every row matches.
//
// Tier honesty: same reasoning as test_gate_evidence.cpp — observing what the
// node PUBLISHES requires rclcpp + a subscription, so this is L3.
//
// What the battery proves: the digest stamped into every GateState is
// sha256(CanonicalizeSeal(...)) over the configuration this process actually
// resolved — recomputed here INDEPENDENTLY from known parameter values, not
// read back from the node. A gate that stamps a stale, empty or fabricated
// digest fails the equality row.

#define PAIL_PEP_GATE_UNDER_TEST 1
#include "../src/pep_gate_node.cpp"

#include "tb7_policy_fixture.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <thread>
#include <vector>

namespace {

int g_failures = 0;

#define ROW(case_name, cond, detail)                                        \
  do {                                                                      \
    if (cond) {                                                             \
      std::printf("PASS: %s — %s\n", case_name, detail);                    \
    } else {                                                                \
      std::printf("FAIL: %s — %s\n", case_name, detail);                    \
      ++g_failures;                                                         \
    }                                                                       \
  } while (0)

template <typename Pred>
bool spin_until(rclcpp::executors::SingleThreadedExecutor &ex, int timeout_ms, Pred pred) {
  const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < until) {
    ex.spin_some();
    if (pred()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return pred();
}

std::string hex_sha256(const std::string &data) {
  unsigned char out[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(out, reinterpret_cast<const unsigned char *>(data.data()), data.size());
  static const char *kHex = "0123456789abcdef";
  std::string s;
  s.reserve(sizeof(out) * 2);
  for (unsigned char b : out) {
    s.push_back(kHex[b >> 4]);
    s.push_back(kHex[b & 0x0f]);
  }
  return s;
}

// The seal this rig is EXPECTED to resolve, mirrored from first principles:
// every value below is either a parameter this test passes explicitly or a
// declared default read from the product source — none is read back from the
// running node. g_deploy_input stays default-empty because the product main()
// (which resolves S0~S3) is compiled out under PAIL_PEP_GATE_UNDER_TEST.
pail_deploy_guard::SealInput expected_seal() {
  pail_deploy_guard::SealInput in;
  in.component = "pep_gate";
  in.robot_id = "tb7-profile-robot";
  // DC-11 / SD5: the node now reads the implicitly-declared use_sim_time and
  // seals it. This rig runs real time, so the resolved value is "0" — the
  // pre-DC-11 seal carried "unknown" here, and this mirror changing is the
  // digest-moves-with-the-value fact C3-C4 wants.
  in.use_sim_time = "0";
  // profile/security_*/keystore/enclave: GuardInput defaults (empty/false).
  in.token_provider_mode = "notoken";
  in.use_token_service = false;
#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
  in.grpc_built = true;  // this battery only exists in the grpc-ON flavor
  // DD-4: the seal carries the transport the channel factory actually chose.
  // main() declared plaintext(acked) above; no CA, so no trust anchors.
  in.control_transport = "plaintext";
#endif
  in.token_service_addr = "127.0.0.1:50051";
  in.keyring_mode = "none";  // notoken path never loads a keyring
  in.thresholds.evidence_conf_threshold = 0.90;
  in.thresholds.evidence_window_ms = 2000;
  in.thresholds.safety_stale_ms = 1000;
  in.thresholds.clock_skew_ms = 500;
  in.thresholds.permit_grace_n = 3;
  in.thresholds.permit_recheck_ms = 100;
  in.permit_rate_hz = 20;
  in.permit_deadline_ms = 100;
  in.policy_file = kTb7PolicyFixture;
  // RQ-7 (DD-4): the seal knows the policy's CONTENT, not just its path. The
  // digest is pinned in the fixture header rather than recomputed with the
  // node's own hasher — a mirror that shares the producer is green even when
  // both are wrong. (The "unknown" branch this line used to exercise is no
  // longer reachable from a wiring battery: D-L2 refuses to start with no
  // policy at all. config_seal.hpp's "unknown" vocabulary survives for the
  // unreadable-but-present case.)
  in.policy_file_sha256 = kTb7PolicyFixtureSha256;
  // SK-5 (S36): the node always measures the safety_controller parameter; the rig
  // leaves it empty, so the mirror measures an empty declaration too.
  in.safety_controller_measured = true;
  in.safety_controller = "";
  in.human_safety_enabled = true;  // the fixture writes human_safety.enabled: true
  return in;
}

// The mirror's canonical text. R-CS1 made assembly fallible; a refusal here
// would mean the mirror itself is malformed, and hashing an empty string would
// silently turn that into a digest that merely fails to match.
std::string expected_seal_canonical() {
  const auto r = pail_deploy_guard::CanonicalizeSeal(expected_seal());
  if (!r.ok) {
    std::fprintf(stderr, "FATAL: mirror seal refused: %s\n", r.reject_reason.c_str());
    std::abort();
  }
  return r.text;
}

// One provider-mode cycle for SealIndependentOfProviderMode: fresh rclcpp
// context, stderr redirected to a file around the node ctor (the seal line is
// a raw fprintf(stderr,...) — SD4's greppable operator fact), then parse the
// capture. The node is constructed and destroyed without spinning: the claim
// is that the SEAL happens in the constructor, in every mode.
struct SealLine {
  bool found = false;
  std::string digest;
  std::string mode;
};

SealLine capture_seal_for_mode(const std::string &mode) {
  const std::vector<std::string> arg_strings = {
      "test_gate_profile", "--ros-args",
      "-p", "token_provider_mode:=" + mode,
      "-p", "robot_id:=tb7-profile-robot",
      "-p", kTb7PolicyFileArg,
  };
  std::vector<const char *> argv;
  argv.reserve(arg_strings.size());
  for (const auto &s : arg_strings) argv.push_back(s.c_str());
  rclcpp::init(static_cast<int>(argv.size()), argv.data());

  const std::string path = "/tmp/tb7_seal_" + mode + ".log";
  std::fflush(stderr);
  const int saved = dup(2);
  const int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd >= 0) {
    dup2(fd, 2);
    close(fd);
  }
  {
    auto gate = std::make_shared<PepGateNode>();
  }
  std::fflush(stderr);
  dup2(saved, 2);
  close(saved);
  rclcpp::shutdown();

  SealLine out;
  std::ifstream f(path);
  std::string line;
  // The WARNING companion line shares the "PAIL CONFIG SEAL:" banner but not
  // the "v<N>" version field — this prefix selects only the seal fact line.
  const std::string prefix = "PAIL CONFIG SEAL: v";
  while (std::getline(f, line)) {
    if (line.rfind(prefix, 0) != 0) continue;
    const auto dpos = line.find("digest=");
    const auto mpos = line.find(" mode=");
    if (dpos == std::string::npos || mpos == std::string::npos) continue;
    const auto dstart = dpos + 7;
    const auto dend = line.find(' ', dstart);
    out.found = true;
    out.digest = line.substr(dstart, dend - dstart);
    out.mode = line.substr(mpos + 6);
    break;
  }
  return out;
}

bool is_hex64(const std::string &s) {
  if (s.size() != 64) return false;
  for (char c : s) {
    if (!std::isxdigit(static_cast<unsigned char>(c)) ||
        std::isupper(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  return true;
}

}  // namespace

int main() {
  // One communication contract (0.2.0-preview.40): no selecting setting; this fixture injects a non-gRPC
  // (non-reporting) test provider.
  unsetenv("PAIL_CORE_COMM_CONTRACT");
  setenv("PAIL_PROFILE", "dev", 1);
  setenv("PAIL_SEAL_DEADLINE_MS", "50", 1);
  // DD-1 : declare a control-transport posture or the node
  // refuses startup — plaintext with the explicit ack (DD-5), no cert files.
  setenv("PAIL_GRPC_TLS", "off", 1);
  setenv("PAIL_GRPC_INSECURE_ACK", "i-accept-plaintext", 1);

  const char *args[] = {
      "test_gate_profile", "--ros-args",
      "-p", "token_provider_mode:=notoken",
      "-p", "robot_id:=tb7-profile-robot",
      "-p", kTb7PolicyFileArg,
  };
  rclcpp::init(static_cast<int>(sizeof(args) / sizeof(args[0])), args);
  int rc = 1;
  {
    auto gate = std::make_shared<PepGateNode>();
    auto probe = std::make_shared<rclcpp::Node>("tb7_profile_probe");

    std::vector<pail_msgs::msg::GateState> states;
    auto gate_sub = probe->create_subscription<pail_msgs::msg::GateState>(
        "/pail/gate_state", 50,
        [&states](pail_msgs::msg::GateState::SharedPtr m) { states.push_back(*m); });
    auto cmd_pub = probe->create_publisher<geometry_msgs::msg::Twist>("/cmd_vel", 10);

    rclcpp::executors::SingleThreadedExecutor ex;
    ex.add_node(gate);
    ex.add_node(probe);

    const bool discovered = spin_until(ex, 5000, [&]() {
      return cmd_pub->get_subscription_count() >= 1 && gate_sub->get_publisher_count() >= 1;
    });
    ROW("Discovery", discovered, "gate matched probe pubs/subs");

    // ---------------------------------------------------------------------
    // PAIL-CASE: ConfigDigestExposed  (G-DEP-04)
    // ---------------------------------------------------------------------
    geometry_msgs::msg::Twist twist;
    twist.linear.x = 0.2;

    // Two decisions, so constancy across publications is a fact, not a guess.
    cmd_pub->publish(twist);
    spin_until(ex, 2000, [&]() { return states.size() >= 1; });
    cmd_pub->publish(twist);
    const bool got_two = spin_until(ex, 2000, [&]() { return states.size() >= 2; });
    ROW("ConfigDigestExposed", got_two, "two GateState publications observed");

    if (got_two) {
      const auto &s0 = states[0];
      const auto &s1 = states[1];
      ROW("ConfigDigestExposed", s0.state == "BLOCK" && s0.reason == "ERR_NO_TOKEN",
          "notoken rig decides BLOCK/ERR_NO_TOKEN (deterministic carrier decision)");

      ROW("ConfigDigestExposed", is_hex64(s0.config_digest),
          "digest is 64 lowercase hex chars");

      const std::string expected =
          hex_sha256(expected_seal_canonical());
      ROW("ConfigDigestExposed", s0.config_digest == expected,
          "digest equals independently recomputed sha256(CanonicalizeSeal(mirror))");
      ROW("ConfigDigestExposed", s1.config_digest == s0.config_digest,
          "digest constant across decisions");
    }

    // -----------------------------------------------------------------------
    // PAIL-CASE: RuntimeParamSealed  (DC-12, implementation contract)
    // -----------------------------------------------------------------------
    // The unit half of C3-C5: the on-set callback's semantics, exercised
    // through the node's own set_parameter path. The live half — an external
    // `ros2 param set` against the running container — is step-11 evidence;
    // this cannot substitute for it (different entry surface), only prove the
    // callback rejects and the value stays.
    {
      const auto res = gate->set_parameter(rclcpp::Parameter("use_sim_time", true));
      ROW("RuntimeParamSealed", !res.successful,
          "use_sim_time runtime set rejected (the parameter rclcpp applies live)");
      ROW("RuntimeParamSealed", res.reason.find("DC-12") != std::string::npos,
          "rejection reason names DC-12");
      rclcpp::Parameter after;
      const bool read_back = gate->get_parameter("use_sim_time", after);
      ROW("RuntimeParamSealed",
          read_back && after.get_type() == rclcpp::ParameterType::PARAMETER_BOOL &&
              !after.as_bool(),
          "use_sim_time still false after the rejected set");
      // A sealed threshold too — the rejection is every-parameter, not a
      // use_sim_time special case (one weakened threshold re-opens O-17).
      const auto res2 = gate->set_parameter(rclcpp::Parameter("clock_skew_ms", 999999));
      ROW("RuntimeParamSealed", !res2.successful,
          "clock_skew_ms runtime set rejected (sealed threshold)");
    }

    ex.remove_node(gate);
    ex.remove_node(probe);
  }
  rclcpp::shutdown();

  // ---------------------------------------------------------------------
  // PAIL-CASE: SealIndependentOfProviderMode  (G-DEP-05)
  // ---------------------------------------------------------------------
  // LLD §6.4 planned to stub-inject this down to L1, but build_seal_input /
  // do_config_seal are private member functions of the node — the same
  // structural fact that re-tiered 미결 3 — and a seal recorded by a stub
  // proves only the stub. This is the product path instead: one ctor cycle
  // per provider mode, and the grpc cycle's SendConfigSeal against the absent
  // issuer is exactly the degraded product behavior (best-effort send, "NOT
  // journalled" warning, never a silent skip of the seal itself).
  const std::string expected_digest =
      hex_sha256(expected_seal_canonical());
  for (const std::string mode : {"notoken", "static", "grpc"}) {
    const SealLine seal = capture_seal_for_mode(mode);
    ROW("SealIndependentOfProviderMode", seal.found,
        ("mode=" + mode + ": seal line emitted on stderr during ctor").c_str());
    if (!seal.found) continue;
    ROW("SealIndependentOfProviderMode", is_hex64(seal.digest),
        ("mode=" + mode + ": sealed digest is 64 lowercase hex chars").c_str());
    ROW("SealIndependentOfProviderMode", seal.mode == mode,
        ("mode=" + mode + ": seal line names the mode it sealed").c_str());
    if (mode == "notoken") {
      // Only the notoken rig's full SealInput is mirrored above; static/grpc
      // vary keyring_mode/degraded axes, so they assert presence, not value.
      ROW("SealIndependentOfProviderMode", seal.digest == expected_digest,
          "mode=notoken: sealed digest equals independently recomputed digest");
    }
  }

  rc = (g_failures == 0) ? 0 : 1;
  if (g_failures) std::printf("test_gate_profile: %d row(s) FAILED\n", g_failures);
  return rc;
}
