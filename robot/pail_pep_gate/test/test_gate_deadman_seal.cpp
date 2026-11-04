// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// D §7.6 (F-CPP-7, OB4 커밋18) — seal v2 key 27 (motion_deadman_ms) 배선 배터리.
//
// U-D1 은 관측 경로를 D 착수 시 결정으로 남겼고, 여기서 A 의 권고대로 결정한다:
// 브리지가 BridgeState.deadman_window_ms 로 자기 침묵 창을 보고하고, 게이트는
// 첫 관측에서 unknown → 정수로 한 번 재봉인한다. 파라미터 조회는 조회 시점의
// 값이지 동작 중 값이 아니고, 브리지 자체 봉인은 봉인 주체를 둘로 늘린다.
//
// 이 배터리가 증명하는 것 (각 행이 정확히 하나를 본다, H-B9):
//   1. 기동 봉인은 motion_deadman_ms="unknown" 의 미러 digest 와 같다 — 관측
//      전에 어떤 정수도 실리지 않는다 (CS2-05: 기본값 100을 실으면 실측으로
//      읽힌다).
//   2. deadman_window_ms=0 (구판 발행자) 은 관측이 아니다 — digest 불변 (H-B2:
//      부재는 부재로).
//   3. 240 관측 → digest 가 "240" 미러로 이동. 240 ≠ 2×100(게이트 자신의 키
//      26에서 유도되는 값) 이므로 값이 관측에서 왔음을 함께 증명한다 (RA-3:
//      두 값의 독립 변동).
//   4. 이후 480 도착 → digest 불변 — 관측 드리프트는 조용한 재봉인이 아니라
//      로그의 몫이고, 봉인은 첫 관측을 지킨다 (DC-12 의 정신: 재기동이 재봉인).
//
// Tier: L3 (test_gate_profile 과 같은 근거 — 노드가 발행하는 digest 관측).

#define PAIL_PEP_GATE_UNDER_TEST 1
#include "../src/pep_gate_node.cpp"

#include "tb7_policy_fixture.hpp"

#include "pail_msgs/msg/bridge_state.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

namespace {

int g_failures = 0;

// 이 배터리 전체가 재는 §8 조건. 통과한 줄도 이 이름을 찍는다 — 실패했을 때만
// 조건을 부르면 초록인 날 출력에 이름이 없고, 그 침묵은 배터리가 지워진 날의
// 침묵과 같다(`H-B2`). `ob4_closure.py` 가 이 대괄호 표식으로 결속을 잰다.
// 다른 조건의 케이스를 여기 붙이려는 다음 사람에게: 이름은 파일 전역이므로
// 새 조건은 이 상수를 스코프로 바꾸고 나서 붙여야 한다.
const char *const kCond = "D14-C6";

#define ROW(case_name, cond, detail)                                        \
  do {                                                                      \
    if (cond) {                                                             \
      std::printf("PASS: [%s] %s — %s\n", kCond, case_name, detail);        \
    } else {                                                                \
      std::printf("FAIL: [%s] %s — %s\n", kCond, case_name, detail);        \
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

// The seal this rig is EXPECTED to resolve (mirrored from first principles,
// same discipline as test_gate_profile: nothing read back from the node),
// parametrized on the one key under test.
std::string expected_digest(const std::string &motion_deadman_ms) {
  pail_deploy_guard::SealInput in;
  in.component = "pep_gate";
  in.robot_id = "tb7-deadman-robot";
  in.use_sim_time = "0";
  in.token_provider_mode = "notoken";
  in.use_token_service = false;
  in.grpc_built = true;  // this battery only exists in the grpc-ON flavor
  in.control_transport = "plaintext";
  in.token_service_addr = "127.0.0.1:50051";
  in.keyring_mode = "none";
  in.thresholds.evidence_conf_threshold = 0.90;
  in.thresholds.evidence_window_ms = 2000;
  in.thresholds.safety_stale_ms = 1000;
  in.thresholds.clock_skew_ms = 500;
  in.thresholds.permit_grace_n = 3;
  in.thresholds.permit_recheck_ms = 100;
  in.permit_rate_hz = 20;
  in.permit_deadline_ms = 100;
  in.motion_deadman_ms = motion_deadman_ms;
  in.policy_file = kTb7PolicyFixture;
  in.policy_file_sha256 = kTb7PolicyFixtureSha256;
  // SK-5 (S36): the node always measures the safety_controller parameter; the rig
  // leaves it empty, so the mirror measures an empty declaration too.
  in.safety_controller_measured = true;
  in.safety_controller = "";
  in.human_safety_enabled = true;
  const auto r = pail_deploy_guard::CanonicalizeSeal(in);
  if (!r.ok) {
    std::fprintf(stderr, "FATAL: mirror seal refused: %s\n", r.reject_reason.c_str());
    std::abort();
  }
  return hex_sha256(r.text);
}

}  // namespace

int main() {
  // One communication contract (0.2.0-preview.40): no selecting setting; this fixture injects a non-gRPC
  // (non-reporting) test provider.
  unsetenv("PAIL_CORE_COMM_CONTRACT");
  setenv("PAIL_PROFILE", "dev", 1);
  setenv("PAIL_SEAL_DEADLINE_MS", "50", 1);
  setenv("PAIL_GRPC_TLS", "off", 1);
  setenv("PAIL_GRPC_INSECURE_ACK", "i-accept-plaintext", 1);

  const char *args[] = {
      "test_gate_deadman_seal", "--ros-args",
      "-p", "token_provider_mode:=notoken",
      "-p", "robot_id:=tb7-deadman-robot",
      "-p", kTb7PolicyFileArg,
  };
  rclcpp::init(static_cast<int>(sizeof(args) / sizeof(args[0])), args);
  int rc = 1;
  {
    auto gate = std::make_shared<PepGateNode>();
    auto probe = std::make_shared<rclcpp::Node>("tb7_deadman_probe");

    std::string latest_digest;
    std::size_t n_states = 0;
    auto gate_sub = probe->create_subscription<pail_msgs::msg::GateState>(
        "/pail/gate_state", 50,
        [&](pail_msgs::msg::GateState::SharedPtr m) {
          latest_digest = m->config_digest;
          ++n_states;
        });
    auto cmd_pub = probe->create_publisher<geometry_msgs::msg::Twist>("/cmd_vel", 10);
    auto bridge_pub = probe->create_publisher<pail_msgs::msg::BridgeState>("/pail/bridge_state", 10);

    rclcpp::executors::SingleThreadedExecutor ex;
    ex.add_node(gate);
    ex.add_node(probe);

    const bool discovered = spin_until(ex, 5000, [&]() {
      return cmd_pub->get_subscription_count() >= 1 &&
             bridge_pub->get_subscription_count() >= 1 &&
             gate_sub->get_publisher_count() >= 1;
    });
    ROW("Discovery", discovered, "gate matched cmd/bridge_state/gate_state endpoints");

    geometry_msgs::msg::Twist twist;
    twist.linear.x = 0.2;
    // One decision = one GateState carrying the digest in effect right then.
    auto sample_digest = [&]() -> std::string {
      const std::size_t before = n_states;
      cmd_pub->publish(twist);
      spin_until(ex, 2000, [&]() { return n_states > before; });
      return latest_digest;
    };
    auto publish_window = [&](int32_t ms) {
      pail_msgs::msg::BridgeState bs;
      bs.stamp = probe->now();
      bs.state = "HOLD";
      bs.deadman_window_ms = ms;
      bridge_pub->publish(bs);
    };

    // ---------------------------------------------------------------------
    // PAIL-CASE: DeadmanSealUnknownAtStartup
    // ---------------------------------------------------------------------
    const std::string d_unknown = expected_digest("unknown");
    ROW("DeadmanSealUnknownAtStartup", sample_digest() == d_unknown,
        "startup digest equals the motion_deadman_ms=\"unknown\" mirror");

    // ---------------------------------------------------------------------
    // PAIL-CASE: ZeroWindowIsNotAnObservation  (H-B2)
    // ---------------------------------------------------------------------
    publish_window(0);
    // Give the (possible) observation a chance to land before sampling.
    spin_until(ex, 300, [&]() { return false; });
    ROW("ZeroWindowIsNotAnObservation", sample_digest() == d_unknown,
        "deadman_window_ms=0 (pre-field publisher) leaves the seal unknown");

    // ---------------------------------------------------------------------
    // PAIL-CASE: ObservedWindowResealsOnce  (RA-3: 240 != 2 x gate key 26)
    // ---------------------------------------------------------------------
    const std::string d_240 = expected_digest("240");
    publish_window(240);
    const bool resealed = spin_until(ex, 3000, [&]() {
      cmd_pub->publish(twist);
      return latest_digest == d_240;
    });
    ROW("ObservedWindowResealsOnce", resealed,
        "digest moves to the motion_deadman_ms=\"240\" mirror after observation");
    ROW("ObservedWindowResealsOnce", d_240 != expected_digest("200"),
        "sealed 240 is not the 2 x permit_deadline_ms=200 the gate could derive itself");

    // ---------------------------------------------------------------------
    // PAIL-CASE: DriftDoesNotResealSilently  (DC-12 의 정신)
    // ---------------------------------------------------------------------
    publish_window(480);
    publish_window(480);
    spin_until(ex, 500, [&]() { return false; });
    ROW("DriftDoesNotResealSilently", sample_digest() == d_240,
        "a later, different window (480) does not move the sealed digest");

    ex.remove_node(gate);
    ex.remove_node(probe);
  }
  rclcpp::shutdown();

  rc = (g_failures == 0) ? 0 : 1;
  if (g_failures) std::printf("test_gate_deadman_seal: %d row(s) FAILED\n", g_failures);
  return rc;
}
