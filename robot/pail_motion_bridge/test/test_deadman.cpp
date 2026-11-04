// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// TB-7 : node-wiring battery — deadman on permit silence (G-ENF-20).
// Plain executable, no gtest : returns 0 only if every row matches.
//
// Tier honesty: MotionBridgeNode's deadman IS its DDS wiring — the deadline
// QoS event, the watchdog timer, the latched hold. There is no pure function
// to extract; the guarantee lives in the node, so the test speaks DDS (L3).
//
// QoS caution (measured earlier on the permit path): the bridge REQUESTS a
// deadline on its permit subscription, so this test's permit publisher must
// OFFER a deadline <= that value — a default (infinite) offer is incompatible
// and DDS silently delivers nothing.

#define PAIL_MOTION_BRIDGE_UNDER_TEST 1
#include "../src/motion_bridge_node.cpp"

#include <chrono>
#include <cstdio>
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

void spin_ms(rclcpp::executors::SingleThreadedExecutor &ex, int ms) {
  const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  while (std::chrono::steady_clock::now() < until) {
    ex.spin_some();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
}

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

bool is_zero(const geometry_msgs::msg::Twist &t) {
  return t.linear.x == 0.0 && t.linear.y == 0.0 && t.linear.z == 0.0 &&
         t.angular.x == 0.0 && t.angular.y == 0.0 && t.angular.z == 0.0;
}

}  // namespace

int main() {
  // Short deadline so silence detection fits a test budget: window = 2x40ms.
  const char *args[] = {
      "test_deadman", "--ros-args",
      "-p", "permit_deadline_ms:=40",
  };
  rclcpp::init(static_cast<int>(sizeof(args) / sizeof(args[0])), args);
  int rc = 1;
  {
    auto bridge = std::make_shared<MotionBridgeNode>();
    auto probe = std::make_shared<rclcpp::Node>("tb7_deadman_probe");

    std::vector<geometry_msgs::msg::Twist> drive;
    std::vector<pail_msgs::msg::BridgeState> bstates;
    auto drive_sub = probe->create_subscription<geometry_msgs::msg::Twist>(
        "/drive_cmd_vel", 50,
        [&drive](geometry_msgs::msg::Twist::SharedPtr m) { drive.push_back(*m); });
    auto bstate_sub = probe->create_subscription<pail_msgs::msg::BridgeState>(
        "/pail/bridge_state", 50,
        [&bstates](pail_msgs::msg::BridgeState::SharedPtr m) { bstates.push_back(*m); });

    rclcpp::QoS permit_qos(rclcpp::KeepLast(1));
    permit_qos.best_effort();
    permit_qos.deadline(std::chrono::milliseconds(40));  // offered <= requested
    auto permit_pub = probe->create_publisher<pail_msgs::msg::Permit>("/pail/permit", permit_qos);
    auto safe_pub = probe->create_publisher<geometry_msgs::msg::Twist>("/safe_cmd_vel", 10);

    rclcpp::executors::SingleThreadedExecutor ex;
    ex.add_node(bridge);
    ex.add_node(probe);

    const bool discovered = spin_until(ex, 5000, [&]() {
      return permit_pub->get_subscription_count() >= 1 &&
             safe_pub->get_subscription_count() >= 1 &&
             drive_sub->get_publisher_count() >= 1;
    });
    ROW("Discovery", discovered, "bridge matched probe pubs/subs");

    geometry_msgs::msg::Twist twist;
    twist.linear.x = 0.25;
    uint32_t seq = 0;
    auto publish_permit = [&]() {
      pail_msgs::msg::Permit p;
      p.active_token_id = "tok-deadman";
      p.permit_seq = ++seq;
      permit_pub->publish(p);
    };

    // ---------------------------------------------------------------------
    // PAIL-CASE: DeadmanSilence  (G-ENF-20)
    // ---------------------------------------------------------------------

    // Control row (mandatory per implementation contract): live permit stream => the SAME
    // command that must later be withheld IS forwarded now.
    bool forwarded = false;
    {
      const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
      while (std::chrono::steady_clock::now() < until && !forwarded) {
        publish_permit();
        safe_pub->publish(twist);
        ex.spin_some();
        forwarded = !drive.empty() && drive.back().linear.x == twist.linear.x;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    }
    ROW("DeadmanSilence", forwarded, "control row: permit alive => /safe_cmd_vel forwarded");

    // Silence row: stop the permit stream. Within the observation window
    // (2x deadline) the bridge must publish exactly one zero-twist and latch
    // HOLD. spin_ms keeps executing so timers/deadline events can fire —
    // silence means no PERMITS, not no spinning.
    drive.clear();
    bstates.clear();
    auto zero_count = [&]() {
      size_t n = 0;
      for (const auto &t : drive) n += is_zero(t) ? 1 : 0;
      return n;
    };
    const bool held = spin_until(ex, 2000, [&]() { return zero_count() >= 1; });
    ROW("DeadmanSilence", held, "permit silence => zero-twist published");
    spin_ms(ex, 300);  // a further window in which a zero-twist STREAM would show
    ROW("DeadmanSilence", held && zero_count() == 1,
        "exactly one zero-twist (then silence, not a stream)");
    const bool hold_state = spin_until(ex, 2000, [&]() {
      return !bstates.empty() && bstates.back().state == "HOLD";
    });
    ROW("DeadmanSilence", hold_state, "BridgeState reports HOLD");

    // A command during HOLD is withheld — absence of permit = stop.
    drive.clear();
    safe_pub->publish(twist);
    spin_ms(ex, 300);
    ROW("DeadmanSilence", drive.empty(), "safe_cmd during HOLD => nothing forwarded");

    // Resume row: a fresh permit stream restores forwarding (the hold is a
    // state, not a ratchet) — and proves the deadman can trip again, i.e. the
    // silence row wasn't a wedged node.
    drive.clear();
    forwarded = false;
    {
      const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
      while (std::chrono::steady_clock::now() < until && !forwarded) {
        publish_permit();
        safe_pub->publish(twist);
        ex.spin_some();
        forwarded = !drive.empty() && drive.back().linear.x == twist.linear.x;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    }
    ROW("DeadmanSilence", forwarded, "fresh permit stream => forwarding resumes");

    // ---------------------------------------------------------------------
    // PAIL-CASE: PermitReplayHold  (G-ENF-20 replay clause)
    // ---------------------------------------------------------------------
    // A non-monotonic permit_seq is replay suspicion => hold immediately.
    //
    // 배수 먼저. 앞의 resume 행이 끝난 뒤에도 permit 하나가 비행 중이고, 그것이
    // 만드는 deadline-missed zero-twist 가 아래 `drive.clear()` **뒤에** 배달될
    // 수 있다. 그러면 `spin_until` 이 그 zero-twist 를 「재생이 홀드를 일으켰다」의
    // 증거로 latch 하고, 진짜 재생 zero-twist 는 그 다음 clear 뒤에 도착해
    // 마지막 행을 붉힌다 — 두 사건이 같은 바이트로 도착한다(H-B2).
    // 실측(2026-08-23, implementation contract 단계 9): 배수 없이 30회 중 4회 FAIL.
    for (int i = 0; i < 10; ++i) {
      const size_t before = drive.size();
      spin_ms(ex, 50);
      if (drive.size() == before) break;
    }
    drive.clear();
    pail_msgs::msg::Permit stale;
    stale.active_token_id = "tok-deadman";
    stale.permit_seq = 1;  // seq already well past 1
    permit_pub->publish(stale);
    const bool replay_held = spin_until(ex, 2000, [&]() {
      return !drive.empty() && is_zero(drive.back());
    });
    ROW("PermitReplayHold", replay_held, "non-monotonic permit_seq => zero-twist hold");
    drive.clear();
    safe_pub->publish(twist);
    spin_ms(ex, 300);
    ROW("PermitReplayHold", drive.empty(), "safe_cmd after replay hold => nothing forwarded");

    ex.remove_node(bridge);
    ex.remove_node(probe);
    rc = (g_failures == 0) ? 0 : 1;
    if (g_failures) std::printf("test_deadman: %d row(s) FAILED\n", g_failures);
  }
  rclcpp::shutdown();
  return rc;
}
