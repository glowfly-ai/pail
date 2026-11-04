// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// TB-7 : node-wiring battery — cognitive evidence & ESTOP cold path.
// Plain executable, no gtest : returns 0 only if every row matches.
//
// Tier honesty (implementation contract 미결 3, resolved): PepGateNode IS an rclcpp::Node —
// its constructor creates participants, publishers and timers, and the only
// way to observe what the wiring PUBLISHES is a subscription. So this battery
// initializes rclcpp and speaks DDS in-process. That makes it L3 by the LLD's
// own vocabulary, and GUARANTEES.yaml says L3. It is NOT re-labelled L2.
//
// What is L3-new here (deliberately not an L1 retread): the L1 truth table
// proved decide() answers correctly; this battery proves the NODE collects
// real topic inputs into decide() and executes its answer — publishes the
// state, forwards or withholds the command, asserts the stop.

#define PAIL_PEP_GATE_UNDER_TEST 1
#include "../src/pep_gate_node.cpp"

#include "tb7_policy_fixture.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
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

struct Captured {
  std::vector<pail_msgs::msg::GateState> gate_states;
  std::vector<geometry_msgs::msg::Twist> safe_cmds;
  std::vector<pail_msgs::msg::StopRequest> stops;
};

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

const pail_msgs::msg::GateState *last_state(const Captured &c) {
  return c.gate_states.empty() ? nullptr : &c.gate_states.back();
}

}  // namespace

int main() {
  // One communication contract (0.2.0-preview.40): no selecting setting; this fixture injects a non-gRPC
  // (non-reporting) test provider.
  unsetenv("PAIL_CORE_COMM_CONTRACT");
  // The constructor preflight refuses notoken+production with exit(78); the
  // test rig is exactly the dev case that refusal exists to gate.
  setenv("PAIL_PROFILE", "dev", 1);
  // grpc-ON build: the config seal dials the (absent) issuer at startup.
  // Bounded small so an unreachable issuer delays this battery, not detains it.
  setenv("PAIL_SEAL_DEADLINE_MS", "50", 1);
  // DD-1 : an undecidable control transport refuses startup.
  // This battery measures DDS wiring, not the control plane, but it still must
  // declare a posture — plaintext with the explicit ack (DD-5), no cert files.
  setenv("PAIL_GRPC_TLS", "off", 1);
  setenv("PAIL_GRPC_INSECURE_ACK", "i-accept-plaintext", 1);

  const char *args[] = {
      "test_gate_evidence", "--ros-args",
      "-p", "token_provider_mode:=notoken",
      "-p", "robot_id:=tb7-robot",
      "-p", kTb7PolicyFileArg,  // D-L2: 부재는 이제 기동 거부 — 최소 정책을 준다
  };
  rclcpp::init(static_cast<int>(sizeof(args) / sizeof(args[0])), args);
  int rc = 1;
  {
    auto gate = std::make_shared<PepGateNode>();
    auto probe = std::make_shared<rclcpp::Node>("tb7_probe");

    Captured cap;
    auto gate_sub = probe->create_subscription<pail_msgs::msg::GateState>(
        "/pail/gate_state", 50,
        [&cap](pail_msgs::msg::GateState::SharedPtr m) { cap.gate_states.push_back(*m); });
    auto safe_sub = probe->create_subscription<geometry_msgs::msg::Twist>(
        "/safe_cmd_vel", 50,
        [&cap](geometry_msgs::msg::Twist::SharedPtr m) { cap.safe_cmds.push_back(*m); });
    rclcpp::QoS stop_qos(rclcpp::KeepLast(1));
    stop_qos.reliable();
    stop_qos.transient_local();
    auto stop_sub = probe->create_subscription<pail_msgs::msg::StopRequest>(
        "/pail/stop_request", stop_qos,
        [&cap](pail_msgs::msg::StopRequest::SharedPtr m) { cap.stops.push_back(*m); });

    auto safety_pub = probe->create_publisher<pail_msgs::msg::SafetyState>("/pail/safety_state", 10);
    auto evidence_pub = probe->create_publisher<pail_msgs::msg::Evidence>("/pail/evidence", 10);
    auto cmd_pub = probe->create_publisher<geometry_msgs::msg::Twist>("/cmd_vel", 10);

    rclcpp::executors::SingleThreadedExecutor ex;
    ex.add_node(gate);
    ex.add_node(probe);

    // Discovery: wait until the gate matched our publishers/subscriptions.
    const bool discovered = spin_until(ex, 5000, [&]() {
      return safety_pub->get_subscription_count() >= 1 &&
             evidence_pub->get_subscription_count() >= 1 &&
             cmd_pub->get_subscription_count() >= 1 &&
             gate_sub->get_publisher_count() >= 1;
    });
    ROW("Discovery", discovered, "gate matched probe pubs/subs");

    auto publish_safety = [&](const char *level) {
      pail_msgs::msg::SafetyState s;
      s.stamp = probe->now();
      s.level = level;
      s.source = "TB7_HARNESS";
      s.detail = "injected";
      safety_pub->publish(s);
    };
    auto publish_evidence = [&](const char *object_id, float conf) {
      pail_msgs::msg::Evidence e;
      e.stamp = probe->now();
      e.source = "VISION";
      e.object_id = object_id;
      e.confidence = conf;
      evidence_pub->publish(e);
    };
    auto valid_grpc_token = [](pail_pep_gate::GateInputs &in, const std::string &hash) {
      in.supplier.provider_mode = "grpc";
      in.supplier.use_token_service = false;
      in.supplier.grpc_built = true;
      in.token_view.ok = true;
      in.token_view.status = "OK";
      in.token_view.chain_id = "chain-tb7";
      in.token_view.token_id = "tok-tb7";
      in.token_view.current_subgraph_hash = hash;
      in.verify_ok = true;
      in.verify_reason.clear();
      in.token_info.target_object_id = "pallet-7";
      in.token_info.action_type = pail_pep_gate::kActionMove;
      in.token_info.max_linear_speed_mps = 1.0;
      in.token_info.max_angular_speed_rps = 1.0;
      in.token_info.not_after_unix_ms = in.now_ms + 30000;
      in.token_info.subgraph_snapshot_hash = hash;
      in.token_consumed = false;
    };
    geometry_msgs::msg::Twist twist;
    twist.linear.x = 0.3;

    // ---------------------------------------------------------------------
    // PAIL-CASE: EstopColdPath  (G-ENF-17)
    // ---------------------------------------------------------------------
    // "OK" — the frozen domain (D §4.1, C-B7) is OK/WARN/UNSAFE. This fixture
    // once said "SAFE", a value the domain never contained; the old code let
    // it pass (blocked on "WARN" alone) AND released the E-STOP latch (else-
    // release) — the fixture had the defect as its expectation.
    publish_safety("OK");
    publish_evidence("pallet-7", 0.97f);
    spin_ms(ex, 200);

    // Row 1: UNSAFE injection => observable ESTOP transition + stop assertion.
    cap = Captured{};
    publish_safety("UNSAFE");
    const bool estopped = spin_until(ex, 2000, [&]() {
      const auto *s = last_state(cap);
      return s != nullptr && s->state == "ESTOP" && !cap.stops.empty();
    });
    ROW("EstopColdPath", estopped, "UNSAFE => GateState ESTOP + StopRequest observed");
    ROW("EstopColdPath",
        estopped && last_state(cap)->reason == "ERR_SAFETY_UNSAFE" &&
            cap.stops.back().reason == "ERR_SAFETY_UNSAFE",
        "reason ERR_SAFETY_UNSAFE on both publications");

    // Row 2: a live command during ESTOP re-publishes ESTOP and is not forwarded.
    cap = Captured{};
    cmd_pub->publish(twist);
    const bool held = spin_until(ex, 2000, [&]() {
      const auto *s = last_state(cap);
      return s != nullptr && s->state == "ESTOP";
    });
    ROW("EstopColdPath", held && cap.safe_cmds.empty(),
        "cmd_vel during ESTOP => ESTOP republished, nothing forwarded");

    // Row 3: authorization-irrelevance at the node level — a fully valid,
    // verified token injected on top of the REAL collected inputs still ends
    // in ESTOP, through the product build_inputs/decide/apply path.
    cap = Captured{};
    auto in_estop = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    ROW("EstopColdPath", in_estop.safety.estop_active,
        "build_inputs collected the injected ESTOP state");
    valid_grpc_token(in_estop, "cafecafecafecafecafecafecafecafe");
    const auto d_estop = pail_pep_gate::decide(in_estop);
    gate->apply(d_estop, &twist, in_estop);
    const bool estop_wins = spin_until(ex, 2000, [&]() {
      const auto *s = last_state(cap);
      return s != nullptr && s->state == "ESTOP" && s->reason == "ERR_SAFETY_UNSAFE";
    });
    ROW("EstopColdPath", estop_wins && cap.safe_cmds.empty(),
        "valid token + fresh evidence + ESTOP => still ESTOP, nothing forwarded");

    // Recovery for the next case (recovery itself requires a new plan; here we
    // only need estop_active_ back to false — kOk is the ONLY release path
    // (D §4.2), so it must be the literal "OK".
    publish_safety("OK");
    publish_evidence("pallet-7", 0.97f);
    spin_ms(ex, 200);

    // ---------------------------------------------------------------------
    // PAIL-CASE: EvidenceHashBinding  (G-PER-04)
    // ---------------------------------------------------------------------
    const std::string h = "abcdabcdabcdabcdabcdabcdabcdabcd";

    // Control row (mandatory per implementation contract): identical hash => PERMIT,
    // command forwarded. Evidence and safety come from the REAL topic path.
    cap = Captured{};
    auto in_ok = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    ROW("EvidenceHashBinding",
        in_ok.evidence.object_id == "pallet-7" && in_ok.evidence.confidence > 0.9,
        "build_inputs collected the published evidence");
    valid_grpc_token(in_ok, h);
    const auto d_ok = pail_pep_gate::decide(in_ok);
    gate->apply(d_ok, &twist, in_ok);
    const bool permitted = spin_until(ex, 2000, [&]() {
      const auto *s = last_state(cap);
      return s != nullptr && s->state == "PERMIT" && !cap.safe_cmds.empty();
    });
    ROW("EvidenceHashBinding",
        permitted && last_state(cap)->reason == "OK" &&
            cap.safe_cmds.back().linear.x == twist.linear.x,
        "control row: matching hash => PERMIT published, command forwarded");

    // Flip row: ONE byte of the signed snapshot hash differs => BLOCK
    // ERR_WORLD_CHANGED published, command NOT forwarded.
    cap = Captured{};
    auto in_flip = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    valid_grpc_token(in_flip, h);
    in_flip.token_info.subgraph_snapshot_hash[0] = 'b';  // 'a' -> 'b'
    const auto d_flip = pail_pep_gate::decide(in_flip);
    gate->apply(d_flip, &twist, in_flip);
    const bool blocked = spin_until(ex, 2000, [&]() {
      const auto *s = last_state(cap);
      return s != nullptr && s->state == "BLOCK";
    });
    ROW("EvidenceHashBinding",
        blocked && last_state(cap)->reason == "ERR_WORLD_CHANGED" && cap.safe_cmds.empty(),
        "flip row: 1-byte hash flip => BLOCK/ERR_WORLD_CHANGED, nothing forwarded");

    ex.remove_node(gate);
    ex.remove_node(probe);
    rc = (g_failures == 0) ? 0 : 1;
    if (g_failures) std::printf("test_gate_evidence: %d row(s) FAILED\n", g_failures);
  }
  rclcpp::shutdown();
  return rc;
}
