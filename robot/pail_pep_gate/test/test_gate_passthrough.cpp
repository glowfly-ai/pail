// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// TB-17 (implementation contract IC-1): 감산성 — 게이트는 명령을 **빼기만** 한다.
//
// 계약이 파는 문장은 이것이다: PAIL 이 False ALLOW 를 내도 로봇은 기존 스택
// 수준으로 회귀할 뿐 **PAIL 이 만든 새 위험은 없다.** 그 문장이 성립하려면
// 게이트가 통과시키는 명령이 상류가 보낸 그 명령이어야 한다. 게이트가 값을
// 조금이라도 만들어 낸다면 — 깎든, 클램프하든, 합성하든 — PAIL 은 필터가
// 아니라 **컨트롤러**이고, 그 순간 비대칭 논증도 Machinery Regulation
// 대응도 서 있던 바닥을 잃는다.
//
// 여기서 재는 것 둘:
//
//   ByteIdentity   수신한 /cmd_vel 이 /safe_cmd_vel 로 **비트 동일**하게 나온다.
//                  필드 비교가 아니라 비트 패턴 비교다: -0.0 == 0.0 이 참이고
//                  NaN != NaN 이 참이므로, `==` 로만 재면 부호와 미측정을
//                  구분하지 못한다 (H-B2 의 부동소수판).
//
//   NoSynthesis    /cmd_vel 이 없는 동안 /safe_cmd_vel 이 **한 번도** 나오지
//                  않는다. 게이트의 주기 타이머는 이 창에서도 계속 돌고
//                  apply() 를 msg=nullptr 로 부른다 — 즉 이 행이 비어 있는
//                  것은 "아무 일도 안 일어났다"가 아니라 "일어났는데 아무것도
//                  발행하지 않았다"이다.
//
// 왜 실경로(DDS)인가. 주입 경로(build_inputs+apply 직접 호출)로도 publish 는
// 재진다. 그러나 그러면 on_cmd_vel 이 msg 를 만진 뒤 apply 에 넘기는 변형을
// 통째로 못 본다 — 관측점이 재는 범위가 조항보다 좁아진다. 그래서 이 배터리는
// 상류 발행자로서 /cmd_vel 을 실제로 쏘고 하류 소비자로서 /safe_cmd_vel 을
// 실제로 받는다. 계약이 주장하는 그 두 지점이다.
//
// static 프로바이더를 쓰는 이유: 실경로 PERMIT 이 필요하고, grpc PERMIT 은
// 발급자를 요구한다. static 은 dev 프로파일에서만 허용되고 production 에서는
// 기동이 거부된다(G-ENF-19) — 이 배터리가 재는 것은 인가가 아니라 **인가가
// 났을 때 명령이 어떻게 지나가는가**이므로 그 축을 빌려도 무방하다.

#define PAIL_PEP_GATE_UNDER_TEST 1
#include "../src/pep_gate_node.cpp"

#include "tb7_policy_fixture.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <thread>
#include <vector>

// 케이스 등재 . 이 배터리는 gtest 가 아니라 ROW 매크로로 판정하므로
// 검사기가 볼 심볼이 소스에 따로 없다 — 마커가 그 자리를 진다.
// PAIL-CASE: ByteIdentity     (G-ICT-01 절1 — 비트 동일 통과)
// PAIL-CASE: NoSynthesis      (G-ICT-01 절2 — 수신 없으면 발행 없음)

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

// 비트 패턴으로 읽는다. `==` 는 -0.0 과 0.0 을 같다고 하고 NaN 과 NaN 을 다르다고
// 한다 — 둘 다 이 조항이 구분해야 하는 차이다(부호를 뒤집는 변형, 값을 미측정으로
// 만드는 변형).
uint64_t bits(double v) {
  uint64_t u;
  std::memcpy(&u, &v, sizeof u);
  return u;
}

bool bit_identical(const geometry_msgs::msg::Twist &a, const geometry_msgs::msg::Twist &b) {
  return bits(a.linear.x) == bits(b.linear.x) && bits(a.linear.y) == bits(b.linear.y) &&
         bits(a.linear.z) == bits(b.linear.z) && bits(a.angular.x) == bits(b.angular.x) &&
         bits(a.angular.y) == bits(b.angular.y) && bits(a.angular.z) == bits(b.angular.z);
}

// 여섯 성분이 전부 다르고, 전부 0 이 아니고, 부호가 섞여 있고, 전부 이진수로
// 정확히 표현되는 값. 정확 표현이 중요한 이유: 근사값을 쓰면 "게이트가 값을
// 만졌다"와 "직렬화가 반올림했다"가 같은 붉은 줄이 된다.
geometry_msgs::msg::Twist subject_twist() {
  geometry_msgs::msg::Twist t;
  t.linear.x = 0.375;
  t.linear.y = -0.125;
  t.linear.z = 0.0625;
  t.angular.x = -0.03125;
  t.angular.y = 0.25;
  t.angular.z = -0.5;
  return t;
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
      "test_gate_passthrough", "--ros-args",
      "-p", "token_provider_mode:=static",
      "-p", "static_target_object_id:=pallet-ict",
      "-p", "robot_id:=tb17-robot",
      "-p", kTb7PolicyFileArg,
  };
  rclcpp::init(static_cast<int>(sizeof(args) / sizeof(args[0])), args);
  int rc = 1;
  {
    auto gate = std::make_shared<PepGateNode>();
    auto probe = std::make_shared<rclcpp::Node>("tb17_probe");

    std::vector<geometry_msgs::msg::Twist> safe_cmds;
    std::vector<pail_msgs::msg::GateState> states;
    auto safe_sub = probe->create_subscription<geometry_msgs::msg::Twist>(
        "/safe_cmd_vel", 50,
        [&safe_cmds](geometry_msgs::msg::Twist::SharedPtr m) { safe_cmds.push_back(*m); });
    auto gate_sub = probe->create_subscription<pail_msgs::msg::GateState>(
        "/pail/gate_state", 50,
        [&states](pail_msgs::msg::GateState::SharedPtr m) { states.push_back(*m); });

    auto safety_pub = probe->create_publisher<pail_msgs::msg::SafetyState>("/pail/safety_state", 10);
    auto evidence_pub = probe->create_publisher<pail_msgs::msg::Evidence>("/pail/evidence", 10);
    auto cmd_pub = probe->create_publisher<geometry_msgs::msg::Twist>("/cmd_vel", 10);

    rclcpp::executors::SingleThreadedExecutor ex;
    ex.add_node(gate);
    ex.add_node(probe);

    const bool discovered = spin_until(ex, 5000, [&]() {
      return safety_pub->get_subscription_count() >= 1 &&
             evidence_pub->get_subscription_count() >= 1 &&
             cmd_pub->get_subscription_count() >= 1 &&
             safe_sub->get_publisher_count() >= 1 && gate_sub->get_publisher_count() >= 1;
    });
    ROW("Passthrough", discovered, "gate matched probe pubs/subs");

    auto feed = [&]() {
      pail_msgs::msg::SafetyState s;
      s.stamp = probe->now();
      s.level = "OK";
      s.source = "TB17_HARNESS";
      s.detail = "injected";
      safety_pub->publish(s);
      pail_msgs::msg::Evidence e;
      e.stamp = probe->now();
      e.source = "VISION";
      e.object_id = "pallet-ict";
      e.confidence = 0.97f;
      evidence_pub->publish(e);
    };

    feed();
    spin_ms(ex, 200);

    // -----------------------------------------------------------------
    // PAIL-CASE: ByteIdentity  (G-ICT-01 절1)
    // -----------------------------------------------------------------
    const geometry_msgs::msg::Twist sent = subject_twist();
    safe_cmds.clear();
    states.clear();
    cmd_pub->publish(sent);

    // 전제 먼저, 판정 나중. 「/safe_cmd_vel 에 뭔가 왔다」로 대기를 끊으면
    // 게이트가 명령을 **합성하는** 변형 아래에서 그 합성물이 먼저 도착해 대기가
    // 조기 반환하고, PERMIT 이 아직 안 났다는 이유로 전제 행이 붉는다 — 즉
    // 「인가가 안 났다」가 「게이트가 명령을 만들었다」를 가린다(실측 2026-08-24).
    // 전제는 자기 신호(GateState)로만 재고 판정은 그 뒤에 잰다.
    const bool permitted = spin_until(ex, 3000, [&]() {
      return !states.empty() && states.back().state == "PERMIT";
    });
    ROW("ByteIdentity", permitted,
        "전제: static PERMIT 이 실제로 났다 (아니면 아래 행은 재지 못한 것)");

    const bool forwarded = spin_until(ex, 2000, [&]() { return !safe_cmds.empty(); });
    ROW("ByteIdentity", forwarded, "/cmd_vel 1건 => /safe_cmd_vel 최소 1건 관측");

    // 두 판정을 일부러 나눈다. 「정확히 1건」은 **증폭·합성**을 잡고 비트 동일은
    // **값 변조**를 잡는다. 비트 비교 대상을 `.back()` 으로 고정하면 합성 변형이
    // 두 판정을 함께 붉혀 어느 쪽이 깨졌는지 못 읽는다 — 「보낸 그 명령이 원문
    // 그대로 나왔는가」는 개수와 독립된 질문이다 (H-B9).
    ROW("ByteIdentity", forwarded && safe_cmds.size() == 1,
        "명령 1건이 정확히 1건으로 나온다 (증폭도 감산성 위반이다)");

    bool verbatim = false;
    for (const auto &got : safe_cmds) {
      if (bit_identical(got, sent)) verbatim = true;
    }
    ROW("ByteIdentity", forwarded && verbatim,
        "보낸 명령이 여섯 성분 비트 동일로 나온다 — 스케일·클램프·부호 변경 없음");

    // -----------------------------------------------------------------
    // PAIL-CASE: NoSynthesis  (G-ICT-01 절2)
    // -----------------------------------------------------------------
    // 명령을 끊고 안전·증거만 계속 먹인다. 게이트의 주기 경로는 이 창에서
    // 계속 돌지만(그래서 GateState 는 는다) 발행할 명령이 없다.
    safe_cmds.clear();
    states.clear();
    for (int i = 0; i < 12; ++i) {
      feed();
      spin_ms(ex, 100);
    }
    ROW("NoSynthesis", !states.empty(),
        "전제: 명령 없는 창에서도 게이트 주기 경로가 돈다 (GateState 관측)");
    ROW("NoSynthesis", safe_cmds.empty(),
        "/cmd_vel 없는 1.2s 동안 /safe_cmd_vel 0건 — 게이트는 명령을 만들지 않는다");

    ex.remove_node(gate);
    ex.remove_node(probe);
    rc = (g_failures == 0) ? 0 : 1;
  }
  rclcpp::shutdown();
  std::printf("%s: %d failure(s)\n", rc == 0 ? "OK" : "FAILED", g_failures);
  return rc;
}
