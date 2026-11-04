// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// L-9 (TB-7 계열, L3): 단계 기계와 단일사용 소비 캐시의 **쓰기 쪽**을 관측한다.
//
// 왜 새 배터리인가 (2026-08-31 FAIL-first 실측, /tmp/l9_ff4.log):
//   `begin_step_if_needed`·`on_step_timer`·`mark_consumed` 를 하나씩 죽인 네 변형이
//   전부 22개 배터리 전건 `100% tests passed` 를 남겼다. 네 변형 모두 테스트
//   바이너리 7개 중 5개의 해시를 바꿨으므로 **재지 못한 것이 아니라 재고도 못 본
//   것**이다. 단계 기계가 하는 일은 어느 토픽에도 나타나지 않는다 — 데드라인을
//   무엇에서 뽑았는지, 단계가 끝났는지, 끝나면서 무엇을 소비 캐시에 적었는지가
//   전부 노드 내부에서만 일어나고 관측점이 0개였다.
//
// 그래서 이 배터리는 `#ifdef PAIL_PEP_GATE_UNDER_TEST` 읽기 전용 접근자
// (`test_step_*`/`test_consumed_*`)로 그 내부 상태를 직접 읽는다. 접근자는 상태를
// 만들지도 바꾸지도 않으며, 구동은 전부 제품 경로다: 실제 토픽으로 수집된 입력에
// 검증된 토큰을 주입해 `build_inputs → decide → apply` 를 태우고, 그 다음은 노드가
// 스스로 건 50ms `step_timer_` 가 단계를 끝낸다.
//
// **소유 범위의 정직한 한계 (읽는 쪽은 이 배터리 것이 아니다):**
//   여기서 재는 것은 소비 캐시의 **쓰기**(`on_step_timer` → `mark_consumed`)뿐이다.
//   **조회**(pep_gate_node.cpp 의 `in.token_consumed = consumed_token_ids_.count(...)`)
//   는 grpc 모드에서 실서명 토큰이 있어야만 닿는 자리라 이 배터리가 닿지 못한다 —
//   그 줄을 지워도 여기는 초록이다. 소유를 주장하지 않는다.
//   2026-08-31(L-10) 부터 그 자리는 `test_gate_lookup_consume` 이 소유한다
//   (`G-ENF-28`, 실측 서명 D5). 이 문단을 남겨 두는 이유는 **이 배터리의 초록이
//   무엇을 뜻하지 않는지**가 여기에 적혀 있어야 하기 때문이다 — 옆 배터리가
//   생겼다고 이쪽 범위가 넓어지지는 않는다.
//
// **2단계 (observe): 모드 독립성** — `deform_shadow.py` 의 DF-SH7 은 소비 캐시
// 등재를 `gate_mode_ != "observe"` 조건 아래로 밀어 넣는다. 그 변형은 **enforce
// 에서 무동작**이라 1단계의 ④ 로는 영원히 관측되지 않는다(2026-08-31 이전까지
// DF-SH7 의 기대값이 `UNMOVED` 였던 이유). 그래서 정책 파일만 바꿔 같은 구동을 한
// 번 더 태운다 — 관문 하나가 모드에 딸려 사라지는 것은 shadow 리그가 만든 공백이
// 아니라 **먼저 있던 공백**이었다.
//
// 케이스 등록 규약 : `// PAIL-CASE: <name>` 은 해당 ROW() **바로 위**에
// 둔다. 파일 머리에 모으면 행이 지워져도 표식이 살아남아 CG-B 가 계속 초록을 낸다.

#define PAIL_PEP_GATE_UNDER_TEST 1
#include "../src/pep_gate_node.cpp"

#include "tb7_policy_fixture.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

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

// 이 토큰이 소비 캐시에 남길 키. 실검증 경로에서는 canon A §3.5 의
// hex(SHA-256("pail-tokenkey:v1:" ‖ bytes)) 지만, 여기서는 strict_verify 를 거치지
// 않으므로 명시적으로 준다 — 캐시가 **무엇을** 적었는지 확인하려면 기대값이 이름을
// 가져야 한다.
const char kKey[] = "l9-consumption-key-0001";
// 대조용: 캐시에 절대 들어가지 않는 키. ④ 가 "무엇에나 예라고 답하는 캐시"가
// 아님을 보이기 위한 짝이다 (④ 없이 이 행만 보면 빈 캐시에서도 참이다).
const char kOtherKey[] = "l9-consumption-key-NEVER";

// max_duration_sec 로 정한 데드라인과 not_after 를 **멀리 떨어뜨린다.** 둘이 가까우면
// "데드라인을 max_duration 에서 뽑았다"와 "not_after 로 대신했다"가 같은 초록이 된다.
constexpr double kMaxDurationSec = 0.3;
constexpr int64_t kNotAfterOffsetMs = 1500;

// 두 단계(enforce·observe)가 **같은 바이트로** 구동돼야 "모드만 다르다"가 참이
// 된다. 구동을 두 벌로 적으면 한쪽이 낡는 자리가 하나 더 생기고, 그때 observe 단계
// 의 붉음은 "모드 때문"과 "구동이 달라서"를 같은 줄로 낸다 (H-B2).
struct Rig {
  std::shared_ptr<PepGateNode> gate;
  std::shared_ptr<rclcpp::Node> probe;
  rclcpp::executors::SingleThreadedExecutor ex;
  rclcpp::Publisher<pail_msgs::msg::SafetyState>::SharedPtr safety_pub;
  rclcpp::Publisher<pail_msgs::msg::Evidence>::SharedPtr evidence_pub;

  explicit Rig(const char *probe_name)
      : gate(std::make_shared<PepGateNode>()),
        probe(std::make_shared<rclcpp::Node>(probe_name)) {
    safety_pub = probe->create_publisher<pail_msgs::msg::SafetyState>("/pail/safety_state", 10);
    evidence_pub = probe->create_publisher<pail_msgs::msg::Evidence>("/pail/evidence", 10);
    ex.add_node(gate);
    ex.add_node(probe);
  }
  ~Rig() {
    ex.remove_node(gate);
    ex.remove_node(probe);
  }

  bool discover() {
    return spin_until(ex, 5000, [&]() {
      return safety_pub->get_subscription_count() >= 1 &&
             evidence_pub->get_subscription_count() >= 1;
    });
  }

  // 실토픽으로 안전/증거를 흘려 넣는다 — 입력 수집은 제품 경로다.
  void feed() {
    pail_msgs::msg::SafetyState s;
    s.stamp = probe->now();
    s.level = "OK";
    s.source = "L9_HARNESS";
    s.detail = "injected";
    safety_pub->publish(s);
    pail_msgs::msg::Evidence e;
    e.stamp = probe->now();
    e.source = "VISION";
    e.object_id = "pallet-7";
    e.confidence = 0.97f;
    evidence_pub->publish(e);
    spin_ms(ex, 200);
  }

  // 검증 결과만 주입한다 (implementation contract 불변 3: sodium 은 strict_verify 이음매 뒤에
  // 남고 결과만 들어온다). test_gate_evidence 와 같은 형태.
  pail_pep_gate::GateInputs permit_inputs(geometry_msgs::msg::Twist *twist) {
    const std::string h = "abcdabcdabcdabcdabcdabcdabcdabcd";
    auto in = gate->build_inputs(pail_pep_gate::GatePath::Command, twist);
    in.supplier.provider_mode = "grpc";
    in.supplier.use_token_service = false;
    in.supplier.grpc_built = true;
    in.token_view.ok = true;
    in.token_view.status = "OK";
    in.token_view.chain_id = "chain-l9";
    in.token_view.token_id = "tok-l9";
    in.token_view.current_subgraph_hash = h;
    in.verify_ok = true;
    in.verify_reason.clear();
    in.token_info.target_object_id = "pallet-7";
    in.token_info.action_type = pail_pep_gate::kActionMove;
    in.token_info.max_linear_speed_mps = 1.0;
    in.token_info.max_angular_speed_rps = 1.0;
    in.token_info.subgraph_snapshot_hash = h;
    in.token_info.chain_id = "chain-l9";
    in.token_info.token_id = "tok-l9";
    in.token_info.consumption_key = kKey;
    in.token_info.max_duration_sec = kMaxDurationSec;
    in.token_info.not_after_unix_ms = in.now_ms + kNotAfterOffsetMs;
    in.token_consumed = false;
    return in;
  }
};

}  // namespace

int main() {
  // One communication contract (0.2.0-preview.40): no selecting setting; this fixture injects a non-gRPC
  // (non-reporting) test provider.
  unsetenv("PAIL_CORE_COMM_CONTRACT");
  // notoken + production 조합은 생성자가 exit(78) 로 거부한다 — 이 리그가 바로 그
  // 거부가 존재하는 이유인 dev 케이스다.
  setenv("PAIL_PROFILE", "dev", 1);
  setenv("PAIL_SEAL_DEADLINE_MS", "50", 1);
  setenv("PAIL_GRPC_TLS", "off", 1);
  setenv("PAIL_GRPC_INSECURE_ACK", "i-accept-plaintext", 1);

  const char *args[] = {
      "test_gate_step_consume", "--ros-args",
      "-p", "token_provider_mode:=notoken",
      "-p", "robot_id:=tb7-stepconsume-robot",
      "-p", kTb7PolicyFileArg,
  };
  rclcpp::init(static_cast<int>(sizeof(args) / sizeof(args[0])), args);
  int rc = 1;
  {
    Rig rig("l9_stepconsume_probe");
    auto &ex = rig.ex;
    auto &gate = rig.gate;

    ROW("Discovery", rig.discover(), "gate matched probe pubs");
    rig.feed();

    geometry_msgs::msg::Twist twist;
    twist.linear.x = 0.3;

    auto in = rig.permit_inputs(&twist);
    ROW("Discovery",
        in.evidence.object_id == "pallet-7" && !in.safety.estop_active,
        "build_inputs collected the published safety/evidence");
    ROW("Discovery", gate->test_gate_mode() == "enforce",
        "phase 1 runs under the enforce policy fixture");

    const int64_t t_begin = in.now_ms;
    const int64_t not_after = in.token_info.not_after_unix_ms;
    const auto d = pail_pep_gate::decide(in);
    gate->apply(d, &twist, in);

    // ---------------------------------------------------------------------
    // PAIL-CASE: StepBeginsOnPermit
    // ---------------------------------------------------------------------
    // 대조행 : 항상 붉은 게이트는 게이트가 아니라 벽이다. 아래 행들이
    // 재려는 상태가 애초에 세워졌는지를 먼저 세운다.
    ROW("StepBeginsOnPermit",
        d.state == "PERMIT" && d.begin_step && gate->test_step_active() &&
            gate->test_step_consumption_key() == kKey,
        "PERMIT => step_active with the VERIFIED consumption_key as its identity");

    const int64_t deadline = gate->test_step_deadline_ms();

    // ---------------------------------------------------------------------
    // PAIL-CASE: StepDeadlineFromMaxDuration
    // ---------------------------------------------------------------------
    // 데드라인의 **출처**를 잰다. max_duration_sec 갈래가 죽으면 not_after 로
    // 조용히 내려앉는데, 그것은 "단계에 시간 제한이 있다"와 "토큰 만료까지
    // 무제한이다"를 같은 초록으로 만든다.
    ROW("StepDeadlineFromMaxDuration",
        deadline >= t_begin + 200 && deadline <= t_begin + 700 &&
            deadline < not_after - 500,
        "deadline came from max_duration_sec (~+300ms), not from not_after (+1500ms)");

    // ---------------------------------------------------------------------
    // PAIL-CASE: NotConsumedBeforeCompletion
    // ---------------------------------------------------------------------
    // ④ 가 재는 것이 "타이머의 쓰기"임을 고정한다. 단계 시작 시점에 이미 적혀
    // 있었다면 ④ 는 타이머가 죽어도 초록이다.
    ROW("NotConsumedBeforeCompletion",
        !gate->test_consumed_contains(kKey) && gate->test_consumed_size() == 0,
        "the key is NOT in the consumed cache while the step is still running");

    // ---------------------------------------------------------------------
    // PAIL-CASE: StepTimerCompletesStep
    // ---------------------------------------------------------------------
    // 대기 창(2500ms)은 not_after(+1500ms)보다 길다 — 데드라인 출처가 틀린 채로도
    // 단계는 끝나므로, 이 행은 ② 의 결함에 물들지 않고 **타이머 자체**만 잰다.
    const bool completed = spin_until(ex, 2500, [&]() { return !gate->test_step_active(); });
    ROW("StepTimerCompletesStep", completed,
        "the node's own 50ms step timer ended the step at its deadline");

    // ---------------------------------------------------------------------
    // PAIL-CASE: CompletedStepIsMarkedConsumed
    // ---------------------------------------------------------------------
    // 단일사용의 쓰기 쪽. 이 행이 없으면 mark_consumed 호출을 통째로 지워도
    // 22개 배터리가 전부 초록이다 (2026-08-31 D1 실측).
    ROW("CompletedStepIsMarkedConsumed",
        gate->test_consumed_contains(kKey) && gate->test_consumed_size() == 1,
        "step completion wrote exactly the consumption_key into the consumed cache");

    // ---------------------------------------------------------------------
    // PAIL-CASE: ConsumedCacheDiscriminates
    // ---------------------------------------------------------------------
    // ④ 의 짝. 홀로 떼면 빈 캐시에서도 참이라 조용하다 — 소유를 주장하는 것은
    // ④ 와 함께일 때의 판별력이다 (GUARDS 등재부의 shadowed 규약).
    ROW("ConsumedCacheDiscriminates", !gate->test_consumed_contains(kOtherKey),
        "a key that was never a step is not reported consumed");
  }
  rclcpp::shutdown();

  // =====================================================================
  // 2단계: observe 판. 정책 파일만 바꾼다.
  // =====================================================================
  // `PepGateNode()` 는 `NodeOptions` 를 받지 않는다 — 정책 경로는 전역
  // `rclcpp::init` 인자로만 들어온다. 그래서 같은 프로세스 안에서 컨텍스트를 한 번
  // 접었다 다시 편다. 별도 TU 로 가르지 않는 이유는 구동을 두 벌로 만들지 않기
  // 위해서다 (위 `Rig` 주석).
  const char *obs_args[] = {
      "test_gate_step_consume", "--ros-args",
      "-p", "token_provider_mode:=notoken",
      "-p", "robot_id:=tb7-stepconsume-robot",
      "-p", kTb7PolicyObserveFileArg,
  };
  rclcpp::init(static_cast<int>(sizeof(obs_args) / sizeof(obs_args[0])), obs_args);
  {
    Rig rig("l9_stepconsume_probe_observe");
    auto &ex = rig.ex;
    auto &gate = rig.gate;

    // 대조행. 정책이 observe 를 내지 못했다면 아래 행은 **enforce 를 재고 있다** —
    // 그러면 "observe 에서도 소비한다"가 참인 채로 아무것도 증명하지 못한다.
    ROW("ObserveRig", rig.discover() && gate->test_gate_mode() == "observe",
        "phase 2 runs under the observe policy fixture");
    rig.feed();

    geometry_msgs::msg::Twist twist;
    twist.linear.x = 0.3;
    auto in = rig.permit_inputs(&twist);
    const auto d = pail_pep_gate::decide(in);
    gate->apply(d, &twist, in);

    ROW("ObserveRig",
        d.state == "PERMIT" && d.begin_step && gate->test_step_active() &&
            gate->test_step_consumption_key() == kKey,
        "the step machine started identically under observe");
    const bool completed = spin_until(ex, 2500, [&]() { return !gate->test_step_active(); });
    ROW("ObserveRig", completed, "the step timer ended the step under observe too");

    // -------------------------------------------------------------------
    // PAIL-CASE: ConsumptionIsModeIndependent
    // -------------------------------------------------------------------
    // 단일사용의 쓰기가 **모드에 딸리지 않는다**는 것. observe 는 모션을 막지
    // 않을 뿐이고, 토큰이 쓰였다는 사실은 두 모드에서 같이 남아야 한다 — 여기가
    // 비면 observe 로 돌린 게이트는 같은 토큰을 무한히 다시 받는다.
    // 위 대조 세 줄이 초록인 채로 이 행만 붉는 것이 이 행의 관할이다.
    ROW("ConsumptionIsModeIndependent",
        gate->test_consumed_contains(kKey) && gate->test_consumed_size() == 1,
        "observe wrote the consumption_key into the consumed cache, same as enforce");

    rc = (g_failures == 0) ? 0 : 1;
    if (g_failures) std::printf("test_gate_step_consume: %d row(s) FAILED\n", g_failures);
  }
  rclcpp::shutdown();
  return rc;
}
