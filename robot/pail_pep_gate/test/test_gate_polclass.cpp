// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// PC-26 (implementation contract 단계 1·2): 정책 파일이 게이트의 판정 경계를 지배하는가.
//
// 이 배터리는 **RED 로 태어난다.** 도입 시점의 as-built 는 `evidence.window_ms`
// 와 `evidence.confidence_threshold` 를 policy.yaml 에서 파싱하지만(Go 쪽), 게이트가
// 실제로 쓰는 값은 ROS 파라미터에서 오고 같은 수가 런치 파일에 한 번 더 적혀 있다
// (P-19: 소비자 0건, 사본 3벌). 셋이 우연히 일치(2000·0.90)해서 지금까지 아무도
// 보지 못했다 — 정책을 조여도 게이트는 예전대로 돈다. `E-C3`(동결은 소비될 때만
// 동결이다)와 `E-W5`(문서가 코드를 실제보다 안전하게 그린다)가 겹치는 자리다.
//
// 그래서 이 배터리가 재는 것은 "게이트가 옳게 판정하는가"가 아니라 **"운영자가 쓴
// 파일이 그 판정을 움직이는가"** 다. 세 줄이 붉으면 정책은 장식이다.
//
// 대조행(PC-26d)이 함께 있는 이유: 항상 붉은 게이트는 게이트가 아니라 벽이다.
// 대조행은 수정 전에도 후에도 초록이어야 한다 — 초록이 아니면 붉은 것은 결함이
// 아니라 하네스다.
//
// 케이스 등록 규약 (implementation contract, gate_core 와 동일): `// PAIL-CASE: <name>` 주석이
// 정본이고 CG-B 가 그것을 grep 한다. 표식은 **해당 ROW() 바로 위**에 둔다 —
// 파일 머리에 목록으로 모으면 행이 삭제돼도 표식이 살아남아 CG-B 가 계속 초록을
// 내고, 그 초록은 "관측점이 있다"와 "관측점이 있었다"를 같은 바이트로 만든다.
// 표식이 붙은 행이 곧 tests/GUARANTEES.yaml 의 G-POL-* 가 소유를 주장하는 행이다.

#define PAIL_PEP_GATE_UNDER_TEST 1
#include "../src/pep_gate_node.cpp"

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
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

// 이 배터리가 쓰는 정책은 **기본값과 일부러 다르다.** 같은 수를 적으면 "정책이
// 지배한다"와 "기본값이 우연히 같다"가 같은 초록이 된다 — P-19 를 몇 달 동안
// 보이지 않게 만든 것이 정확히 그 우연이다(2000·0.90).
constexpr double kPolicyConfThreshold = 0.99;   // 노드 기본값 0.90 과 다름
constexpr int64_t kPolicyWindowMS = 250;        // 노드 기본값 2000 과 다름
// 단계 6 (D-L1 이월분): 노드 기본값 1000 과 다르다. 생산 정책의
// preconditions[safety_feed].freshness_ms 도 1000 이라, 같은 수를 쓰면
// "정책이 지배한다"와 "기본값이 우연히 같다"가 같은 초록이 된다.
constexpr int64_t kPolicySafetyStaleMS = 700;
// `evidence.window_ms` 는 이 픽스처에 **없다**. 단계 6 이전에는 그 키와
// `preconditions[id=evidence_claim].freshness_ms` 가 같은 수를 말했고 생산
// 파일에서 둘은 우연히 2000 으로 같았다 — P-19 를 몇 달 보이지 않게 만든 그
// 우연이 이 절 쌍에서 재발해 있었다. 이 배터리가 둘을 어긋나게 적어 지배하는
// 절이 `preconditions` 임을 실측한 뒤(RED_P19_STEP6.txt), 지배하지 않는 쪽을
// 스키마에서 지웠다. 되살리면 Go 가 `S16b`(unknown key)로 거부한다.
const char *kPolicyPath = "/tmp/pail_polclass_policy.yaml";
// D-L8 (§7 항3): 같은 배터리의 두 번째 정책. `revocation_classes` 절만 없다 —
// 다른 것은 바이트까지 같다. 두 절이 다르면 배너의 침묵이 "선언이 없다" 때문인지
// 다른 무엇 때문인지 갈리지 않는다 (H-B9).
const char *kPolicyPathNoRevoke = "/tmp/pail_polclass_policy_norevoke.yaml";
// `G-P6` (§8, D-L9): 지평만 바꾼 배치가 다른 seal digest 를 내는가. 세 번의 기동이
// **같은 경로**를 쓴다 — 경로를 바꾸면 봉인의 `policy_file`(경로) 키만으로도 digest
// 가 갈려서, 내용 해시(`policy_file_sha256`)를 통째로 빼도 이 줄이 초록으로 남는다.
// RQ-7 이 요구하는 것이 정확히 그 구별이다: 같은 경로 다른 바이트.
const char *kPolicyPathHorizon = "/tmp/pail_polclass_policy_horizon.yaml";
// 두 지평은 **`token_ttl_ms` 한 줄만** 다르다 (H-B9). 1시간은 이전 전 env 기본값
// (`PAIL_LEASE_TTL_MS`)이 말하던 수이고, 60초는 그것과 다른 수다.
const char *kHorizonTtlLong = "3600000";
const char *kHorizonTtlShort = "60000";

// §7 항3 이 글자 그대로 요구하는 문장. 설계서가 인용부호까지 적어 둔 것은 이
// 문장이 운영자의 grep 대상이기 때문이다 — 문면을 바꾸면 이 줄이 붉는다.
const char *kUnboundedBanner =
    "PAIL CONFIG SEAL: NOTICE — revocation class \"issuer_key\" has no bounded "
    "effective delay; it takes effect at gate restart";
// 절이 아예 없을 때의 문장. 침묵이 아니다 — 침묵은 "선언된 철회가 전부 유한하다"와
// 같은 바이트가 되고, 그 읽기가 더 안전해 **보인다**(H-B2).
const char *kUndeclaredBanner =
    "PAIL CONFIG SEAL: NOTICE — revocation_classes is not declared in this policy "
    "file; this gate cannot say whether any revocation has a bounded effective delay";

void write_policy_body(std::ostream &f, bool with_revocation, const char *horizon_ttl_ms) {
  f << "gate_mode: enforce\n"
    << "human_safety:\n"
    << "  enabled: true\n"
    << "evidence:\n"
    << "  confidence_threshold: " << kPolicyConfThreshold << "\n"
    // D-L5: 바닥은 `identity_bearing`(rank 3). TB-7 배선 픽스처는 반대로
    // `inferential` 이다 — 거기는 VISION 대조행이 배선을 재고, 여기는 그 차이
    // 자체가 관측 대상이다.
    << "  min_trust_class: identity_bearing\n"
    << "preconditions:\n"
    << "  - id: safety_feed\n"
    << "    class: must_check_live\n"
    << "    freshness_ms: " << kPolicySafetyStaleMS << "\n"
    // PC-27: 이 값이 `false` 다. 생산 정책(config/policy.yaml)은 `true` 이므로
    // 이 픽스처는 **정책이 예외를 거두면 게이트가 실제로 거둔다**를 잰다.
    << "    exempt_in_progress_step: false\n"
    << "  - id: evidence_claim\n"
    << "    class: must_check_live\n"
    << "    freshness_ms: " << kPolicyWindowMS << "\n"
    << "    exempt_in_progress_step: false\n"
    << "trust_classes:\n"
    << "  - id: identity_bearing\n"
    << "    rank: 3\n"
    << "    sources: [RFID, NFC, BARCODE]\n"
    << "  - id: inferential\n"
    << "    rank: 2\n"
    << "    sources: [VISION]\n"
    << "  - id: asserted\n"
    << "    rank: 1\n"
    << "    sources: [MANUAL]\n";
  // 게이트는 `horizon` 을 **읽지 않는다**(발급자만 읽는다, `polclass:"issuer_only"`).
  // 그래서 이 절은 판정을 하나도 움직이지 않는다 — 움직여야 하는 것은 봉인뿐이고,
  // 그것이 `G-P6` 가 재는 전부다.
  if (horizon_ttl_ms) {
    f << "horizon:\n"
      << "  token_ttl_ms: " << horizon_ttl_ms << "\n"
      << "  max_steps: 5\n";
  }
  if (!with_revocation) return;
  // 셋 중 **하나만** `unbounded` 다. 전부 unbounded 로 적으면 "무경계인 것만
  // 이름을 부른다"와 "클래스마다 한 줄씩 찍는다"가 같은 초록이 된다 (PC-29).
  f << "revocation_classes:\n"
    << "  - id: world_state\n"
    << "    mechanism: recheck_at_decision\n"
    << "    max_effective_delay_ms: 0\n"
    << "  - id: operator_key\n"
    << "    mechanism: recheck_at_use\n"
    << "    max_effective_delay_ms: 0\n"
    << "  - id: issuer_key\n"
    << "    mechanism: reload_scoped\n"
    << "    max_effective_delay_ms: unbounded\n";
}

bool write_policy_file(const char *path, bool with_revocation, const char *horizon_ttl_ms) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) return false;
  write_policy_body(f, with_revocation, horizon_ttl_ms);
  return static_cast<bool>(f);
}

bool write_policy() { return write_policy_file(kPolicyPath, true, nullptr); }

struct Captured {
  std::vector<pail_msgs::msg::GateState> gate_states;
};

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

// D-L8: seal 배너는 생성자 끝(`do_config_seal`, pep_gate_node.cpp:457)에서 stderr
// 로 나간다. `test_gate_profile.cpp:148-163` 과 같은 형태로 그 구간만 파일로
// 돌린다 — 배터리의 나머지 출력(stdout 의 ROW)은 건드리지 않는다.
std::vector<std::string> capture_seal_lines(const char *policy_path, const char *log_path) {
  const std::string policy_arg = std::string("policy_file:=") + policy_path;
  const std::vector<std::string> arg_strings = {
      "test_gate_polclass_seal", "--ros-args",
      "-p", "token_provider_mode:=notoken",
      "-p", "robot_id:=polclass-seal-robot",
      "-p", policy_arg,
  };
  std::vector<const char *> argv;
  argv.reserve(arg_strings.size());
  for (const auto &s : arg_strings) argv.push_back(s.c_str());
  rclcpp::init(static_cast<int>(argv.size()), argv.data());

  std::fflush(stderr);
  const int saved = dup(2);
  const int fd = open(log_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
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

  std::vector<std::string> lines;
  std::ifstream f(log_path);
  std::string line;
  while (std::getline(f, line)) lines.push_back(line);
  return lines;
}

bool has_line(const std::vector<std::string> &lines, const std::string &needle) {
  for (const auto &l : lines) {
    if (l.find(needle) != std::string::npos) return true;
  }
  return false;
}

// `G-P6`: 봉인 한 줄에서 digest 만 떼어낸다. 못 찾으면 빈 문자열이 아니라
// 눈에 띄는 표를 돌려준다 — 두 번의 "못 읽었다"는 서로 같고, 그 같음이
// "두 배치가 같은 digest 를 냈다"가 아니라 **"디코더가 죽었다"** 를 뜻한다.
// 두 뜻이 같은 붉은 줄로 도착하지 않도록 판정에서 따로 본다 (H-B2).
const char *kDigestUnread = "(not-read)";

std::string seal_digest(const std::vector<std::string> &lines) {
  const std::string key = "digest=";
  for (const auto &l : lines) {
    if (l.find("PAIL CONFIG SEAL: v") == std::string::npos) continue;
    const auto at = l.find(key);
    if (at == std::string::npos) continue;
    const auto start = at + key.size();
    const auto end = l.find(' ', start);
    return l.substr(start, end == std::string::npos ? std::string::npos : end - start);
  }
  return kDigestUnread;
}

void spin_ms(rclcpp::executors::SingleThreadedExecutor &ex, int ms) {
  const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  while (std::chrono::steady_clock::now() < until) {
    ex.spin_some();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
}

}  // namespace

int main() {
  // One communication contract (0.2.0-preview.40): no selecting setting; this fixture injects a non-gRPC
  // (non-reporting) test provider.
  unsetenv("PAIL_CORE_COMM_CONTRACT");
  if (!write_policy()) {
    std::printf("FAIL: Fixture — could not write %s\n", kPolicyPath);
    return 1;
  }

  if (!write_policy_file(kPolicyPathNoRevoke, false, nullptr)) {
    std::printf("FAIL: Fixture — could not write %s\n", kPolicyPathNoRevoke);
    return 1;
  }

  setenv("PAIL_PROFILE", "dev", 1);
  setenv("PAIL_SEAL_DEADLINE_MS", "50", 1);
  setenv("PAIL_GRPC_TLS", "off", 1);
  setenv("PAIL_GRPC_INSECURE_ACK", "i-accept-plaintext", 1);

  // ── D-L8 (§7 항3): 철회 클래스 배너 ────────────────────────────────────────
  //
  // 배너를 이 배터리의 본 노드에서 재지 않는 이유: 무경계 선언이 **있는** 트리
  // 하나만으로는 "무경계일 때 말한다"와 "언제나 그 줄을 찍는다"가 구별되지
  // 않는다. 선언이 없는 두 번째 정책이 그 구별을 만든다.
  {
    const auto declared = capture_seal_lines(kPolicyPath, "/tmp/pail_polclass_seal_declared.log");
    const auto absent =
        capture_seal_lines(kPolicyPathNoRevoke, "/tmp/pail_polclass_seal_absent.log");

    // PAIL-CASE: PC-28
    ROW("PC-28", has_line(declared, kUnboundedBanner),
        "unbounded 로 선언된 철회 클래스가 seal 배너에 사실 문장으로 나온다 (§7 항3)");
    ROW("PC-29",
        !has_line(declared, "revocation class \"world_state\"") &&
            !has_line(declared, "revocation class \"operator_key\""),
        "유한 상한을 선언한 클래스는 배너에 나오지 않는다 — 무경계인 것만 이름을 부른다");
    ROW("PC-28b",
        has_line(absent, kUndeclaredBanner) && !has_line(absent, kUnboundedBanner),
        "절이 아예 없으면 '모른다'고 말한다 — 침묵은 '전부 유한하다'와 같은 바이트다 (H-B2)");
  }

  // ── G-P6 (§8, D-L9): 권한 지평이 봉인에 덮인다 ─────────────────────────────
  //
  // 지평의 출처가 env 였을 때, 운영자가 토큰 수명을 1시간에서 1분으로 조여도
  // 배치의 seal digest 는 한 비트도 움직이지 않았다 — 봉인이 "이 배치는 이런
  // 권한을 내준다"를 말하지 못했다. 이전(`D-L9`)이 일어났다는 것을 값의 일치로는
  // 증명할 수 없다(이전 전에도 두 수는 우연히 같았다, `E-W5`). 기계 판정은
  // **다른 지평이 다른 digest 를 낸다** 하나다.
  //
  // 세 번 기동한다. 셋 다 같은 경로이고, 1↔2 는 `token_ttl_ms` 한 줄만 다르며,
  // 3 은 1 의 바이트를 그대로 되쓴다. 대조행이 없으면 "지평이 digest 를
  // 움직인다"와 "digest 가 매 기동 달라진다"가 같은 초록이다.
  {
    const bool wrote_a = write_policy_file(kPolicyPathHorizon, true, kHorizonTtlLong);
    const auto d_long =
        seal_digest(capture_seal_lines(kPolicyPathHorizon, "/tmp/pail_polclass_seal_h1.log"));
    const bool wrote_b = write_policy_file(kPolicyPathHorizon, true, kHorizonTtlShort);
    const auto d_short =
        seal_digest(capture_seal_lines(kPolicyPathHorizon, "/tmp/pail_polclass_seal_h2.log"));
    const bool wrote_c = write_policy_file(kPolicyPathHorizon, true, kHorizonTtlLong);
    const auto d_long_again =
        seal_digest(capture_seal_lines(kPolicyPathHorizon, "/tmp/pail_polclass_seal_h3.log"));

    const bool readable = d_long != kDigestUnread && d_short != kDigestUnread &&
                          d_long_again != kDigestUnread && d_long != "(unavailable)" &&
                          d_short != "(unavailable)";
    // PAIL-CASE: G-P6-fixture
    ROW("G-P6-fixture", wrote_a && wrote_b && wrote_c && readable,
        "세 기동 모두 봉인 한 줄을 남겼고 digest 를 읽어냈다 — 못 읽은 digest 두 개는 "
        "서로 같고, 그 같음이 아래 줄을 조용히 붉힌다 (H-B2)");

    {
      char detail[320];
      std::snprintf(detail, sizeof(detail),
                    "token_ttl_ms %s vs %s at the SAME policy path => digest %.16s… vs "
                    "%.16s…; equal means the horizon is outside the seal",
                    kHorizonTtlLong, kHorizonTtlShort, d_long.c_str(), d_short.c_str());
      // PAIL-CASE: G-P6
      ROW("G-P6", readable && d_long != d_short, detail);
    }
    {
      char detail[320];
      std::snprintf(detail, sizeof(detail),
                    "control: rewriting the first horizon byte-for-byte returns the first "
                    "digest (%.16s… vs %.16s…) — otherwise the row above is free",
                    d_long.c_str(), d_long_again.c_str());
      // PAIL-CASE: G-P6-control
      ROW("G-P6-control", readable && d_long == d_long_again, detail);
    }
  }

  const std::string policy_arg = std::string("policy_file:=") + kPolicyPath;
  const char *args[] = {
      "test_gate_polclass", "--ros-args",
      "-p", "token_provider_mode:=notoken",
      "-p", "robot_id:=polclass-robot",
      "-p", policy_arg.c_str(),
  };
  rclcpp::init(static_cast<int>(sizeof(args) / sizeof(args[0])), args);
  int rc = 1;
  {
    auto gate = std::make_shared<PepGateNode>();
    auto probe = std::make_shared<rclcpp::Node>("polclass_probe");

    Captured cap;
    auto gate_sub = probe->create_subscription<pail_msgs::msg::GateState>(
        "/pail/gate_state", 50,
        [&cap](pail_msgs::msg::GateState::SharedPtr m) { cap.gate_states.push_back(*m); });
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
             gate_sub->get_publisher_count() >= 1;
    });
    ROW("Discovery", discovered, "gate matched probe pubs/subs");
    if (!discovered) {
      // 발견이 실패하면 아래 줄들의 붉음은 P-19 가 아니라 배선을 말한다.
      // 두 뜻이 같은 붉은 줄로 도착하지 않도록 여기서 끊는다 (H-B2).
      rclcpp::shutdown();
      std::printf("test_gate_polclass: discovery failed — remaining rows not measured\n");
      return 1;
    }

    auto publish_safety = [&](const char *level) {
      pail_msgs::msg::SafetyState s;
      s.stamp = probe->now();
      s.level = level;
      s.source = "POLCLASS_HARNESS";
      s.detail = "injected";
      safety_pub->publish(s);
    };
    // D-L5: `source` 는 이제 판정 입력이다. 픽스처가 그것을 인자로 받지 않으면
    // 신뢰 클래스 행과 신뢰도 행이 같은 자극을 공유하게 되고, 둘 중 하나를
    // 지워도 다른 하나가 대신 걸린다 (H-B9 의 픽스처판, 2026-08-22 UIR 교훈 3).
    auto publish_evidence_src = [&](const char *object_id, float conf, const char *source) {
      pail_msgs::msg::Evidence e;
      e.stamp = probe->now();
      e.source = source;
      e.object_id = object_id;
      e.confidence = conf;
      evidence_pub->publish(e);
    };
    auto publish_evidence = [&](const char *object_id, float conf) {
      publish_evidence_src(object_id, conf, "RFID");
    };
    auto valid_grpc_token = [](pail_pep_gate::GateInputs &in) {
      in.supplier.provider_mode = "grpc";
      in.supplier.use_token_service = false;
      in.supplier.grpc_built = true;
      in.token_view.ok = true;
      in.token_view.status = "OK";
      in.token_view.chain_id = "chain-polclass";
      in.token_view.token_id = "tok-polclass";
      in.token_view.current_subgraph_hash = "abcdabcdabcdabcdabcdabcdabcdabcd";
      in.verify_ok = true;
      in.verify_reason.clear();
      in.token_info.target_object_id = "pallet-7";
      in.token_info.action_type = pail_pep_gate::kActionMove;
      in.token_info.max_linear_speed_mps = 1.0;
      in.token_info.max_angular_speed_rps = 1.0;
      in.token_info.not_after_unix_ms = in.now_ms + 30000;
      in.token_info.subgraph_snapshot_hash = "abcdabcdabcdabcdabcdabcdabcdabcd";
      // PC-27 은 진행 중 스텝의 신원으로 예외를 주장한다 — 그 신원은 envelope
      // 이름이 아니라 소비 키다 ([OR3/X12②]).
      in.token_info.consumption_key = "ck-polclass";
      in.token_consumed = false;
    };
    geometry_msgs::msg::Twist twist;
    twist.linear.x = 0.3;

    publish_safety("OK");
    spin_ms(ex, 200);

    // -----------------------------------------------------------------------
    // PC-24 — 증거를 한 번도 못 받은 게이트 (D-L7 §6.4, O-3 의 첫 값)
    // -----------------------------------------------------------------------
    // **이 행은 반드시 첫 증거보다 먼저 돈다.** 한 번 발행하면 부재 상태는 이
    // 프로세스에서 다시 만들 수 없다 — 뒤로 옮기면 재려던 상태를 없앤 뒤 그
    // 부재를 재게 된다.
    //
    // 수정 전에는 생성자가 `last_evidence_wall_ms_` 에 현재 시각을 찍어서, 증거를
    // 한 번도 못 받은 게이트가 "방금 받았다"로 읽혔고 사유는 물건이 다르다는
    // 뜻의 `ERR_TARGET_MISMATCH` 로 나갔다. 운영자는 로봇을 다시 정렬하러 간다 —
    // 정렬은 아무것도 고치지 못한다.
    bool absent_ever_received = true;
    {
      auto in_absent = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
      absent_ever_received = in_absent.evidence.ever_received;
      valid_grpc_token(in_absent);
      const auto d_absent = pail_pep_gate::decide(in_absent);
      char detail[256];
      std::snprintf(detail, sizeof(detail),
                    "no evidence ever published => expected BLOCK/ERR_NO_EVIDENCE, "
                    "got %s/%s (ever_received=%s)",
                    d_absent.state.c_str(), d_absent.reason.c_str(),
                    absent_ever_received ? "true" : "false");
      // PAIL-CASE: EvidenceAbsent
      ROW("EvidenceAbsent",
          d_absent.state == "BLOCK" && d_absent.reason == "ERR_NO_EVIDENCE" &&
              !absent_ever_received,
          detail);

      // ---------------------------------------------------------------------
      // PC-24b — 부재는 **입력 층에서도** 부재다 (단계 7 변형 DF-P8 이 세운 행)
      // ---------------------------------------------------------------------
      // 위 행은 판정만 잰다. 그것만으로는 생성자가 `last_evidence_wall_ms_` 에
      // 현재 시각을 도로 찍어도 **아무 줄도 안 붉는다** — `ever_received` 조기
      // 거절이 대신 막아 주기 때문이다(2026-08-23 실측: DF-P8 전 배터리 초록).
      // 그러면 "받은 적 없다"를 지키는 방어가 둘인데 증인은 하나뿐이고, 하나가
      // 죽어도 초록이 유지된다. 이 행이 재는 것은 판정이 아니라 **표현**이다:
      // 받은 적 없는 게이트는 받은 시각을 들고 있으면 안 된다. 그 시각이 살아
      // 있으면 창 산술이 "방금 받았다"로 읽고, 조기거절이 사라지는 날 사유는
      // `ERR_TARGET_MISMATCH` 로 나가 운영자를 정렬하러 보낸다(P-8 의 형상).
      char rep[256];
      std::snprintf(rep, sizeof(rep),
                    "never received, yet the gate carries received_ms=%lld "
                    "(expected 0 — absence must read as absence at the input layer)",
                    static_cast<long long>(in_absent.evidence.received_ms));
      // PAIL-CASE: EvidenceAbsentCarriesNoTimestamp
      ROW("EvidenceAbsentCarriesNoTimestamp",
          !absent_ever_received && in_absent.evidence.received_ms == 0, rep);
    }

    // -----------------------------------------------------------------------
    // PC-26a — 정책의 confidence_threshold 가 게이트의 한계값이다
    // -----------------------------------------------------------------------
    // 값을 직접 재는 이유: 판정만 재면 "정책이 안 읽혔다"와 "판정 논리가 틀렸다"가
    // 같은 붉은 줄로 온다. 값과 판정을 따로 재면 어느 쪽인지 말할 수 있다.
    publish_evidence("pallet-7", 0.95f);
    spin_ms(ex, 100);
    auto in_probe = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    {
      char detail[256];
      std::snprintf(detail, sizeof(detail),
                    "policy said confidence_threshold=%.2f; gate is using %.2f",
                    kPolicyConfThreshold, in_probe.limits.evidence_conf_threshold);
      // PAIL-CASE: PolicyGovernsThreshold
      ROW("PolicyGovernsThreshold",
          in_probe.limits.evidence_conf_threshold == kPolicyConfThreshold, detail);
    }

    // -----------------------------------------------------------------------
    // PC-26b — 증거 창의 출처는 preconditions[evidence_claim].freshness_ms 다
    // -----------------------------------------------------------------------
    // 250 은 단계 6 이전의 두 출처(ROS 파라미터 기본값 · `evidence.window_ms`)가
    // 말하던 2000 과 다르다. 이 행이 붉으면 게이트가 정책이 아닌 무언가를 읽고
    // 있는 것이고, 그때 `preconditions` 절은 봉인에 들어가면서도 아무것도
    // 지배하지 않는다 — 읽히지 않는 선언이 검토된 선언처럼 보인다.
    {
      char detail[256];
      std::snprintf(detail, sizeof(detail),
                    "preconditions[evidence_claim].freshness_ms=%lld (the pre-단계6 "
                    "sources both said 2000); gate is using %lld",
                    static_cast<long long>(kPolicyWindowMS),
                    static_cast<long long>(in_probe.limits.evidence_window_ms));
      // PAIL-CASE: PolicyGovernsWindow
      ROW("PolicyGovernsWindow",
          in_probe.limits.evidence_window_ms == kPolicyWindowMS, detail);
    }

    // -----------------------------------------------------------------------
    // PC-28 — 안전 피드의 신선도도 정책에서 온다 (D-L1 이월분, §3.1 넷째 줄)
    // -----------------------------------------------------------------------
    // 이 값은 단계 6 이전에 ROS 파라미터 `safety_stale_ms` 에서 왔다. 파라미터의
    // 기본값과 생산 정책의 선언이 **둘 다 1000** 이라, 운영자가 정책을 조여도
    // 게이트는 예전 창으로 계속 돌았다. 700 은 그 1000 과 다르다. PC-26b 와
    // **다른 절**을 재므로 한쪽을 지워도 다른 쪽이 대신 걸리지 않는다 (H-B9).
    {
      char detail[256];
      std::snprintf(detail, sizeof(detail),
                    "preconditions[safety_feed].freshness_ms=%lld; gate is using %lld",
                    static_cast<long long>(kPolicySafetyStaleMS),
                    static_cast<long long>(in_probe.limits.safety_stale_ms));
      // PAIL-CASE: PolicyGovernsSafetyStale
      ROW("PolicyGovernsSafetyStale",
          in_probe.limits.safety_stale_ms == kPolicySafetyStaleMS, detail);
    }

    // -----------------------------------------------------------------------
    // PC-26c — 판정 경계가 실제로 움직인다 (0.95 < 정책 0.99 => BLOCK)
    // -----------------------------------------------------------------------
    // PC-26d 와 **신뢰도 하나만** 다르다. 두 줄이 다른 것을 함께 바꾸면 어느
    // 조건이 판정을 뒤집었는지 말할 수 없다 (H-B9).
    cap = Captured{};
    auto in_below = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    valid_grpc_token(in_below);
    const auto d_below = pail_pep_gate::decide(in_below);
    {
      char detail[256];
      std::snprintf(detail, sizeof(detail),
                    "evidence 0.95 under policy threshold %.2f => expected BLOCK/"
                    "ERR_TARGET_MISMATCH, got %s/%s",
                    kPolicyConfThreshold, d_below.state.c_str(), d_below.reason.c_str());
      // PAIL-CASE: PolicyMovesDecision
      ROW("PolicyMovesDecision",
          d_below.state == "BLOCK" && d_below.reason == "ERR_TARGET_MISMATCH" &&
              !d_below.forward,
          detail);
    }

    // -----------------------------------------------------------------------
    // PC-26d — 대조행: 정책 한계값 위의 증거는 통과한다
    // -----------------------------------------------------------------------
    // 수정 전에도 후에도 초록이어야 한다. 이 줄이 붉으면 위의 붉음은 P-19 가
    // 아니라 하네스를 말하는 것이다.
    publish_evidence("pallet-7", 0.995f);
    spin_ms(ex, 100);
    auto in_above = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    valid_grpc_token(in_above);
    const auto d_above = pail_pep_gate::decide(in_above);
    {
      char detail[256];
      std::snprintf(detail, sizeof(detail),
                    "control: evidence 0.995 above policy threshold %.2f => expected "
                    "PERMIT/OK, got %s/%s",
                    kPolicyConfThreshold, d_above.state.c_str(), d_above.reason.c_str());
      ROW("PolicyMovesDecision", d_above.state == "PERMIT" && d_above.reason == "OK",
          detail);
    }

    // -----------------------------------------------------------------------
    // PC-21 — 신뢰 클래스가 바닥에 못 미치면 막는다 (D-L5 §6.2)
    // -----------------------------------------------------------------------
    // PC-26d 와 **source 하나만** 다르다: 둘 다 0.995 로 신뢰도 바닥 위에 있고,
    // 물건도 같다. 신뢰도가 높은 추론(VISION 0.995)은 신원 응답이 아니라는 것 —
    // 두 값이 재는 것이 다르다는 주장이 이 한 줄에 걸린다.
    publish_evidence_src("pallet-7", 0.995f, "VISION");
    spin_ms(ex, 100);
    auto in_vision = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    {
      const int vision_rank = in_vision.evidence.trust_rank;
      const int floor_rank = in_vision.limits.min_trust_rank;
      valid_grpc_token(in_vision);
      const auto d_vision = pail_pep_gate::decide(in_vision);
      char detail[320];
      std::snprintf(detail, sizeof(detail),
                    "VISION resolved to rank=%d against floor rank=%d "
                    "(policy floor identity_bearing) => expected BLOCK/"
                    "ERR_EVIDENCE_TRUST_CLASS, got %s/%s",
                    vision_rank, floor_rank, d_vision.state.c_str(),
                    d_vision.reason.c_str());
      // PAIL-CASE: TrustClassBelowFloor
      ROW("TrustClassBelowFloor",
          d_vision.state == "BLOCK" && d_vision.reason == "ERR_EVIDENCE_TRUST_CLASS" &&
              !d_vision.forward,
          detail);
    }

    // -----------------------------------------------------------------------
    // PC-21b — 바닥은 **닿으면 통과**다 (단계 7 변형 DF-P5 가 세운 행)
    // -----------------------------------------------------------------------
    // PC-21 은 바닥 *아래*(VISION rank 2)만 잰다. 그래서 비교를 `<` 에서 `<=` 로
    // 한 칸 옮겨도 PC-21 은 초록이고, PC-22 도 초록이다 — PC-22 의 증거는 신뢰도
    // 미달이라 신뢰등급 검사에 **도달하지 못한다**(사유 순서: 신뢰도가 먼저).
    // 2026-08-23 실측: 그 변형에서 붉은 것은 `ExemptionFollowsPolicy` 와
    // `PolicyMovesDecision` 뿐이었고, 둘 다 주제가 다른 행이다. 즉 경계의 유일한
    // 증인이 **우연**이었다 — 그 두 행을 다른 이유로 손보는 날 경계는 아무도 안
    // 재는 채 남는다. 이 행이 재는 것은 경계 그 자체다: 바닥에 정확히 닿은 신원
    // 응답(RFID rank 3 = floor 3)은 신뢰등급을 이유로 거절되면 안 된다.
    publish_evidence_src("pallet-7", 0.995f, "RFID");
    spin_ms(ex, 100);
    auto in_at_floor = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    {
      const int at_rank = in_at_floor.evidence.trust_rank;
      const int floor_rank = in_at_floor.limits.min_trust_rank;
      valid_grpc_token(in_at_floor);
      const auto d_at_floor = pail_pep_gate::decide(in_at_floor);
      char detail[320];
      std::snprintf(detail, sizeof(detail),
                    "RFID rank=%d sits exactly on floor rank=%d => the floor is "
                    "inclusive, expected PERMIT/OK, got %s/%s",
                    at_rank, floor_rank, d_at_floor.state.c_str(),
                    d_at_floor.reason.c_str());
      // 등급 동일을 함께 판정한다: 어휘가 바뀌어 rank 가 바닥에서 떨어지면 이
      // 행은 경계를 재지도 못한 채 초록이 된다(`H-B9` 의 픽스처판).
      // PAIL-CASE: TrustClassFloorIsInclusive
      ROW("TrustClassFloorIsInclusive",
          at_rank == floor_rank && d_at_floor.state == "PERMIT" &&
              d_at_floor.reason == "OK",
          detail);
    }

    // -----------------------------------------------------------------------
    // PC-22 — 인접행: 바닥을 넘은 증거의 신뢰도 미달은 여전히 신뢰도 사유다
    // -----------------------------------------------------------------------
    // PC-26c 와 자극이 같아 보이지만 재는 주장이 다르다. PC-26c 는 신뢰 클래스가
    // 없던 시절에 "정책이 판정을 움직인다"를 재려고 쓰였고, 이 줄은 **새 규칙이
    // 옛 규칙을 삼키지 않았다**를 잰다 — 집행이 착지한 뒤 이 줄이
    // ERR_EVIDENCE_TRUST_CLASS 로 바뀌면 두 방어는 사실 하나다.
    publish_evidence_src("pallet-7", 0.95f, "RFID");
    spin_ms(ex, 100);
    auto in_rank_ok = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    {
      valid_grpc_token(in_rank_ok);
      const auto d_rank_ok = pail_pep_gate::decide(in_rank_ok);
      char detail[320];
      std::snprintf(detail, sizeof(detail),
                    "RFID rank=%d meets floor rank=%d but confidence 0.95 < %.2f => "
                    "expected BLOCK/ERR_TARGET_MISMATCH (not the trust-class reason), "
                    "got %s/%s",
                    in_rank_ok.evidence.trust_rank, in_rank_ok.limits.min_trust_rank,
                    kPolicyConfThreshold, d_rank_ok.state.c_str(),
                    d_rank_ok.reason.c_str());
      // PAIL-CASE: TrustClassDoesNotSwallowConfidence
      ROW("TrustClassDoesNotSwallowConfidence",
          d_rank_ok.state == "BLOCK" && d_rank_ok.reason == "ERR_TARGET_MISMATCH",
          detail);
    }

    // -----------------------------------------------------------------------
    // PC-23 — 어휘 밖 source 는 rank 0 이고, rank 0 은 "아무거나"가 아니다
    // -----------------------------------------------------------------------
    // 정책의 trust_classes 는 닫힌 어휘다. 표에 없는 이름이 오면 노드는 rank 0 을
    // 준다 — 미사상은 최상위 사상이 아니라 **거절**이어야 한다 ([OR3/X26]).
    // 신뢰도는 대조행과 같은 0.995 로 둔다: 붉음이 신뢰도에서 오면 안 된다.
    publish_evidence_src("pallet-7", 0.995f, "LIDAR");
    spin_ms(ex, 100);
    auto in_unmapped = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    {
      valid_grpc_token(in_unmapped);
      const auto d_unmapped = pail_pep_gate::decide(in_unmapped);
      char detail[320];
      std::snprintf(detail, sizeof(detail),
                    "source LIDAR is outside the policy vocabulary => rank=%d "
                    "(floor %d); expected BLOCK/ERR_EVIDENCE_TRUST_CLASS, got %s/%s",
                    in_unmapped.evidence.trust_rank, in_unmapped.limits.min_trust_rank,
                    d_unmapped.state.c_str(), d_unmapped.reason.c_str());
      // PAIL-CASE: TrustClassUnmappedSource
      ROW("TrustClassUnmappedSource",
          d_unmapped.state == "BLOCK" &&
              d_unmapped.reason == "ERR_EVIDENCE_TRUST_CLASS" &&
              in_unmapped.evidence.trust_rank == 0,
          detail);
    }

    // -----------------------------------------------------------------------
    // PC-25 — 낡음은 부재와 **다른 경로**로 도착한다 (D-L7 §6.4, O-3 의 셋째 값)
    // -----------------------------------------------------------------------
    // 사유는 PC-24 와 같은 ERR_NO_EVIDENCE 다. 그것만 재면 두 값은 구분되지
    // 않는다 — 구분은 `ever_received` 에만 있고, 그래서 이 줄은 PC-24 가 잡아 둔
    // 값과 **짝으로** 판정한다. 둘이 같은 값을 내면 D-L7 은 도로 두 값이다.
    publish_evidence_src("pallet-7", 0.995f, "RFID");
    spin_ms(ex, 100);
    spin_ms(ex, 400);  // 정책 창 250ms 를 넘긴다
    auto in_stale = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    {
      valid_grpc_token(in_stale);
      const auto d_stale = pail_pep_gate::decide(in_stale);
      char detail[320];
      std::snprintf(detail, sizeof(detail),
                    "evidence %lldms old against window %lldms => expected BLOCK/"
                    "ERR_NO_EVIDENCE with ever_received=true (absent row measured "
                    "%s), got %s/%s ever_received=%s",
                    static_cast<long long>(in_stale.now_ms - in_stale.evidence.received_ms),
                    static_cast<long long>(in_stale.limits.evidence_window_ms),
                    absent_ever_received ? "true" : "false", d_stale.state.c_str(),
                    d_stale.reason.c_str(),
                    in_stale.evidence.ever_received ? "true" : "false");
      // PAIL-CASE: EvidenceStaleDistinctFromAbsent
      ROW("EvidenceStaleDistinctFromAbsent",
          d_stale.state == "BLOCK" && d_stale.reason == "ERR_NO_EVIDENCE" &&
              in_stale.evidence.ever_received && !absent_ever_received,
          detail);
    }

    // -----------------------------------------------------------------------
    // PC-27 — 정책이 예외를 거두면 게이트가 실제로 거둔다 (D-L3, §9.2)
    // -----------------------------------------------------------------------
    // 진행 중 스텝은 저하된 안전 피드를 통과할 수 있다 — 단 정책이 그 예외를
    // 줬을 때만. 이 픽스처의 preconditions[safety_feed].exempt_in_progress_step
    // 은 `false` 이므로 예외는 없다. 지금은 예외가 정책과 무관하게 코드에
    // 박혀 있어 이 줄이 PERMIT 을 낸다.
    //
    // 신원은 envelope 이름이 아니라 소비 키로 맞춘다 ([OR3/X12②]) — 그래야 이
    // 줄이 재는 것이 "예외가 정책을 따르는가"이지 "예외가 애초에 안 걸리는가"가
    // 아니다.
    publish_evidence_src("pallet-7", 0.995f, "RFID");
    publish_safety("WARN");
    spin_ms(ex, 150);
    auto in_exempt = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);
    {
      valid_grpc_token(in_exempt);
      in_exempt.step_active = true;
      in_exempt.step_consumption_key = "ck-polclass";
      const auto d_exempt = pail_pep_gate::decide(in_exempt);
      char detail[320];
      std::snprintf(detail, sizeof(detail),
                    "policy withdrew the in-progress-step exemption "
                    "(limits.safety_exempt_in_progress_step=%s) yet the step claims "
                    "it under a WARN feed => expected BLOCK/ERR_SAFETY_STALE, got %s/%s",
                    in_exempt.limits.safety_exempt_in_progress_step ? "true" : "false",
                    d_exempt.state.c_str(), d_exempt.reason.c_str());
      ROW("ExemptionFollowsPolicy",
          d_exempt.state == "BLOCK" && d_exempt.reason == "ERR_SAFETY_STALE" &&
              !in_exempt.limits.safety_exempt_in_progress_step,
          detail);
    }

    ex.remove_node(gate);
    ex.remove_node(probe);
    rc = (g_failures == 0) ? 0 : 1;
    if (g_failures) std::printf("test_gate_polclass: %d row(s) FAILED\n", g_failures);
  }
  rclcpp::shutdown();
  return rc;
}
