// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// L-10 (TB-7 계열, L3): 단일사용 소비 캐시의 **조회 쪽**을 관측한다.
//
// 왜 새 배터리인가 (2026-08-31 FAIL-first 실측, /tmp/l10_ff.log):
//   `pep_gate_node.cpp` 의
//     in.token_consumed = consumed_token_ids_.count(in.token_info.consumption_key) > 0;
//   를 `false` 로 굳히면 **소비된 토큰이 영원히 미소비로 읽힌다** — 단일사용
//   방어의 우회다. 그런데 그 변형은 23개 배터리 전건 `100% tests passed` 를
//   남겼다(산출물 해시 005c0b70188749b7 → 13cb9f0ccd60bbd0, 즉 재지 못한 것이
//   아니라 **재고도 못 본 것**). L-9 가 닫은 것은 쓰기 쪽(`mark_consumed`)뿐이고
//   읽는 쪽은 그때 위임으로 남겨 두었다 — 이 배터리가 그 위임을 닫는다.
//
// 왜 기존 TB-7 리그로는 못 닿았는가:
//   그 줄은 네 조건이 **동시에** 참일 때만 실행된다 — (가) 명령 경로 + 비ESTOP,
//   (나) grpc 모드, (다) `StrictVerifyActiveTokenView` 통과, (라) 세계 해시 일치.
//   기존 배터리는 전부 `build_inputs` 가 돌려준 뒤 검증 결과를 **주입**해서
//   `decide` 를 태운다(implementation contract 불변 3). 주입은 이 줄보다 뒤에 일어나므로
//   그 자리를 영원히 건너뛴다. 그래서 여기서는 주입하지 않고 네 조건을 **실물로**
//   세운다: 실 ed25519 키쌍으로 서명한 토큰을 **진짜 gRPC 이슈어**가 내놓고,
//   신뢰근은 **서명된 키링 번들**(제품 기본 신뢰 경로)로 싣는다. 제품
//   `GrpcTokenProvider` → `StrictVerifyActiveTokenView` → 조회면이 그대로 돈다.
//
// **관측의 정직성 (H-B2):**
//   "조회면에 닿았고 미소비였다" 와 "조회면에 닿지도 못했다" 는 둘 다
//   `token_consumed == false` 다 — 같은 바이트다. 그래서 이 배터리의 판정은
//   **단계 완료 뒤의 `true`** 가 진다: `true` 는 그 줄이 실행되지 않고는 나올 수
//   없는 값이다. 완료 전의 `false` 는 홀로 서면 빈 캐시에서도 참이라 조용하다 —
//   ④ 의 짝으로만 의미가 있다(L-9 의 `ConsumedCacheDiscriminates` 와 같은 규약).
//   그 위의 두 대조행은 (다)·(라) 가 실제로 성립했는지를 따로 세운다. 대조행이
//   붉으면 아래 두 행의 초록은 "관측했다" 가 아니라 "도달하지 못했다" 를 뜻한다.
//
// 케이스 등록 규약 : `// PAIL-CASE: <name>` 은 해당 ROW() **바로 위**에
// 둔다. 파일 머리에 모으면 행이 지워져도 표식이 살아남아 CG-B 가 계속 초록을 낸다.

#define PAIL_PEP_GATE_UNDER_TEST 1
#include "../src/pep_gate_node.cpp"

#include "tb7_policy_fixture.hpp"

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_builder.h>

#include "pail.pb.h"
#include "token_service.grpc.pb.h"
#include "token_service.pb.h"

#include <sodium.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
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

const char kRobotId[] = "tb7-lookup-robot";
const char kChainId[] = "chain-l10";
const char kTokenId[] = "tok-l10";
const char kKeyId[] = "l10-issuer-1";
const char kObjectId[] = "pallet-7";

// 단계 데드라인의 출처가 아니라 **길이**만 쓰는 값. 조회를 두 번 하는 사이에
// 단계가 끝나야 하므로 짧게 잡는다.
constexpr double kMaxDurationSec = 0.3;

std::string b64(const unsigned char *data, size_t len) {
  std::string out(sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL), '\0');
  sodium_bin2base64(&out[0], out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
  out.resize(std::strlen(out.c_str()));
  return out;
}

void write_file(const std::string &path, const std::string &content) {
  std::ofstream f(path, std::ios::trunc);
  f << content;
}

std::string temp_dir() {
  char tmpl[] = "/tmp/l10lookup.XXXXXX";
  char *d = mkdtemp(tmpl);
  if (d == nullptr) {
    std::fprintf(stderr, "mkdtemp failed\n");
    std::exit(2);
  }
  return std::string(d);
}

// 제품 기본 신뢰 경로(KM2-1 §6.3)를 그대로 쓴다. `unsigned-dev` 로 우회하면
// 이 배터리는 배치가 실제로 쓰는 적재 경로를 시험하지 않게 된다.
void install_keyring_bundle(const std::string &dir, const unsigned char *issuer_pub) {
  unsigned char root_pk[crypto_sign_PUBLICKEYBYTES], root_sk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(root_pk, root_sk);

  const std::string payload =
      "{\"bundle_version\":1,\"issued_at_unix\":" + std::to_string((long long)std::time(nullptr)) +
      ",\"expires_at_unix\":" + std::to_string((long long)std::time(nullptr) + 24 * 3600) +
      ",\"keys\":[{\"key_id\":\"" + kKeyId + "\",\"ed25519_public_key_base64\":\"" +
      b64(issuer_pub, crypto_sign_PUBLICKEYBYTES) + "\",\"role\":\"issuer\"}]}";

  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, nullptr,
                       reinterpret_cast<const unsigned char *>(payload.data()),
                       payload.size(), root_sk);

  write_file(dir + "/keyring_bundle.json",
             "{\"schema_version\":1,\"payload_b64\":\"" +
                 b64(reinterpret_cast<const unsigned char *>(payload.data()), payload.size()) +
                 "\",\"root_key_id\":\"root-l10\",\"root_sig_b64\":\"" + b64(sig, sizeof sig) +
                 "\"}");
  write_file(dir + "/root.pub", b64(root_pk, sizeof root_pk));

  setenv("PAIL_KEYRING_BUNDLE", (dir + "/keyring_bundle.json").c_str(), 1);
  setenv("PAIL_ROOT_PUBKEY_FILE", (dir + "/root.pub").c_str(), 1);
  setenv("PAIL_KEYRING_STATE", (dir + "/keyring_bundle.state.json").c_str(), 1);
}

// 정직한 이슈어. `test_token_id_binding` 의 LyingIssuer 와 반대편 — 여기서
// 시험하려는 것은 봉투의 거짓말이 아니라 **검증을 통과한 뒤** 게이트가 자기
// 소비 캐시를 어떻게 읽는가이므로, 이슈어는 규격대로 답해야 한다.
class HonestIssuer final : public pail::token::v1::TokenService::Service {
 public:
  std::atomic<bool> delay_attest{false}, attest_inflight{false};
  std::string action_token_bytes;
  std::string signature;
  std::string subgraph_hash;

  grpc::Status GetActiveToken(grpc::ServerContext *context,
                              const pail::token::v1::GetActiveTokenRequest *,
                              pail::token::v1::GetActiveTokenResponse *resp) override {
    auto id=context->client_metadata().find("pail-execution-instance");
    if(id!=context->client_metadata().end())context->AddInitialMetadata("pail-execution-instance",std::string(id->second.data(),id->second.length()));

    resp->set_status(pail::token::v1::OK);
    resp->set_chain_id(kChainId);
    resp->set_expected_sequence_index(1);
    resp->set_current_subgraph_hash(subgraph_hash);
    auto *st = resp->mutable_token();
    st->set_action_token_bytes(action_token_bytes);
    st->set_signature(signature);
    st->set_key_id(kKeyId);
    return grpc::Status::OK;
  }

  grpc::Status ReportDecision(grpc::ServerContext *,
                              const pail::token::v1::ReportDecisionRequest *,
                              pail::token::v1::ReportDecisionResponse *) override {
    return grpc::Status::OK;
  }

  grpc::Status Attest(grpc::ServerContext *context,
                      const pail::token::v1::AttestRequest *,
                      pail::token::v1::AttestResponse *resp) override {
    if (delay_attest.load()) {
      attest_inflight.store(true);
      const auto end=std::chrono::steady_clock::now()+std::chrono::milliseconds(1500);
      while(delay_attest.load() && !context->IsCancelled() && std::chrono::steady_clock::now()<end)
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
      attest_inflight.store(false);
    }
    resp->set_status("OK");
    return grpc::Status::OK;
  }

  grpc::Status SealConfig(grpc::ServerContext *,
                          const pail::token::v1::SealConfigRequest *,
                          pail::token::v1::SealConfigResponse *resp) override {
    resp->set_status("OK");
    return grpc::Status::OK;
  }
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

}  // namespace

int main() {
  if (sodium_init() < 0) {
    std::fprintf(stderr, "sodium_init failed\n");
    return 2;
  }

  // ---- 실 ed25519 이슈어 키 + 실서명 토큰 -------------------------------
  unsigned char ipk[crypto_sign_PUBLICKEYBYTES], isk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(ipk, isk);

  // 세계 해시는 토큰(서명이 덮는 field 61)과 응답 봉투에 **같은 32바이트**로
  // 실린다. 다르면 world_match 가 kMatch 를 내지 않아 조회면에 닿지 못한다.
  const std::string subgraph(32, '\x5a');

  const int64_t now_ms = pail_pep_gate::WallNowMs();
  pail::v1::ActionToken tok;
  tok.set_token_id(kTokenId);
  tok.set_chain_id(kChainId);
  tok.set_sequence_index(1);
  tok.set_robot_id(kRobotId);
  // `R-A` (E-W5): plan_id 도 canon 식별자다 — 비어 있으면 ERR_IDENTIFIER_FORMAT.
  tok.set_plan_id("plan-l10");
  tok.set_step_id("step-1");
  tok.set_target_object_id(kObjectId);
  tok.set_issued_at_unix_ms(now_ms);
  tok.set_not_before_unix_ms(now_ms - 1000);
  tok.set_not_after_unix_ms(now_ms + 60000);
  tok.set_action_type(pail::v1::ACTION_MOVE);
  tok.mutable_constraints()->set_max_linear_speed_mps(1.0);
  tok.mutable_constraints()->set_max_angular_speed_rps(1.0);
  tok.mutable_constraints()->set_max_duration_sec(kMaxDurationSec);
  tok.set_schema_version(3);
  tok.set_subgraph_snapshot_hash(subgraph);

  HonestIssuer issuer;
  issuer.action_token_bytes = tok.SerializeAsString();
  issuer.subgraph_hash = subgraph;
  {
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(
        sig, nullptr,
        reinterpret_cast<const unsigned char *>(issuer.action_token_bytes.data()),
        issuer.action_token_bytes.size(), isk);
    issuer.signature.assign(reinterpret_cast<const char *>(sig), sizeof sig);
  }
  // 소비 캐시의 키. 제품 함수로 유도한다 — 여기서 다시 구현하면 그 계산이
  // 바뀌는 것을 이 배터리가 못 본다.
  const std::string expect_key = pail_pep_gate::ConsumptionKeyHex(issuer.action_token_bytes);

  // ---- 신뢰근 + 이슈어를 노드보다 **먼저** 세운다 -----------------------
  const std::string dir = temp_dir();
  install_keyring_bundle(dir, ipk);

  setenv("PAIL_PROFILE", "dev", 1);
  setenv("PAIL_SEAL_DEADLINE_MS", "200", 1);
  setenv("PAIL_GRPC_TLS", "off", 1);
  setenv("PAIL_GRPC_INSECURE_ACK", "i-accept-plaintext", 1);

  int port = 0;
  grpc::ServerBuilder builder;
  builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
  builder.RegisterService(&issuer);
  std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
  if (!server || port == 0) {
    std::fprintf(stderr, "FAIL: issuer server did not start\n");
    return 2;
  }
  const std::string addr_arg = "token_service_addr:=127.0.0.1:" + std::to_string(port);

  const char *args[] = {
      "test_gate_lookup_consume", "--ros-args",
      "-p", "token_provider_mode:=grpc",
      "-p", "attest_interval_s:=1",
      "-p", addr_arg.c_str(),
      "-p", "robot_id:=tb7-lookup-robot",
      "-p", kTb7PolicyFileArg,
  };
  rclcpp::init(static_cast<int>(sizeof(args) / sizeof(args[0])), args);

  int rc = 1;
  {
    auto gate = std::make_shared<PepGateNode>();
    auto probe = std::make_shared<rclcpp::Node>("l10_lookup_probe");
    rclcpp::executors::SingleThreadedExecutor ex;
    auto safety_pub = probe->create_publisher<pail_msgs::msg::SafetyState>("/pail/safety_state", 10);
    auto evidence_pub = probe->create_publisher<pail_msgs::msg::Evidence>("/pail/evidence", 10);
    ex.add_node(gate);
    ex.add_node(probe);

    ROW("Discovery",
        spin_until(ex, 5000,
                   [&]() {
                     return safety_pub->get_subscription_count() >= 1 &&
                            evidence_pub->get_subscription_count() >= 1;
                   }),
        "gate matched probe pubs");

    // TOA A07: a real delayed Attest RPC must not occupy the ROS executor.
    // No physical robot or motor latency is measured by this fixture.
    issuer.delay_attest.store(true);
    ROW("PeriodicAttestRunsOffExecutor",
        spin_until(ex,3000,[&]{return issuer.attest_inflight.load();}),
        "actual gRPC Attest remains in flight while spin_some returns");

    {
      pail_msgs::msg::SafetyState s;
      s.stamp = probe->now();
      s.level = "OK";
      s.source = "L10_HARNESS";
      s.detail = "injected";
      safety_pub->publish(s);
      pail_msgs::msg::Evidence e;
      e.stamp = probe->now();
      e.source = "VISION";
      e.object_id = kObjectId;
      e.confidence = 0.97f;
      evidence_pub->publish(e);
      spin_ms(ex, 200);
    }

    geometry_msgs::msg::Twist twist;
    twist.linear.x = 0.3;

    // 주입 없음. `build_inputs` 가 스스로 이슈어를 부르고, 스스로 검증하고,
    // 스스로 조회한다 — 그것이 이 배터리의 전부다.
    auto in1 = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);

    // -------------------------------------------------------------------
    // PAIL-CASE: LookupRigVerifiesForReal
    // -------------------------------------------------------------------
    // 대조행 . 조회면은 검증 통과 **뒤에만** 있다. 여기가 붉으면
    // 아래 두 행의 값은 "조회했다"가 아니라 "조회에 닿지 못했다"의 값이다.
    // 붉을 때 어느 연언지가 깨졌는지 사람이 읽을 수 있게 값을 함께 찍는다 —
    // "거짓이었다"만 남기면 다음 사람이 다시 계측해야 한다.
    std::cerr << "  [rig] verify_ok=" << in1.verify_ok
              << " reason=" << in1.verify_reason
              << " token_id=" << in1.token_info.token_id
              << " key=" << in1.token_info.consumption_key.substr(0, 16)
              << " expect=" << expect_key.substr(0, 16) << "\n";
    ROW("LookupRigVerifiesForReal",
        in1.verify_ok && in1.verify_reason == "OK" &&
            in1.token_info.consumption_key == expect_key &&
            in1.token_info.token_id == kTokenId,
        "the node fetched, verified and parsed a genuinely signed token itself");

    // -------------------------------------------------------------------
    // PAIL-CASE: LookupRigWorldMatched
    // -------------------------------------------------------------------
    // 둘째 대조행. 조회면은 세계 해시가 **일치했을 때만** 실행된다(C-B8).
    // 두 해시가 같은 비어 있지 않은 값으로 도착했는지를 여기서 따로 세운다.
    ROW("LookupRigWorldMatched",
        !in1.token_info.subgraph_snapshot_hash.empty() &&
            in1.token_info.subgraph_snapshot_hash == in1.token_view.current_subgraph_hash,
        "token-embedded and issuer-served subgraph hashes arrived equal and non-empty");

    // -------------------------------------------------------------------
    // PAIL-CASE: NotConsumedBeforeStepCompletes
    // -------------------------------------------------------------------
    // ④ 의 짝. 홀로 떼면 빈 캐시에서도, **조회면에 닿지 못해도** 참이라 조용하다
    // (H-B2). 소유를 주장하는 것은 ④ 와 함께일 때의 판별력이다.
    ROW("NotConsumedBeforeStepCompletes", !in1.token_consumed,
        "an unused token reads NOT consumed on the lookup face");

    // 셋째·넷째 대조행. 이름을 앞의 행과 나누는 이유: 변형이 붉힌 행의 목록은
    // **이름으로만** 읽힌다. 같은 이름을 세 번 쓰면 "어느 단계에서 끊겼는가"가
    // 목록에서 사라지고 세 사실이 같은 바이트가 된다 (H-B2). 실제로 거울상
    // 변형(D5m)은 여기 둘을 함께 붉히고 그것이 **연쇄**임을 이름이 말해 준다.
    const auto d = pail_pep_gate::decide(in1);
    gate->apply(d, &twist, in1);
    ROW("LookupRigStepBegan",
        d.state == "PERMIT" && gate->test_step_active() &&
            gate->test_step_consumption_key() == expect_key,
        "PERMIT started a step keyed by the verified consumption_key");

    const auto completion_started=std::chrono::steady_clock::now();
    const bool completed =
        spin_until(ex, 2500, [&]() { return !gate->test_step_active(); });
    const auto completion_ms=std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now()-completion_started).count();
    ROW("StepTimerContinuesDuringAttest",
        completed && issuer.attest_inflight.load() && completion_ms<700,
        "verified step completion timer progresses during delayed network attestation");
    issuer.delay_attest.store(false);
    std::printf("TOA_A07 step_completion_wait_ms=%lld scope=ROS_callback_not_motor\n",(long long)completion_ms);
    ROW("LookupRigStepCompleted",
        completed && gate->test_consumed_contains(expect_key),
        "the step timer completed and wrote the key into the consumed cache");

    // 같은 토큰으로 다시 묻는다. 이슈어는 같은 바이트를 다시 내주므로
    // consumption_key 도 같고, 캐시는 이제 그 키를 갖고 있다.
    auto in2 = gate->build_inputs(pail_pep_gate::GatePath::Command, &twist);

    // -------------------------------------------------------------------
    // PAIL-CASE: ConsumedTokenReadsConsumed
    // -------------------------------------------------------------------
    // 단일사용의 **읽는** 쪽. `true` 는 조회면이 실제로 실행되지 않고는 나올 수
    // 없는 값이다 — 그래서 이 배터리의 판정은 이 행이 진다. 이 행이 없으면
    // 조회를 `false` 로 굳혀도 23개 배터리가 전부 초록이다 (2026-08-31 D5 실측).
    ROW("ConsumedTokenReadsConsumed",
        in2.verify_ok && in2.token_info.consumption_key == expect_key && in2.token_consumed,
        "the same token now reads CONSUMED — the single-use lookup is live");

    ex.remove_node(gate);
    ex.remove_node(probe);
    rc = (g_failures == 0) ? 0 : 1;
    if (g_failures) std::printf("test_gate_lookup_consume: %d row(s) FAILED\n", g_failures);
  }
  rclcpp::shutdown();
  server->Shutdown();
  server->Wait();
  return rc;
}
