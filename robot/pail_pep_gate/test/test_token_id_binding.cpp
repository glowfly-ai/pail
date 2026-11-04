// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// E-W2 : 이름은 서명이 덮은 바이트에서 온다 — 의미 축.
//
// `RED-E1` 은 구조 축이다: 게이트가 `SignedToken.token`(무서명 봉투 사본)의
// 판정 필드를 **읽지 않는다**는 것만 본다. 그런데 부재는 조용하다(`H-B2`) —
// 참조가 0건인 채로 `token_id` 가 아예 안 채워져도, 파싱 실패가 조용히
// 통과해도 구조 검사는 초록이다. 그 둘을 재는 것이 이 배터리다.
//
// 대상은 실제 생산 경로다. 봉투가 다른 이름을 말하는 응답을 **진짜 gRPC
// 서버**가 내놓고, `GrpcTokenProvider::GetActiveToken` 이 무엇을 들고
// 돌아오는지 본다. 호출 대상을 흉내 내면 흉내가 옳은지를 시험하게 된다.
//
// Plain executable (gtest 없음): 모든 항 통과 시에만 0 반환.
// GRPC-ON 전용 — 시험 대상 TU 자체가 ON 플레이버에만 존재한다.
//
// PAIL-CASE: TokenIdBindsToSignedBytes   (E1-C1/E1-C2)

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_builder.h>

#include <cstdio>
#include <atomic>
#include <cstdlib>
#include <memory>
#include <string>

#include "pail.pb.h"
#include "token_service.grpc.pb.h"
#include "token_service.pb.h"

#include "pail_pep_gate/token_provider_grpc.hpp"

using pail_pep_gate::ActiveTokenView;
using pail_pep_gate::GrpcTokenProvider;

static int g_failures = 0;

#define CHECK(cond, msg)                                                 \
  do {                                                                   \
    if (!(cond)) {                                                       \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); \
      ++g_failures;                                                      \
    }                                                                    \
  } while (0)

namespace {

// 봉투와 서명본이 서로 다른 이름을 말하도록 응답을 조립한다. 이 서버는
// 정직한 이슈어가 아니라 **응답을 전달하는 자**의 자리다(F-PR-12): 서명은
// 건드릴 수 없지만 그 옆의 사본은 자유롭게 다시 말할 수 있다.
class LyingIssuer final : public pail::token::v1::TokenService::Service {
 public:
  std::atomic<bool> echo_execution{true};
  std::atomic<bool> duplicate_execution{false};
  std::string envelope_token_id;   // 봉투가 말하는 이름
  std::string signed_bytes;        // 서명이 덮은 바이트 (그대로 실린다)

  grpc::Status GetActiveToken(grpc::ServerContext *context,
                              const pail::token::v1::GetActiveTokenRequest *,
                              pail::token::v1::GetActiveTokenResponse *resp) override {
    auto id=context->client_metadata().find("pail-execution-instance");
    if(echo_execution.load() && id!=context->client_metadata().end())context->AddInitialMetadata("pail-execution-instance",std::string(id->second.data(),id->second.length()));
    if(duplicate_execution.load() && id!=context->client_metadata().end())context->AddInitialMetadata("pail-execution-instance",std::string(id->second.data(),id->second.length()));

    resp->set_status(pail::token::v1::OK);
    resp->set_chain_id("chain-1");
    resp->set_expected_sequence_index(1);
    auto *st = resp->mutable_token();
    st->mutable_token()->set_token_id(envelope_token_id);
    st->set_signature("not-a-real-signature");
    st->set_key_id("dev-key-1");
    st->set_action_token_bytes(signed_bytes);
    return grpc::Status::OK;
  }
};

std::string MarshalTokenId(const std::string &token_id) {
  pail::v1::ActionToken t;
  t.set_token_id(token_id);
  return t.SerializeAsString();
}

}  // namespace

int main() {
  // 이 배터리는 전송 자세를 시험하지 않는다 — 시험 대상은 응답을 읽는 쪽이다.
  // 평문은 두 변수를 함께 선언해야 열린다(DD-5). 하나만 두면 기동이 거부되고,
  // 그 거부는 여기서 재려는 것이 아니다(`test_control_transport` 의 몫).
  setenv("PAIL_GRPC_TLS", "off", 1);
  setenv("PAIL_GRPC_INSECURE_ACK", "i-accept-plaintext", 1);
  unsetenv("PAIL_GRPC_UDS_PATH");

  LyingIssuer svc;
  int port = 0;
  grpc::ServerBuilder builder;
  builder.AddListeningPort("127.0.0.1:0", grpc::InsecureServerCredentials(), &port);
  builder.RegisterService(&svc);
  std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
  if (!server || port == 0) {
    std::fprintf(stderr, "FAIL: 시험용 이슈어를 띄우지 못했다 — 판정하지 않는다\n");
    return 2;
  }
  const std::string addr = "127.0.0.1:" + std::to_string(port);
  GrpcTokenProvider provider(addr);

  // ① 가드레일이 발동할 수 있는가. 봉투와 서명본이 같은 이름을 말할 때
  //    정상 응답이 실제로 통과해야 한다 — 항상 거부하는 것은 게이트가
  //    아니라 벽이고, 아래 두 항의 거부에는 아무 의미가 없어진다.
  svc.envelope_token_id = "tok-agree";
  svc.signed_bytes = MarshalTokenId("tok-agree");
  {
    ActiveTokenView v = provider.GetActiveToken("robot-1");
    CHECK(v.ok, "일치하는 정상 응답이 통과해야 한다");
    CHECK(v.status == "OK", "일치하는 정상 응답의 status 는 OK");
    CHECK(v.token_id == "tok-agree", "일치할 때 그 이름이 실려야 한다");
  }

  // ② 봉투가 다른 이름을 말한다. 실린 이름은 서명이 덮은 쪽이어야 한다.
  //    이것이 이 절의 명제다 — 봉투 사본은 pail.proto:206 이 "informational
  //    only" 라고 적은 자리이고, 판정에 쓰이는 순간 서명 밖의 값이 판정에
  //    들어온다.
  svc.envelope_token_id = "tok-envelope-lie";
  svc.signed_bytes = MarshalTokenId("tok-signed-real");
  {
    ActiveTokenView v = provider.GetActiveToken("robot-1");
    CHECK(v.ok, "서명본이 파싱되면 응답은 살아 있어야 한다");
    CHECK(v.token_id == "tok-signed-real",
          "token_id 는 서명이 덮은 바이트에서 와야 한다");
    CHECK(v.token_id != "tok-envelope-lie",
          "봉투 사본의 이름이 실려서는 안 된다");
    std::printf("E-W2: envelope=%s carried=%s\n", svc.envelope_token_id.c_str(),
                v.token_id.c_str());
  }

  // ③ 서명본이 파싱되지 않는다. 잘린 varint 는 어떤 서명으로도 검증될 수
  //    없으므로 여기서 거부해도 정당한 결과는 하나도 바뀌지 않는다 —
  //    바뀌는 것은 빈 이름이 "이슈어가 답했다"의 얼굴로 계속 가는 것뿐이다.
  svc.envelope_token_id = "tok-envelope-lie";
  svc.signed_bytes = std::string("\x08", 1);  // 값 없는 varint 태그
  {
    ActiveTokenView v = provider.GetActiveToken("robot-1");
    CHECK(!v.ok, "파싱 불가한 서명본은 fail-closed 여야 한다");
    CHECK(v.status == "ERROR", "파싱 불가의 status 는 ERROR");
    CHECK(v.token_id.empty(), "파싱 불가일 때 이름이 남아 있으면 안 된다");
  }

  // ④ 서명본이 비어 있다. proto3 에서 빈 바이트는 **파싱에 성공한다** —
  //    "파싱 실패" 로만 막으면 이 구멍은 열린 채로 남고, 이름 없는 응답이
  //    ok=true 로 지나간다. 부재를 성공과 같은 바이트로 두지 않는다(`H-B2`).
  svc.envelope_token_id = "tok-envelope-lie";
  svc.signed_bytes.clear();
  {
    ActiveTokenView v = provider.GetActiveToken("robot-1");
    CHECK(!v.ok, "빈 서명본은 fail-closed 여야 한다");
    CHECK(v.status == "ERROR", "빈 서명본의 status 는 ERROR");
    CHECK(v.token_id.empty(), "빈 서명본에서 이름이 나와서는 안 된다");
  }

  svc.envelope_token_id="tok-old-peer";
  svc.signed_bytes=MarshalTokenId("tok-old-peer");
  svc.duplicate_execution.store(true);
  {
    ActiveTokenView v=provider.GetActiveToken("robot-1");
    CHECK(!v.ok && v.status=="ERROR", "duplicate execution acknowledgements must fail closed");
  }
  svc.duplicate_execution.store(false);
  svc.echo_execution.store(false);
  {
    ActiveTokenView v=provider.GetActiveToken("robot-1");
    CHECK(!v.ok && v.status=="ERROR", "missing execution acknowledgement must fail closed");
  }
  server->Shutdown();
  server->Wait();

  if (g_failures == 0) {
    std::printf("test_token_id_binding: all PASS\n");
    return 0;
  }
  std::fprintf(stderr, "test_token_id_binding: %d FAILURES\n", g_failures);
  return 1;
}
