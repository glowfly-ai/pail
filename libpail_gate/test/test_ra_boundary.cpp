// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// E-W5 게이트 경계  — `R-A` 를 검증본 파싱 직후에.
//
// 골든 벡터(TB-2)를 쓰지 않는 이유: 그 19벡터는 동결본이고 서명을 다시 만들지
// 않는 것이 규율이다. 여기서 필요한 것은 **`:` 를 품은 식별자를 가진 유효
// 서명본**인데 동결집합에 그런 벡터가 없다 — 있으면 그 벡터가 이미 이 결함의
// 관측점이었을 것이다. 그래서 이 배터리는 자기 키를 만들어 자기 토큰에
// 서명한다. 동결본을 건드리지 않으므로 두 규율이 충돌하지 않는다.
//
// 팔 ①이 먼저 오는 이유: 항상 거부하는 것은 게이트가 아니라 벽이다. 정상
// 식별자가 실제로 통과하는 것을 보이지 않으면 아래 거부들은 "옳게 거부했다"가
// 아니라 "아무것도 통과시키지 않는다"의 사례일 뿐이다.
//
// 각 거부 팔은 **정확히 하나**만 위반한다(`H-B9`). 그래서 `plan_id` 를 깨는 팔은
// `robot_id` 를 정상으로 두고, 시간창·제약·action_type 은 전부 유효값으로 채운다
// — 하나라도 비워 두면 거부는 일어나되 그 근거가 `R-A` 가 아니게 되고, 사유
// 문자열을 함께 재지 않으면 그 차이가 보이지 않는다.
//
// PAIL-CASE: RAAtGateBoundary        (E1-C6 게이트 절반)

#include <sodium.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "pail.pb.h"
#include "pail_gate/strict_verify.hpp"
#include "pail_gate/token_provider.hpp"

using pail_pep_gate::ActiveTokenView;
using pail_pep_gate::Keyring;
using pail_pep_gate::StrictVerifyActiveTokenView;
using pail_pep_gate::VerifiedTokenInfo;

namespace {

int g_failures = 0;

void Check(bool ok, const char *what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

unsigned char g_sk[crypto_sign_SECRETKEYBYTES];
std::vector<unsigned char> g_pk(crypto_sign_PUBLICKEYBYTES);

// 이 토큰은 `R-A` 를 뺀 모든 검사를 통과하도록 채운다. 부족한 필드가 있으면
// 거부의 근거가 다른 규칙으로 옮겨 가고, 이 배터리는 그것을 알아채지 못한다.
std::string MakeSignedToken(const std::string &token_id, const std::string &chain_id,
                            const std::string &robot_id, const std::string &plan_id,
                            std::string *sig_out) {
  pail::v1::ActionToken t;
  t.set_token_id(token_id);
  t.set_chain_id(chain_id);
  t.set_robot_id(robot_id);
  t.set_plan_id(plan_id);
  t.set_step_id("step-1");
  t.set_sequence_index(1);
  t.set_target_object_id("obj-crate-7");
  t.set_action_type(pail::v1::ACTION_MOVE);
  t.set_schema_version(3);
  const int64_t now = 1750000000000LL;
  t.set_issued_at_unix_ms(now);
  t.set_not_before_unix_ms(0);          // 0 = 하한 없음. 창 검사는 이것을 관용한다.
  t.set_not_after_unix_ms(now + 86400000LL * 3650);  // 먼 미래 — 시계와 무관하게 유효
  t.mutable_constraints()->set_max_linear_speed_mps(0.5);
  t.mutable_constraints()->set_max_angular_speed_rps(0.5);
  t.mutable_constraints()->set_max_duration_sec(10.0);

  const std::string bytes = t.SerializeAsString();
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, nullptr,
                       reinterpret_cast<const unsigned char *>(bytes.data()),
                       bytes.size(), g_sk);
  sig_out->assign(reinterpret_cast<const char *>(sig), sizeof(sig));
  return bytes;
}

// (판정, 사유). 사유를 함께 돌려주는 이유는 `H-B9` 다 — "거부됐다"만 재면
// 어느 규칙이 거부했는지 모르고, 그러면 이 배터리는 `R-A` 가 통째로 사라져도
// 초록이다(다른 규칙이 대신 거부해 주므로).
bool VerifyOne(const std::string &bytes, const std::string &sig,
               const std::string &expected_robot_id, std::string *reason) {
  ActiveTokenView tv;
  tv.action_token_bytes = bytes;
  tv.signature_bytes = sig;
  tv.key_id_bytes = "ra-key-1";

  Keyring kr;
  kr.pubkeys["ra-key-1"] = g_pk;

  VerifiedTokenInfo info;
  return StrictVerifyActiveTokenView(tv, expected_robot_id, kr, 0, &info, reason);
}

}  // namespace

int main() {
  if (sodium_init() < 0) {
    std::fprintf(stderr, "FAIL: sodium_init — 판정하지 않는다\n");
    return 2;
  }
  crypto_sign_keypair(g_pk.data(), g_sk);

  // ① 가드레일이 발동할 수 있는가.
  {
    std::string sig;
    const std::string bytes = MakeSignedToken("tok-1", "chain-1", "robot-1", "plan-1", &sig);
    std::string reason;
    const bool ok = VerifyOne(bytes, sig, "robot-1", &reason);
    Check(ok, "정상 식별자 토큰이 통과해야 한다 (벽이 아니라 게이트)");
    Check(reason == "OK", "정상 토큰의 사유는 OK");
    std::printf("RA-GATE cpp legal valid=%d reason=%s\n", ok ? 1 : 0, reason.c_str());
  }

  // ②~⑤ 네 식별자를 각각 하나씩 깬다. 한 팔에 둘을 담으면 하나가 죽어도
  //     그 팔은 여전히 붉어 검사의 소실이 보이지 않는다.
  struct Case {
    const char *name;
    const char *token_id;
    const char *chain_id;
    const char *robot_id;
    const char *plan_id;
    const char *expected_robot_id;  // 로봇 결속 검사가 R-A 를 가리지 않도록
  };
  const Case cases[] = {
      {"colon_token_id", "tok:1", "chain-1", "robot-1", "plan-1", "robot-1"},
      {"colon_chain_id", "tok-1", "chain:1", "robot-1", "plan-1", "robot-1"},
      {"colon_robot_id", "tok-1", "chain-1", "robot-1:shadow", "plan-1", "robot-1:shadow"},
      {"colon_plan_id", "tok-1", "chain-1", "robot-1", "plan:1", "robot-1"},
      {"empty_token_id", "", "chain-1", "robot-1", "plan-1", "robot-1"},
      {"empty_plan_id", "tok-1", "chain-1", "robot-1", "", "robot-1"},
  };
  for (const Case &c : cases) {
    std::string sig;
    const std::string bytes =
        MakeSignedToken(c.token_id, c.chain_id, c.robot_id, c.plan_id, &sig);
    std::string reason;
    const bool ok = VerifyOne(bytes, sig, c.expected_robot_id, &reason);
    char buf[160];
    std::snprintf(buf, sizeof(buf), "%s: R-A 위반 토큰이 통과했다", c.name);
    Check(!ok, buf);
    std::snprintf(buf, sizeof(buf),
                  "%s: 사유가 ERR_IDENTIFIER_FORMAT 이어야 한다 (실측 %s)", c.name,
                  reason.c_str());
    Check(reason == "ERR_IDENTIFIER_FORMAT", buf);
    std::printf("RA-GATE cpp %s valid=%d reason=%s\n", c.name, ok ? 1 : 0, reason.c_str());
  }

  // ⑥ 서명이 먼저다. `R-A` 를 서명 검사 앞으로 옮기면 서명되지 않은 바이트의
  //    식별자에 대해 판정을 내리게 된다 — 그것은 이슈어가 말한 것이 아니다.
  {
    std::string sig;
    const std::string bytes = MakeSignedToken("tok-1", "chain-1", "robot-1", "plan:1", &sig);
    sig[0] = static_cast<char>(sig[0] ^ 0x01);
    std::string reason;
    const bool ok = VerifyOne(bytes, sig, "robot-1", &reason);
    Check(!ok, "서명이 깨진 토큰은 통과하지 못한다");
    Check(reason == "ERR_TAMPERED",
          "서명 실패가 R-A 보다 먼저다 — 서명되지 않은 바이트를 R-A 로 판정하지 않는다");
    std::printf("RA-GATE cpp sig_before_ra valid=%d reason=%s\n", ok ? 1 : 0, reason.c_str());
  }

  if (g_failures) {
    std::fprintf(stderr, "RA-GATE FAILURES=%d\n", g_failures);
    return 1;
  }
  std::printf("RA-GATE cpp ALL OK\n");
  return 0;
}
