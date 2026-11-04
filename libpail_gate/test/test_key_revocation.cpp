// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// `C-B16` — 폐기된 key_id 가 검증자에게 **값으로 도달한다** .
//
// 이 배터리가 재는 것은 "폐기된 키가 거부되는가"가 아니다. 그것은 폐기 항목을
// 목록에서 지우기만 해도 참이 된다. 재는 것은 **그 거부가 다른 거부와 구별되는가**
// 다 — `EVIDENCE_CB16_FAILFIRST.txt` 가 실측한 대로, 지우는 방식에서는 폐기된
// 키의 거부와 오타난 key_id 의 거부가 바이트까지 같았고(`H-B2`), 운영자는
// "유출된 키가 실제로 쓰이고 있다"와 "설정이 틀렸다"를 구별할 수 없었다.
//
// 그래서 팔 ③과 ④는 **함께** 있어야 한다. ③만 두면 사유 문자열을 아무 값으로
// 바꿔도 초록이고, ④만 두면 오늘의 트리도 초록이다. 두 사유가 서로 다르다는
// 것을 명시적으로 재는 팔 ④' 가 이 배터리의 중심이다.
//
// 팔 ①이 먼저 오는 이유는 `test_ra_boundary.cpp` 와 같다 — 항상 거부하는 것은
// 게이트가 아니라 벽이다.
//
// 동결 벡터(TB-2)를 쓰지 않는다: 폐기된 키로 서명된 유효 벡터는 동결집합에
// 없고, 있으면 그 벡터가 이미 이 결함의 관측점이었을 것이다. 자기 키를 만들어
// 자기 토큰에 서명하므로 동결본을 건드리지 않는다.
//
// PAIL-CASE: RevokedKeyIsAValue        (C16-C3 게이트 · C16-C1/C16-C4 적재기)

#include <sodium.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "pail.pb.h"
#include "pail_gate/strict_verify.hpp"
#include "pail_gate/token_provider.hpp"

using pail_pep_gate::ActiveTokenView;
using pail_pep_gate::Keyring;
using pail_pep_gate::LoadKeyringJSON;
using pail_pep_gate::StrictVerifyActiveTokenView;
using pail_pep_gate::VerifiedTokenInfo;

namespace {

int g_failures = 0;

void Check(bool ok, const std::string &what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what.c_str());
    ++g_failures;
  }
}

struct KeyPair {
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
};

KeyPair MakeKey() {
  KeyPair k;
  crypto_sign_keypair(k.pk, k.sk);
  return k;
}

std::vector<unsigned char> PubVec(const KeyPair &k) {
  return std::vector<unsigned char>(k.pk, k.pk + crypto_sign_PUBLICKEYBYTES);
}

std::string B64(const unsigned char *data, size_t len) {
  std::string out(sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL), '\0');
  sodium_bin2base64(&out[0], out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
  out.resize(std::strlen(out.c_str()));
  return out;
}

// 다른 모든 검사를 통과하도록 채운다 — 거부가 일어나면 그 근거가 반드시 키
// 조회여야 한다(`H-B9`). 시간창·제약·action_type·`R-A` 를 하나라도 비우면
// 이 배터리는 폐기 판정이 통째로 사라져도 초록이다.
std::string MakeSignedToken(const KeyPair &signer, std::string *sig_out) {
  pail::v1::ActionToken t;
  t.set_token_id("tok-rev-1");
  t.set_chain_id("chain-rev-1");
  t.set_robot_id("robot-1");
  t.set_plan_id("plan-rev-1");
  t.set_step_id("step-1");
  t.set_sequence_index(1);
  t.set_target_object_id("obj-crate-7");
  t.set_action_type(pail::v1::ACTION_MOVE);
  t.set_schema_version(3);
  const int64_t now = 1750000000000LL;
  t.set_issued_at_unix_ms(now);
  t.set_not_before_unix_ms(0);
  t.set_not_after_unix_ms(now + 86400000LL * 3650);
  t.mutable_constraints()->set_max_linear_speed_mps(0.5);
  t.mutable_constraints()->set_max_angular_speed_rps(0.5);
  t.mutable_constraints()->set_max_duration_sec(10.0);

  const std::string bytes = t.SerializeAsString();
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, nullptr,
                       reinterpret_cast<const unsigned char *>(bytes.data()),
                       bytes.size(), signer.sk);
  sig_out->assign(reinterpret_cast<const char *>(sig), sizeof(sig));
  return bytes;
}

bool VerifyWith(const Keyring &kr, const std::string &key_id, const std::string &bytes,
                const std::string &sig, std::string *reason) {
  ActiveTokenView tv;
  tv.action_token_bytes = bytes;
  tv.signature_bytes = sig;
  tv.key_id_bytes = key_id;
  VerifiedTokenInfo info;
  return StrictVerifyActiveTokenView(tv, "robot-1", kr, 0, &info, reason);
}

void WriteFile(const std::string &path, const std::string &content) {
  std::ofstream f(path, std::ios::trunc);
  f << content;
}

std::string TempDir() {
  char tmpl[] = "/tmp/cb16test.XXXXXX";
  char *d = mkdtemp(tmpl);
  if (d == nullptr) {
    std::fprintf(stderr, "FAIL: mkdtemp — 판정하지 않는다\n");
    std::exit(2);
  }
  return std::string(d);
}

std::string Entry(const std::string &key_id, const std::string &pub_b64) {
  return "{\"key_id\":\"" + key_id + "\",\"ed25519_public_key_base64\":\"" + pub_b64 +
         "\",\"role\":\"issuer\"}";
}

}  // namespace

int main() {
  if (sodium_init() < 0) {
    std::fprintf(stderr, "FAIL: sodium_init — 판정하지 않는다\n");
    return 2;
  }

  const KeyPair active = MakeKey();
  const KeyPair leaked = MakeKey();

  // 게이트가 보는 키링: 활성 하나 + 폐기 하나. 폐기된 키의 **공개 절반**을
  // 갖고 있다는 것이 이 배터리의 전제다 — 갖고 있지 않으면 아래 ③은 물리적으로
  // 불가능하고, 그 불가능이 곧 FAIL-first 에서 관측한 결함이었다.
  Keyring kr;
  kr.pubkeys["issuer-active"] = PubVec(active);
  kr.revoked["issuer-leaked"] = PubVec(leaked);

  // ① 게이트가 벽이 아닌가.
  {
    std::string sig;
    const std::string bytes = MakeSignedToken(active, &sig);
    std::string reason;
    const bool ok = VerifyWith(kr, "issuer-active", bytes, sig, &reason);
    Check(ok, "활성 키로 서명한 토큰이 통과해야 한다 (벽이 아니라 게이트)");
    Check(reason == "OK", "활성 토큰의 사유는 OK, 실측 " + reason);
    std::printf("CB16 cpp active valid=%d reason=%s\n", ok ? 1 : 0, reason.c_str());
  }

  // ② 폐기된 키로 서명한 토큰은 통과하지 못한다.
  // ③ 그 사유는 `ERR_REVOKED_KEY_ID` 다.
  std::string revoked_reason;
  {
    std::string sig;
    const std::string bytes = MakeSignedToken(leaked, &sig);
    const bool ok = VerifyWith(kr, "issuer-leaked", bytes, sig, &revoked_reason);
    Check(!ok, "폐기된 키로 서명한 토큰이 통과했다 — 폐기 집합은 신뢰 집합이 아니다");
    Check(revoked_reason == "ERR_REVOKED_KEY_ID",
          "폐기 사유가 ERR_REVOKED_KEY_ID 이어야 한다, 실측 " + revoked_reason);
    std::printf("CB16 cpp revoked valid=%d reason=%s\n", ok ? 1 : 0, revoked_reason.c_str());
  }

  // ④ 진짜 모르는 key_id 는 `ERR_UNKNOWN_KEY_ID` 로 남는다.
  std::string unknown_reason;
  {
    std::string sig;
    const std::string bytes = MakeSignedToken(active, &sig);
    const bool ok = VerifyWith(kr, "issuer-typo", bytes, sig, &unknown_reason);
    Check(!ok, "모르는 key_id 는 통과하지 못한다");
    Check(unknown_reason == "ERR_UNKNOWN_KEY_ID",
          "모르는 key_id 의 사유는 ERR_UNKNOWN_KEY_ID, 실측 " + unknown_reason);
    std::printf("CB16 cpp unknown valid=%d reason=%s\n", ok ? 1 : 0, unknown_reason.c_str());
  }

  // ④' 이 배터리의 중심. 두 사유가 **다른 값**인가.
  //     ③과 ④를 따로 재는 것만으로는 부족하다 — 두 기대값을 같은 문자열로
  //     맞춰 놓아도 각각은 통과하기 때문이다. 구별 자체를 재야 한다.
  Check(revoked_reason != unknown_reason,
        "폐기와 미상이 같은 사유로 접혔다 (" + revoked_reason + ") — H-B2");
  std::printf("CB16 cpp distinct revoked=%s unknown=%s distinct=%d\n",
              revoked_reason.c_str(), unknown_reason.c_str(),
              revoked_reason != unknown_reason ? 1 : 0);

  // ⑤ 폐기 키의 공개 절반은 **식별 전용**이다. 그 key_id 를 사칭하되 서명은
  //    다른 키로 한 토큰은 `ERR_TAMPERED` 여야 한다 — `ERR_REVOKED_KEY_ID` 가
  //    나오면 아무나 그 사유를 만들어 낼 수 있고, 그 사유를 보고 유출 대응을
  //    시작하는 사람에게 거짓을 말하게 된다.
  {
    std::string sig;
    const std::string bytes = MakeSignedToken(active, &sig);  // 서명은 활성 키
    std::string reason;
    const bool ok = VerifyWith(kr, "issuer-leaked", bytes, sig, &reason);  // 이름만 폐기 키
    Check(!ok, "사칭 토큰이 통과했다");
    Check(reason == "ERR_TAMPERED",
          "폐기 key_id 사칭은 ERR_TAMPERED — 서명이 맞을 때만 폐기라고 말한다, 실측 " + reason);
    std::printf("CB16 cpp impersonate valid=%d reason=%s\n", ok ? 1 : 0, reason.c_str());
  }

  // --- 적재기 (`C16-C1`, `C16-C4`) -----------------------------------------
  // 게이트 판정이 3값이어도 적재기가 폐기 목록을 읽지 못하면 그 값은 배치에서
  // 절대 나타나지 않는다. 위의 ①~⑤는 손으로 채운 Keyring 을 쓰므로 이 절이
  // 없으면 배터리 전체가 "코드가 할 수 있는 일"만 재고 "배치가 하는 일"은
  // 재지 않는다.
  const std::string dir = TempDir();
  const std::string ab = B64(active.pk, sizeof active.pk);
  const std::string lb = B64(leaked.pk, sizeof leaked.pk);

  // ⑥ revoked_keys 를 읽는다.
  {
    const std::string path = dir + "/kr_both.json";
    WriteFile(path, "{\"keys\":[" + Entry("issuer-active", ab) + "],\"revoked_keys\":[" +
                        Entry("issuer-leaked", lb) + "]}\n");
    std::string reason;
    Keyring k = LoadKeyringJSON(path, &reason);
    Check(reason.empty(), "정상 키링이 거부됐다: " + reason);
    Check(k.pubkeys.count("issuer-active") == 1, "활성 키가 신뢰 앵커여야 한다");
    Check(k.revoked.count("issuer-leaked") == 1, "폐기 항목이 적재돼야 한다");
    Check(k.pubkeys.count("issuer-leaked") == 0, "폐기 항목이 신뢰 앵커가 됐다");
    std::printf("CB16 cpp load_both keys=%zu revoked=%zu reason=%s\n", k.pubkeys.size(),
                k.revoked.size(), reason.c_str());
  }

  // ⑦ revoked_keys 가 **앞에** 놓여도 keys 배열을 옳게 읽는다.
  //    `find("\"keys\"")` 가 `"revoked_keys"` 안에서 걸리지 않는다는 성질은
  //    우연처럼 보이지만 이 적재기가 서 있는 전제다. 순서를 뒤집어 잰다.
  {
    const std::string path = dir + "/kr_order.json";
    WriteFile(path, "{\"revoked_keys\":[" + Entry("issuer-leaked", lb) + "],\"keys\":[" +
                        Entry("issuer-active", ab) + "]}\n");
    std::string reason;
    Keyring k = LoadKeyringJSON(path, &reason);
    Check(reason.empty(), "배열 순서를 뒤집었더니 거부됐다: " + reason);
    Check(k.pubkeys.count("issuer-active") == 1 && k.pubkeys.size() == 1,
          "revoked_keys 가 앞에 와도 keys 배열이 옳게 읽혀야 한다");
    Check(k.revoked.count("issuer-leaked") == 1, "순서와 무관하게 폐기 항목이 적재돼야 한다");
    std::printf("CB16 cpp load_order keys=%zu revoked=%zu reason=%s\n", k.pubkeys.size(),
                k.revoked.size(), reason.c_str());
  }

  // ⑧ revoked_keys 가 아예 없는 키링은 그대로 적재된다 — 오늘 배포된
  //    keyring.json 이 이 변경으로 부팅마다 거부되면 그것은 게이트가 아니라 벽이다.
  {
    const std::string path = dir + "/kr_none.json";
    WriteFile(path, "{\"keys\":[" + Entry("issuer-active", ab) + "]}\n");
    std::string reason;
    Keyring k = LoadKeyringJSON(path, &reason);
    Check(reason.empty(), "revoked_keys 없는 키링이 거부됐다: " + reason);
    Check(k.pubkeys.size() == 1 && k.revoked.empty(), "폐기 목록은 비어 있어야 한다");
    std::printf("CB16 cpp load_none keys=%zu revoked=%zu reason=%s\n", k.pubkeys.size(),
                k.revoked.size(), reason.c_str());
  }

  // ⑨ 같은 key_id 가 양쪽에 있으면 파일 전체를 거부한다 (`C16-C4`).
  //    검사는 role 여과 **전**, 날것의 key_id 위에서 한다 — 그래서 role 을
  //    갈라 적어도 통과하지 못한다.
  {
    const std::string path = dir + "/kr_overlap.json";
    WriteFile(path, "{\"keys\":[" + Entry("issuer-active", ab) + "],\"revoked_keys\":[" +
                        Entry("issuer-active", ab) + "]}\n");
    std::string reason;
    Keyring k = LoadKeyringJSON(path, &reason);
    Check(reason == "ERR_KEYRING_REVOKED_OVERLAP",
          "겹친 key_id 가 거부되지 않았다, 실측 " + reason);
    Check(k.pubkeys.empty() && k.revoked.empty(), "거부된 키링이 키를 남겼다");
    std::printf("CB16 cpp load_overlap keys=%zu revoked=%zu reason=%s\n", k.pubkeys.size(),
                k.revoked.size(), reason.c_str());
  }

  // ⑩ role 을 갈라 적은 겹침도 거부된다. ⑨만 두면 여과 뒤에 재는 구현으로
  //    바꿔도 초록이다 — 그 구현에서 이 팔은 통과한다(keys 쪽이 operator 로
  //    걸러져 겹침이 사라지므로).
  {
    const std::string path = dir + "/kr_overlap_role.json";
    WriteFile(path,
              "{\"keys\":[{\"key_id\":\"issuer-active\",\"ed25519_public_key_base64\":\"" + ab +
                  "\",\"role\":\"operator\"}],\"revoked_keys\":[" + Entry("issuer-active", ab) +
                  "]}\n");
    std::string reason;
    Keyring k = LoadKeyringJSON(path, &reason);
    Check(reason == "ERR_KEYRING_REVOKED_OVERLAP",
          "role 을 가른 겹침이 통과했다 — 여과 뒤에 재고 있다, 실측 " + reason);
    std::printf("CB16 cpp load_overlap_role reason=%s\n", reason.c_str());
  }

  // ⑪ 이름은 실렸는데 값이 배열이 아닌 형태(`null`)는 거부한다. 이 팔이 없으면
  //    스캐너가 이름 뒤의 **다음 배열**을 자기 것으로 삼는 구현도 초록이고,
  //    그 구현은 `revoked_keys` 가 앞에 놓였을 때 활성 키를 폐기 목록에 싣는다
  //    — 관측이 아니라 오염이다.
  {
    const std::string path = dir + "/kr_null.json";
    WriteFile(path, "{\"revoked_keys\":null,\"keys\":[" + Entry("issuer-active", ab) + "]}\n");
    std::string reason;
    Keyring k = LoadKeyringJSON(path, &reason);
    Check(reason == "ERR_KEYRING_PAYLOAD",
          "revoked_keys:null 이 거부되지 않았다, 실측 " + reason);
    Check(k.revoked.empty(), "null 항목이 남의 배열을 폐기 목록으로 실었다");
    std::printf("CB16 cpp load_null keys=%zu revoked=%zu reason=%s\n", k.pubkeys.size(),
                k.revoked.size(), reason.c_str());
  }

  if (g_failures) {
    std::fprintf(stderr, "CB16 FAILURES=%d\n", g_failures);
    return 1;
  }
  std::printf("CB16 cpp ALL OK\n");
  return 0;
}
