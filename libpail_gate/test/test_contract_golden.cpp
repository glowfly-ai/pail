// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// TB-2 : C++ 골든 벡터 리더 — 검증기(사유 생산자) 축.
//
// tokens.vec 의 15 벡터를 StrictVerifyActiveTokenView 에 그대로 먹여
// 판정(valid)과 사유(ERR_*)를 대조한다. 서명은 절대 재생성하지 않는다 —
// 벡터의 바이트가 정본이고, 이 테스트는 소비만 한다.
//
// Plain executable (gtest 없음): 모든 행 통과 시에만 0 반환.
// GRPC-ON 전용 — 검증기 실체(sodium + pail.pb)는 ON 플레이버에만 존재하고,
// OFF 스텁은 사유 없이 false 만 낸다(설계 관측 D-F5, 여기서 시험 대상 아님).
//
// PAIL-CASE: TokenGoldenVerdicts        (G-CTR-01)
//
// 교차 언어 대조(§7.3-3): 각 벡터에 대해
//   GOLDEN-VERDICT cpp <id> valid=<0|1> reason=<ERR_*|OK>
// 를 stdout 에 낸다. Go(원시 서명 축)·Python(사유 어휘 축)의 같은 형식
// 라인과 grep 으로 맞춘다.

#include <sodium.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "pail_gate/strict_verify.hpp"
#include "pail_gate/token_provider.hpp"

using pail_pep_gate::ActiveTokenView;
using pail_pep_gate::Keyring;
using pail_pep_gate::StrictVerifyActiveTokenView;
using pail_pep_gate::VerifiedTokenInfo;

static int g_failures = 0;

#define CHECK(cond, msg)                                                 \
  do {                                                                   \
    if (!(cond)) {                                                       \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); \
      ++g_failures;                                                      \
    }                                                                    \
  } while (0)

namespace {

struct VecRecord {
  std::string id;
  std::map<std::string, std::string> fields;
  int line = 0;
};

// .vec 파서 (§2.1): key<TAB>value. '#'/빈 줄 무시. 'id' 가 레코드를 연다.
// 레코드 안 중복 key = 파싱 오류(마지막 승 금지). 탭 없는 줄 = 빈 값.
bool readVec(const std::string &path, std::vector<VecRecord> *out, std::string *err) {
  std::ifstream f(path);
  if (!f) {
    *err = "open failed: " + path;
    return false;
  }
  std::string line;
  int line_no = 0;
  while (std::getline(f, line)) {
    ++line_no;
    if (line.empty() || line[0] == '#') continue;
    std::string key = line, val;
    auto tab = line.find('\t');
    if (tab != std::string::npos) {
      key = line.substr(0, tab);
      val = line.substr(tab + 1);
    }
    if (key == "id") {
      VecRecord r;
      r.id = val;
      r.line = line_no;
      r.fields["id"] = val;
      out->push_back(r);
      continue;
    }
    if (out->empty()) {
      *err = "line " + std::to_string(line_no) + ": key before first id";
      return false;
    }
    auto &cur = out->back();
    if (cur.fields.count(key)) {
      *err = "line " + std::to_string(line_no) + ": duplicate key '" + key +
             "' in record " + cur.id + " (last-wins forbidden)";
      return false;
    }
    cur.fields[key] = val;
  }
  return !out->empty();
}

bool getField(const VecRecord &r, const std::string &key, std::string *out) {
  auto it = r.fields.find(key);
  if (it == r.fields.end()) return false;
  *out = it->second;
  return true;
}

// hex → 바이트 (빈 문자열 = 빈 바이트열, TV-05).
bool hexDecode(const std::string &hex, std::string *out) {
  out->clear();
  if (hex.empty()) return true;
  std::vector<unsigned char> buf(hex.size() / 2 + 1);
  size_t bin_len = 0;
  if (sodium_hex2bin(buf.data(), buf.size(), hex.data(), hex.size(), nullptr,
                     &bin_len, nullptr) != 0) {
    return false;
  }
  out->assign(reinterpret_cast<const char *>(buf.data()), bin_len);
  return true;
}

std::string goldenPath() {
  const char *root = std::getenv("PAIL_REPO_ROOT");
  if (root && *root) {
    const std::string public_path = std::string(root) + "/spec/vectors/token/tokens.vec";
    if (std::ifstream(public_path).good()) return public_path;
    return std::string(root) + "/tests/golden/token/tokens.vec";
  }
  // 직접 실행 폴백: 컨테이너 마운트 관례 (/repo).
  return "/repo/tests/golden/token/tokens.vec";
}

}  // namespace

int main() {
  CHECK(sodium_init() >= 0, "sodium_init");

  std::vector<VecRecord> recs;
  std::string err;
  if (!readVec(goldenPath(), &recs, &err)) {
    std::fprintf(stderr, "FAIL vec parse: %s\n", err.c_str());
    return 1;
  }
  CHECK(recs.size() == 29, "tokens.vec must hold 29 vectors (TV-01~27, TV-90, TV-91 — AL-3 added TV-18~20, SK-4 added TV-21~27)");

  for (const auto &r : recs) {
    std::string bytes_hex, sig_hex, pub_hex, key_id, keyring_key_id, robot,
        skew_s, valid_s, reason_want, layer;
    bool ok = getField(r, "action_token_bytes", &bytes_hex) &&
              getField(r, "signature", &sig_hex) &&
              getField(r, "pubkey", &pub_hex) &&
              getField(r, "key_id", &key_id) &&
              getField(r, "keyring_key_id", &keyring_key_id) &&
              getField(r, "expected_robot_id", &robot) &&
              getField(r, "clock_skew_ms", &skew_s) &&
              getField(r, "expect_valid", &valid_s) &&
              getField(r, "expect_reason", &reason_want) &&
              getField(r, "verify_layer", &layer);
    if (!ok) {
      std::fprintf(stderr, "FAIL %s: missing required field\n", r.id.c_str());
      ++g_failures;
      continue;
    }

    ActiveTokenView tv;
    std::string pub;
    if (!hexDecode(bytes_hex, &tv.action_token_bytes) ||
        !hexDecode(sig_hex, &tv.signature_bytes) || !hexDecode(pub_hex, &pub)) {
      std::fprintf(stderr, "FAIL %s: hex decode\n", r.id.c_str());
      ++g_failures;
      continue;
    }
    tv.key_id_bytes = key_id;

    Keyring kr;
    kr.pubkeys[keyring_key_id] =
        std::vector<unsigned char>(pub.begin(), pub.end());

    const int64_t skew_ms = std::strtoll(skew_s.c_str(), nullptr, 10);
    const bool expect_valid = (valid_s == "1");

    // [implementation contract / B3-C3] 교차 구현 대조. 이 값은 제3자가 재현해야 하는
    // 공개 스펙(A §3.5)이므로, Go 와 C++ 이 같은 값을 낸다는 증명이 없으면
    // 스펙이 아니라 구현 세부다. Go 쪽 절반은 같은 파일을 읽는
    // internal/contract/consumption_key_golden_test.go 가 수행한다.
    // 서명 유효성과 무관한 순수 함수이므로 거부 벡터에서도 대조한다 —
    // 유효 벡터에서만 보면 두 구현이 거부 경로에서 갈라져도 보이지 않는다.
    std::string ck_want;
    if (!getField(r, "consumption_key", &ck_want)) {
      std::fprintf(stderr, "FAIL %s: consumption_key column missing (§4.3)\n",
                   r.id.c_str());
      ++g_failures;
      continue;
    }
    const std::string ck_got =
        pail_pep_gate::ConsumptionKeyHex(tv.action_token_bytes);
    if (ck_got != ck_want) {
      std::fprintf(stderr, "FAIL %s: consumption_key=%s want=%s\n", r.id.c_str(),
                   ck_got.c_str(), ck_want.c_str());
      ++g_failures;
      continue;
    }
    std::printf("GOLDEN-CONSUMPTION-KEY cpp %s %s\n", r.id.c_str(),
                ck_got.c_str());

    VerifiedTokenInfo info;
    std::string reason;
    const bool got_valid = StrictVerifyActiveTokenView(
        tv, robot, kr, skew_ms, &info, &reason);

    std::printf("GOLDEN-VERDICT cpp %s valid=%d reason=%s\n", r.id.c_str(),
                got_valid ? 1 : 0, reason.c_str());

    if (got_valid != expect_valid) {
      std::fprintf(stderr, "FAIL %s: valid=%d want=%d (reason=%s)\n",
                   r.id.c_str(), got_valid ? 1 : 0, expect_valid ? 1 : 0,
                   reason.c_str());
      ++g_failures;
      continue;
    }
    if (reason != reason_want) {
      std::fprintf(stderr, "FAIL %s: reason=%s want=%s\n", r.id.c_str(),
                   reason.c_str(), reason_want.c_str());
      ++g_failures;
      continue;
    }
    // 유효 벡터의 파생 정보 최소 검증 (검증기 → 게이트 전달 계약).
    if (got_valid) {
      // AL-3 (2026-09-04, TV-18~20): validity no longer implies MOVE. A v4 token
      // carries a class MASK (TV-18 = MOVE|MANIPULATE = 3) and a v3 token may carry
      // any enum the issuer minted (TV-20 = PLACE = 3); whether /cmd_vel is
      // authorized is gate_core 3e's question, outside the verifier contract.
      // The old `== kActionMove` assertion predates those vectors and was red
      // for both since dc85926 — nobody ran this battery in between (measured
      // 2026-09-06 while landing AD-1). What the verifier DOES promise: a
      // non-UNSPECIFIED action, and for v4 a mask inside the four specified bits.
      CHECK(info.action_type != pail_pep_gate::kActionTypeUnspecified,
            "valid vector must carry a non-UNSPECIFIED action");
      if (info.schema_version >= pail_pep_gate::kTokenSchemaMask) {
        CHECK((info.action_type & ~pail_pep_gate::kClassMaskAll) == 0,
              "valid v4 vector's mask must stay inside the four class bits");
      }
      CHECK(info.max_linear_speed_mps == 0.5, "constraints must survive parse");
      // [OR3/X12②] 게이트가 캐시 키로 쓰는 값은 검증기가 건네는 이 필드다.
      // 자유 함수만 대조하면 검증기가 다른 값을 실어 보내도 드러나지 않는다.
      CHECK(info.consumption_key == ck_want,
            "VerifiedTokenInfo.consumption_key must match the golden column");
    }
  }

  if (g_failures == 0) {
    std::printf("test_contract_golden: all %zu vectors PASS\n", recs.size());
    return 0;
  }
  std::fprintf(stderr, "test_contract_golden: %d FAILURES\n", g_failures);
  return 1;
}
