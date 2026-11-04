// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_gate/keyring_bundle.hpp"

#if PAIL_ENABLE_GRPC == 1

#include <sodium.h>

#include <cstdint>
#include <cerrno>
#include <limits>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace pail_pep_gate {

namespace {

std::string trustHash(const unsigned char *data, size_t size) {
  unsigned char digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest,data,size);
  char hex[crypto_hash_sha256_BYTES*2+1];
  sodium_bin2hex(hex,sizeof hex,digest,sizeof digest);
  return hex;
}

bool readFile(const std::string &path, std::string *out) {
  std::ifstream f(path);
  if (!f.good()) return false;
  std::stringstream ss;
  ss << f.rdbuf();
  *out = ss.str();
  return true;
}

// Minimal JSON field extraction (same approach as LoadKeyringJSON below):
// the formats are fixed and produced by our own signing CLI, so this is a
// deliberate no-dependency parser, not a general one.
bool extractString(const std::string &s, size_t start, size_t end,
                   const std::string &field, std::string *out) {
  const std::string needle = "\"" + field + "\"";
  size_t p = s.find(needle, start);
  if (p == std::string::npos || p >= end) return false;
  p = s.find(':', p + needle.size());
  if (p == std::string::npos || p >= end) return false;
  p = s.find('"', p);
  if (p == std::string::npos || p >= end) return false;
  size_t q = s.find('"', p + 1);
  if (q == std::string::npos || q > end) return false;
  *out = s.substr(p + 1, q - (p + 1));
  return true;
}

bool extractInt(const std::string &s, size_t start, size_t end,
                const std::string &field, long long *out) {
  const std::string needle = "\"" + field + "\"";
  size_t p = s.find(needle, start);
  if (p == std::string::npos || p >= end) return false;
  p = s.find(':', p + needle.size());
  if (p == std::string::npos || p >= end) return false;
  ++p;
  while (p < end && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n' || s[p] == '\r')) ++p;
  size_t q = p;
  if (q < end && s[q] == '-') ++q;
  size_t digits_start = q;
  while (q < end && s[q] >= '0' && s[q] <= '9') ++q;
  if (q == digits_start) return false;
  errno = 0;
  const long long v = std::strtoll(s.substr(p, q - p).c_str(), nullptr, 10);
  if (errno != 0) return false;
  *out = v;
  return true;
}

// Strict base64 decode (standard alphabet, no ignored characters — parity
// with Go's base64.StdEncoding).
bool b64Decode(const std::string &b64, std::vector<unsigned char> *out) {
  out->assign(b64.size() + 1, 0);
  size_t bin_len = 0;
  if (sodium_base642bin(out->data(), out->size(), b64.c_str(), b64.size(),
                        nullptr, &bin_len, nullptr,
                        sodium_base64_VARIANT_ORIGINAL) != 0) {
    return false;
  }
  out->resize(bin_len);
  return true;
}

bool writeFileAtomic(const std::string &path, const std::string &content) {
  std::error_code ec;
  const auto dir = std::filesystem::path(path).parent_path();
  if (!dir.empty()) {
    std::filesystem::create_directories(dir, ec);
    if (ec) return false;
  }
  const std::string tmp = path + ".tmp";
  {
    std::ofstream f(tmp, std::ios::trunc);
    if (!f.good()) return false;
    f << content;
    if (!f.good()) return false;
  }
  std::filesystem::rename(tmp, path, ec);
  return !ec;
}

// Reads the persisted version floor. Missing file = first load (floor 0).
// An unreadable/garbled state file is an error, not a floor reset — resetting
// would silently re-open the rollback window (fail-closed, parity with Go).
bool readBundleState(const std::string &state_path, uint64_t *last) {
  *last = 0;
  std::error_code ec;
  if (!std::filesystem::exists(state_path, ec)) return true;
  std::string s;
  if (!readFile(state_path, &s)) return false;
  long long v = 0;
  if (!extractInt(s, 0, s.size(), "last_version", &v) || v < 0) return false;
  *last = static_cast<uint64_t>(v);
  return true;
}

const char *envOr(const char *name, const char *fallback) {
  const char *v = std::getenv(name);
  return (v != nullptr && v[0] != '\0') ? v : fallback;
}

// 3-valued key read (H-B2): "key not in the file" and "key present but
// unreadable" must not share an answer — extractInt alone returns false for
// both, and treating garble as absence would let a corrupted floor read as
// "no floor" (rewind window silently reopened).
enum class KeyRead { Absent, Ok, Error };
KeyRead readStateKey(const std::string &s, const char *key, long long *out) {
  if (s.find(std::string("\"") + key + "\"") == std::string::npos) return KeyRead::Absent;
  if (!extractInt(s, 0, s.size(), key, out) || *out < 0) return KeyRead::Error;
  return KeyRead::Ok;
}

// DC-10: the state file has TWO writers now — the version bump below and the
// node's wall floor. Each used to write its own literal object, which means
// either write erases the other's key, and an erased floor is
// indistinguishable from a first boot. Both writers go through this merged
// write: read what is there, overlay the one value being set, refuse to
// clobber anything that is present but unreadable.
bool writeStateMerged(const std::string &state_path,
                      const uint64_t *version, const int64_t *wall_ms0) {
  long long cur_version = -1;  // -1 = not present
  long long cur_wall = -1;
  std::error_code ec;
  if (std::filesystem::exists(state_path, ec)) {
    std::string s;
    if (!readFile(state_path, &s)) return false;
    long long v = 0;
    switch (readStateKey(s, "last_version", &v)) {
      case KeyRead::Ok: cur_version = v; break;
      case KeyRead::Absent: break;
      case KeyRead::Error: return false;
    }
    switch (readStateKey(s, "wall_ms0", &v)) {
      case KeyRead::Ok: cur_wall = v; break;
      case KeyRead::Absent: break;
      case KeyRead::Error: return false;
    }
  }
  if (version != nullptr) cur_version = static_cast<long long>(*version);
  if (wall_ms0 != nullptr) cur_wall = *wall_ms0;
  std::ostringstream st;
  st << "{";
  bool first = true;
  if (cur_version >= 0) {
    st << "\n  \"last_version\": " << cur_version;
    first = false;
  }
  if (cur_wall >= 0) {
    st << (first ? "" : ",") << "\n  \"wall_ms0\": " << cur_wall;
  }
  st << "\n}\n";
  return writeFileAtomic(state_path, st.str());
}

// `C16-C1` : 키 항목 배열 하나를 훑는다. `keys` 와
// `revoked_keys` 가 **같은 코드**로 읽히도록 뽑아냈다 — 두 벌로 두면 한쪽만
// 엄격해지는 날이 오고, 느슨해지는 쪽은 언제나 덜 쓰이는 쪽(폐기 목록)이다.
struct RawKeyEntry {
  std::string key_id;
  std::vector<unsigned char> pub;
  std::string role;
  bool role_present = false;
};

// Same length-prefixed material digest as Go crypto.TrustMaterialDigest.
std::string trustMaterialDigest(const std::vector<RawKeyEntry> &active,
                                const std::vector<RawKeyEntry> &revoked) {
  const char domain[]="pail.trust-material/v1";
  std::string raw(domain,sizeof domain); // includes exactly one NUL
  auto count=[&raw](uint64_t n){for(int shift=56;shift>=0;shift-=8)raw.push_back(static_cast<char>((n>>shift)&255));};
  auto text=[&](const std::string &s){count(s.size());raw.append(s);};
  for(const auto *group:{&active,&revoked}) {
    count(group->size());
    for(const auto &entry:*group) {
      text(entry.key_id);text(entry.role);count(entry.pub.size());
      raw.append(reinterpret_cast<const char*>(entry.pub.data()),entry.pub.size());
    }
  }
  return trustHash(reinterpret_cast<const unsigned char*>(raw.data()),raw.size());
}

// 원인별 계수(B6-2). "4개 중 3개를 읽었다"와 "3개를 다 읽었다"가 같은 결과를
// 내면 안 된다(`H-B2`).
struct EntryFaults {
  int key_id = 0, key_id_empty = 0, pubkey = 0, b64 = 0, pubkey_len = 0;
  int total() const { return key_id + key_id_empty + pubkey + b64 + pubkey_len; }
};

enum class ArrayScan { Ok, Absent, Malformed };

// 스캔은 배열 자신의 대괄호를 벗어나지 않는다(B6-2). 이름은 따옴표째 찾으므로
// `"keys"` 는 `"revoked_keys"` 안에서 걸리지 않는다 — `keys"` 앞이 '_' 라서.
// 이 성질은 우연이 아니라 요구사항이고, `C16-C7` 이 배열 순서를 뒤집어 잰다.
ArrayScan scanKeyArray(const std::string &s, const std::string &name,
                       std::vector<RawKeyEntry> *out, EntryFaults *faults) {
  const std::string needle = "\"" + name + "\"";
  const size_t name_pos = s.find(needle);
  if (name_pos == std::string::npos) return ArrayScan::Absent;
  // 이름 바로 뒤가 배열이어야 한다. `find('[', name_pos)` 만 쓰면 `"name": null`
  // 이 **다음 배열**을 자기 것으로 삼는다 — 이름을 실은 채 값이 배열이 아닌
  // 형태를 조용히 통과시키는 것이고, 그 통과의 결과는 남의 항목을 자기 목록에
  // 싣는 것이다. Go 쪽이 nil 슬라이스를 `null` 로 내보내면 실제로 일어난다.
  size_t p = s.find(':', name_pos + needle.size());
  if (p == std::string::npos) return ArrayScan::Malformed;
  ++p;
  while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n' || s[p] == '\r')) ++p;
  if (p >= s.size() || s[p] != '[') return ArrayScan::Malformed;
  const size_t arr_start = p;
  const size_t arr_end = s.find(']', arr_start);
  if (arr_end == std::string::npos) return ArrayScan::Malformed;

  size_t pos = arr_start;
  while (true) {
    const size_t obj_start = s.find('{', pos);
    if (obj_start == std::string::npos || obj_start > arr_end) break;
    const size_t obj_end = s.find('}', obj_start);
    if (obj_end == std::string::npos || obj_end > arr_end) return ArrayScan::Malformed;
    pos = obj_end + 1;

    // 필드 읽기는 role 검사보다 먼저다: 잘못된 항목은 어떤 role 을 주장하든
    // 파일을 잘못된 것으로 만들고, 잘 읽히는지도 모르는 role 은 아무것도
    // 면제할 수 없다.
    RawKeyEntry e;
    std::string pub_b64;
    if (!extractString(s, obj_start, obj_end, "key_id", &e.key_id)) {
      ++faults->key_id;
      continue;
    }
    if (e.key_id.empty()) {
      ++faults->key_id_empty;
      continue;
    }
    if (!extractString(s, obj_start, obj_end, "ed25519_public_key_base64", &pub_b64)) {
      ++faults->pubkey;
      continue;
    }
    if (!b64Decode(pub_b64, &e.pub)) {
      ++faults->b64;
      continue;
    }
    if (e.pub.size() != crypto_sign_PUBLICKEYBYTES) {
      ++faults->pubkey_len;
      continue;
    }
    e.role_present = extractString(s, obj_start, obj_end, "role", &e.role);
    out->push_back(std::move(e));
  }
  return ArrayScan::Ok;
}

// `C16-C4`: 두 배열의 key_id 는 서로소여야 한다. 검사는 **role 여과 전, 날것의
// key_id 위에서** 한다 — 여과 뒤에 재면 `keys` 에 operator 로, `revoked_keys` 에
// issuer 로 같은 id 를 적는 형태가 조용히 통과한다.
//
// 겹침을 여기서 한 번 거부하기 때문에 검증기(`strict_verify.cpp`)는 순서만
// 정하면 된다. 양쪽에서 판정하면 같은 규칙이 두 자리에 살고, 한쪽만 고쳐지는
// 날이 온다.
bool keyIdsDisjoint(const std::vector<RawKeyEntry> &a, const std::vector<RawKeyEntry> &b) {
  for (const auto &x : a) {
    for (const auto &y : b) {
      if (x.key_id == y.key_id) return false;
    }
  }
  return true;
}

}  // namespace

Keyring LoadKeyringJSON(const std::string &path, std::string *reason) {
  Keyring kr;
  if (reason) *reason = "";

  std::string s;
  if (!readFile(path, &s)) {
    if (reason) *reason = "ERR_KEYRING_READ";
    return kr;
  }

  // Minimal JSON extraction without a full JSON parser.
  // Expected fixed format (M9 adds optional "role"):
  // {"keys":[{"key_id":"...","ed25519_public_key_base64":"...","role":"issuer"|"operator"}, ...]}
  // Entries are flat objects; we parse each {...} block independently.
  // SECURITY (LLD-v2 §7.2): only role=="issuer" (or absent, backward compat)
  // may become a token trust anchor — an operator key in the keyring must NOT
  // be able to sign tokens.
  // B6-2 : bound the scan to the "keys" array, the same way
  // the bundle parser below does. Without the bound, any object elsewhere in
  // the file is read as an entry — harmless while bad entries were skipped,
  // but once they reject it would turn a valid keyring into a refusal, and a
  // gate that cannot be satisfied is a wall.
  //
  // B6-2: read failures are counted by cause and reject the whole file.
  // "3 of 4 entries were read" and "all 3 entries were read" must not produce
  // the same result (H-B2). A non-issuer entry is NOT a read failure: it is a
  // well-formed entry that is not a token trust anchor, and counting it would
  // make this refuse the shipped 4-entry keyring on every boot.
  EntryFaults faults;
  std::vector<RawKeyEntry> active, revoked;
  if (scanKeyArray(s, "keys", &active, &faults) != ArrayScan::Ok) {
    if (reason) *reason = "ERR_KEYRING_PAYLOAD";
    return kr;
  }
  // `C16-C1`: `revoked_keys` 는 없어도 된다 — 폐기가 하나도 없는 배치가 정상이고,
  // 부재를 오류로 읽으면 오늘 배포된 keyring.json 이 부팅마다 거부된다.
  if (scanKeyArray(s, "revoked_keys", &revoked, &faults) == ArrayScan::Malformed) {
    if (reason) *reason = "ERR_KEYRING_PAYLOAD";
    return kr;
  }

  if (faults.total() > 0) {
    // Per-cause counts, not a single tally: the operator has to be able to see
    // which entry is wrong to fix it, and a bare "rejected" sends them reading
    // the whole file.
    kr.pubkeys.clear();
    if (reason) {
      *reason = "ERR_KEYRING_ENTRY:key_id=" + std::to_string(faults.key_id) +
                ",key_id_empty=" + std::to_string(faults.key_id_empty) +
                ",pubkey=" + std::to_string(faults.pubkey) +
                ",b64=" + std::to_string(faults.b64) +
                ",pubkey_len=" + std::to_string(faults.pubkey_len);
    }
    return kr;
  }

  if (!keyIdsDisjoint(active, revoked)) {
    kr.pubkeys.clear();
    if (reason) *reason = "ERR_KEYRING_REVOKED_OVERLAP";
    return kr;
  }

  // 두 목록 모두 issuer(또는 role 부재)만 담는다. 게이트의 키맵은 토큰 신뢰
  // 앵커의 거울이므로, operator 키의 폐기가 여기 실리면 토큰 검증이 자기와
  // 무관한 이름을 알게 된다 — 활성 operator 키가 여기 없는 것과 같은 이유다.
  for (const auto &e : active) {
    if (e.role_present && e.role != "issuer") continue;
    kr.pubkeys[e.key_id] = e.pub;
  }
  for (const auto &e : revoked) {
    if (e.role_present && e.role != "issuer") continue;
    kr.revoked[e.key_id] = e.pub;
  }

  if (kr.pubkeys.empty()) {
    if (reason) *reason = "ERR_KEYRING_EMPTY";
  }
  return kr;
}

bool ReadRootPubFile(const std::string &path,
                     std::vector<unsigned char> *out,
                     std::string *reason) {
  if (reason) *reason = "";
  std::string s;
  if (!readFile(path, &s)) {
    if (reason) *reason = "ERR_ROOT_PUBKEY";
    return false;
  }
  // Tolerate surrounding whitespace/newline (parity with Go decodeRootPub).
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\n' || s[b] == '\r')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\n' || s[e - 1] == '\r')) --e;
  if (!b64Decode(s.substr(b, e - b), out) || out->size() != crypto_sign_PUBLICKEYBYTES) {
    if (reason) *reason = "ERR_ROOT_PUBKEY";
    return false;
  }
  return true;
}

Keyring LoadKeyringBundle(const std::string &bundle_path,
                          const std::vector<unsigned char> &root_pub,
                          const std::string &state_path,
                          std::string *reason) {
  Keyring kr;
  if (reason) *reason = "";

  if (sodium_init() < 0) {
    if (reason) *reason = "ERR_CRYPTO_INIT";
    return kr;
  }
  if (root_pub.size() != crypto_sign_PUBLICKEYBYTES) {
    if (reason) *reason = "ERR_ROOT_PUBKEY";
    return kr;
  }

  std::string s;
  if (!readFile(bundle_path, &s)) {
    if (reason) *reason = "ERR_BUNDLE_READ";
    return kr;
  }

  // Envelope. "schema_version"/"payload_b64" literals cannot collide with
  // payload content: the payload travels base64-encoded (no '"' in base64).
  long long schema = 0;
  if (!extractInt(s, 0, s.size(), "schema_version", &schema) || schema != 1) {
    if (reason) *reason = "ERR_BUNDLE_SCHEMA";
    return kr;
  }
  std::string payload_b64, sig_b64;
  if (!extractString(s, 0, s.size(), "payload_b64", &payload_b64) ||
      !extractString(s, 0, s.size(), "root_sig_b64", &sig_b64)) {
    if (reason) *reason = "ERR_BUNDLE_PARSE";
    return kr;
  }
  std::vector<unsigned char> payload, sig;
  if (!b64Decode(payload_b64, &payload) || !b64Decode(sig_b64, &sig)) {
    if (reason) *reason = "ERR_BUNDLE_PARSE";
    return kr;
  }
  if (sig.size() != crypto_sign_BYTES) {
    if (reason) *reason = "ERR_BUNDLE_SIG";
    return kr;
  }

  // 1) Root signature over the exact payload bytes (no re-serialization).
  if (crypto_sign_ed25519_verify_detached(sig.data(), payload.data(),
                                          payload.size(), root_pub.data()) != 0) {
    if (reason) *reason = "ERR_BUNDLE_SIG";
    return kr;
  }

  // Payload (only trusted after the signature check above).
  const std::string p(payload.begin(), payload.end());
  long long version_ll = 0, expires = 0;
  if (!extractInt(p, 0, p.size(), "bundle_version", &version_ll) || version_ll < 1) {
    if (reason) *reason = "ERR_BUNDLE_PAYLOAD";
    return kr;
  }
  const uint64_t version = static_cast<uint64_t>(version_ll);
  if (!extractInt(p, 0, p.size(), "expires_at_unix", &expires) || expires <= 0) {
    if (reason) *reason = "ERR_BUNDLE_PAYLOAD";
    return kr;
  }

  // keys[]: every entry must be well-formed (parity with Go parsePayload —
  // one bad entry rejects the whole bundle); only issuer/role-absent entries
  // become trust anchors.
  //
  // `C16-C2`: 폐기 목록은 **서명된 payload 안에서** 실린다. 서명 밖에 두면
  // 폐기를 지우는 것이 서명을 깨지 않고, 공격자가 붙일 수 없는 것이 아니라
  // 뗄 수 있는 것이 된다 — 그리고 떼어낸 뒤의 판정은 `ERR_UNKNOWN_KEY_ID` 가
  // 아니라 **OK** 다(키가 keys 로 돌아가는 것이 아니라, 폐기가 사라지면 그
  // key_id 는 그냥 모르는 키가 되고 그것은 거부다 — 즉 fail-closed 는
  // 유지되지만 「폐기가 관측된다」는 성질이 조용히 죽는다).
  EntryFaults faults;
  std::vector<RawKeyEntry> active, revoked;
  if (scanKeyArray(p, "keys", &active, &faults) != ArrayScan::Ok ||
      scanKeyArray(p, "revoked_keys", &revoked, &faults) == ArrayScan::Malformed ||
      faults.total() > 0 || active.empty()) {
    if (reason) *reason = "ERR_BUNDLE_PAYLOAD";
    return kr;
  }
  if (!keyIdsDisjoint(active, revoked)) {
    if (reason) *reason = "ERR_KEYRING_REVOKED_OVERLAP";
    return kr;
  }

  // 2) Monotonic version (rollback defense). Strictly-smaller versions are
  // rejected; the SAME version must load — §6.3 applies bundles by restart,
  // so a plain restart re-reads the unchanged bundle (equal-version reload is
  // not a rollback; content is fixed by the root signature).
  //
  // 키맵 충전은 이 아래 검사를 전부 통과한 뒤에 한 번만 한다. 예전에는 여기서
  // 이미 채운 뒤 각 거부 경로가 `pubkeys.clear()` 로 되돌렸는데, 그 형태는
  // 맵이 늘어날 때마다 모든 거부 경로에 한 줄씩 더하기를 요구한다 — 실제로
  // `revoked` 를 더하면서 네 곳이 조용히 낡을 뻔했다. 관리가 아니라 범주 제거.
  uint64_t last = 0;
  if (!readBundleState(state_path, &last)) {
    if (reason) *reason = "ERR_BUNDLE_STATE";
    return kr;
  }
  if (version < last) {
    if (reason) *reason = "ERR_BUNDLE_ROLLBACK";
    return kr;
  }

  // 3) Expiry and the declared remaining-validity ceiling. Like Go's
  // BundlePolicy, this measures expires-now at LOAD time, not bundle age.
  const auto now = static_cast<long long>(std::time(nullptr));
  if (now < 0) { if (reason) *reason = "ERR_BUNDLE_CLOCK"; return kr; }
  if (now >= expires) {
    if (reason) *reason = "ERR_BUNDLE_EXPIRED";
    return kr;
  }
  long long max_remaining = 86400;  // C++ compatibility default; deployments should declare it
  if (const char *raw = std::getenv("PAIL_KEYRING_MAX_LIFETIME_SEC")) {
    bool digits = *raw != '\0';
    for (const char *p = raw; *p; ++p) digits = digits && *p >= '0' && *p <= '9';
    char *end = nullptr; errno = 0;
    const long long value = std::strtoll(raw, &end, 10);
    // Keep the value representable by the Go duration used by the peer loader.
    if (!digits || errno == ERANGE || end == raw || *end || value <= 0 ||
        value > std::numeric_limits<int64_t>::max() / 1000000000LL) {
      if (reason) *reason = "ERR_BUNDLE_POLICY";
      return kr;
    }
    max_remaining = value;
  }
  if (expires - now > max_remaining) {
    if (reason) *reason = "ERR_BUNDLE_LIFETIME";
    return kr;
  }

  // Persist the accepted version only after all checks pass, and before
  // returning, so a monotonic floor exists even if the caller crashes while
  // applying the keyring (parity with Go). Equal-version reloads leave the
  // floor untouched.
  if (version > last) {
    // Merged, not literal (DC-10): a version bump must not erase the wall
    // floor — an erased floor reads as first boot and the rewind window
    // silently reopens.
    if (!writeStateMerged(state_path, &version, nullptr)) {
      if (reason) *reason = "ERR_BUNDLE_STATE";
      return kr;
    }
  }

  for (const auto &e : active) {
    if (e.role_present && e.role != "issuer") continue;
    kr.pubkeys[e.key_id] = e.pub;
  }
  for (const auto &e : revoked) {
    if (e.role_present && e.role != "issuer") continue;
    kr.revoked[e.key_id] = e.pub;
  }

  if (kr.pubkeys.size() + kr.revoked.size() <= 128 && !kr.pubkeys.empty()) {
    std::ostringstream metadata;
    metadata << "{\"schema_version\":1,\"loaded_mode\":\"bundle\",\"load_verdict\":\"LOADED\","
             << "\"bundle_sha256\":\"" << trustHash(reinterpret_cast<const unsigned char*>(s.data()),s.size())
             << "\",\"root_fingerprint_sha256\":\"" << trustHash(root_pub.data(),root_pub.size())
             << "\",\"material_digest_sha256\":\"" << trustMaterialDigest(active,revoked)
             << "\",\"max_bundle_version_decimal\":\"" << std::numeric_limits<long long>::max()
             << "\",\"bundle_version\":" << version << ",\"expires_at_unix\":" << expires
             << ",\"loaded_at_unix\":" << now << ",\"max_remaining_seconds\":" << max_remaining
             << ",\"role_fingerprints\":[";
    bool first=true;
    for(const auto &entry:kr.pubkeys){
      if(!first)metadata << ',';
      first=false;
      metadata << "{\"role\":\"issuer\",\"fingerprint_sha256\":\""
               << trustHash(entry.second.data(),entry.second.size()) << "\"}";
    }
    metadata << "]}";
    kr.loaded_trust_json=metadata.str();
  }

  if (kr.pubkeys.empty()) {
    // Signed + accepted but carries no issuer keys — the gate has no trust
    // anchor and will fail closed at token verification.
    if (reason) *reason = "ERR_KEYRING_EMPTY";
  }
  return kr;
}

std::string KeyringStatePathFromEnv(const std::string &legacy_path) {
  const std::filesystem::path legacy(legacy_path);
  const std::string bundle_path =
      envOr("PAIL_KEYRING_BUNDLE", (legacy.parent_path() / "keyring_bundle.json").c_str());
  return envOr(
      "PAIL_KEYRING_STATE",
      (std::filesystem::path(bundle_path).parent_path() / "keyring_bundle.state.json").c_str());
}

WallFloor CheckWallFloor(const std::string &state_path, int64_t boot_wall_ms) {
  std::error_code ec;
  if (!std::filesystem::exists(state_path, ec)) return WallFloor::NoFloor;
  std::string s;
  if (!readFile(state_path, &s)) return WallFloor::StateError;
  long long stored = 0;
  switch (readStateKey(s, "wall_ms0", &stored)) {
    case KeyRead::Absent: return WallFloor::NoFloor;  // pre-DC10 state file
    case KeyRead::Error: return WallFloor::StateError;
    case KeyRead::Ok: break;
  }
  // Strict: any boot wall behind the last persisted wall is a rewind. A
  // legitimate restart only ever moves forward of the previous boot's stamp.
  return boot_wall_ms < stored ? WallFloor::Rewind : WallFloor::Ok;
}

bool PersistWallFloor(const std::string &state_path, int64_t wall_ms) {
  if (wall_ms < 0) return false;
  return writeStateMerged(state_path, nullptr, &wall_ms);
}

Keyring LoadTrustedKeyring(const std::string &legacy_path,
                           std::string *mode,
                           std::string *reason) {
  const std::string m = envOr("PAIL_KEYRING_MODE", "");
  if (reason) *reason = "";

  if (m == "unsigned-dev") {
    if (mode) *mode = "unsigned-dev";
    auto kr = LoadKeyringJSON(legacy_path, reason);
    if (!kr.pubkeys.empty() && (!reason || reason->empty()))
      kr.loaded_trust_json=R"({"schema_version":1,"loaded_mode":"unsigned-dev","load_verdict":"UNSIGNED_DEVELOPMENT","expiry_applicability":"NOT_APPLICABLE"})";
    return kr;
  }
  if (mode) *mode = "bundle";
  if (!m.empty() && m != "bundle") {
    if (mode) *mode = m;
    if (reason) *reason = "ERR_KEYRING_MODE";
    return Keyring{};
  }

  const std::filesystem::path legacy(legacy_path);
  const std::string bundle_path =
      envOr("PAIL_KEYRING_BUNDLE", (legacy.parent_path() / "keyring_bundle.json").c_str());

  const char *root_pub_file = std::getenv("PAIL_ROOT_PUBKEY_FILE");
  if (root_pub_file == nullptr || root_pub_file[0] == '\0') {
    // Fail-closed default: without a root trust anchor there is no keyring.
    // PAIL_KEYRING_MODE=unsigned-dev must be set explicitly for dev stacks.
    if (reason) *reason = "ERR_ROOT_PUBKEY";
    return Keyring{};
  }
  std::vector<unsigned char> root_pub;
  if (!ReadRootPubFile(root_pub_file, &root_pub, reason)) {
    return Keyring{};
  }

  return LoadKeyringBundle(bundle_path, root_pub, KeyringStatePathFromEnv(legacy_path), reason);
}

}  // namespace pail_pep_gate

#else  // PAIL_ENABLE_GRPC == 0 stubs

namespace pail_pep_gate {

Keyring LoadKeyringJSON(const std::string &, std::string *reason) {
  if (reason) *reason = "ERR_GRPC_DISABLED";
  return Keyring{};
}

bool ReadRootPubFile(const std::string &, std::vector<unsigned char> *, std::string *reason) {
  if (reason) *reason = "ERR_GRPC_DISABLED";
  return false;
}

Keyring LoadKeyringBundle(const std::string &, const std::vector<unsigned char> &,
                          const std::string &, std::string *reason) {
  if (reason) *reason = "ERR_GRPC_DISABLED";
  return Keyring{};
}

Keyring LoadTrustedKeyring(const std::string &, std::string *mode, std::string *reason) {
  if (mode) *mode = "disabled";
  if (reason) *reason = "ERR_GRPC_DISABLED";
  return Keyring{};
}

std::string KeyringStatePathFromEnv(const std::string &) { return std::string(); }

// StateError, not NoFloor: a build without the trust path cannot rule a
// rewind out, and "could not check" must not read as "checked, clean" (H-B2).
WallFloor CheckWallFloor(const std::string &, int64_t) { return WallFloor::StateError; }

bool PersistWallFloor(const std::string &, int64_t) { return false; }

}  // namespace pail_pep_gate

#endif
