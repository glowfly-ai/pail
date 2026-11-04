// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// `L10` 관측점 : the C++ half of the process-identity line.
// Go 쌍둥이는 internal/deploysec/identity_test.go 이고 팔 셋이 같다 — 값 · 접힘 ·
// 순서. 형식이 한쪽에서만 바뀌면 두 배포가 다른 줄을 내는데, 그것은 로그를 읽는
// 쪽에서 "한쪽 컴포넌트가 줄을 안 낸다"와 구분되지 않는다.
//
// Plain executable, no gtest: exit 0 only if every arm holds.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <sstream>
#include <string>
#include <unistd.h>

#include "pail_deploy_guard/deploy_guard.hpp"

using pail_deploy_guard::EmitProcessIdentity;

namespace {

// stderr 를 파일로 갈아끼운다. 방출기가 로거가 아니라 stderr 로 직접 쓰므로
// 주입할 이음매가 없다 — 파일을 바꾸는 것이 이음매다.
template<typename Fn>
std::string CaptureStderr(Fn fn)
{
  char path[] = "/tmp/pail_identity_XXXXXX";
  const int fd = ::mkstemp(path);
  if (fd < 0) {
    std::printf("FAIL capture: mkstemp\n");
    std::exit(2);
  }
  std::fflush(stderr);
  const int saved = ::dup(STDERR_FILENO);
  ::dup2(fd, STDERR_FILENO);
  fn();
  std::fflush(stderr);
  ::dup2(saved, STDERR_FILENO);
  ::close(saved);

  ::lseek(fd, 0, SEEK_SET);
  std::string out;
  char buf[4096];
  ssize_t n;
  while ((n = ::read(fd, buf, sizeof(buf))) > 0) {
    out.append(buf, static_cast<size_t>(n));
  }
  ::close(fd);
  ::unlink(path);
  return out;
}

std::string IdentityLine(const std::string & out)
{
  std::istringstream is(out);
  std::string line;
  while (std::getline(is, line)) {
    if (line.rfind(pail_deploy_guard::kIdentityPrefix, 0) == 0) {
      return line;
    }
  }
  return std::string();
}

// 값 팔. 줄의 존재만 재면 하드코딩된 `uid=10001` 도 통과하는데, 하드코딩된 값은
// 줄이 없는 것보다 나쁘다 — 측정처럼 읽히기 때문이다.
int ValueArm()
{
  const std::string out = CaptureStderr([] { EmitProcessIdentity("unit"); });
  char want[256];
  std::snprintf(want, sizeof(want), "%s uid=%d euid=%d gid=%d egid=%d component=unit",
                pail_deploy_guard::kIdentityPrefix,
                static_cast<int>(::getuid()), static_cast<int>(::geteuid()),
                static_cast<int>(::getgid()), static_cast<int>(::getegid()));
  if (out.find(want) == std::string::npos) {
    std::printf("FAIL value: want=%s got=%s\n", want, out.c_str());
    return 1;
  }
  return 0;
}

// 접힘 팔. 보통의 실행에서는 uid == euid 라서 한 값을 두 번 찍어도 위 팔은 그대로
// 통과한다. 여기서는 칸의 **이름**이 따로 있는지를 재는데, 접힘이 없애는 것이
// 정확히 그것이다.
int FoldArm()
{
  const std::string line = IdentityLine(CaptureStderr([] { EmitProcessIdentity("unit"); }));
  if (line.empty()) {
    std::printf("FAIL fold: identity line absent\n");
    return 1;
  }
  std::istringstream is(line);
  std::string tok;
  std::map<std::string, int> seen;
  while (is >> tok) {
    const size_t eq = tok.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    seen[tok.substr(0, eq)] += 1;
  }
  int bad = 0;
  for (const char * k : {"uid", "euid", "gid", "egid"}) {
    const auto it = seen.find(k);
    if (it == seen.end()) {
      std::printf("FAIL fold: field %s absent — 접힌 칸은 조용하다\n", k);
      ++bad;
    } else if (it->second > 1) {
      std::printf("FAIL fold: field %s appears twice — 같은 이름의 두 칸은 대조되지 않는다\n", k);
      ++bad;
    }
  }
  return bad;
}

// 순서 팔. EnforceDeployGuard 의 세 갈래 중 마지막은 exit(78) 이라 이 프로세스에서
// 돌릴 수 없다 — 여기서 재는 것은 검사 가능한 절반이다: 신원 줄이 판정 줄보다
// 먼저 나온다. 소스 위치 주장(함수의 첫 문장)은 러너의 구조 팔이 잰다.
int OrderArm()
{
  ::setenv("PAIL_PROFILE", "dev", 1);
  const char * argv[] = {"test_process_identity"};
  const std::string out = CaptureStderr([&argv] {
    pail_deploy_guard::EnforceDeployGuard("unit", 1, argv);
  });
  const size_t i = out.find(pail_deploy_guard::kIdentityPrefix);
  if (i == std::string::npos) {
    std::printf("FAIL order: EnforceDeployGuard emitted no identity line:\n%s\n", out.c_str());
    return 1;
  }
  const size_t j = out.find("PAIL PREFLIGHT: profile=");
  if (j == std::string::npos) {
    std::printf("FAIL order: no verdict line — 이 팔의 전제가 없다:\n%s\n", out.c_str());
    return 1;
  }
  if (i > j) {
    std::printf("FAIL order: identity after verdict (identity@%zu verdict@%zu)\n", i, j);
    return 1;
  }
  return 0;
}

}  // namespace

int main()
{
  const int bad = ValueArm() + FoldArm() + OrderArm();
  if (bad != 0) {
    std::printf("L10 cpp: %d failure(s)\n", bad);
    return 1;
  }
  std::printf("L10 cpp: identity line ok (value, fold, order)\n");
  return 0;
}
