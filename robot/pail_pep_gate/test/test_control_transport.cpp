// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// D4-C2/C3/C4/C7 (implementation contract, unit half): the transport decision measured
// branch by branch — absence refused by name, contradiction refused, socket
// permissions actually checked, plaintext only behind the explicit ack. The
// live half (a real node refusing to start, rc!=0) is the live tier's.
//
// Plain executable, no gtest . Direct DecideControlTransport calls
// carry the table; fork cases run ControlTransportStrict for real and read the
// exit code and ERR_BAD_ENV off a pipe (env_strict.cpp precedent — a refusal
// nobody exercised is a claim). Positive controls included: a table that only
// ever refuses proves a wall, not a gate.

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

#include "pail_pep_gate/control_transport.hpp"

using pail_pep_gate::ControlTransportDecision;
using pail_pep_gate::ControlTransportEnv;
using pail_pep_gate::ControlTransportStrict;
using pail_pep_gate::DecideControlTransport;

namespace {

int failures = 0;

// 지금 재고 있는 §8 조건. 통과한 줄도 이 이름을 찍는다 — 실패했을 때만 이름을
// 부르는 검사는 초록인 날 출력에 자기 이름이 없고, 그러면 "지켜졌다"와 "테스트가
// 지워졌다"가 같은 침묵으로 도착한다(`H-B2`). `ob4_closure.py` 가 이 대괄호
// 표식으로 §8 칸의 결속을 잰다.
const char *g_cond = "UNSCOPED";

// 스코프로 붙인다: 호출부 30여 곳에 id 를 복사하면 그중 하나가 낡는 것을 아무도
// 모른다. 함수당 한 줄이면 조건과 케이스가 1:1 이고, 빠뜨린 함수는 `[UNSCOPED]`
// 로 출력에 나타난다 — 침묵이 아니라 이름으로.
struct Cond {
  const char *prev;
  explicit Cond(const char *id) : prev(g_cond) { g_cond = id; }
  ~Cond() { g_cond = prev; }
};

void check(bool ok, const char *what) {
  if (!ok) {
    std::fprintf(stderr, "  FAIL [%s] %s\n", g_cond, what);
    ++failures;
  } else {
    std::printf("  ok   [%s] %s\n", g_cond, what);
  }
}

bool contains(const std::string &hay, const char *needle) {
  return hay.find(needle) != std::string::npos;
}

std::string write_file(const std::string &dir, const char *name, const std::string &bytes) {
  const std::string path = dir + "/" + name;
  std::ofstream f(path, std::ios::binary);
  f << bytes;
  return path;
}

// A real AF_UNIX socket: the filesystem entry outlives the fd, which is all
// stat() sees. A regular file at the same path is a distinct (refused) case.
std::string make_socket(const std::string &dir, mode_t mode) {
  const std::string path = dir + "/ctl.sock";
  ::unlink(path.c_str());
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    check(false, "socket() failed");
    return path;
  }
  sockaddr_un sa;
  std::memset(&sa, 0, sizeof sa);
  sa.sun_family = AF_UNIX;
  std::strncpy(sa.sun_path, path.c_str(), sizeof(sa.sun_path) - 1);
  if (::bind(fd, reinterpret_cast<sockaddr *>(&sa), sizeof sa) != 0) {
    check(false, "bind() failed");
  }
  ::close(fd);
  ::chmod(path.c_str(), mode);
  return path;
}

// PAIL-CASE: TransportBothSet
// DD-2: contradiction refuses; the as-built precedence (UDS silently wins)
// is the defect under test.
void case_both_set() {
  Cond c("D4-C3");  // UDS 와 TLS 동시 지정 → 기동 거부
  ControlTransportEnv e;
  e.uds_set = true;
  e.uds_path = "/tmp/whatever.sock";
  e.tls_set = true;
  e.tls_value = "on";
  const ControlTransportDecision d = DecideControlTransport(e);
  check(!d.ok, "both set refused");
  check(contains(d.reason, "both set"), "both-set reason names the contradiction");
}

// PAIL-CASE: TransportUds
// DD-3: the 0660 claim is verified, not asserted. stat failure != safe (H-B2).
void case_uds(const std::string &dir) {
  Cond c("D4-C4");  // o+rw 소켓 거부 (+ stat 실패·비소켓)
  ControlTransportEnv e;
  e.uds_set = true;

  e.uds_path = make_socket(dir, 0660);
  ControlTransportDecision d = DecideControlTransport(e);
  check(d.ok && d.transport == "uds", "0660 socket accepted as uds");
  check(d.uds_path == e.uds_path, "uds path carried in decision");

  e.uds_path = make_socket(dir, 0666);
  d = DecideControlTransport(e);
  check(!d.ok, "0666 socket refused");
  check(contains(d.reason, "other-accessible"), "o+rw reason names the permission");

  e.uds_path = make_socket(dir, 0662);  // o+w alone is enough to void the gate
  d = DecideControlTransport(e);
  check(!d.ok, "0662 socket refused (o+w)");

  e.uds_path = dir + "/absent.sock";
  d = DecideControlTransport(e);
  check(!d.ok, "missing socket refused");
  check(contains(d.reason, "cannot stat"), "stat failure is refusal, not absence-of-problem");

  e.uds_path = write_file(dir, "regular.sock", "not a socket");
  ::chmod(e.uds_path.c_str(), 0660);
  d = DecideControlTransport(e);
  check(!d.ok, "regular file refused");
  check(contains(d.reason, "not a socket"), "non-socket reason");
}

// PAIL-CASE: TransportMtls
// DD-1: absent / unreadable / empty credentials refuse by file name — none of
// them fold into empty SslCredentialsOptions.
void case_mtls(const std::string &dir) {
  Cond c("D4-C2");  // CA/키/인증서 부재·빈 파일 → 거부
  ControlTransportEnv e;  // nothing set -> default mtls posture
  e.ca_path = write_file(dir, "ca.crt", "CA-BYTES");
  e.key_path = write_file(dir, "client.key", "KEY-BYTES");
  e.cert_path = write_file(dir, "client.crt", "CERT-BYTES");

  ControlTransportDecision d = DecideControlTransport(e);
  check(d.ok && d.transport == "mtls", "all three credentials -> mtls");
  check(d.ca_pem == "CA-BYTES" && d.key_pem == "KEY-BYTES" && d.cert_pem == "CERT-BYTES",
        "pems carry the exact bytes read");

  ControlTransportEnv missing = e;
  missing.key_path = dir + "/absent.key";
  d = DecideControlTransport(missing);
  check(!d.ok, "missing key refused");
  check(contains(d.reason, "absent.key"), "missing-file reason names the file");

  ControlTransportEnv empty = e;
  empty.ca_path = write_file(dir, "empty_ca.crt", "");
  d = DecideControlTransport(empty);
  check(!d.ok, "empty ca refused");
  check(contains(d.reason, "empty credential"), "empty-file reason distinct from unreadable");

  // tls explicitly "on" is the same posture as unset, not a third state
  ControlTransportEnv on = e;
  on.tls_set = true;
  on.tls_value = "on";
  d = DecideControlTransport(on);
  check(d.ok && d.transport == "mtls", "explicit on -> mtls");
}

// PAIL-CASE: TransportPlaintextAck
// DD-5: "off" alone refuses; only the two-variable declaration opens plaintext.
void case_plaintext() {
  Cond c("D4-C7");  // 평문은 명시 선언(ACK) 없이는 불가
  ControlTransportEnv e;
  e.tls_set = true;
  e.tls_value = "off";

  ControlTransportDecision d = DecideControlTransport(e);
  check(!d.ok, "off without ack refused");
  check(contains(d.reason, "PAIL_GRPC_INSECURE_ACK"), "refusal names the missing declaration");

  e.ack_set = true;
  e.ack_value = "yes";
  d = DecideControlTransport(e);
  check(!d.ok, "off with wrong ack refused");

  e.ack_value = "i-accept-plaintext";
  d = DecideControlTransport(e);
  check(d.ok && d.transport == "plaintext", "off + exact ack -> plaintext");

  // closed vocabulary: a typo must not mean "on" (and must not mean "off")
  ControlTransportEnv typo;
  typo.tls_set = true;
  typo.tls_value = "offf";
  d = DecideControlTransport(typo);
  check(!d.ok, "tls typo refused");
  check(contains(d.reason, "{on, off}"), "vocabulary reason shows the closed set");
}

void clear_transport_env() {
  ::unsetenv("PAIL_GRPC_UDS_PATH");
  ::unsetenv("PAIL_GRPC_TLS");
  ::unsetenv("PAIL_GRPC_INSECURE_ACK");
  ::unsetenv("PAIL_GRPC_CA");
  ::unsetenv("PAIL_GRPC_KEY");
  ::unsetenv("PAIL_GRPC_CERT");
}

// PAIL-CASE: TransportStrictRefusal
// The wrapper must actually exit 78 and name ERR_BAD_ENV on stderr. Runs in a
// fork so the parent's memoized Strict state is never initialized here.
void refusal_case(const char *cond, const char *label, void (*set_env)()) {
  Cond c(cond);  // 어느 §8 칸을 재는 fork 인지는 호출부가 정한다
  int fds[2];
  if (pipe(fds) != 0) {
    check(false, "pipe() failed");
    return;
  }
  const pid_t pid = fork();
  if (pid < 0) {
    check(false, "fork() failed");
    return;
  }
  if (pid == 0) {
    close(fds[0]);
    dup2(fds[1], 2);
    clear_transport_env();
    set_env();
    const auto &d = ControlTransportStrict();
    // reaching here is the defect being tested for
    std::fprintf(stdout, "unexpected decision %s\n", d.transport.c_str());
    _exit(0);
  }
  close(fds[1]);
  std::string err;
  char buf[512];
  ssize_t n;
  while ((n = read(fds[0], buf, sizeof buf)) > 0) err.append(buf, static_cast<size_t>(n));
  close(fds[0]);
  int status = 0;
  waitpid(pid, &status, 0);

  const std::string what = std::string("strict(") + label + ")";
  check(WIFEXITED(status) && WEXITSTATUS(status) == 78, (what + " exit 78").c_str());
  check(contains(err, "ERR_BAD_ENV"), (what + " names ERR_BAD_ENV").c_str());
  check(contains(err, "PAIL PREFLIGHT FAIL"), (what + " greppable preflight prefix").c_str());
}

// PAIL-CASE: TransportStrictGoodPath
// Good env returns in-process (no refusal on the happy path) — run last, after
// every fork case, because Strict memoizes its first answer.
void good_strict_case(const std::string &dir) {
  // 양성 대조 — 조건 id 를 붙이지 않는다. 이 줄은 "거부만 하는 표는 게이트가
  // 아니라 벽"임을 보이는 것이지 §8 의 어느 칸을 판정하는 것이 아니다.
  Cond c("D4-STRICT-OK");
  clear_transport_env();
  const std::string sock = make_socket(dir, 0660);
  ::setenv("PAIL_GRPC_UDS_PATH", sock.c_str(), 1);
  const ControlTransportDecision &d = ControlTransportStrict();
  check(d.ok && d.transport == "uds" && d.uds_path == sock, "good uds env decided in-process");
}

}  // namespace

int main() {
  char tmpl[] = "/tmp/pail_ct_XXXXXX";
  const char *dir_c = mkdtemp(tmpl);
  if (dir_c == nullptr) {
    std::fprintf(stderr, "FAIL: mkdtemp\n");
    return 1;
  }
  const std::string dir(dir_c);

  case_both_set();
  case_uds(dir);
  case_mtls(dir);
  case_plaintext();

  refusal_case("D4-C7", "off-no-ack", [] { ::setenv("PAIL_GRPC_TLS", "off", 1); });
  refusal_case("D4-C3", "both-set", [] {
    ::setenv("PAIL_GRPC_UDS_PATH", "/tmp/x.sock", 1);
    ::setenv("PAIL_GRPC_TLS", "on", 1);
  });
  refusal_case("D4-C2", "mtls-missing-certs", [] {
    ::setenv("PAIL_GRPC_CA", "/nonexistent/pail_ct/ca.crt", 1);
  });

  good_strict_case(dir);

  if (failures == 0) {
    std::printf("test_control_transport: all cases passed\n");
    return 0;
  }
  std::fprintf(stderr, "test_control_transport: %d failure(s)\n", failures);
  return 1;
}
