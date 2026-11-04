// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// DD-1..DD-5 (implementation contract, C-B4): control-plane transport decision. The
// as-built channel factory read certs with ReadFileOrEmpty (absence folded to
// empty options), let PAIL_GRPC_UDS_PATH silently override PAIL_GRPC_TLS, and
// opened plaintext on the single token "off" — three shapes of "unknown read
// as safe". Here the decision is pure and std-only (same tier as env_strict:
// tolerance cannot hide behind grpc linkage), and every unknown is a startup
// refusal, not a default.
//
// Two layers on purpose (env_strict.hpp precedent): DecideControlTransport is
// pure and unit-testable, ControlTransportStrict is the refusing wrapper —
// test_control_transport.cpp forks and measures the exit code, because a
// refusal nobody exercised is a claim, not a guardrail.

#pragma once

#include <sys/stat.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace pail_pep_gate {

// The explicit plaintext declaration (DD-5). PAIL_GRPC_TLS=off alone refuses:
// one flipped token must not be able to open an unauthenticated control plane.
inline constexpr const char *kInsecureAckValue = "i-accept-plaintext";

struct ControlTransportEnv {
  bool uds_set = false;
  std::string uds_path;
  bool tls_set = false;
  std::string tls_value;
  bool ack_set = false;
  std::string ack_value;
  std::string ca_path = "/etc/pail/grpc_certs/ca.crt";
  std::string key_path = "/etc/pail/grpc_certs/client.key";
  std::string cert_path = "/etc/pail/grpc_certs/client.crt";
};

// Set = present and non-empty, the same reading EnvOr gave these variables —
// an empty string keeps meaning "unset", it does not become a third state.
inline ControlTransportEnv ReadControlTransportEnv() {
  ControlTransportEnv e;
  const auto get = [](const char *key, bool &set, std::string &value) {
    const char *v = std::getenv(key);
    if (v != nullptr && v[0] != '\0') {
      set = true;
      value = v;
    }
  };
  get("PAIL_GRPC_UDS_PATH", e.uds_set, e.uds_path);
  get("PAIL_GRPC_TLS", e.tls_set, e.tls_value);
  get("PAIL_GRPC_INSECURE_ACK", e.ack_set, e.ack_value);
  bool dummy = false;
  get("PAIL_GRPC_CA", dummy, e.ca_path);
  get("PAIL_GRPC_KEY", dummy, e.key_path);
  get("PAIL_GRPC_CERT", dummy, e.cert_path);
  return e;
}

struct ControlTransportDecision {
  bool ok = false;
  std::string reason;     // human-readable cause when !ok
  std::string transport;  // "uds" | "mtls" | "plaintext" (canon v2 vocabulary)
  std::string uds_path;
  std::string ca_pem;
  std::string key_pem;
  std::string cert_pem;
};

namespace control_transport_detail {

// Absent, unreadable and empty are three ways to not have a credential; all
// three refuse by name (DD-1). ReadFileOrEmpty folded them into empty options
// and left the diagnosis to a TLS handshake log nobody attributes.
inline bool ReadPemStrict(const std::string &path, std::string &out, std::string &reason) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    reason = "cannot read " + path;
    return false;
  }
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  if (out.empty()) {
    reason = "empty credential file " + path;
    return false;
  }
  return true;
}

}  // namespace control_transport_detail

// Pure. Every branch either returns ok with the chosen posture or refuses
// with a named cause — there is no fallback arm.
inline ControlTransportDecision DecideControlTransport(const ControlTransportEnv &env) {
  ControlTransportDecision d;

  // DD-2: both set is a contradiction, not a precedence question. The as-built
  // order (UDS wins) meant a stray PAIL_GRPC_UDS_PATH silently disabled the
  // mTLS an operator believed was on.
  if (env.uds_set && env.tls_set) {
    d.reason =
        "PAIL_GRPC_UDS_PATH and PAIL_GRPC_TLS are both set — the transport is "
        "contradictory, not layered; unset one";
    return d;
  }

  if (env.uds_set) {
    // DD-3: "socket file permissions (0660) do the gating" was a comment, not
    // a check. stat failure is refusal, not absence-of-problem (H-B2).
    struct stat st;
    if (stat(env.uds_path.c_str(), &st) != 0) {
      d.reason = "cannot stat UDS socket " + env.uds_path +
                 " — unverifiable is not safe";
      return d;
    }
    if (!S_ISSOCK(st.st_mode)) {
      d.reason = "UDS path " + env.uds_path + " is not a socket";
      return d;
    }
    if ((st.st_mode & (S_IROTH | S_IWOTH)) != 0) {
      d.reason = "UDS socket " + env.uds_path +
                 " is other-accessible — 0660 is the gate this transport "
                 "claims; o+rw voids it";
      return d;
    }
    d.ok = true;
    d.transport = "uds";
    d.uds_path = env.uds_path;
    return d;
  }

  const std::string tls = env.tls_set ? env.tls_value : "on";
  if (tls == "off") {
    // DD-5: plaintext exists only as an explicit two-variable declaration
    // (U-D8: kept, not deleted — bench rigs are real, silent plaintext is not).
    if (!env.ack_set || env.ack_value != kInsecureAckValue) {
      d.reason =
          "PAIL_GRPC_TLS=off without PAIL_GRPC_INSECURE_ACK=" +
          std::string(kInsecureAckValue) +
          " — plaintext control plane requires the explicit declaration";
      return d;
    }
    d.ok = true;
    d.transport = "plaintext";
    return d;
  }
  if (tls != "on") {
    // A typo like "offf" must not mean "on" — the vocabulary is closed.
    d.reason = "PAIL_GRPC_TLS=\"" + tls + "\" is not in {on, off}";
    return d;
  }

  ControlTransportDecision m;
  if (!control_transport_detail::ReadPemStrict(env.ca_path, m.ca_pem, d.reason)) return d;
  if (!control_transport_detail::ReadPemStrict(env.key_path, m.key_pem, d.reason)) return d;
  if (!control_transport_detail::ReadPemStrict(env.cert_path, m.cert_pem, d.reason)) return d;
  m.ok = true;
  m.transport = "mtls";
  return m;
}

// Refusing wrapper, memoized: the channel factory and the config seal must see
// the *same* decision, or the seal describes a posture nobody is running
// (D §2.3 — seal the chosen branch, not the env declaration). Static local in
// an inline function is one instance program-wide.
inline const ControlTransportDecision &ControlTransportStrict() {
  static const ControlTransportDecision d = [] {
    const ControlTransportDecision r = DecideControlTransport(ReadControlTransportEnv());
    if (!r.ok) {
      // "ERR_BAD_ENV" stands alone so the reason drift scan (drift_test.go
      // errLiteral) sees it — same shape as env_strict.hpp.
      std::fprintf(stderr, "PAIL PREFLIGHT FAIL: %s control transport — %s\n",
                   "ERR_BAD_ENV", r.reason.c_str());
      std::fprintf(stderr,
                   "PAIL PREFLIGHT FAIL: refusing to start. The control plane "
                   "runs exactly one of uds | mtls | plaintext(acked); an "
                   "undecidable transport does not degrade, it refuses.\n");
      std::fflush(stderr);
      std::exit(78);
    }
    return r;
  }();
  return d;
}

}  // namespace pail_pep_gate
