// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_pep_gate/config_seal_client.hpp"

#include "pail_pep_gate/grpc_channel.hpp"

#include <grpcpp/grpcpp.h>

#include "token_service.grpc.pb.h"
#include "token_service.pb.h"

#include <chrono>
#include <cstdlib>

namespace pail_pep_gate {
namespace {

// The seal is a one-shot at start-up, like Attest, so it gets a start-up sized
// budget rather than the 50ms steady-state deadline. It is still bounded: an
// unreachable issuer must delay the gate, not detain it.
std::chrono::milliseconds SealDeadline() {
  const char *v = std::getenv("PAIL_SEAL_DEADLINE_MS");
  int ms = (v != nullptr && v[0] != '\0') ? std::atoi(v) : 2000;
  if (ms < 5) ms = 5;
  return std::chrono::milliseconds(ms);
}

std::string ToHex(const std::string &raw) {
  static const char *k = "0123456789abcdef";
  std::string h;
  h.reserve(raw.size() * 2);
  for (unsigned char c : raw) {
    h.push_back(k[c >> 4]);
    h.push_back(k[c & 0x0f]);
  }
  return h;
}

}  // namespace

SealDelivery SendConfigSeal(const std::string &addr,
                            const std::string &robot_id,
                            const std::string &component,
                            int seal_version,
                            const std::string &canonical,
                            bool verifies_authorization,
                            const std::vector<std::string> &degraded,
                            const std::string &build_info) {
  SealDelivery out;

  pail::token::v1::SealConfigRequest req;
  req.set_robot_id(robot_id);
  req.set_component(component);
  req.set_seal_version(seal_version);
  req.set_canonical(canonical);
  req.set_verifies_authorization(verifies_authorization);
  for (const auto &d : degraded) req.add_degraded(d);
  req.set_build_info(build_info);

  // Its own channel: in static/notoken mode there is no GrpcTokenProvider to
  // borrow one from, and that is the case this call exists for.
  auto stub = pail::token::v1::TokenService::NewStub(MakeControlChannel(addr));

  pail::token::v1::SealConfigResponse resp;
  grpc::ClientContext ctx;
  ctx.set_deadline(std::chrono::system_clock::now() + SealDeadline());
  const auto status = stub->SealConfig(&ctx, req, &resp);
  if (!status.ok()) {
    out.sent = false;
    // Carry the wire code into the status the node logs. Folding every non-OK
    // into a bare "UNREACHABLE" made a PermissionDenied read as a network
    // problem (measured 2026-08-12: the issuer was refusing the gate's
    // unregistered client cert, and the log said the issuer was down).
    out.status = "UNREACHABLE(code=" + std::to_string(status.error_code()) +
                 " " + status.error_message() + ")";
    return out;
  }
  out.sent = true;
  out.status = resp.status();
  out.digest_hex = ToHex(resp.config_digest());
  return out;
}

}  // namespace pail_pep_gate
