// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_pep_gate/grpc_channel.hpp"

#include <grpcpp/grpcpp.h>

#include <cstdio>

#include "pail_pep_gate/control_transport.hpp"

namespace pail_pep_gate {

// gRPC control-plane auth (LLD-v2 §3, M7; posture decided per implementation contract).
// SROS2 only covers ROS2 topics; an unauthenticated :50051 lets any process
// forge ReportDecision. The transport is decided by ControlTransportStrict —
// absence, contradiction and unacked plaintext all refused at startup before
// this point, so the EX-1/U-D7 dispute ("do empty SslCredentials fail the
// handshake?") cannot arise: there is no path that hands grpc empty options.
std::shared_ptr<grpc::Channel> MakeControlChannel(const std::string &addr) {
  const ControlTransportDecision &t = ControlTransportStrict();
  if (t.transport == "uds") {
    // Same-host transport: the 0660 socket is the gate, and Strict verified it
    // (socket exists, is a socket, no o+rw) instead of asserting it in a comment.
    std::fprintf(stderr, "[pail_pep_gate] control plane via UDS %s\n", t.uds_path.c_str());
    return grpc::CreateChannel("unix:" + t.uds_path, grpc::InsecureChannelCredentials());
  }
  if (t.transport == "plaintext") {
    std::fprintf(stderr,
                 "[pail_pep_gate] WARNING: plaintext gRPC — explicitly acknowledged via "
                 "PAIL_GRPC_INSECURE_ACK; DEV ONLY\n");
    return grpc::CreateChannel(addr, grpc::InsecureChannelCredentials());
  }
  grpc::SslCredentialsOptions ssl;
  ssl.pem_root_certs = t.ca_pem;
  ssl.pem_private_key = t.key_pem;
  ssl.pem_cert_chain = t.cert_pem;
  std::fprintf(stderr, "[pail_pep_gate] control plane via mTLS %s\n", addr.c_str());
  return grpc::CreateChannel(addr, grpc::SslCredentials(ssl));
}

}  // namespace pail_pep_gate
