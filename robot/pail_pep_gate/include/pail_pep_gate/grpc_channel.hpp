// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#pragma once

// The one definition of how this gate authenticates to the control plane
// (LLD-v2 §3, M7): UDS file permissions, mTLS, or — dev only — plaintext.
//
// It lives on its own because SD4's config seal needs a channel in provider
// modes where no GrpcTokenProvider is constructed. Two channel builders would
// be two auth policies, and the second one would be the one nobody audits.

#include <memory>
#include <string>

#if defined(PAIL_ENABLE_GRPC) && (PAIL_ENABLE_GRPC == 1)
#include <grpcpp/channel.h>

namespace pail_pep_gate {

std::shared_ptr<grpc::Channel> MakeControlChannel(const std::string &addr);

}  // namespace pail_pep_gate
#endif
