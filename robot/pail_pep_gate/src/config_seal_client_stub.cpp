// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#include "pail_pep_gate/config_seal_client.hpp"

// PAIL_ENABLE_GRPC=0 build: there is no control-plane client linked, so the
// seal cannot leave this process. The canonical text and its local digest are
// still computed and logged by the node — the honest limitation is that in this
// build the seal is not journalled anywhere durable, and NO_GRPC says so
// instead of pretending the seal was delivered.

namespace pail_pep_gate {

SealDelivery SendConfigSeal(const std::string &, const std::string &, const std::string &,
                            int, const std::string &, bool,
                            const std::vector<std::string> &, const std::string &) {
  SealDelivery out;
  out.sent = false;
  out.status = "NO_GRPC";
  return out;
}

}  // namespace pail_pep_gate
