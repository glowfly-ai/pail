// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

#pragma once

// SD4 (설정봉인 LLD §3.3): ship the gate's own configuration declaration to the
// issuer so it can be hashed and journalled.
//
// Deliberately NOT a method on ITokenProvider. The seal must be sent in EVERY
// provider mode, and the modes worth recording most — static, notoken — are
// exactly the ones whose provider talks to nobody. Hanging the seal off the
// provider would make it vanish in precisely the runs SD4 exists to make
// visible, and the completion criterion would then be met by "the degraded run
// left nothing at all", which is not distinguishability, it is absence.
//
// It is best-effort by construction: a rig that runs `static` with no issuer
// reachable (PC1/PC2 perception benches) must still start. A seal that cannot
// be delivered is a warning, never a refusal — refusing here would be the
// enforcement SD4 explicitly does not claim (쉬운설명 §8.1).

#include <string>
#include <vector>

namespace pail_pep_gate {

struct SealDelivery {
  bool sent = false;         // the RPC completed (any verdict)
  std::string status;        // OK | REJECTED | ERROR | UNREACHABLE | NO_GRPC
  std::string digest_hex;    // the digest the ISSUER computed, when it answered
};

// Returns without throwing under any condition.
SealDelivery SendConfigSeal(const std::string &addr,
                            const std::string &robot_id,
                            const std::string &component,
                            int seal_version,
                            const std::string &canonical,
                            bool verifies_authorization,
                            const std::vector<std::string> &degraded,
                            const std::string &build_info);

}  // namespace pail_pep_gate
