// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package deploysec

import (
	"fmt"
	"os"
)

// IdentityPrefix is the greppable head of the `L10` line. It is a constant so
// the checker and the emitter cannot drift apart by a typo — a test that
// retypes the literal would pass while the deployment emits something else.
const IdentityPrefix = "PAIL PREFLIGHT IDENTITY:"

// EmitProcessIdentity writes the process credentials the deployment actually
// runs with (`L10`, implementation contract).
//
// It reports, it does not judge. `uid=0` is not refused here: whether root is
// acceptable is a deployment decision, and `U-E3` kept `L10` delegated. What
// was missing was not the isolation — the containers already run as
// `uid=10001` — but any line that says so. Without it, a unit shipped without
// `User=` looks exactly like one shipped with it.
//
// Both the real and the effective ids are printed. Equal is the common case;
// when they differ the process was launched setuid, and folding the two into
// one field would make that indistinguishable from the ordinary case (`H-B2`).
func EmitProcessIdentity(component string) {
	fmt.Fprintf(os.Stderr, "%s uid=%d euid=%d gid=%d egid=%d component=%s\n",
		IdentityPrefix, os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), component)
}
