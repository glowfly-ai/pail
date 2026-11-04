// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"time"

	"github.com/glowfly/pail/services/internal/ledgerq"
)

// A pass that found the ledger changed while it was being read has verified
// nothing: neither that the ledger is sound nor that it is damaged. While a
// robot moves the ledger copy is replaced about once a second, and one such
// pass would leave the plan column UNKNOWN until the next cycle. The cycle
// therefore reads again, a bounded number of times. Every pass is a full
// verification that publishes its own verdict; what counts as verified is not
// changed, and a verdict about the ledger itself is never read away.
const ledgerPasses = 3
const ledgerPassPause = 250 * time.Millisecond

type chainVerifier interface {
	IngestChain(dir string, now time.Time) (ledgerq.ChainStatus, error)
}

func verifyLedger(v chainVerifier, dir string, now func() time.Time, pause func(time.Duration)) (cs ledgerq.ChainStatus, passes int, err error) {
	for passes = 1; ; passes++ {
		cs, err = v.IngestChain(dir, now())
		if err != nil || cs.State != "unverified" || cs.Error != "SOURCE_UNSTABLE" || passes >= ledgerPasses {
			return cs, passes, err
		}
		pause(ledgerPassPause)
	}
}
