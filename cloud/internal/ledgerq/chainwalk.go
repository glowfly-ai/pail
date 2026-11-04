// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package ledgerq

import (
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

// ChainWalk receives what one verification pass saw: every record the walk
// verified, in ledger order, and then the verdict of the pass. It is how a
// reader that needs more than the index columns (the step count of a plan, the
// decision of a gate record) gets it without a second reading of the ledger.
//
// Record is called while the pass is still open: nothing it was given is
// trustworthy until Done says so. A pass that ends without a published verdict
// must leave the receiver's earlier result unusable, not current.
type ChainWalk interface {
	Record(seq int64, rec blackbox.Record)
	Done(v ChainVerdict)
}

// ChainVerdict is the outcome of one pass as the index published it.
type ChainVerdict struct {
	State       string // ok | chain_error | absent | unverified
	Code        string // closed fault code; empty when State is ok
	VerifiedSeq int64  // records 1..VerifiedSeq are verified; 0 = none may be shown
	TipSeq      *int64 // observed end of the ledger; nil = not known
	LagRecords  *int64 // TipSeq - VerifiedSeq; nil = not known
	At          time.Time
	Published   bool // the index transaction committed
}

// RecordName is the outcome vocabulary of the index for a record type.
func RecordName(t uint32) string { return recordName(t) }

func chainVerdict(st ChainStatus, diag ChainDiagnostic, now time.Time, published bool) ChainVerdict {
	v := ChainVerdict{State: st.State, VerifiedSeq: st.CheckedToSeq, TipSeq: diag.ObservedTip.Sequence, LagRecords: diag.IndexLag.Records, At: now, Published: published}
	if diag.Error != nil {
		v.Code = diag.Error.Code
	}
	return v
}
