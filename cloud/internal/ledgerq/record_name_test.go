// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package ledgerq

import (
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/blackbox"
)

// Every record kind the blackbox defines has a name in the mirror's vocabulary; the C1 receipts (100/101) are
// CORE_OPERATION / CORE_REPORT, never the TYPE_<n> fallback (preview.38 RV09).
func TestRecordNameCoversCoreRecords(t *testing.T) {
	if got := recordName(blackbox.RecordCoreOperation); got != "CORE_OPERATION" {
		t.Fatalf("RecordCoreOperation -> %q", got)
	}
	if got := recordName(blackbox.RecordCoreReport); got != "CORE_REPORT" {
		t.Fatalf("RecordCoreReport -> %q", got)
	}
	for _, k := range []uint32{blackbox.RecordTokenIssued, blackbox.RecordGateDecision, blackbox.RecordCoreOperation, blackbox.RecordCoreReport} {
		if strings.HasPrefix(recordName(k), "TYPE_") {
			t.Fatalf("record kind %d has no name", k)
		}
	}
	if got := recordName(250); got != "TYPE_250" {
		t.Fatalf("unknown kinds keep the explicit fallback: %q", got)
	}
}
