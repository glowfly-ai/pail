// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import "testing"

func TestFirstReleaseCompletionObservation(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		v                             int
		result, wantState, wantReason string
	}{
		{"accepted", 10, "accepted", "COMPLETED", ""},
		{"rejected", 10, "rejected", "ACCEPTED", ""},
		{"legacy", 9, "", "UNKNOWN", "LEGACY_COMPLETION_UNDETERMINED"},
		{"future", 11, "accepted", "UNKNOWN", "COMPLETION_RECORD_UNSUPPORTED"},
		{"missing_result", 10, "", "UNKNOWN", "COMPLETION_RECORD_UNSUPPORTED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := ledgerFixture(t)
			w := (&written{}).accepted("robot-1", "plan", "chain-a", 1)
			f := fields{"kind": "GATE_DECISION", "journal_v": tc.v, "robot_id": "robot-1", "chain_id": "chain-a", "token_id": tokenOf("chain-a", 1), "decision": "PERMIT", "step_complete": true, "fatal": false, "chain_attributed": true}
			if tc.v >= 10 {
				f["completion_result"] = tc.result
				f["completion_reason"] = "TEST"
			}
			if tc.result == "accepted" {
				f["consumed_sequence_index"] = 1
				f["next_expected_index"] = 2
				f["lease_reported_at_after"] = 0
			}
			w.add("GATE_DECISION", f).ok(c)
			got := ledgerFacet(t, c, "robot-1", "plan")
			if got.Value.State != tc.wantState || (tc.wantReason != "" && got.Reason != tc.wantReason) {
				t.Fatalf("got %+v / %+v", got.Value, got)
			}
			if tc.result != "accepted" && got.Plan.StepsCompleted != 0 {
				t.Fatalf("report counted as accepted: %+v", got.Plan)
			}
		})
	}
}
