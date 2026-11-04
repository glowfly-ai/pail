// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package completion

import (
	"testing"
)

func TestFirstReleaseCompletionValidation(t *testing.T) {
	p := func(v int32) *int32 { return &v }
	yes := true
	good := Record{JournalV: 10, CompletionResult: "accepted", CompletionReason: "COMPLETION_SIGNAL_MATCHED", ConsumedSequenceIndex: p(2), NextExpectedIndex: p(3), LeaseReportedAtAfter: p(2)}
	for _, tc := range []struct {
		name            string
		change          func(*Record)
		accept, wantErr bool
	}{
		{"accepted", func(*Record) {}, true, false},
		{"legacy_unknown", func(c *Record) { *c = Record{JournalV: 9} }, false, false},
		{"future_refused", func(c *Record) { c.JournalV = 11 }, false, true},
		{"missing_result", func(c *Record) { c.CompletionResult = "" }, false, true},
		{"missing_reason", func(c *Record) { c.CompletionReason = "" }, false, true},
		{"missing_index", func(c *Record) { c.ConsumedSequenceIndex = nil }, false, true},
		{"missing_next", func(c *Record) { c.NextExpectedIndex = nil }, false, true},
		{"missing_lease_presence", func(c *Record) { c.LeaseReportedAtAfter = nil }, false, true},
		{"wrong_next", func(c *Record) { c.NextExpectedIndex = p(4) }, false, true},
		{"zero_index", func(c *Record) { c.ConsumedSequenceIndex = p(0) }, false, true},
		{"overflow_index", func(c *Record) { c.ConsumedSequenceIndex = p(2147483647) }, false, true},
		{"wrong_lease", func(c *Record) { c.LeaseReportedAtAfter = p(1) }, false, true},
		{"rejected_with_effect", func(c *Record) { c.CompletionResult = "rejected" }, false, true},
		{"not_requested_with_effect", func(c *Record) { c.CompletionResult = "not_requested" }, false, true},
		{"unknown_result", func(c *Record) { c.CompletionResult = "maybe" }, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.change(&c)
			a, e := c.Validate("PERMIT", true, false, &yes)
			if a != tc.accept || (e != nil) != tc.wantErr {
				t.Fatalf("accepted=%v error=%v", a, e)
			}
		})
	}
	for _, tc := range []struct {
		name, decision  string
		complete, fatal bool
		attributed      *bool
	}{
		{"wrong_decision", "BLOCK", true, false, &yes}, {"not_complete", "PERMIT", false, false, &yes}, {"fatal_permit", "PERMIT", true, true, &yes}, {"unknown_attribution", "PERMIT", true, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if a, e := good.Validate(tc.decision, tc.complete, tc.fatal, tc.attributed); a || e == nil {
				t.Fatal(a, e)
			}
		})
	}
}
