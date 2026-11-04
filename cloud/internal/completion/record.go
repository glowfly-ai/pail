// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package completion

import "fmt"

// JournalVersion changes interpretation, not just JSON shape. Older
// readers must not be used for operational replay of this version.
const JournalVersion = 10

// Completion describes the issuer's result separately from the gate's report.
// Pointer indices distinguish absence from the meaningful zero (no lease).
type Record struct {
	JournalV              int    `json:"journal_v"`
	CompletionResult      string `json:"completion_result"`
	CompletionReason      string `json:"completion_reason"`
	ConsumedSequenceIndex *int32 `json:"consumed_sequence_index,omitempty"`
	NextExpectedIndex     *int32 `json:"next_expected_index,omitempty"`
	LeaseReportedAtAfter  *int32 `json:"lease_reported_at_after,omitempty"`
}

// Validate returns whether the record commits consumption. Legacy absence is
// unknown, never an accepted completion. Operational legacy policy is decided
// by the caller using the issuance record, not today's skill configuration.
func (c Record) Validate(decision string, complete, fatal bool, attributed *bool) (bool, error) {
	if c.JournalV > JournalVersion {
		return false, fmt.Errorf("unsupported completion journal version %d", c.JournalV)
	}
	if c.JournalV < JournalVersion {
		return false, nil
	}
	if c.CompletionReason == "" {
		return false, fmt.Errorf("missing completion_reason")
	}
	indices := c.ConsumedSequenceIndex != nil || c.NextExpectedIndex != nil || c.LeaseReportedAtAfter != nil
	switch c.CompletionResult {
	case "not_requested":
		if decision == "PERMIT" && complete || indices {
			return false, fmt.Errorf("inconsistent non-completion")
		}
		return false, nil
	case "rejected":
		if decision != "PERMIT" || !complete || indices {
			return false, fmt.Errorf("inconsistent rejected completion")
		}
		return false, nil
	case "accepted":
		if decision != "PERMIT" || !complete || fatal || attributed == nil || !*attributed {
			return false, fmt.Errorf("invalid accepted completion report")
		}
		if c.ConsumedSequenceIndex == nil || c.NextExpectedIndex == nil || c.LeaseReportedAtAfter == nil {
			return false, fmt.Errorf("incomplete consumption effect")
		}
		i, next, lease := *c.ConsumedSequenceIndex, *c.NextExpectedIndex, *c.LeaseReportedAtAfter
		if i < 1 || i == 2147483647 || next != i+1 || (lease != 0 && lease != i) {
			return false, fmt.Errorf("invalid consumption indices")
		}
		return true, nil
	default:
		return false, fmt.Errorf("unknown completion_result %q", c.CompletionResult)
	}
}

func ValidSignal(s string) bool {
	return s == "" || s == "duration" || s == "robot_report" || s == "robot_report+evidence"
}
