// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package config

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/glowfly/pail/services/internal/deploysec"
)

// Retention is the evidence-retention declaration of `policy.yaml` (`retention:`).
//
// Why it lives in the policy file and not in an environment variable: the
// config seal already covers this file through `policy_file_sha256`, so a
// retention value declared here is part of what the chain attests the robot
// was running under. A value in the process environment is not sealed, and an
// unsealed retention promise is a promise nobody can later check.
//
// What this declares is "we do not delete before N years". It does not make
// media last N years — that is the durability track's and the anchor's job.
// The blackbox writer has no deletion path for a healthy segment at all
// (tests/contract/test_blackbox_no_delete_path.py measures that), so the
// number here is a floor an auditor can read, not a timer that fires.
type Retention struct {
	// Declared is false when the section is absent. Absence is only allowed
	// outside production (S24) and must stay distinguishable from "declared
	// zero" — a zero here would read as "keep nothing".
	Declared        bool
	BlackboxYears   int
	AnchorYears     int
	LowerBoundYears int
}

// RetentionFloorYears is the lowest `lower_bound_years` this loader accepts.
// Five is the smallest figure the regulatory drafts we track ask for; a policy
// that sets its own floor below it has declared a floor that is not one.
const RetentionFloorYears = 5

// validateRetention is the single implementation of R-RET2 (S25). The startup
// loader and the offline verifier both call it; two copies would let the
// verifier accept a file the issuer refuses, and report that as "matched".
//
// Each rule is a separate return so that removing one is observed by exactly
// one test (H-B9): missing leaf · floor · blackbox ≥ floor · anchor ≥ blackbox.
func validateRetention(blackbox, anchor, lower *int) (Retention, error) {
	var missing []string
	if blackbox == nil {
		missing = append(missing, "blackbox_years")
	}
	if anchor == nil {
		missing = append(missing, "anchor_years")
	}
	if lower == nil {
		missing = append(missing, "lower_bound_years")
	}
	if len(missing) > 0 {
		return Retention{}, deploysec.Cfg("S25", "policy: retention: missing %v — absence is not a zero", missing)
	}
	if *lower < RetentionFloorYears {
		return Retention{}, deploysec.Cfg("S25",
			"policy: retention.lower_bound_years=%d is below the floor %d — a floor below the floor is not a floor",
			*lower, RetentionFloorYears)
	}
	if *blackbox < *lower {
		return Retention{}, deploysec.Cfg("S25",
			"policy: retention.blackbox_years=%d is below retention.lower_bound_years=%d",
			*blackbox, *lower)
	}
	if *anchor < *blackbox {
		return Retention{}, deploysec.Cfg("S25",
			"policy: retention.anchor_years=%d is below retention.blackbox_years=%d — the outside copy must outlive the one on the robot",
			*anchor, *blackbox)
	}
	return Retention{Declared: true, BlackboxYears: *blackbox, AnchorYears: *anchor, LowerBoundYears: *lower}, nil
}

// retentionAbsent is R-RET1 (S24). Production refuses; any other profile gets a
// banner and an undeclared retention. The banner is written, not logged, so
// that a process whose logger is not yet wired still leaves the line.
func retentionAbsent(profile string, banner io.Writer) (Retention, error) {
	if profile == "production" {
		return Retention{}, deploysec.Cfg("S24",
			"policy: retention: section missing — production requires blackbox_years/anchor_years/lower_bound_years to be declared and sealed")
	}
	fmt.Fprintf(banner,
		"PAIL PREFLIGHT WARN: S24 policy: retention: section missing — evidence retention is undeclared (PAIL_PROFILE=%q; production refuses)\n",
		profile)
	return Retention{Declared: false}, nil
}

// retentionOnly is the lenient shape the offline verifier reads. It ignores
// every other key on purpose: the verifier answers "what does the sealed file
// declare about retention", not "would the issuer start on it" — the second
// question is the loader's, and the loader is strict.
type retentionOnly struct {
	Retention *struct {
		BlackboxYears   *int `yaml:"blackbox_years"`
		AnchorYears     *int `yaml:"anchor_years"`
		LowerBoundYears *int `yaml:"lower_bound_years"`
	} `yaml:"retention"`
}

// RetentionFromPolicyBytes reads only the `retention:` section of a policy
// file. An absent section returns Declared=false and no error — the verifier
// prints "undeclared" for that; a present but invalid section returns the same
// S25 error the loader would, because the two must agree on what is valid.
func RetentionFromPolicyBytes(b []byte) (Retention, error) {
	var doc retentionOnly
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return Retention{}, fmt.Errorf("policy: %w", err)
	}
	if doc.Retention == nil {
		return Retention{Declared: false}, nil
	}
	return validateRetention(doc.Retention.BlackboxYears, doc.Retention.AnchorYears, doc.Retention.LowerBoundYears)
}
