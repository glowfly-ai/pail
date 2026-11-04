// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import "sort"

type Status string

const (
	Pass          Status = "PASS"
	Fail          Status = "FAIL"
	CannotCheck   Status = "CANNOT_CHECK"
	NotApplicable Status = "NOT_APPLICABLE"
)

type Finding struct {
	CheckID       string `json:"check_id"`
	Status        Status `json:"status"`
	Subject       string `json:"subject_ref"`
	Field         string `json:"logical_field"`
	Reason        string `json:"reason"`
	Expected      string `json:"expected,omitempty"`
	Observed      string `json:"observed,omitempty"`
	EvidenceBasis string `json:"evidence_basis"`
}
type Report struct {
	SchemaVersion    int                 `json:"schema_version"`
	Scope            string              `json:"scope"`
	DeploymentID     string              `json:"deployment_id"`
	RequiredChecks   []string            `json:"required_checks"`
	RequiredSubjects map[string][]string `json:"required_subjects"`
	Findings         []Finding           `json:"findings"`
	InputHashes      map[string]string   `json:"input_hashes"`
	Counts           map[Status]int      `json:"counts"`
	Summary          Status              `json:"summary"`
	ReadyForApply    bool                `json:"ready_for_apply"`
	RuntimeObserved  bool                `json:"runtime_observed"`
}

func NewReport(scope, dep string, required []string) Report {
	return Report{SchemaVersion: 1, Scope: scope, DeploymentID: dep, RequiredChecks: required, Findings: []Finding{}, InputHashes: map[string]string{}}
}
func (r *Report) Add(id string, status Status, subject, field, reason, expected, observed string) {
	r.Findings = append(r.Findings, Finding{id, status, subject, field, reason, expected, observed, "declared configuration snapshot; not loaded runtime attestation"})
}
func (r *Report) Finish() int {
	r.ReadyForApply = false
	r.RuntimeObserved = false
	r.Counts = map[Status]int{Pass: 0, Fail: 0, CannotCheck: 0, NotApplicable: 0}
	seen := map[string]bool{}
	coverage := map[string]map[string]bool{}
	for _, f := range r.Findings {
		if f.Status == NotApplicable {
			r.Add("CONTRACT", CannotCheck, f.Subject, "status", "N/A has no supported contract in the current offline profile", "", "")
		}
		seen[f.CheckID] = true
		if coverage[f.CheckID] == nil {
			coverage[f.CheckID] = map[string]bool{}
		}
		coverage[f.CheckID][f.Subject] = true
		if _, ok := r.Counts[f.Status]; !ok {
			r.Add("CONTRACT", CannotCheck, "report", "status", "unknown finding status", "", "")
			break
		}
	}
	for _, id := range r.RequiredChecks {
		if !seen[id] {
			r.Add(id, CannotCheck, "report", "required_checks", "required check did not execute", "", "")
		}
	}
	for id, subjects := range r.RequiredSubjects {
		for _, subject := range subjects {
			if !coverage[id][subject] {
				r.Add(id, CannotCheck, subject, "coverage", "required subject did not execute", "", "")
			}
		}
	}
	if len(r.RequiredChecks) == 0 {
		r.Add("CONTRACT", CannotCheck, "report", "required_checks", "empty check denominator", "", "")
	}
	for _, f := range r.Findings {
		r.Counts[f.Status]++
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.CheckID != b.CheckID {
			return a.CheckID < b.CheckID
		}
		return a.Subject < b.Subject
	})
	r.Summary = Pass
	if r.Counts[Fail] > 0 {
		r.Summary = Fail
	}
	if r.Counts[CannotCheck] > 0 {
		r.Summary = CannotCheck
	}
	if r.Summary == CannotCheck {
		return 2
	}
	if r.Summary == Fail {
		return 1
	}
	return 0
}
