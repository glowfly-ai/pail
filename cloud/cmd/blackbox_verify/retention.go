// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	"github.com/glowfly/pail/services/internal/config"
)

// -retention (EC-1, EUC D1): does the policy file in hand match the one the
// chain says the robot was sealed under, and if so, what does it promise about
// how long each segment is kept?
//
// Three answers for the policy, never folded into two:
//
//	matched     the file's SHA-256 equals the `policy_file_sha256` line of the
//	            newest CONFIG_SEALED canonical text in the chain
//	mismatched  a seal exists and the file is not the sealed one — the file's
//	            retention numbers say nothing about this chain
//	unsealed    no CONFIG_SEALED record carries a policy hash — nothing to
//	            compare against; "cannot check" is not "checked and fine"
//
// Segments are only evaluated under `matched`, and only when the sealed file
// declares retention at all (`undeclared` otherwise — a fourth word, on
// purpose). The tool never writes: it reports `beyond`, it does not act on it.

const sealedPolicyKey = "policy_file_sha256="

type segInfo struct {
	Seq       uint64
	CreatedMs uint64
}

type segRetention struct {
	Seq       uint64
	CreatedMs uint64
	UntilMs   uint64
	State     string // within | beyond
}

type retentionReport struct {
	Policy    string // matched | mismatched | unsealed
	SealedSHA string
	FileSHA   string
	Retention string // declared | undeclared | (empty when policy != matched)
	Years     config.Retention
	Segments  []segRetention
}

// sealedPolicySHA returns the policy hash of the newest CONFIG_SEALED record,
// or "" when no record carries one. A record whose payload does not parse is
// skipped, not treated as a hash of "" — a malformed seal must not become
// "unsealed" silently either, so the count of skipped records is returned.
func sealedPolicySHA(records []record) (sha string, skipped int) {
	for _, r := range records {
		if r.recType != blackbox.RecordConfigSealed {
			continue
		}
		var ev struct {
			Canonical string `json:"canonical"`
		}
		if err := json.Unmarshal(r.payload, &ev); err != nil {
			skipped++
			continue
		}
		for _, line := range strings.Split(ev.Canonical, "\n") {
			if strings.HasPrefix(line, sealedPolicyKey) {
				sha = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, sealedPolicyKey)))
			}
		}
	}
	return sha, skipped
}

// evaluateRetention is the pure judgement; main feeds it what it read.
func evaluateRetention(sealedSHA string, policyBytes []byte, segs []segInfo, now time.Time) (retentionReport, error) {
	sum := sha256.Sum256(policyBytes)
	rep := retentionReport{SealedSHA: sealedSHA, FileSHA: hex.EncodeToString(sum[:])}
	switch {
	case sealedSHA == "":
		rep.Policy = "unsealed"
		return rep, nil
	case rep.FileSHA != sealedSHA:
		rep.Policy = "mismatched"
		return rep, nil
	}
	rep.Policy = "matched"

	years, err := config.RetentionFromPolicyBytes(policyBytes)
	if err != nil {
		return rep, err
	}
	if !years.Declared {
		rep.Retention = "undeclared"
		return rep, nil
	}
	rep.Retention = "declared"
	rep.Years = years

	nowMs := uint64(now.UnixMilli())
	const msPerYear = uint64(365.25 * 24 * 60 * 60 * 1000)
	for _, s := range segs {
		until := s.CreatedMs + uint64(years.BlackboxYears)*msPerYear
		state := "within"
		if nowMs >= until {
			state = "beyond"
		}
		rep.Segments = append(rep.Segments, segRetention{Seq: s.Seq, CreatedMs: s.CreatedMs, UntilMs: until, State: state})
	}
	return rep, nil
}

// printRetention writes the report and returns the exit code it implies:
// 0 matched, 4 mismatched, 5 unsealed. A policy error (S24 in the sealed file)
// is 6 — the chain was sealed under a declaration the loader would refuse.
func printRetention(w io.Writer, rep retentionReport, skipped int) int {
	fmt.Fprintf(w, "RETENTION policy=%s file_sha256=%s sealed_sha256=%s\n",
		rep.Policy, rep.FileSHA, orDash(rep.SealedSHA))
	if skipped > 0 {
		fmt.Fprintf(w, "RETENTION NOTE: %d CONFIG_SEALED record(s) with unreadable payload were skipped\n", skipped)
	}
	switch rep.Policy {
	case "mismatched":
		fmt.Fprintln(w, "RETENTION NOT_EVALUATED: the file in hand is not the sealed policy — its retention numbers do not describe this chain")
		return 4
	case "unsealed":
		fmt.Fprintln(w, "RETENTION NOT_EVALUATED: no CONFIG_SEALED record carries a policy hash — nothing to compare the file against")
		return 5
	}
	if rep.Retention == "undeclared" {
		fmt.Fprintln(w, "RETENTION retention=undeclared: the sealed policy has no retention: section")
		return 0
	}
	fmt.Fprintf(w, "RETENTION retention=declared blackbox_years=%d anchor_years=%d lower_bound_years=%d\n",
		rep.Years.BlackboxYears, rep.Years.AnchorYears, rep.Years.LowerBoundYears)
	for _, s := range rep.Segments {
		fmt.Fprintf(w, "RETENTION seg=%d created=%s until=%s %s\n", s.Seq,
			time.UnixMilli(int64(s.CreatedMs)).UTC().Format(time.RFC3339),
			time.UnixMilli(int64(s.UntilMs)).UTC().Format(time.RFC3339), s.State)
	}
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// classCounts (EC-3, EUC D3) folds a chain's records into intervention classes.
// `unclassified` is its own bucket: a record type the table does not know is
// reported as such, never as `system`.
func classCounts(records []record) map[string]int {
	out := map[string]int{"legitimate": 0, "illegitimate": 0, "system": 0, "by_payload": 0, "unclassified": 0}
	for _, r := range records {
		c, ok := blackbox.ClassOf(r.recType)
		if !ok {
			out["unclassified"]++
			continue
		}
		out[c.Class]++
	}
	return out
}

func printClassCounts(w io.Writer, counts map[string]int) {
	fmt.Fprintf(w, "CLASSES: legitimate=%d illegitimate=%d system=%d by_payload=%d unclassified=%d\n",
		counts["legitimate"], counts["illegitimate"], counts["system"], counts["by_payload"], counts["unclassified"])
}
