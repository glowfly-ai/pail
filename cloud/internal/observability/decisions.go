// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"github.com/glowfly/pail/services/internal/completion"
	"net/http"
	"net/url"
	"sort"
	"strconv"
)

// The decision history is what the issuer wrote into the ledger and the
// collector verified. It is not what happened on the robot: a gate decision
// the robot agent could not deliver is not in the ledger, and the time of a
// record is the time the issuer wrote it.
const DecisionsEndpoint = "/v2/observation/decisions"
const DecisionTimeBasis = "issuer_ledger_record_time"

// MaxDecisions bounds the list of one robot. The newest are kept.
const MaxDecisions = 200

// Decision is one decision record of the ledger.
type Decision struct {
	CompletionResult string `json:"completion_result,omitempty"`
	CompletionReason string `json:"completion_reason,omitempty"`
	Seq              string `json:"record_seq"`
	RecordMS         int64  `json:"ledger_record_ms"`
	Kind             string `json:"kind"`
	Decision         string `json:"decision,omitempty"`
	ReasonCode       string `json:"reason_code,omitempty"`
	Trigger          string `json:"trigger,omitempty"`
	StepComplete     *bool  `json:"step_complete,omitempty"`
	Fatal            *bool  `json:"fatal,omitempty"`
	Attributed       *bool  `json:"chain_attributed,omitempty"`
	Accepted         *bool  `json:"accepted,omitempty"`
	PlanID           string `json:"plan_id,omitempty"`
	ChainID          string `json:"chain_id,omitempty"`
	// OI-01: when the gate decided (the robot agent's clock) and how the report
	// reached the issuer — "live", "replayed" (after a failed attempt or an
	// agent restart) or "gap" (one summary of reports the agent's queue dropped;
	// decision/reason then describe the summary, not a gate verdict).
	DecidedMS int64  `json:"decided_unix_ms,omitempty"`
	Delivery  string `json:"delivery,omitempty"`
	// A robot reports the decision on a running step many times a second: a
	// permit while it moves, a block while it is refused. Reports that say
	// the same about the same token and follow each other are one row: Seq
	// and RecordMS are those of the last report, Repeats counts them all.
	Repeats  int    `json:"repeats,omitempty"`
	FirstSeq string `json:"first_record_seq,omitempty"`
	FirstMS  int64  `json:"first_ledger_record_ms,omitempty"`
	seq      int64
	token    string
}
type decisionList struct {
	rows    []Decision
	dropped uint64
}
type RobotDecisions struct {
	Key       RobotKey   `json:"robot_key"`
	Decisions []Decision `json:"decisions"`
	Dropped   uint64     `json:"dropped_older"`
}
type DecisionHistory struct {
	SchemaVersion   int              `json:"schema_version"`
	DocumentKind    string           `json:"document_kind"`
	SourceID        string           `json:"source_id"`
	Instance        string           `json:"collector_instance_id"`
	DeploymentID    string           `json:"deployment_id"`
	SourceRef       string           `json:"source_ref"`
	Trust           string           `json:"trust"`
	TimeBasis       string           `json:"time_basis"`
	ChainState      string           `json:"chain_state"`
	ErrorCode       string           `json:"error_code,omitempty"`
	LedgerVerified  bool             `json:"ledger_verified"`
	VerifiedThrough string           `json:"verified_through_seq"`
	VerifiedAtMS    int64            `json:"verified_at_ms"`
	VerificationAge *int64           `json:"verification_age_ms"`
	GeneratedMS     int64            `json:"generated_at_ms"`
	Limit           int              `json:"limit_per_robot"`
	Robots          []RobotDecisions `json:"robots"`
	Deployment      RobotDecisions   `json:"deployment"`
}

// repeatable is a gate report that may be one of many saying the same. The
// report that completes a step and a fatal report are events of their own.
func (d Decision) repeatable() bool {
	return d.Kind == "GATE_DECISION" && !*d.StepComplete && !*d.Fatal
}

// same reports whether two gate reports say the same about the same token.
func (d Decision) same(p Decision) bool {
	return p.Decision == d.Decision && p.token == d.token && p.ChainID == d.ChainID && p.ReasonCode == d.ReasonCode &&
		(p.Attributed == nil) == (d.Attributed == nil) && (p.Attributed == nil || *p.Attributed == *d.Attributed) &&
		p.Delivery == d.Delivery // OI-01: a replayed run is its own row, a gap never folds
}

func (l *decisionList) add(d Decision) {
	if n := len(l.rows); n > 0 && d.repeatable() {
		if p := &l.rows[n-1]; p.repeatable() && d.same(*p) {
			if p.Repeats == 0 {
				p.Repeats, p.FirstSeq, p.FirstMS = 1, p.Seq, p.RecordMS
			}
			p.Repeats++
			p.Seq, p.RecordMS, p.seq = d.Seq, d.RecordMS, d.seq
			return
		}
	}
	if len(l.rows) >= MaxDecisions {
		l.rows = append(l.rows[:0], l.rows[1:]...)
		l.dropped++
	}
	l.rows = append(l.rows, d)
}

func code(s string) string {
	if s == "" || ledgerCode.MatchString(s) {
		return s
	}
	return "OTHER"
}

// decision reads a decision record. ok is false for every other record.
func decision(r LedgerRecord, x ledgerPayload) (d Decision, ok bool) {
	d = Decision{Seq: strconv.FormatInt(r.Seq, 10), RecordMS: int64(r.Ms), Kind: r.Kind, ReasonCode: code(x.ReasonCode), seq: r.Seq}
	if identifier.MatchString(x.PlanID) {
		d.PlanID = x.PlanID
	}
	if identifier.MatchString(x.ChainID) {
		d.ChainID = x.ChainID
	}
	switch r.Kind {
	case "GATE_DECISION":
		// OI-01: a duplicate is the issuer's note that this delivery repeated a
		// record already held — not a second decision. It is not listed.
		if x.Duplicate {
			return d, false
		}
		if x.Decision != "PERMIT" && x.Decision != "BLOCK" && x.Decision != "ESTOP" {
			d.Decision = "UNKNOWN"
		} else {
			d.Decision = x.Decision
		}
		d.StepComplete, d.Fatal, d.Attributed, d.token = ptr(x.StepComplete), ptr(x.Fatal), x.Attributed, x.TokenID
		if x.JournalV >= completion.JournalVersion {
			_, err := x.Record.Validate(x.Decision, x.StepComplete, x.Fatal, x.Attributed)
			if err != nil {
				d.CompletionResult = "unknown"
			} else {
				d.CompletionResult, d.CompletionReason = x.CompletionResult, x.CompletionReason
			}
		} else if x.StepComplete && x.Decision == "PERMIT" {
			d.CompletionResult = "unknown"
		}
		d.DecidedMS = x.DecidedMS
		switch {
		case x.Gap:
			d.Delivery = "gap"
		case x.Delivery == "live" || x.Delivery == "replayed":
			d.Delivery = x.Delivery
		}
	case "SAFE_STOP":
	case "CHAIN_REVOKED":
		if x.Kind != "CHAIN_REVOKED" && x.Kind != "CHAIN_CANCELLED" {
			return d, false
		}
		d.Kind, d.Trigger = x.Kind, code(x.Trigger)
	case "OPERATOR_EVENT":
		d.Trigger, d.Accepted = code(x.Kind), x.Accepted
	default:
		return d, false
	}
	return d, true
}

// decide files a decision record under the robots it names. A robot the
// source map does not declare gets no list, so the lists are bounded by the
// declaration. A record that names no robot (an operator action, a safe stop
// of the issuer on a report without a robot) belongs to the deployment.
func (f *LedgerFold) decide(r LedgerRecord, x ledgerPayload) {
	d, ok := decision(r, x)
	if !ok {
		return
	}
	names := x.Robots
	if x.RobotID != "" {
		names = []string{x.RobotID}
	}
	if len(names) == 0 {
		f.fleet.add(d)
		return
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !f.declared[name] || seen[name] {
			continue
		}
		seen[name] = true
		l := f.decisions[name]
		if l == nil {
			l = &decisionList{}
			f.decisions[name] = l
		}
		l.add(d)
	}
}

// verified returns the rows up to the verified position, newest first. A row
// of several reports is listed only when all of them are verified.
func (l *decisionList) verified(through int64) []Decision {
	out := []Decision{}
	if l == nil {
		return out
	}
	for i := len(l.rows) - 1; i >= 0; i-- {
		if l.rows[i].seq <= through {
			out = append(out, l.rows[i])
		}
	}
	return out
}

// Decisions is the decision history as of the collector's last verification,
// read from memory only.
func (c *Collector) Decisions() DecisionHistory {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.settleLedger(now)
	h := DecisionHistory{SchemaVersion: 1, DocumentKind: "LedgerDecisionHistory", SourceID: c.config.SourceID, Instance: c.instance, DeploymentID: c.config.DeploymentID,
		SourceRef: c.ledgerProvider(), Trust: LedgerTrust, TimeBasis: DecisionTimeBasis, ChainState: "INDEX_UNAVAILABLE", VerifiedThrough: "0",
		GeneratedMS: now.UnixMilli(), Limit: MaxDecisions, Robots: []RobotDecisions{}, Deployment: RobotDecisions{Decisions: []Decision{}}}
	keys := []RobotKey{}
	for _, p := range c.config.Providers {
		if p.Kind != LedgerKind && p.DeploymentID == c.config.DeploymentID {
			keys = append(keys, RobotKey{p.DeploymentID, p.RobotID})
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].RobotID < keys[j].RobotID })
	s := c.ledger
	var through int64
	var fold *LedgerFold
	if s != nil && s.chain != "" {
		h.ChainState, h.ErrorCode = s.chain, s.verdict.Code
		elapsed := now.Sub(s.at)
		if s.chain != "VERIFYING" {
			h.VerifiedAtMS = s.at.UnixMilli()
			if elapsed >= 0 {
				h.VerificationAge = ptr(elapsed.Milliseconds())
			}
			// Only the verified prefix may be shown.
			through, fold = s.verdict.VerifiedSeq, s.fold
		}
		h.VerifiedThrough = strconv.FormatInt(through, 10)
		h.LedgerVerified = s.chain == "CHAIN_OK" && elapsed >= 0 && elapsed < LedgerFreshness
	}
	last := RobotKey{}
	for i, key := range keys {
		if i > 0 && key == last {
			continue
		}
		last = key
		row := RobotDecisions{Key: key, Decisions: []Decision{}}
		if fold != nil {
			if l := fold.decisions[key.RobotID]; l != nil {
				row.Decisions, row.Dropped = l.verified(through), l.dropped
			}
		}
		h.Robots = append(h.Robots, row)
	}
	if fold != nil {
		h.Deployment.Decisions, h.Deployment.Dropped = fold.fleet.verified(through), fold.fleet.dropped
	}
	h.Deployment.Key = RobotKey{DeploymentID: c.config.DeploymentID}
	return h
}

// signedFeed reports whether the source map declares a signed event source.
func (c *Collector) signedFeed() bool {
	for _, p := range c.config.Providers {
		if p.Kind == "legacy_burst" || p.Kind == "legacy_permit" {
			return true
		}
	}
	return false
}

// Decisions serves the decision history. It exists only where the source map
// declares the ledger source.
func (a *API) Decisions(w http.ResponseWriter, r *http.Request) {
	if !readRequest(w, r) {
		return
	}
	if a.collector == nil {
		http.Error(w, "SOURCE_MAP_UNCONFIGURED", 503)
		return
	}
	if !a.collector.HasLedgerSource() {
		http.Error(w, "LEDGER_SOURCE_NOT_DECLARED", 404)
		return
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		http.Error(w, "INVALID_QUERY", 400)
		return
	}
	for k, v := range q {
		if k != "robot_id" {
			http.Error(w, "UNKNOWN_QUERY", 400)
			return
		}
		if len(v) != 1 || !identifier.MatchString(v[0]) {
			http.Error(w, "INVALID_QUERY", 400)
			return
		}
	}
	h := a.collector.Decisions()
	if q.Has("robot_id") {
		rows := []RobotDecisions{}
		for _, row := range h.Robots {
			if row.Key.RobotID == q.Get("robot_id") {
				rows = append(rows, row)
			}
		}
		h.Robots = rows
		h.Deployment.Decisions, h.Deployment.Dropped = []Decision{}, 0
	}
	write(w, r, h)
}
