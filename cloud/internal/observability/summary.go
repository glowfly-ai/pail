// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import "time"

// SummaryWait is how long an accepted plan may sit without motion and without
// a permit before the summary calls it out: the short gap right after an
// acceptance is not a warning.
const SummaryWait = 10 * time.Second

// A record stream is fresh for the summary only when its age is the
// producer's age. What the receiver alone saw arrive is not counted.
var boundBasis = map[string]bool{"producer_clock_bound": true, "challenge_bound": true}

// SummaryInputs is what the deciding row read. Stream inputs say how fresh the
// observation is; the observed value is given only when it is fresh.
type SummaryInputs struct {
	Source      string `json:"source"`   // CONNECTED | DISCONNECTED | CONFLICT
	Liveness    string `json:"liveness"` // FRESH | NOT_BOUND | STALE | UNKNOWN | MISSING | NOT_DECLARED
	Ledger      string `json:"ledger"`   // chain state | INDEX_UNAVAILABLE | NOT_DECLARED
	Plan        string `json:"plan"`     // ACCEPTED | REJECTED | CANCELLED | COMPLETED | NONE | UNKNOWN
	Gate        string `json:"gate"`
	GateState   string `json:"gate_state,omitempty"`
	Motion      string `json:"motion"`
	MotionState string `json:"motion_state,omitempty"`
	Permit      string `json:"permit"` // RECEIVED | EXPIRED | NONE | UNKNOWN
	Wait        string `json:"progress_wait,omitempty"`
}

// Summary is one word about a robot and the row of the table that chose it.
// It is a reading of observations: it never proves that a robot stands still.
type Summary struct {
	State              string        `json:"state"`
	Reason             *string       `json:"reason"`
	Rule               int           `json:"decided_by_rule"`
	Inputs             SummaryInputs `json:"inputs"`
	PhysicalStopProven bool          `json:"physical_stop_proven"`
}

type summaryRule struct {
	n             int
	state, reason string
	when          func(SummaryInputs) bool
}

func idle(i SummaryInputs) bool { return i.Motion == "FRESH" && i.MotionState == "OBSERVED_ZERO" }
func noPermit(i SummaryInputs) bool {
	return i.Permit == "EXPIRED" || i.Permit == "NONE"
}

// settled: the verified ledger says this robot has no plan in progress.
func settled(i SummaryInputs) bool {
	return i.Plan == "NONE" || i.Plan == "REJECTED" || i.Plan == "CANCELLED" || i.Plan == "COMPLETED"
}

// stalled is the condition of row 10 without its duration.
func stalled(i SummaryInputs) bool { return idle(i) && noPermit(i) && i.Plan == "ACCEPTED" }

// summaryRules is the decision table; the first row that matches decides.
var summaryRules = []summaryRule{
	{1, "UNKNOWN", "SOURCE_DISCONNECTED", func(i SummaryInputs) bool { return i.Source != "CONNECTED" }},
	{2, "UNKNOWN", "LIVENESS_MISSING", func(i SummaryInputs) bool { return i.Liveness != "FRESH" }},
	{3, "ATTENTION", "LEDGER_ERROR", func(i SummaryInputs) bool { return i.Ledger == "CHAIN_ERROR" }},
	{4, "ATTENTION", "PLAN_CANCELLED", func(i SummaryInputs) bool { return i.Plan == "CANCELLED" }},
	{5, "ATTENTION", "GATE_BLOCK", func(i SummaryInputs) bool { return i.Gate == "FRESH" && i.GateState == "BLOCK" }},
	{6, "MOVING", "", func(i SummaryInputs) bool { return i.Motion == "FRESH" && i.MotionState == "OBSERVED_MOVING" }},
	{7, "UNKNOWN", "MOTION_MISSING", func(i SummaryInputs) bool { return i.Motion != "FRESH" }},
	{8, "MOVING", "PERMIT_HELD", func(i SummaryInputs) bool { return idle(i) && i.Permit == "RECEIVED" }},
	{9, "IDLE_READY", "", func(i SummaryInputs) bool { return idle(i) && noPermit(i) && settled(i) }},
	{10, "ATTENTION", "PLAN_NOT_PROGRESSING", func(i SummaryInputs) bool { return stalled(i) && i.Wait == "OVER_10S" }},
	{11, "UNKNOWN", "UNCLASSIFIED", func(i SummaryInputs) bool { return true }},
}

func decide(i SummaryInputs) *Summary {
	for _, r := range summaryRules {
		if !r.when(i) {
			continue
		}
		s := &Summary{State: r.state, Rule: r.n, Inputs: i, PhysicalStopProven: false}
		if r.reason != "" {
			s.Reason = ptr(r.reason)
		}
		return s
	}
	// not reached while the table ends with a row that matches everything
	return &Summary{State: "UNKNOWN", Reason: ptr("TABLE_INCOMPLETE"), Rule: 0, Inputs: i, PhysicalStopProven: false}
}

// summaryDeclared: a source map written before the summary existed declares
// neither the liveness kind nor the ledger source, and keeps its exact answer.
func summaryDeclared(c SourceMap) bool {
	for _, p := range c.Providers {
		if p.Kind == LedgerKind {
			return true
		}
		for _, k := range p.Allowed {
			if k == "liveness" {
				return true
			}
		}
	}
	return false
}

var streamRank = map[string]int{"NOT_DECLARED": 0, "MISSING": 1, "UNKNOWN": 2, "STALE": 3, "NOT_BOUND": 4, "FRESH": 5}

// streamClass says how far one facet of a record source can be relied on.
func streamClass(f Facet) string {
	switch {
	case f.Quality == "UNSUPPORTED":
		return "NOT_DECLARED"
	case f.Value == nil:
		return "MISSING"
	case f.Quality == "FRESH" && boundBasis[f.FreshnessBasis]:
		return "FRESH"
	case f.Quality == "FRESH", f.Reason == "PRODUCER_CLOCK_NOT_BOUND", f.Reason == "CLOCK_BINDING_MISMATCH", f.Reason == "CLOCK_BINDING_UNAVAILABLE":
		return "NOT_BOUND"
	case f.Quality == "STALE":
		return "STALE"
	}
	return "UNKNOWN"
}

// readStream reads one kind over the record sources of a robot. Where two fresh
// sources disagree, the value in `first` wins: the one that asks for caution.
func readStream(sources []SourceRow, kind, first string) (string, string, *Value) {
	class, state := "NOT_DECLARED", ""
	var last *Value
	for _, s := range sources {
		f, ok := s.Facets[kind]
		if !ok {
			continue
		}
		c := streamClass(f)
		if streamRank[c] > streamRank[class] {
			class = c
		}
		if f.Value != nil && last == nil {
			last = f.Value
		}
		if c == "FRESH" && (state == "" || f.Value.State == first) {
			state = f.Value.State
		}
	}
	return class, state, last
}

// readInputs collects what the table reads from one robot row. It works on
// the row as served, so a cached page is judged by its aged facets.
func readInputs(r Robot) SummaryInputs {
	in := SummaryInputs{Source: "DISCONNECTED", Ledger: "NOT_DECLARED", Plan: "UNKNOWN"}
	records := []SourceRow{}
	for _, s := range r.Sources {
		own := false
		for _, f := range s.Facets {
			if f.Trust == LedgerTrust {
				own = true
			}
		}
		if !own {
			records = append(records, s)
			if s.Health == "CONNECTED" {
				in.Source = "CONNECTED"
			}
			continue
		}
		ledger, plan := s.Facets["ledger"], s.Facets["plan"]
		verified := false
		switch {
		case ledger.FreshnessBasis == LedgerBasis && ledger.Value != nil:
			in.Ledger = ledger.Value.State
			verified = ledger.Quality == "FRESH"
		case ledger.FreshnessBasis == LedgerBasis:
			in.Ledger = "INDEX_UNAVAILABLE"
		case plan.FreshnessBasis == LedgerBasis && plan.Quality == "FRESH":
			in.Ledger = "CHAIN_OK"
			verified = true
		case plan.FreshnessBasis == LedgerBasis && plan.Reason == "CHAIN_ERROR":
			in.Ledger = "CHAIN_ERROR"
		case plan.FreshnessBasis == LedgerBasis:
			in.Ledger = "UNKNOWN"
		}
		// A plan is read only from a verification that is current: an old
		// reading cannot say that no newer plan exists.
		if plan.FreshnessBasis == LedgerBasis && plan.Value != nil {
			if plan.Quality == "FRESH" && plan.Value.State != "UNKNOWN" {
				in.Plan = plan.Value.State
			} else if plan.Reason == "NO_PLAN_RECORD" && plan.Quality == "UNKNOWN" && (verified || ledger.FreshnessBasis != LedgerBasis) && in.Ledger == "CHAIN_OK" {
				in.Plan = "NONE"
			}
		}
	}
	if r.Quality == "CONFLICT" {
		in.Source = "CONFLICT"
	}
	in.Liveness, _, _ = readStream(records, "liveness", "")
	in.Gate, in.GateState, _ = readStream(records, "gate", "BLOCK")
	in.Motion, in.MotionState, _ = readStream(records, "motion", "OBSERVED_MOVING")
	class, state, last := readStream(records, "permit", "RECEIVED")
	switch {
	case class == "FRESH" && (state == "RECEIVED" || state == "EXPIRED"):
		in.Permit = state
	case class == "MISSING":
		// the producer reports a permit only while one is held
		in.Permit = "NONE"
	case class == "STALE" && last != nil && last.State == "EXPIRED":
		// EXPIRED is written once, on the transition; nothing follows it
		in.Permit = "EXPIRED"
	default:
		in.Permit = "UNKNOWN"
	}
	return in
}

// summarize decides the summary of one robot row. wait is the state of row
// 10's duration as the collector tracked it.
func summarize(r Robot, wait string) *Summary {
	in := readInputs(r)
	if stalled(in) {
		in.Wait = wait
		if in.Wait != "OVER_10S" {
			in.Wait = "WITHIN_10S"
		}
	}
	return decide(in)
}

// waited notes whether row 10's condition holds for this robot now and says
// for how long it has held without interruption.
func (c *Collector) waited(key RobotKey, r Robot, now time.Time) string {
	if !stalled(readInputs(r)) {
		delete(c.waiting, key)
		return ""
	}
	since, ok := c.waiting[key]
	if !ok || now.Before(since) {
		c.waiting[key], since = now, now
	}
	// The plan is known as of the last verification only. The wait is counted
	// up to it: a plan that ended since then is not called stalled.
	upto := now
	if c.ledger != nil && c.ledger.at.Before(upto) {
		upto = c.ledger.at
	}
	if upto.Sub(since) >= SummaryWait {
		return "OVER_10S"
	}
	return "WITHIN_10S"
}

// track evaluates row 10's condition for one robot. It is called before and
// after every record and every ledger reading, so an interruption between two
// requests is never bridged: a record replaces the one before it, and what it
// replaces is judged first. A source fault stays until the next record and is
// seen there.
func (c *Collector) track(key RobotKey) {
	if !c.summary {
		return
	}
	if _, ok := c.robots[key]; !ok {
		return
	}
	now := c.now()
	c.waited(key, c.robotRow(key, now), now)
}
func (c *Collector) trackAll() {
	for key := range c.robots {
		c.track(key)
	}
}
