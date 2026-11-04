// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// unclassified matches no row but the last: every other test input is this
// one with the single change that makes one row true.
func unclassified() SummaryInputs {
	return SummaryInputs{Source: "CONNECTED", Liveness: "FRESH", Ledger: "CHAIN_OK", Plan: "COMPLETED", Gate: "FRESH", GateState: "PERMIT", Motion: "FRESH", MotionState: "OBSERVED_ZERO", Permit: "UNKNOWN"}
}

type tableRow struct {
	rule          int
	state, reason string
	change        func(*SummaryInputs)
}

func tableRows() []tableRow {
	return []tableRow{
		{1, "UNKNOWN", "SOURCE_DISCONNECTED", func(i *SummaryInputs) { i.Source = "DISCONNECTED" }},
		{2, "UNKNOWN", "LIVENESS_MISSING", func(i *SummaryInputs) { i.Liveness = "STALE" }},
		{3, "ATTENTION", "LEDGER_ERROR", func(i *SummaryInputs) { i.Ledger, i.Plan = "CHAIN_ERROR", "UNKNOWN" }},
		{4, "ATTENTION", "PLAN_CANCELLED", func(i *SummaryInputs) { i.Plan = "CANCELLED" }},
		{5, "ATTENTION", "GATE_BLOCK", func(i *SummaryInputs) { i.GateState = "BLOCK" }},
		{6, "MOVING", "", func(i *SummaryInputs) { i.MotionState = "OBSERVED_MOVING" }},
		{7, "UNKNOWN", "MOTION_MISSING", func(i *SummaryInputs) { i.Motion, i.MotionState = "STALE", "" }},
		{8, "MOVING", "PERMIT_HELD", func(i *SummaryInputs) { i.Permit = "RECEIVED" }},
		{9, "IDLE_READY", "", func(i *SummaryInputs) { i.Permit = "EXPIRED" }},
		{10, "ATTENTION", "PLAN_NOT_PROGRESSING", func(i *SummaryInputs) { i.Permit, i.Plan, i.Wait = "NONE", "ACCEPTED", "OVER_10S" }},
		{11, "UNKNOWN", "UNCLASSIFIED", func(i *SummaryInputs) {}},
	}
}
func reasonOf(s *Summary) string {
	if s.Reason == nil {
		return ""
	}
	return *s.Reason
}

// T10: every row of the table, each with an input that this row alone decides.
func TestOpsviewSummaryTable(t *testing.T) {
	if len(summaryRules) != 11 {
		t.Fatal("the table has eleven rows, not ", len(summaryRules))
	}
	for n, r := range summaryRules {
		if r.n != n+1 {
			t.Fatal("row order", n, r.n)
		}
	}
	seen := map[int]bool{}
	for _, row := range tableRows() {
		in := unclassified()
		row.change(&in)
		got := decide(in)
		if got.Rule != row.rule || got.State != row.state || reasonOf(got) != row.reason || (row.reason == "") != (got.Reason == nil) {
			t.Fatalf("row %d: got rule %d %s %s", row.rule, got.Rule, got.State, reasonOf(got))
		}
		if got.Inputs != in || got.PhysicalStopProven {
			t.Fatalf("row %d: %+v", row.rule, got)
		}
		// the input is decided by this row alone: no other row but the last matches it
		for _, other := range summaryRules[:10] {
			if other.when(in) != (other.n == row.rule) {
				t.Fatalf("input of row %d: row %d says %v", row.rule, other.n, other.when(in))
			}
		}
		if !summaryRules[10].when(in) {
			t.Fatal("the last row matches everything")
		}
		seen[row.rule] = true
	}
	if len(seen) != 11 {
		t.Fatal("rows covered: ", len(seen))
	}
}

// T10: the first matching row decides. Each input makes row k and every row
// below it true.
func TestOpsviewSummaryOrder(t *testing.T) {
	rows := tableRows()
	pairs, lower := 0, map[int]bool{}
	for k := 0; k < 10; k++ {
		for j := k + 1; j < 10; j++ {
			in := unclassified()
			rows[j].change(&in)
			rows[k].change(&in)
			if !summaryRules[k].when(in) || !summaryRules[j].when(in) {
				continue // the two rows exclude each other: one motion value, one plan state
			}
			pairs++
			lower[j+1] = true
			if got := decide(in); got.Rule != k+1 {
				t.Fatalf("rows %d+%d: decided by %d", k+1, j+1, got.Rule)
			}
		}
	}
	// every row from 2 to 10 was the lower one of some pair
	if pairs != 31 || len(lower) != 9 {
		t.Fatal("pairs that were compared: ", pairs, lower)
	}
}

// T10: the inputs a row does not name do not decide it.
func TestOpsviewSummaryRowConditions(t *testing.T) {
	// row 9 refuses by itself what row 7 refuses before it
	for name, change := range map[string]func(*SummaryInputs){
		"motion not bound": func(i *SummaryInputs) { i.Motion = "NOT_BOUND" },
		"motion old":       func(i *SummaryInputs) { i.Motion = "STALE" },
		"motion moving":    func(i *SummaryInputs) { i.MotionState = "OBSERVED_MOVING" },
		"permit held":      func(i *SummaryInputs) { i.Permit = "RECEIVED" },
		"permit unknown":   func(i *SummaryInputs) { i.Permit = "UNKNOWN" },
		"plan in progress": func(i *SummaryInputs) { i.Plan = "ACCEPTED" },
		"plan unknown":     func(i *SummaryInputs) { i.Plan = "UNKNOWN" },
	} {
		in := unclassified()
		in.Permit = "EXPIRED"
		if !summaryRules[8].when(in) || summaryRules[8].state != "IDLE_READY" {
			t.Fatal("row 9 does not match its own input")
		}
		change(&in)
		if summaryRules[8].when(in) {
			t.Fatal("row 9 matches: ", name)
		}
	}
	for name, c := range map[string]struct {
		change func(*SummaryInputs)
		rule   int
	}{
		"gate BLOCK that is not fresh":         {func(i *SummaryInputs) { i.Gate, i.GateState = "STALE", "" }, 11},
		"gate BLOCK seen by the receiver only": {func(i *SummaryInputs) { i.Gate, i.GateState = "NOT_BOUND", "BLOCK" }, 11},
		"moving, not bound":                    {func(i *SummaryInputs) { i.Motion, i.MotionState = "NOT_BOUND", "OBSERVED_MOVING" }, 7},
		"zero, not bound, no permit":           {func(i *SummaryInputs) { i.Motion, i.Permit = "NOT_BOUND", "EXPIRED" }, 7},
		"motion missing":                       {func(i *SummaryInputs) { i.Motion, i.MotionState = "MISSING", "" }, 7},
		"motion value UNKNOWN":                 {func(i *SummaryInputs) { i.MotionState, i.Permit = "UNKNOWN", "EXPIRED" }, 11},
		"liveness seen by the receiver only":   {func(i *SummaryInputs) { i.Liveness, i.Permit = "NOT_BOUND", "EXPIRED" }, 2},
		"liveness not declared":                {func(i *SummaryInputs) { i.Liveness, i.Permit = "NOT_DECLARED", "EXPIRED" }, 2},
		"source in conflict":                   {func(i *SummaryInputs) { i.Source, i.Permit = "CONFLICT", "EXPIRED" }, 1},
		"chain not verified, idle":             {func(i *SummaryInputs) { i.Ledger, i.Plan, i.Permit = "UNVERIFIED", "UNKNOWN", "EXPIRED" }, 11},
		"no ledger source, idle":               {func(i *SummaryInputs) { i.Ledger, i.Plan, i.Permit = "NOT_DECLARED", "UNKNOWN", "EXPIRED" }, 11},
		"no plan yet":                          {func(i *SummaryInputs) { i.Plan, i.Permit = "NONE", "NONE" }, 9},
		"refused plan":                         {func(i *SummaryInputs) { i.Plan, i.Permit = "REJECTED", "NONE" }, 9},
		"accepted, within the wait":            {func(i *SummaryInputs) { i.Plan, i.Permit, i.Wait = "ACCEPTED", "NONE", "WITHIN_10S" }, 11},
		"accepted, wait not tracked":           {func(i *SummaryInputs) { i.Plan, i.Permit = "ACCEPTED", "NONE" }, 11},
		"accepted and permit held":             {func(i *SummaryInputs) { i.Plan, i.Permit, i.Wait = "ACCEPTED", "RECEIVED", "OVER_10S" }, 8},
		"wait flag without the condition":      {func(i *SummaryInputs) { i.Wait = "OVER_10S" }, 11},
		"permit state unknown":                 {func(i *SummaryInputs) { i.Plan = "ACCEPTED"; i.Wait = "OVER_10S" }, 11},
	} {
		in := unclassified()
		c.change(&in)
		if got := decide(in); got.Rule != c.rule || got.PhysicalStopProven {
			t.Fatalf("%s: rule %d %s", name, got.Rule, got.State)
		}
	}
}

// scene is one robot whose observer shares the collector's clock, with the
// collector's ledger source.
type scene struct {
	t   *testing.T
	c   *Collector
	p   Provider
	b   *boundClock
	seq map[string]int
	id  string // clock name the producer writes
}

func summaryScene(t *testing.T, binding string) *scene {
	t.Helper()
	p := v2provider("motion", "pose", "gate", "permit", "liveness")
	p.ClockBinding = binding
	c, now := fixture(t, p, ledgerSource())
	v2clock = now
	b := &boundClock{wall: now, mono: monoStart, ok: true}
	c.clockID, c.clockOK = vectorZero, true
	c.mono = func() (int64, bool) { return b.mono, b.ok }
	return &scene{t: t, c: c, p: p, b: b, seq: map[string]int{}, id: vectorZero}
}
func (s *scene) send(kind, state string) {
	s.t.Helper()
	// the first record of a producer is its baseline; the second is judged
	for n := 0; n < 2; n++ {
		s.seq[kind]++
		e := produced(s.p, s.b, kind, s.seq[kind], s.id, 0)
		e.Value.State = state
		if kind == "liveness" {
			e.Value.Component = "adapter"
		}
		if kind == "motion" && state == "OBSERVED_MOVING" {
			e.Value.LinearMPS = ptr(0.1)
		}
		if s.seq[kind] > 1 && n == 0 {
			n++
		}
		observe(s.t, s.c, s.p, e)
	}
}

// calm: the adapter answers, the robot stands, no permit is held.
func (s *scene) calm() *scene {
	s.send("liveness", "ALIVE")
	s.send("motion", "OBSERVED_ZERO")
	return s
}
func (s *scene) ledger(w *written) *scene { w.ok(s.c); return s }
func (s *scene) summary() *Summary {
	s.t.Helper()
	r := s.c.Snapshot().Robots
	if len(r) != 1 || r[0].Summary == nil {
		s.t.Fatalf("no summary: %+v", r)
	}
	return r[0].Summary
}
func (s *scene) want(rule int, state, reason string) {
	s.t.Helper()
	got := s.summary()
	if got.Rule != rule || got.State != state || reasonOf(got) != reason || got.PhysicalStopProven {
		s.t.Fatalf("want rule %d %s %s, got rule %d %s %s, inputs %+v", rule, state, reason, got.Rule, got.State, reasonOf(got), got.Inputs)
	}
}
func finished() *written {
	return (&written{}).accepted("robot-1", "plan", "chain-a", 1).done("robot-1", "chain-a", 1)
}

// T10: the rows as the collector reaches them from records and from the ledger.
func TestOpsviewSummaryFromObservations(t *testing.T) {
	t.Run("1 no source connected", func(t *testing.T) {
		s := summaryScene(t, ClockBindingShared).ledger(finished())
		s.want(1, "UNKNOWN", "SOURCE_DISCONNECTED")
		s.calm()
		s.want(9, "IDLE_READY", "")
		s.c.Fault("one", "READ_ERROR")
		s.want(1, "UNKNOWN", "SOURCE_DISCONNECTED")
	})
	t.Run("1 contact lost", func(t *testing.T) {
		s := summaryScene(t, ClockBindingShared).ledger(finished()).calm()
		s.b.advance(5 * time.Second)
		s.ledger(finished())
		s.want(1, "UNKNOWN", "SOURCE_DISCONNECTED")
	})
	t.Run("2 liveness missing, then old", func(t *testing.T) {
		s := summaryScene(t, ClockBindingShared).ledger(finished())
		s.send("motion", "OBSERVED_ZERO")
		s.want(2, "UNKNOWN", "LIVENESS_MISSING")
		if in := s.summary().Inputs; in.Liveness != "MISSING" || in.Motion != "FRESH" {
			t.Fatalf("%+v", in)
		}
		s.send("liveness", "ALIVE")
		s.want(9, "IDLE_READY", "")
		s.b.advance(2999 * time.Millisecond)
		s.send("motion", "OBSERVED_ZERO")
		s.want(9, "IDLE_READY", "")
		s.b.advance(time.Millisecond)
		s.send("motion", "OBSERVED_ZERO")
		s.want(2, "UNKNOWN", "LIVENESS_MISSING")
		if in := s.summary().Inputs; in.Liveness != "STALE" || in.Motion != "FRESH" {
			t.Fatalf("%+v", in)
		}
	})
	t.Run("3 chain error", func(t *testing.T) {
		s := summaryScene(t, ClockBindingShared).calm()
		finished().publish(s.c, LedgerVerdict{State: "chain_error", Code: "HASH_MISMATCH", VerifiedSeq: 1, Published: true})
		s.want(3, "ATTENTION", "LEDGER_ERROR")
		s.ledger(finished())
		s.want(9, "IDLE_READY", "")
	})
	t.Run("4 plan cancelled", func(t *testing.T) {
		s := summaryScene(t, ClockBindingShared).calm()
		w := (&written{}).accepted("robot-1", "plan", "chain-a", 1).lifecycle("CHAIN_CANCELLED", "robot-1", "chain-a")
		s.ledger(w)
		s.want(4, "ATTENTION", "PLAN_CANCELLED")
		// a newer plan ends it
		s.ledger(w.accepted("robot-1", "plan-2", "chain-b", 1).done("robot-1", "chain-b", 1))
		s.want(9, "IDLE_READY", "")
	})
	t.Run("5 gate block", func(t *testing.T) {
		s := summaryScene(t, ClockBindingShared).ledger(finished()).calm()
		s.send("gate", "PERMIT")
		s.want(9, "IDLE_READY", "")
		s.send("gate", "BLOCK")
		s.want(5, "ATTENTION", "GATE_BLOCK")
		// an old BLOCK is not the latest observation any more
		s.b.advance(3 * time.Second)
		s.calm()
		s.ledger(finished())
		s.want(9, "IDLE_READY", "")
		if in := s.summary().Inputs; in.Gate != "STALE" || in.GateState != "" {
			t.Fatalf("%+v", in)
		}
	})
	t.Run("6 moving", func(t *testing.T) {
		s := summaryScene(t, ClockBindingShared).ledger(finished())
		s.send("liveness", "ALIVE")
		s.send("motion", "OBSERVED_MOVING")
		s.want(6, "MOVING", "")
	})
	t.Run("7 motion missing, then old", func(t *testing.T) {
		s := summaryScene(t, ClockBindingShared).ledger(finished())
		s.send("liveness", "ALIVE")
		s.want(7, "UNKNOWN", "MOTION_MISSING")
		s.send("motion", "OBSERVED_ZERO")
		s.want(9, "IDLE_READY", "")
		s.b.advance(999 * time.Millisecond)
		s.want(9, "IDLE_READY", "")
		s.b.advance(time.Millisecond)
		s.want(7, "UNKNOWN", "MOTION_MISSING")
	})
	t.Run("8 permit held", func(t *testing.T) {
		s := summaryScene(t, ClockBindingShared).ledger((&written{}).accepted("robot-1", "plan", "chain-a", 1)).calm()
		s.send("permit", "RECEIVED")
		s.want(8, "MOVING", "PERMIT_HELD")
		s.send("permit", "EXPIRED")
		s.ledger(finished())
		s.want(9, "IDLE_READY", "")
	})
	t.Run("9 idle and ready", func(t *testing.T) {
		for name, w := range map[string]*written{
			"completed": finished(),
			"no plan":   (&written{}).accepted("robot-2", "plan", "chain-z", 1),
			"refused":   (&written{}).add("PLAN_REJECTED", fields{"kind": "PLAN_REJECTED", "robot_id": "robot-1", "plan_id": "plan", "reject_code": "ERR_ENVELOPE_EXCEEDED"}),
		} {
			s := summaryScene(t, ClockBindingShared).ledger(w).calm()
			s.want(9, "IDLE_READY", "")
			got := s.summary()
			if got.Reason != nil || got.Inputs.Source != "CONNECTED" || got.Inputs.Liveness != "FRESH" || got.Inputs.Ledger != "CHAIN_OK" || got.Inputs.Motion != "FRESH" || got.Inputs.MotionState != "OBSERVED_ZERO" || got.Inputs.Permit != "NONE" {
				t.Fatalf("%s: %+v", name, got)
			}
			// EXPIRED is written once; it stays the last word after its record is old
			s.send("permit", "RECEIVED")
			s.send("permit", "EXPIRED")
			s.b.advance(3 * time.Second)
			s.calm()
			s.ledger(w)
			s.want(9, "IDLE_READY", "")
			if in := s.summary().Inputs; in.Permit != "EXPIRED" {
				t.Fatalf("%s: %+v", name, in)
			}
		}
	})
	t.Run("10 accepted plan that does not progress", func(t *testing.T) {
		s := summaryScene(t, ClockBindingShared).ledger((&written{}).accepted("robot-1", "plan", "chain-a", 1)).calm()
		s.want(11, "UNKNOWN", "UNCLASSIFIED")
		for i := 0; i < 20; i++ {
			s.b.advance(500 * time.Millisecond)
			s.calm()
			s.ledger((&written{}).accepted("robot-1", "plan", "chain-a", 1))
		}
		s.want(10, "ATTENTION", "PLAN_NOT_PROGRESSING")
	})
	t.Run("11 nothing else applies", func(t *testing.T) {
		// the adapter answers, the last permit report said held, and it is old
		s := summaryScene(t, ClockBindingShared).ledger(finished()).calm()
		s.send("permit", "RECEIVED")
		s.b.advance(3 * time.Second)
		s.calm()
		s.ledger(finished())
		s.want(11, "UNKNOWN", "UNCLASSIFIED")
		if in := s.summary().Inputs; in.Permit != "UNKNOWN" {
			t.Fatalf("%+v", in)
		}
		// a ledger that is not verified says nothing about a plan in progress
		for name, v := range map[string]LedgerVerdict{
			"absent":     {State: "absent", Published: true},
			"unverified": {State: "unverified", Code: "SOURCE_UNSTABLE", Published: true},
			"no index":   {},
		} {
			s := summaryScene(t, ClockBindingShared).calm()
			finished().publish(s.c, v)
			s.want(11, "UNKNOWN", "UNCLASSIFIED")
			if in := s.summary().Inputs; in.Plan != "UNKNOWN" || in.Ledger == "CHAIN_OK" {
				t.Fatalf("%s: %+v", name, in)
			}
		}
		// a verification older than 30 s cannot say that no newer plan exists
		s = summaryScene(t, ClockBindingShared).ledger(finished())
		s.b.advance(30 * time.Second)
		s.calm()
		s.want(11, "UNKNOWN", "UNCLASSIFIED")
		if in := s.summary().Inputs; in.Plan != "UNKNOWN" || in.Ledger != "CHAIN_OK" {
			t.Fatalf("%+v", in)
		}
		// the same for a robot of which the old verification held no plan
		s = summaryScene(t, ClockBindingShared).ledger(&written{})
		s.calm()
		s.want(9, "IDLE_READY", "")
		s.b.advance(30 * time.Second)
		s.calm()
		s.want(11, "UNKNOWN", "UNCLASSIFIED")
		if in := s.summary().Inputs; in.Plan != "UNKNOWN" {
			t.Fatalf("%+v", in)
		}
	})
	t.Run("1 two identities for one robot", func(t *testing.T) {
		a := v2provider("motion", "liveness")
		a.ClockBinding = ClockBindingShared
		b := a
		b.ProviderID, b.Identity, b.StreamID = "two", "device-other", "ec054792-0db0-4162-83c1-ce2b7c401783"
		c, now := fixture(t, a, b, ledgerSource())
		v2clock = now
		clock := &boundClock{wall: now, mono: monoStart, ok: true}
		c.clockID, c.clockOK = vectorZero, true
		c.mono = func() (int64, bool) { return clock.mono, clock.ok }
		finished().ok(c)
		s := &scene{t: t, c: c, p: a, b: clock, seq: map[string]int{}, id: vectorZero}
		s.calm()
		s.want(1, "UNKNOWN", "SOURCE_DISCONNECTED")
		if in := s.summary().Inputs; in.Source != "CONFLICT" {
			t.Fatalf("%+v", in)
		}
	})
}

// Row 10 waits 10 s, and the wait starts again after every interruption,
// whether or not anybody asked in between.
func TestOpsviewSummaryWait(t *testing.T) {
	accepted := func() *written { return (&written{}).accepted("robot-1", "plan", "chain-a", 1) }
	step := func(s *scene, d time.Duration) {
		s.b.advance(d)
		s.calm()
		s.ledger(accepted())
	}
	s := summaryScene(t, ClockBindingShared).ledger(accepted()).calm()
	if got := s.summary(); got.Rule != 11 || got.Inputs.Wait != "WITHIN_10S" {
		t.Fatalf("%+v", got)
	}
	for i := 0; i < 19; i++ {
		step(s, 500*time.Millisecond)
	}
	step(s, 499*time.Millisecond)
	if got := s.summary(); got.Rule != 11 || got.Inputs.Wait != "WITHIN_10S" {
		t.Fatalf("9.999 s: %+v", got)
	}
	step(s, time.Millisecond)
	if got := s.summary(); got.Rule != 10 || got.Inputs.Wait != "OVER_10S" {
		t.Fatalf("10 s: %+v", got)
	}
	// interruptions nobody asked about: no Snapshot between the records
	for name, interrupt := range map[string]func(*scene){
		"moved":       func(s *scene) { s.send("motion", "OBSERVED_MOVING"); s.send("motion", "OBSERVED_ZERO") },
		"permit held": func(s *scene) { s.send("permit", "RECEIVED"); s.send("permit", "EXPIRED") },
		"motion was old": func(s *scene) {
			s.b.advance(time.Second)
			s.send("motion", "OBSERVED_ZERO")
			s.send("liveness", "ALIVE")
		},
		"plan ended": func(s *scene) {
			s.ledger(accepted().lifecycle("CHAIN_CANCELLED", "robot-1", "chain-a"))
			s.ledger(accepted())
		},
		"chain not verified": func(s *scene) {
			accepted().publish(s.c, LedgerVerdict{State: "unverified", Code: "TORN_TAIL", Published: true})
			s.ledger(accepted())
		},
		"source fault": func(s *scene) { s.c.Fault("one", "READ_ERROR"); s.calm() },
	} {
		s := summaryScene(t, ClockBindingShared).ledger(accepted()).calm()
		for i := 0; i < 12; i++ {
			step(s, 500*time.Millisecond)
		}
		interrupt(s)
		for i := 0; i < 12; i++ {
			step(s, 500*time.Millisecond)
		}
		if got := s.summary(); got.Rule != 11 || got.Inputs.Wait != "WITHIN_10S" {
			t.Fatalf("%s: the wait was not started again: %+v", name, got)
		}
		for i := 0; i < 8; i++ {
			step(s, 500*time.Millisecond)
		}
		if got := s.summary(); got.Rule != 10 {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	// without an interruption the same twelve seconds do reach row 10
	s = summaryScene(t, ClockBindingShared).ledger(accepted()).calm()
	for i := 0; i < 24; i++ {
		step(s, 500*time.Millisecond)
	}
	s.want(10, "ATTENTION", "PLAN_NOT_PROGRESSING")
	// the plan is known as of the last verification: twelve seconds at rest
	// after it do not make the plan stalled, the next verification does
	s = summaryScene(t, ClockBindingShared).ledger(accepted()).calm()
	for i := 0; i < 24; i++ {
		s.b.advance(500 * time.Millisecond)
		s.calm()
	}
	if got := s.summary(); got.Rule != 11 || got.Inputs.Wait != "WITHIN_10S" || got.Inputs.Plan != "ACCEPTED" {
		t.Fatalf("no verification since the wait began: %+v", got)
	}
	s.ledger(accepted())
	s.want(10, "ATTENTION", "PLAN_NOT_PROGRESSING")
	s = summaryScene(t, ClockBindingShared).ledger(accepted()).calm()
	for i := 0; i < 24; i++ {
		s.b.advance(500 * time.Millisecond)
		s.calm()
	}
	s.ledger(finished())
	s.want(9, "IDLE_READY", "")
	// a collector clock that went back starts the wait again
	*s.b.wall = s.b.wall.Add(-time.Hour)
	s.calm()
	s.ledger(accepted())
	if got := s.summary(); got.Rule == 10 {
		t.Fatalf("%+v", got)
	}
}

// T11: a deployment whose clock binding is not confirmed never shows
// IDLE_READY. The same records on a bound deployment do.
func TestOpsviewSummaryNeverIdleWithoutBinding(t *testing.T) {
	play := func(s *scene) map[string]bool {
		states := map[string]bool{}
		look := func() {
			got := s.summary()
			states[got.State] = true
			if got.PhysicalStopProven {
				t.Fatal("physical_stop_proven")
			}
		}
		for _, w := range []*written{finished(), {}, (&written{}).accepted("robot-1", "plan", "chain-a", 1)} {
			s.ledger(w)
			for _, permit := range []string{"", "RECEIVED", "EXPIRED"} {
				for _, motion := range []string{"OBSERVED_ZERO", "OBSERVED_MOVING", "OBSERVED_ZERO"} {
					s.send("liveness", "ALIVE")
					s.send("gate", "PERMIT")
					s.send("motion", motion)
					if permit != "" {
						s.send("permit", permit)
					}
					look()
					s.b.advance(500 * time.Millisecond)
					look()
					s.b.advance(4 * time.Second)
					s.ledger(w)
					look()
				}
			}
		}
		return states
	}
	if got := play(summaryScene(t, ClockBindingShared)); !got["IDLE_READY"] || !got["MOVING"] {
		t.Fatalf("control: the bound deployment shows %v", got)
	}
	for name, prepare := range map[string]func() *scene{
		"no binding request": func() *scene { return summaryScene(t, "") },
		"collector clock unreadable": func() *scene {
			s := summaryScene(t, ClockBindingShared)
			s.c.clockID, s.c.clockOK = "", false
			return s
		},
		"another clock": func() *scene { s := summaryScene(t, ClockBindingShared); s.id = otherClock; return s },
		"producer could not read its clock": func() *scene {
			s := summaryScene(t, ClockBindingShared)
			s.id = hashOfUnavailable
			return s
		},
		"collector monotonic time unreadable": func() *scene { s := summaryScene(t, ClockBindingShared); s.b.ok = false; return s },
	} {
		got := play(prepare())
		if got["IDLE_READY"] || got["MOVING"] || got["ATTENTION"] {
			t.Fatalf("%s: %v", name, got)
		}
		if !got["UNKNOWN"] {
			t.Fatalf("%s: %v", name, got)
		}
	}
	// records without monotonic time on a deployment that asked for binding
	s := summaryScene(t, ClockBindingShared).ledger(finished())
	for n := 1; n <= 3; n++ {
		for _, kind := range []string{"liveness", "motion"} {
			e := produced(s.p, s.b, kind, n, vectorZero, 0)
			e.MonoNS = ""
			e.Value.State = map[string]string{"liveness": "ALIVE", "motion": "OBSERVED_ZERO"}[kind]
			if kind == "liveness" {
				e.Value.Component = "adapter"
			}
			observe(t, s.c, s.p, e)
		}
	}
	s.want(2, "UNKNOWN", "LIVENESS_MISSING")
	if in := s.summary().Inputs; in.Liveness != "NOT_BOUND" || in.Motion != "NOT_BOUND" {
		t.Fatalf("%+v", in)
	}
}

// §6.3: the answer of /v2/observation/robots carries the summary with the row
// that decided and what it read; a cached page is judged on its aged facets.
func TestOpsviewSummaryHTTP(t *testing.T) {
	s := summaryScene(t, ClockBindingShared).ledger(finished()).calm()
	api := NewAPI(s.c)
	api.now = func() time.Time { return *s.b.wall }
	read := func(query string) (map[string]any, string) {
		t.Helper()
		w := httptest.NewRecorder()
		api.Robots(w, httptest.NewRequest("GET", "/v2/observation/robots"+query, nil))
		var doc struct {
			Robots []map[string]any `json:"robots"`
			Next   string           `json:"next_cursor"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &doc) != nil || len(doc.Robots) != 1 {
			t.Fatal(w.Code, w.Body.String())
		}
		summary, ok := doc.Robots[0]["summary"].(map[string]any)
		if !ok {
			t.Fatal("no summary in ", w.Body.String())
		}
		for _, key := range []string{"state", "reason", "decided_by_rule", "inputs", "physical_stop_proven"} {
			if _, ok := summary[key]; !ok {
				t.Fatal("summary without ", key)
			}
		}
		if len(summary) != 5 || summary["physical_stop_proven"] != false {
			t.Fatalf("%v", summary)
		}
		if _, ok := doc.Robots[0]["quality"]; !ok {
			t.Fatal("the quality field is kept")
		}
		return summary, doc.Next
	}
	got, _ := read("")
	in := got["inputs"].(map[string]any)
	if got["state"] != "IDLE_READY" || got["reason"] != nil || got["decided_by_rule"] != float64(9) || in["liveness"] != "FRESH" || in["motion"] != "FRESH" || in["motion_state"] != "OBSERVED_ZERO" || in["permit"] != "NONE" || in["plan"] != "COMPLETED" || in["ledger"] != "CHAIN_OK" || in["source"] != "CONNECTED" {
		t.Fatalf("%v", got)
	}
	s.send("motion", "OBSERVED_MOVING")
	if got, _ = read("?robot_id=robot-1"); got["state"] != "MOVING" || got["decided_by_rule"] != float64(6) {
		t.Fatalf("%v", got)
	}
	// a page served from the cache one second later: the motion record is old
	s.send("motion", "OBSERVED_ZERO")
	first := pageOf(t, api, "?limit=1")
	if first.Robots[0].Summary == nil || first.Robots[0].Summary.Rule != 9 {
		t.Fatalf("%+v", first.Robots[0].Summary)
	}
	if first.Next != "" {
		t.Fatal("one robot, one page")
	}
}
func pageOf(t *testing.T, api *API, query string) page {
	t.Helper()
	w := httptest.NewRecorder()
	api.Robots(w, httptest.NewRequest("GET", "/v2/observation/robots"+query, nil))
	var p page
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	return p
}

// A cached page never shows a verdict that its aged facets no longer carry.
func TestOpsviewSummaryOnCachedPage(t *testing.T) {
	a := v2provider("motion", "pose", "gate", "permit", "liveness")
	a.ClockBinding = ClockBindingShared
	b := a
	b.ProviderID, b.RobotID, b.Identity = "two", "robot-2", "device-robot-2"
	c, now := fixture(t, a, b, ledgerSource())
	v2clock = now
	clock := &boundClock{wall: now, mono: monoStart, ok: true}
	c.clockID, c.clockOK = vectorZero, true
	c.mono = func() (int64, bool) { return clock.mono, clock.ok }
	for _, p := range []Provider{a, b} {
		s := &scene{t: t, c: c, p: p, b: clock, seq: map[string]int{}, id: vectorZero}
		s.calm()
	}
	(&written{}).ok(c)
	api := NewAPI(c)
	api.now = func() time.Time { return *now }
	first := pageOf(t, api, "?limit=1")
	if first.Robots[0].Summary.Rule != 9 || first.Next == "" {
		t.Fatalf("%+v", first.Robots[0].Summary)
	}
	clock.advance(999 * time.Millisecond)
	if got := pageOf(t, api, "?limit=1&cursor="+first.Next).Robots[0]; got.Key.RobotID != "robot-2" || got.Summary.Rule != 9 || got.Summary.State != "IDLE_READY" {
		t.Fatalf("%+v", got.Summary)
	}
	clock.advance(time.Millisecond)
	if got := pageOf(t, api, "?limit=1&cursor="+first.Next).Robots[0].Summary; got.Rule != 7 || got.State != "UNKNOWN" || reasonOf(got) != "MOTION_MISSING" || got.Inputs.Motion != "STALE" {
		t.Fatalf("%+v", got)
	}
	clock.advance(2 * time.Second)
	if got := pageOf(t, api, "?limit=1&cursor="+first.Next).Robots[0].Summary; got.Rule != 2 || reasonOf(got) != "LIVENESS_MISSING" {
		t.Fatalf("%+v", got)
	}
}

// T21: a source map that declares neither liveness nor the ledger source
// answers without the summary.
func TestOpsviewSummaryOnlyWhereDeclared(t *testing.T) {
	p := provider("one", "robot-1", dep)
	c, _ := fixture(t, p)
	send(t, c, p, "1")
	send(t, c, p, "2")
	b, _ := json.Marshal(c.Snapshot())
	for _, word := range []string{"summary", "decided_by_rule", "IDLE_READY"} {
		if strings.Contains(string(b), word) {
			t.Fatal(word)
		}
	}
	for name, ps := range map[string][]Provider{
		"liveness":      {v2provider("gate", "liveness")},
		"ledger source": {provider("one", "robot-1", dep), ledgerSource()},
	} {
		if len(ps) == 2 {
			ps[0].Allowed = []string{"gate", "motion", "pose"}
		}
		c, _ := fixture(t, ps...)
		s := c.Snapshot().Robots[0].Summary
		if s == nil || s.Rule != 1 || s.PhysicalStopProven {
			t.Fatalf("%s: %+v", name, s)
		}
	}
}

// A reading that found the ledger changing under it is read again within the
// cycle. It is shown only when no other reading replaced it within a second:
// a robot at rest is not called unknown for the length of a second reading.
func TestOpsviewSummaryLedgerReadAgain(t *testing.T) {
	unstable := LedgerVerdict{State: "unverified", Code: "SOURCE_UNSTABLE", Published: true}
	s := summaryScene(t, ClockBindingShared).ledger(finished()).calm()
	s.want(9, "IDLE_READY", "")
	finished().publish(s.c, unstable)
	s.want(9, "IDLE_READY", "")
	if f := ledgerFacet(t, s.c, "robot-1", "ledger"); f.Value.State != "CHAIN_OK" || *f.AgeMS != 0 {
		t.Fatalf("%+v", f)
	}
	s.b.advance(500 * time.Millisecond)
	s.calm()
	// the age of what is shown is the age of the reading that verified it
	if f := ledgerFacet(t, s.c, "robot-1", "ledger"); f.Value.State != "CHAIN_OK" || *f.AgeMS != 500 {
		t.Fatalf("%+v", f)
	}
	finished().publish(s.c, unstable) // the second reading does not start the second again
	s.b.advance(499 * time.Millisecond)
	s.calm()
	s.want(9, "IDLE_READY", "")
	s.b.advance(time.Millisecond)
	s.calm()
	s.want(11, "UNKNOWN", "UNCLASSIFIED")
	if in := s.summary().Inputs; in.Ledger != "UNVERIFIED" || in.Plan != "UNKNOWN" {
		t.Fatalf("%+v", in)
	}
	if f := ledgerFacet(t, s.c, "robot-1", "ledger"); f.Ledger == nil || f.Ledger.ErrorCode != "SOURCE_UNSTABLE" {
		t.Fatalf("%+v", f)
	}
	// replaced within the second: the unstable reading is never shown
	s = summaryScene(t, ClockBindingShared).ledger(finished()).calm()
	finished().publish(s.c, unstable)
	s.b.advance(300 * time.Millisecond)
	s.ledger(finished())
	s.b.advance(900 * time.Millisecond)
	s.calm()
	s.want(9, "IDLE_READY", "")
	// a verdict about the ledger itself is shown at once
	for name, v := range map[string]LedgerVerdict{
		"damaged":   {State: "chain_error", Code: "HASH_MISMATCH", VerifiedSeq: 1, Published: true},
		"absent":    {State: "absent", Published: true},
		"torn":      {State: "unverified", Code: "TORN_TAIL", Published: true},
		"no index":  {},
		"not saved": {State: "unverified", Code: "SOURCE_UNSTABLE"},
	} {
		s := summaryScene(t, ClockBindingShared).ledger(finished()).calm()
		finished().publish(s.c, v)
		if got := s.summary(); got.State == "IDLE_READY" || got.Inputs.Ledger == "CHAIN_OK" {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	// held back behind a damaged ledger too: it replaces nothing that is better than itself
	s = summaryScene(t, ClockBindingShared).calm()
	finished().publish(s.c, LedgerVerdict{State: "chain_error", Code: "HASH_MISMATCH", VerifiedSeq: 1, Published: true})
	finished().publish(s.c, unstable)
	s.want(3, "ATTENTION", "LEDGER_ERROR")
	// the first reading of a collector has nothing to keep
	s = summaryScene(t, ClockBindingShared).calm()
	s.c.LedgerVerifying()
	finished().publish(s.c, unstable)
	if in := s.summary().Inputs; in.Ledger != "UNVERIFIED" {
		t.Fatalf("%+v", in)
	}
}

// §15.5: what counts as fresh is the basis of the age, not the word FRESH.
func TestOpsviewSummaryFreshBasis(t *testing.T) {
	v := &Value{State: "ALIVE"}
	for basis, want := range map[string]string{"producer_clock_bound": "FRESH", "challenge_bound": "FRESH", "receiver_only": "NOT_BOUND", "verified_frontier": "NOT_BOUND", "": "NOT_BOUND"} {
		if got := streamClass(Facet{Quality: "FRESH", FreshnessBasis: basis, Value: v}); got != want {
			t.Fatal(basis, got)
		}
	}
	for name, c := range map[string]struct {
		f    Facet
		want string
	}{
		"not declared":     {Facet{Quality: "UNSUPPORTED", Reason: "NO_CONFIGURED_FEED"}, "NOT_DECLARED"},
		"nothing yet":      {Facet{Quality: "UNKNOWN", Reason: "NO_OBSERVATION"}, "MISSING"},
		"old":              {Facet{Quality: "STALE", Reason: "TTL_EXPIRED", FreshnessBasis: "producer_clock_bound", Value: v}, "STALE"},
		"first record":     {Facet{Quality: "UNKNOWN", Reason: "NEW_PRODUCER_BASELINE", Value: v}, "UNKNOWN"},
		"conflict":         {Facet{Quality: "CONFLICT", Reason: "SOURCE_IDENTITY_CONFLICT", FreshnessBasis: "producer_clock_bound", Value: v}, "UNKNOWN"},
		"motion unbound":   {Facet{Quality: "UNKNOWN", Reason: "PRODUCER_CLOCK_NOT_BOUND", Value: v}, "NOT_BOUND"},
		"another clock":    {Facet{Quality: "UNKNOWN", Reason: "CLOCK_BINDING_MISMATCH", Value: v}, "NOT_BOUND"},
		"clock unreadable": {Facet{Quality: "UNKNOWN", Reason: "CLOCK_BINDING_UNAVAILABLE", Value: v}, "NOT_BOUND"},
		"from the future":  {Facet{Quality: "UNKNOWN", Reason: "CLOCK_UNCERTAIN", FreshnessBasis: "producer_clock_bound", Value: v}, "UNKNOWN"},
	} {
		if got := streamClass(c.f); got != c.want {
			t.Fatal(name, got)
		}
	}
	if got := decide(SummaryInputs{}); got.Rule != 1 {
		t.Fatalf("%+v", got)
	}
}

// Two sources of one robot that disagree: the value that asks for caution wins.
func TestOpsviewSummaryTwoSources(t *testing.T) {
	a := v2provider("motion", "gate", "permit", "liveness")
	a.ClockBinding = ClockBindingShared
	b := a
	b.ProviderID, b.Role, b.StreamID = "two", "secondary", "ec054792-0db0-4162-83c1-ce2b7c401783"
	c, now := fixture(t, a, b, ledgerSource())
	v2clock = now
	clock := &boundClock{wall: now, mono: monoStart, ok: true}
	c.clockID, c.clockOK = vectorZero, true
	c.mono = func() (int64, bool) { return clock.mono, clock.ok }
	one := &scene{t: t, c: c, p: a, b: clock, seq: map[string]int{}, id: vectorZero}
	two := &scene{t: t, c: c, p: b, b: clock, seq: map[string]int{}, id: vectorZero}
	finished().ok(c)
	one.calm()
	one.want(9, "IDLE_READY", "")
	two.send("motion", "OBSERVED_MOVING")
	one.want(6, "MOVING", "")
	two.send("motion", "OBSERVED_ZERO")
	two.send("gate", "BLOCK")
	one.send("gate", "PERMIT")
	one.want(5, "ATTENTION", "GATE_BLOCK")
	two.send("gate", "PERMIT")
	two.send("permit", "RECEIVED")
	one.send("permit", "EXPIRED")
	one.want(8, "MOVING", "PERMIT_HELD")
}
