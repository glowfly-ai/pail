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

func ledgerSource() Provider {
	return Provider{ProviderID: "ledger", Kind: LedgerKind, Trust: LedgerTrust, Allowed: []string{"plan", "ledger"}, Role: "primary"}
}

// ledgerFixture declares robot-1 and robot-2 by self report, and the ledger source.
func ledgerFixture(t *testing.T) (*Collector, *time.Time) {
	t.Helper()
	a := provider("one", "robot-1", dep)
	a.Allowed = []string{"gate", "motion", "pose"}
	b := provider("two", "robot-2", dep)
	b.Allowed = []string{"gate", "motion", "pose"}
	return fixture(t, a, b, ledgerSource())
}

type fields map[string]any

// written is a ledger under construction: records in the form the issuer writes them.
type written struct{ records []LedgerRecord }

func (w *written) add(kind string, f fields) *written {
	b, _ := json.Marshal(f)
	n := int64(len(w.records) + 1)
	w.records = append(w.records, LedgerRecord{Seq: n, Kind: kind, Ms: uint64(1700000000000 + n), Payload: b})
	return w
}
func (w *written) accepted(robot, plan, chain string, steps int) *written {
	w.add("PLAN_ACCEPTED", fields{"kind": "PLAN_ACCEPTED", "v": 2, "robot_id": robot, "plan_id": plan, "chain_id": chain, "step_count": steps})
	for i := 1; i <= steps; i++ {
		w.token(robot, plan, chain, i)
	}
	return w
}
func tokenOf(chain string, index int) string { return chain + "-token-" + string(rune('0'+index)) }
func (w *written) token(robot, plan, chain string, index int) *written {
	return w.add("TOKEN_ISSUED", fields{"kind": "TOKEN_ISSUED", "journal_v": 8, "robot_id": robot, "plan_id": plan, "chain_id": chain, "token_id": tokenOf(chain, index), "sequence_index": index})
}
func (w *written) done(robot, chain string, index int) *written {
	return w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "journal_v": 10, "completion_result": "accepted", "completion_reason": "COMPLETION_SIGNAL_MATCHED", "consumed_sequence_index": index, "next_expected_index": index + 1, "lease_reported_at_after": 0, "robot_id": robot, "chain_id": chain, "token_id": tokenOf(chain, index), "decision": "PERMIT", "step_complete": true, "fatal": false, "chain_attributed": true})
}
func (w *written) lifecycle(kind, robot, chain string) *written {
	return w.add("CHAIN_REVOKED", fields{"kind": kind, "robot_id": robot, "chain_id": chain, "plan_id": "plan"})
}
func verified(n int64) LedgerVerdict {
	zero := int64(0)
	return LedgerVerdict{State: "ok", VerifiedSeq: n, TipSeq: &n, LagRecords: &zero, Published: true}
}
func (w *written) publish(c *Collector, v LedgerVerdict) {
	f := c.NewLedgerFold()
	for _, r := range w.records {
		f.Record(r)
	}
	c.PublishLedger(f, v)
}
func (w *written) ok(c *Collector) { w.publish(c, verified(int64(len(w.records)))) }

func ledgerFacet(t *testing.T, c *Collector, robot, kind string) Facet {
	t.Helper()
	for _, r := range c.Snapshot().Robots {
		if r.Key.RobotID != robot {
			continue
		}
		for _, s := range r.Sources {
			if s.ProviderID == "ledger" {
				f, ok := s.Facets[kind]
				if !ok {
					t.Fatal("ledger source has no facet ", kind)
				}
				return f
			}
		}
	}
	t.Fatal("no ledger source on ", robot)
	return Facet{}
}
func progress(f Facet) string {
	if f.Plan == nil {
		return "none"
	}
	total := "?"
	if f.Plan.StepsTotal != nil {
		total = string(rune('0' + *f.Plan.StepsTotal))
	}
	return string(rune('0'+f.Plan.StepsCompleted)) + "/" + string(rune('0'+f.Plan.StepsIssued)) + "/" + total
}

// T01: the plan column of the latest plan, one case per value. The source is
// the collector's own verified ledger, and its freshness is the verification.
func TestOpsviewPlanColumn(t *testing.T) {
	for name, x := range map[string]struct {
		write           func(w *written)
		state, progress string
		code, ended     string
	}{
		"accepted": {func(w *written) { w.accepted("robot-1", "plan", "chain-a", 3) }, "ACCEPTED", "0/3/3", "", ""},
		"accepted in progress": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 3).done("robot-1", "chain-a", 1).done("robot-1", "chain-a", 2)
		}, "ACCEPTED", "2/3/3", "", ""},
		"completed": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).done("robot-1", "chain-a", 1).done("robot-1", "chain-a", 2)
		}, "COMPLETED", "2/2/2", "", ""},
		"rejected": {func(w *written) {
			w.add("PLAN_REJECTED", fields{"kind": "PLAN_REJECTED", "v": 2, "robot_id": "robot-1", "plan_id": "plan", "reject_code": "ERR_EMPTY_PLAN"})
		}, "REJECTED", "0/0/?", "ERR_EMPTY_PLAN", ""},
		"rejected after accepted": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).add("PLAN_REJECTED", fields{"kind": "PLAN_REJECTED", "robot_id": "robot-1", "plan_id": "next", "reject_code": "not a code"})
		}, "REJECTED", "0/0/?", "UNKNOWN_CODE", ""},
		"cancelled": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).lifecycle("CHAIN_CANCELLED", "robot-1", "chain-a")
		}, "CANCELLED", "0/2/2", "", "CHAIN_CANCELLED"},
		"revoked": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).done("robot-1", "chain-a", 1).lifecycle("CHAIN_REVOKED", "robot-1", "chain-a")
		}, "CANCELLED", "1/2/2", "", "CHAIN_REVOKED"},
		"fatal block": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).add("GATE_DECISION", fields{"robot_id": "robot-1", "chain_id": "chain-a", "token_id": tokenOf("chain-a", 1), "decision": "BLOCK", "fatal": true, "chain_attributed": true})
		}, "CANCELLED", "0/2/2", "", "GATE_FATAL"},
		"over lease": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).add("LEASE_RECONCILED", fields{"kind": "LEASE_RECONCILED", "robot_id": "robot-1", "chain_id": "chain-a", "verdict": "OVER_LEASE"})
		}, "CANCELLED", "0/2/2", "", "OVER_LEASE"},
		"new plan after end": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).lifecycle("CHAIN_CANCELLED", "robot-1", "chain-a").accepted("robot-1", "next", "chain-b", 1)
		}, "ACCEPTED", "0/1/1", "", ""},
		"end of an earlier chain": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).accepted("robot-1", "next", "chain-b", 2).lifecycle("CHAIN_CANCELLED", "robot-1", "chain-a").done("robot-1", "chain-a", 1).done("robot-1", "chain-a", 2)
		}, "ACCEPTED", "0/2/2", "", ""},
		"superseded is not an end": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).lifecycle("CHAIN_SUPERSEDED", "robot-1", "chain-a").lifecycle("RECOMPILE_REJECTED", "robot-1", "chain-a")
		}, "ACCEPTED", "0/2/2", "", ""},
		"block that is not fatal": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).add("GATE_DECISION", fields{"robot_id": "robot-1", "chain_id": "chain-a", "token_id": tokenOf("chain-a", 1), "decision": "BLOCK", "fatal": false})
		}, "ACCEPTED", "0/2/2", "", ""},
		"fatal report that names an earlier chain": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).accepted("robot-1", "next", "chain-b", 2).add("GATE_DECISION", fields{"robot_id": "robot-1", "chain_id": "chain-a", "token_id": tokenOf("chain-a", 1), "decision": "ESTOP", "fatal": true, "chain_attributed": false})
		}, "ACCEPTED", "0/2/2", "", ""},
		"another robot's records": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).lifecycle("CHAIN_CANCELLED", "robot-2", "chain-a").add("PLAN_REJECTED", fields{"robot_id": "robot-2", "plan_id": "plan", "reject_code": "ERR_X"}).done("robot-2", "chain-a", 1)
		}, "ACCEPTED", "0/2/2", "", ""},
		"completion after the end": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 1).lifecycle("CHAIN_REVOKED", "robot-1", "chain-a").done("robot-1", "chain-a", 1)
		}, "CANCELLED", "0/1/1", "", "CHAIN_REVOKED"},
		"end after completion": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 1).done("robot-1", "chain-a", 1).lifecycle("CHAIN_REVOKED", "robot-1", "chain-a")
		}, "COMPLETED", "1/1/1", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := ledgerFixture(t)
			w := &written{}
			x.write(w)
			w.ok(c)
			f := ledgerFacet(t, c, "robot-1", "plan")
			if f.Value == nil || f.Value.State != x.state || progress(f) != x.progress || f.Plan.RejectCode != x.code || f.Plan.EndedBy != x.ended {
				t.Fatalf("%+v %+v %s", f.Value, f.Plan, progress(f))
			}
			if f.Trust != "collector_verified" || f.FreshnessBasis != "verified_frontier" || f.SourceRef != "ledger" || f.Quality != "FRESH" || f.Reason != "VERIFIED_FRONTIER_CURRENT" || f.Active != nil {
				t.Fatalf("%+v", f)
			}
		})
	}
}

// T01: whatever the ledger holds, a chain that is not CHAIN_OK says nothing
// about a plan. The records are those that read ACCEPTED when verified.
func TestOpsviewPlanUnknownUnlessChainVerified(t *testing.T) {
	w := (&written{}).accepted("robot-1", "plan", "chain-a", 2).done("robot-1", "chain-a", 1)
	c, _ := ledgerFixture(t)
	w.ok(c)
	if f := ledgerFacet(t, c, "robot-1", "plan"); f.Value.State != "ACCEPTED" {
		t.Fatal(f)
	}
	for state, reason := range map[string]string{"chain_error": "CHAIN_ERROR", "absent": "ABSENT", "unverified": "UNVERIFIED", "something new": "UNVERIFIED"} {
		c, _ := ledgerFixture(t)
		v := verified(3)
		v.State, v.Code = state, "RECORD_HASH_MISMATCH"
		w.publish(c, v)
		f := ledgerFacet(t, c, "robot-1", "plan")
		if f.Value == nil || f.Value.State != "UNKNOWN" || f.Quality != "UNKNOWN" || f.Reason != reason || f.Plan != nil || f.Observed != nil {
			t.Fatalf("%s: %+v %+v", state, f, f.Value)
		}
	}
	c, _ = ledgerFixture(t)
	c.LedgerVerifying()
	if f := ledgerFacet(t, c, "robot-1", "plan"); f.Value.State != "UNKNOWN" || f.Quality != "UNKNOWN" || f.Reason != "VERIFYING" || f.Plan != nil {
		t.Fatalf("%+v", f)
	}
	// a robot the verified ledger never names has no plan record
	c, _ = ledgerFixture(t)
	w.ok(c)
	if f := ledgerFacet(t, c, "robot-2", "plan"); f.Value.State != "UNKNOWN" || f.Quality != "UNKNOWN" || f.Reason != "NO_PLAN_RECORD" || f.Plan != nil {
		t.Fatalf("%+v", f)
	}
}

// T02: a plan whose step count the ledger does not state is never shown as
// completed, however many completion records it has.
func TestOpsviewCompletionIsNotGuessed(t *testing.T) {
	all := func(w *written) {
		w.token("robot-1", "plan", "chain-a", 1).token("robot-1", "plan", "chain-a", 2).done("robot-1", "chain-a", 1).done("robot-1", "chain-a", 2)
	}
	for name, accept := range map[string]fields{
		"version 1 record":       {"kind": "PLAN_ACCEPTED", "robot_id": "robot-1", "plan_id": "plan", "chain_id": "chain-a"},
		"version 1 with a count": {"kind": "PLAN_ACCEPTED", "robot_id": "robot-1", "plan_id": "plan", "chain_id": "chain-a", "step_count": 2},
		"no count":               {"kind": "PLAN_ACCEPTED", "v": 2, "robot_id": "robot-1", "plan_id": "plan", "chain_id": "chain-a"},
		"count zero":             {"kind": "PLAN_ACCEPTED", "v": 2, "robot_id": "robot-1", "plan_id": "plan", "chain_id": "chain-a", "step_count": 0},
		"count negative":         {"kind": "PLAN_ACCEPTED", "v": 2, "robot_id": "robot-1", "plan_id": "plan", "chain_id": "chain-a", "step_count": -2},
		"count beyond the limit": {"kind": "PLAN_ACCEPTED", "v": 2, "robot_id": "robot-1", "plan_id": "plan", "chain_id": "chain-a", "step_count": MaxSteps + 1},
	} {
		c, _ := ledgerFixture(t)
		w := (&written{}).add("PLAN_ACCEPTED", accept)
		all(w)
		w.ok(c)
		f := ledgerFacet(t, c, "robot-1", "plan")
		if f.Value.State != "ACCEPTED" || progress(f) != "2/2/?" || f.Plan.StepsTotal != nil {
			t.Fatalf("%s: %+v %s", name, f.Value, progress(f))
		}
	}
	for name, x := range map[string]struct {
		write           func(w *written)
		state, progress string
	}{
		"last step open": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 3).done("robot-1", "chain-a", 1).done("robot-1", "chain-a", 2)
		}, "ACCEPTED", "2/3/3"},
		"permit, not complete": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 1).add("GATE_DECISION", fields{"robot_id": "robot-1", "chain_id": "chain-a", "token_id": tokenOf("chain-a", 1), "decision": "PERMIT", "step_complete": false, "chain_attributed": true})
		}, "ACCEPTED", "0/1/1"},
		"block, complete": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 1).add("GATE_DECISION", fields{"robot_id": "robot-1", "chain_id": "chain-a", "token_id": tokenOf("chain-a", 1), "decision": "BLOCK", "step_complete": true, "chain_attributed": true})
		}, "ACCEPTED", "0/1/1"},
		"not attributed": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 1).add("GATE_DECISION", fields{"robot_id": "robot-1", "chain_id": "chain-a", "token_id": tokenOf("chain-a", 1), "decision": "PERMIT", "step_complete": true, "chain_attributed": false})
		}, "ACCEPTED", "0/1/1"},
		"token never issued": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 1).add("GATE_DECISION", fields{"robot_id": "robot-1", "chain_id": "chain-a", "token_id": "other", "decision": "PERMIT", "step_complete": true, "chain_attributed": true})
		}, "ACCEPTED", "0/1/1"},
		"another chain": {func(w *written) { w.accepted("robot-1", "plan", "chain-a", 1).done("robot-1", "chain-b", 1) }, "ACCEPTED", "0/1/1"},
		"same step twice": {func(w *written) {
			w.accepted("robot-1", "plan", "chain-a", 2).done("robot-1", "chain-a", 1).done("robot-1", "chain-a", 1)
		}, "ACCEPTED", "1/2/2"},
		"tokens of a chain that was never accepted": {func(w *written) { w.token("robot-1", "plan", "chain-a", 1).done("robot-1", "chain-a", 1) }, "UNKNOWN", "0/1/?"},
	} {
		c, _ := ledgerFixture(t)
		w := &written{}
		x.write(w)
		w.ok(c)
		f := ledgerFacet(t, c, "robot-1", "plan")
		if f.Value.State != x.state || progress(f) != x.progress {
			t.Fatalf("%s: %+v %s", name, f.Value, progress(f))
		}
		if x.state == "UNKNOWN" && (f.Quality != "UNKNOWN" || f.Reason != "ACCEPT_RECORD_MISSING") {
			t.Fatalf("%s: %+v", name, f)
		}
	}
}

// T04: the ledger column, and the last record of each robot.
func TestOpsviewLedgerColumn(t *testing.T) {
	w := (&written{}).accepted("robot-1", "plan", "chain-a", 1).accepted("robot-2", "plan", "chain-b", 1).lifecycle("CHAIN_CANCELLED", "robot-2", "chain-b").done("robot-1", "chain-a", 1)
	c, now := ledgerFixture(t)
	w.ok(c)
	one, two := ledgerFacet(t, c, "robot-1", "ledger"), ledgerFacet(t, c, "robot-2", "ledger")
	if one.Value.State != "CHAIN_OK" || two.Value.State != "CHAIN_OK" || one.Quality != "FRESH" || one.Reason != "VERIFIED_FRONTIER_CURRENT" || one.Trust != "collector_verified" || one.FreshnessBasis != "verified_frontier" {
		t.Fatalf("%+v", one)
	}
	if d := one.Ledger; d == nil || d.ChainState != "CHAIN_OK" || d.ErrorCode != "" || d.VerifiedThrough != "6" || d.VerifiedAtMS != now.UnixMilli() || d.LagRecords == nil || *d.LagRecords != 0 || d.LastRecord == nil || *d.LastRecord != (LedgerLast{"6", "GATE_DECISION", 1700000000006}) {
		t.Fatalf("%+v %+v", d, d.LastRecord)
	}
	if d := two.Ledger; d.LastRecord == nil || *d.LastRecord != (LedgerLast{"5", "CHAIN_CANCELLED", 1700000000005}) {
		t.Fatalf("%+v", d.LastRecord)
	}
	for state, x := range map[string]struct{ code, shown, chain string }{
		"chain_error": {"RECORD_HASH_MISMATCH", "RECORD_HASH_MISMATCH", "CHAIN_ERROR"},
		"absent":      {"SOURCE_ABSENT", "SOURCE_ABSENT", "ABSENT"},
		"unverified":  {"TORN_TAIL", "TORN_TAIL", "UNVERIFIED"},
		"other":       {"open /state/secret: permission denied", "CHAIN_ERROR_OTHER", "UNVERIFIED"},
	} {
		c, _ := ledgerFixture(t)
		v := verified(4)
		v.State, v.Code, v.LagRecords, v.TipSeq = state, x.code, nil, nil
		if state == "chain_error" {
			v.State = "chain_error"
		}
		w.publish(c, v)
		f := ledgerFacet(t, c, "robot-1", "ledger")
		if f.Value.State != x.chain || f.Quality != "UNKNOWN" || f.Reason != x.chain || f.Ledger.ErrorCode != x.shown || f.Ledger.VerifiedThrough != "4" {
			t.Fatalf("%s: %+v %+v", state, f, f.Ledger)
		}
		// both robots have a record beyond the verified position: neither is shown
		if f.Ledger.LastRecord != nil {
			t.Fatalf("%s: a record beyond the verified position is shown: %+v", state, f.Ledger.LastRecord)
		}
		if g := ledgerFacet(t, c, "robot-2", "ledger"); g.Ledger.LastRecord != nil {
			t.Fatalf("%s: %+v", state, g.Ledger.LastRecord)
		}
		b, _ := json.Marshal(c.Snapshot())
		if strings.Contains(string(b), "secret") {
			t.Fatal("raw error text reached the response")
		}
	}
	// a walk that was rolled back verified nothing
	c, _ = ledgerFixture(t)
	v := verified(0)
	v.State, v.Code = "unverified", "SOURCE_UNSTABLE"
	w.publish(c, v)
	if f := ledgerFacet(t, c, "robot-1", "ledger"); f.Value.State != "UNVERIFIED" || f.Ledger.LastRecord != nil || f.Ledger.VerifiedThrough != "0" {
		t.Fatalf("%+v", f.Ledger)
	}
	c, _ = ledgerFixture(t)
	c.LedgerVerifying()
	if f := ledgerFacet(t, c, "robot-1", "ledger"); f.Value.State != "VERIFYING" || f.Quality != "UNKNOWN" || f.Reason != "VERIFYING" || f.Ledger.VerifiedAtMS != 0 || f.Ledger.LastRecord != nil {
		t.Fatalf("%+v %+v", f, f.Ledger)
	}
	// a verdict is not replaced by "verifying": the next pass is in flight, the last one stands
	w.ok(c)
	c.LedgerVerifying()
	if f := ledgerFacet(t, c, "robot-1", "ledger"); f.Value.State != "CHAIN_OK" {
		t.Fatalf("%+v", f.Value)
	}
	// no verdict and no index: nothing is said
	c, _ = ledgerFixture(t)
	for _, kind := range []string{"ledger", "plan"} {
		if f := ledgerFacet(t, c, "robot-1", kind); f.Value != nil || f.Quality != "UNKNOWN" || f.Reason != "INDEX_UNAVAILABLE" || f.Ledger != nil || f.Plan != nil {
			t.Fatalf("%+v", f)
		}
	}
}

// §5.4: a state is as fresh as its verification.
func TestOpsviewStateFreshness(t *testing.T) {
	w := (&written{}).accepted("robot-1", "plan", "chain-a", 2)
	c, now := ledgerFixture(t)
	w.ok(c)
	check := func(name, quality, reason, state string) {
		t.Helper()
		for kind, value := range map[string]string{"plan": state, "ledger": "CHAIN_OK"} {
			f := ledgerFacet(t, c, "robot-1", kind)
			if f.Quality != quality || f.Reason != reason || f.Value == nil || f.Value.State != value || f.FreshnessBasis != "verified_frontier" {
				t.Fatalf("%s %s: %+v %+v", name, kind, f, f.Value)
			}
		}
	}
	check("now", "FRESH", "VERIFIED_FRONTIER_CURRENT", "ACCEPTED")
	// far beyond the limit of a plan record (3 s): a state does not age with a record
	*now = now.Add(LedgerFreshness - time.Millisecond)
	check("just inside", "FRESH", "VERIFIED_FRONTIER_CURRENT", "ACCEPTED")
	*now = now.Add(time.Millisecond)
	check("at the limit", "STALE", "VERIFICATION_OLD", "ACCEPTED")
	w.ok(c)
	check("verified again", "FRESH", "VERIFIED_FRONTIER_CURRENT", "ACCEPTED")
	for name, lag := range map[string]*int64{"behind": ptr(int64(1)), "unknown": nil} {
		v := verified(3)
		v.LagRecords = lag
		w.publish(c, v)
		check(name, "STALE", "INDEX_BEHIND", "ACCEPTED")
	}
	*now = now.Add(-time.Second)
	if f := ledgerFacet(t, c, "robot-1", "plan"); f.Quality != "UNKNOWN" || f.Reason != "CLOCK_UNCERTAIN" {
		t.Fatalf("%+v", f)
	}
	*now = now.Add(time.Second)
	// the cycle failed: the earlier reading is not presented as the present one
	w.ok(c)
	w.publish(c, LedgerVerdict{State: "ok", VerifiedSeq: 3, Published: false})
	for _, kind := range []string{"ledger", "plan"} {
		if f := ledgerFacet(t, c, "robot-1", kind); f.Value != nil || f.Plan != nil || f.Ledger != nil || f.Quality != "UNKNOWN" || f.Reason != "INDEX_UNAVAILABLE" || f.Received != nil {
			t.Fatalf("%s: %+v", kind, f)
		}
	}
	w.ok(c)
	c.PublishLedger(nil, verified(3))
	if f := ledgerFacet(t, c, "robot-1", "plan"); f.Value != nil || f.Reason != "INDEX_UNAVAILABLE" {
		t.Fatalf("%+v", f)
	}
}

// A page served from the cache ages the state by its verification limit, not
// by the limit of a plan record.
func TestOpsviewStateFreshnessOnCachedPage(t *testing.T) {
	c, now := ledgerFixture(t)
	(&written{}).accepted("robot-1", "plan", "chain-a", 2).accepted("robot-2", "plan", "chain-b", 2).ok(c)
	api := NewAPI(c)
	api.now = func() time.Time { return *now }
	*now = now.Add(10 * time.Second)
	read := func(query string) page {
		t.Helper()
		w := httptest.NewRecorder()
		api.Robots(w, httptest.NewRequest("GET", "/v2/observation/robots"+query, nil))
		var p page
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return p
	}
	plan := func(p page) Facet {
		for _, s := range p.Robots[0].Sources {
			if s.ProviderID == "ledger" {
				return s.Facets["plan"]
			}
		}
		t.Fatal("no ledger source")
		return Facet{}
	}
	first := read("?limit=1")
	if f := plan(first); f.Quality != "FRESH" || *f.AgeMS != 10000 || f.Value.State != "ACCEPTED" {
		t.Fatalf("%+v", f)
	}
	*now = now.Add(19 * time.Second)
	if f := plan(read("?limit=1&cursor=" + first.Next)); f.Quality != "FRESH" || f.Reason != "VERIFIED_FRONTIER_CURRENT" || *f.AgeMS != 29000 {
		t.Fatalf("%+v", f)
	}
	*now = now.Add(time.Second)
	if f := plan(read("?limit=1&cursor=" + first.Next)); f.Quality != "STALE" || f.Reason != "VERIFICATION_OLD" || f.ReceiptQuality != "STALE" {
		t.Fatalf("%+v", f)
	}
}

// T05 and §5.1: what may declare the ledger, and what the ledger source may declare.
func TestOpsviewLedgerSourceDeclaration(t *testing.T) {
	robot := provider("one", "robot-1", dep)
	for _, kind := range []string{"ledger", "management"} {
		p := robot
		p.Allowed = []string{"gate", kind}
		if e := (SourceMap{1, source, dep, []Provider{p}}).Validate(); e == nil || e.Error() != "SOURCE_MAP_VERIFIED_PROVIDER_REQUIRED" {
			t.Fatal(kind, e)
		}
	}
	for _, kinds := range [][]string{{"plan", "ledger"}, {"ledger", "plan"}, {"plan"}, {"ledger"}} {
		p := ledgerSource()
		p.Allowed = kinds
		if e := (SourceMap{1, source, dep, []Provider{robot, p}}).Validate(); e != nil {
			t.Fatal(kinds, e)
		}
	}
	for name, change := range map[string]func(*Provider){
		"self report":              func(p *Provider) { p.Trust = "local_self_report" },
		"signature":                func(p *Provider) { p.Trust = "verified_signature" },
		"no trust":                 func(p *Provider) { p.Trust = "" },
		"gate":                     func(p *Provider) { p.Allowed = []string{"plan", "gate"} },
		"permit":                   func(p *Provider) { p.Allowed = []string{"permit"} },
		"management":               func(p *Provider) { p.Allowed = []string{"ledger", "management"} },
		"no kinds":                 func(p *Provider) { p.Allowed = nil },
		"same kind twice":          func(p *Provider) { p.Allowed = []string{"plan", "plan"} },
		"three kinds":              func(p *Provider) { p.Allowed = []string{"plan", "ledger", "plan"} },
		"path":                     func(p *Provider) { p.PathRef = "/state/ledger" },
		"address":                  func(p *Provider) { p.EndpointRef = "ledger:9000" },
		"robot":                    func(p *Provider) { p.RobotID = "robot-1" },
		"identity":                 func(p *Provider) { p.Identity = "device-robot-1" },
		"deployment":               func(p *Provider) { p.DeploymentID = dep },
		"owner":                    func(p *Provider) { p.Owner = "actor" },
		"run":                      func(p *Provider) { p.RunID = dep },
		"stream":                   func(p *Provider) { p.StreamID = stream },
		"clock binding":            func(p *Provider) { p.ClockBinding = ClockBindingShared },
		"no role":                  func(p *Provider) { p.Role = "" },
		"name of a robot's source": func(p *Provider) { p.ProviderID = "one" },
		"no name":                  func(p *Provider) { p.ProviderID = "" },
	} {
		p := ledgerSource()
		change(&p)
		if e := (SourceMap{1, source, dep, []Provider{robot, p}}).Validate(); e == nil {
			t.Fatal(name, " was accepted")
		}
	}
	second := ledgerSource()
	second.ProviderID = "ledger-2"
	if e := (SourceMap{1, source, dep, []Provider{robot, ledgerSource(), second}}).Validate(); e == nil || e.Error() != "SOURCE_MAP_LEDGER_PROVIDER" {
		t.Fatal(e)
	}
	// the ledger source is not a record stream: nothing can be sent to it
	c, _ := ledgerFixture(t)
	e := v2event(robot, "plan", "COMPLETED", 1)
	e.SchemaVersion, e.MonoNS = 1, ""
	if err := c.Observe("ledger", e); err == nil || err.Error() != "UNKNOWN_PROVIDER" {
		t.Fatal(err)
	}
	c.ObserveLegacy(LedgerKind, "00000000000000000000000000000000", 1, true, false)
	if f := ledgerFacet(t, c, "robot-1", "plan"); f.Value != nil {
		t.Fatalf("%+v", f)
	}
	// it shows the two kinds it declares and no other
	only := ledgerSource()
	only.Allowed = []string{"ledger"}
	c, _ = fixture(t, robot, only)
	(&written{}).accepted("robot-1", "plan", "chain-a", 1).ok(c)
	if f := ledgerFacet(t, c, "robot-1", "plan"); f.Quality != "UNSUPPORTED" || f.Value != nil || f.Plan != nil {
		t.Fatalf("%+v", f)
	}
	if f := ledgerFacet(t, c, "robot-1", "gate"); f.Quality != "UNSUPPORTED" {
		t.Fatalf("%+v", f)
	}
}

// §5.1: a ledger record of a robot no source declares is an unresolved
// observation, never a new row, and only a verified ledger can name one.
func TestOpsviewLedgerRobotNotDeclared(t *testing.T) {
	w := (&written{}).accepted("robot-1", "plan", "chain-a", 1).accepted("robot-9", "plan", "chain-z", 1).accepted("not a name", "plan", "chain-y", 1)
	c, _ := ledgerFixture(t)
	w.ok(c)
	s := c.Snapshot()
	if len(s.Robots) != 2 || len(s.Unresolved) != 1 || s.Unresolved[0].ProviderID != "ledger" || s.Unresolved[0].Reason != "LEDGER_ROBOT_NOT_DECLARED" || len(s.Unresolved[0].RobotHash) != 32 {
		t.Fatalf("%+v %+v", s.Robots, s.Unresolved)
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "robot-9") {
		t.Fatal("the name of an undeclared robot reached the response")
	}
	// the list follows the ledger: it is not a history
	(&written{}).accepted("robot-1", "plan", "chain-a", 1).ok(c)
	if s = c.Snapshot(); len(s.Unresolved) != 0 {
		t.Fatalf("%+v", s.Unresolved)
	}
	v := verified(3)
	v.State = "chain_error"
	w.publish(c, v)
	if s = c.Snapshot(); len(s.Unresolved) != 0 {
		t.Fatalf("an unverified ledger named a robot: %+v", s.Unresolved)
	}
	// a robot of another deployment is not this ledger's robot
	far := provider("far", "robot-1", dep2)
	c, _ = fixture(t, far, ledgerSource())
	(&written{}).accepted("robot-1", "plan", "chain-a", 1).ok(c)
	s = c.Snapshot()
	if len(s.Robots) != 1 || len(s.Robots[0].Sources) != 1 || len(s.Unresolved) != 1 {
		t.Fatalf("%+v %+v", s.Robots, s.Unresolved)
	}
}

// A source map without the ledger source answers with the same keys as before.
func TestOpsviewNoLedgerSourceNoNewKeys(t *testing.T) {
	p := provider("one", "robot-1", dep)
	c, _ := fixture(t, p)
	(&written{}).accepted("robot-1", "plan", "chain-a", 1).ok(c)
	c.LedgerVerifying()
	send(t, c, p, "1")
	send(t, c, p, "2")
	b, _ := json.Marshal(c.Snapshot())
	for _, word := range []string{"plan_detail", "ledger_detail", "verified_frontier", "collector_verified"} {
		if strings.Contains(string(b), word) {
			t.Fatal(word)
		}
	}
	if s := c.Snapshot(); len(s.Robots[0].Sources) != 1 || len(s.Unresolved) != 0 || c.HasLedgerSource() {
		t.Fatalf("%+v", s)
	}
}

// A snapshot is complete only while the ledger source has a current verdict.
func TestOpsviewLedgerSourceHealth(t *testing.T) {
	robot := provider("one", "robot-1", dep)
	health := func(c *Collector) (string, bool) {
		s := c.Snapshot()
		for _, row := range s.Robots[0].Sources {
			if row.ProviderID == "ledger" {
				return row.Health, s.Complete
			}
		}
		t.Fatal("no ledger source")
		return "", false
	}
	heard := func() (*Collector, *time.Time) {
		c, now := fixture(t, robot, ledgerSource())
		send(t, c, robot, "1")
		send(t, c, robot, "2")
		return c, now
	}
	w := (&written{}).accepted("robot-1", "plan", "chain-a", 1)
	c, now := heard()
	if h, complete := health(c); h != "UNKNOWN" || complete {
		t.Fatal(h, complete)
	}
	c.LedgerVerifying()
	if h, complete := health(c); h != "UNKNOWN" || complete {
		t.Fatal(h, complete)
	}
	w.ok(c)
	if h, complete := health(c); h != "CONNECTED" || !complete {
		t.Fatal(h, complete)
	}
	// a damaged ledger is a verdict the source delivered: the source is connected
	v := verified(1)
	v.State, v.Code = "chain_error", "RECORD_HASH_MISMATCH"
	w.publish(c, v)
	if h, complete := health(c); h != "CONNECTED" || !complete {
		t.Fatal(h, complete)
	}
	w.publish(c, LedgerVerdict{})
	if h, complete := health(c); h != "INDEX_UNAVAILABLE" || complete {
		t.Fatal(h, complete)
	}
	w.ok(c)
	*now = now.Add(LedgerFreshness)
	send(t, c, robot, "3")
	send(t, c, robot, "4")
	if h, complete := health(c); h != "STALE" || complete {
		t.Fatal(h, complete)
	}
}
