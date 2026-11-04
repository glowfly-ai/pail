// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func (w *written) gate(robot, chain, decision, reason string, fatal bool) *written {
	return w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "journal_v": 6, "robot_id": robot, "chain_id": chain, "token_id": tokenOf(chain, 1), "decision": decision, "reason_code": reason, "step_complete": false, "fatal": fatal, "chain_attributed": true})
}

// history is a ledger with every kind of decision record, for two declared
// robots and one robot the source map does not declare.
func history() *written {
	w := &written{}
	w.accepted("robot-1", "plan-a", "chain-a", 1)                                                          // 1 2
	w.accepted("robot-2", "plan-b", "chain-b", 1)                                                          // 3 4
	w.done("robot-1", "chain-a", 1)                                                                        // 5
	w.gate("robot-2", "chain-b", "BLOCK", "ERR_ZONE_FORBIDDEN", false)                                     // 6
	w.gate("robot-2", "chain-b", "ESTOP", "ERR_SIGNATURE", true)                                           // 7
	w.add("SAFE_STOP", fields{"kind": "SAFE_STOP", "robot_id": "robot-2", "reason_code": "ERR_SIGNATURE"}) // 8
	w.add("CHAIN_REVOKED", fields{"kind": "CHAIN_REVOKED", "trigger": "GATE_FATAL", "robot_id": "robot-2", "chain_id": "chain-b", "plan_id": "plan-b", "reason_code": "ERR_SIGNATURE"})
	w.add("CHAIN_REVOKED", fields{"kind": "CHAIN_CANCELLED", "trigger": "NORTHBOUND_CANCEL", "robot_id": "robot-1", "chain_id": "chain-a", "plan_id": "plan-a"}) // 10
	w.add("OPERATOR_EVENT", fields{"kind": "UNLOCK", "accepted": true, "detail": "free text that is not shown"})                                                 // 11
	w.add("OPERATOR_EVENT", fields{"kind": "OPS_HOLD_SET", "robots": []string{"robot-1", "robot-9", "robot-1"}})                                                 // 12
	w.gate("robot-9", "chain-z", "BLOCK", "ERR_EXPIRED", false)                                                                                                  // 13
	w.add("CHAIN_REVOKED", fields{"kind": "LEASE_SOMETHING", "robot_id": "robot-1", "chain_id": "chain-a"})                                                      // 14: not a decision
	w.add("SAFE_STOP", fields{"kind": "SAFE_STOP", "robot_id": "", "reason_code": "ERR_SIGNATURE"})                                                              // 15: names no robot
	w.add("TOKEN_ISSUED", fields{"kind": "TOKEN_ISSUED"})                                                                                                        // 16: not a decision
	return w
}

func kinds(rows []Decision) string {
	out := []string{}
	for _, d := range rows {
		out = append(out, d.Seq+":"+d.Kind+":"+d.Decision)
	}
	return strings.Join(out, " ")
}
func robotRows(t *testing.T, h DecisionHistory, robot string) []Decision {
	t.Helper()
	for _, r := range h.Robots {
		if r.Key.RobotID == robot {
			return r.Decisions
		}
	}
	t.Fatal("no row for ", robot)
	return nil
}

// T12: decision records per robot, newest first, from the verified ledger.
func TestOpsviewDecisionsPerRobot(t *testing.T) {
	c, _ := ledgerFixture(t)
	history().ok(c)
	h := c.Decisions()
	if !h.LedgerVerified || h.ChainState != "CHAIN_OK" || h.VerifiedThrough != "16" || h.Trust != "collector_verified" || h.SourceRef != "ledger" || h.TimeBasis != "issuer_ledger_record_time" || len(h.Robots) != 2 {
		t.Fatalf("%+v", h)
	}
	if got := kinds(robotRows(t, h, "robot-1")); got != "12:OPERATOR_EVENT: 10:CHAIN_CANCELLED: 5:GATE_DECISION:PERMIT" {
		t.Fatal(got)
	}
	if got := kinds(robotRows(t, h, "robot-2")); got != "9:CHAIN_REVOKED: 8:SAFE_STOP: 7:GATE_DECISION:ESTOP 6:GATE_DECISION:BLOCK" {
		t.Fatal(got)
	}
	// a record that names no robot belongs to the deployment
	if got := kinds(h.Deployment.Decisions); got != "15:SAFE_STOP: 11:OPERATOR_EVENT:" {
		t.Fatal(got)
	}
	two := robotRows(t, h, "robot-2")
	if d := two[3]; d.ReasonCode != "ERR_ZONE_FORBIDDEN" || d.RecordMS != 1700000000006 || *d.Fatal || d.ChainID != "chain-b" || !*d.Attributed {
		t.Fatalf("%+v", d)
	}
	if d := two[2]; !*d.Fatal || d.ReasonCode != "ERR_SIGNATURE" {
		t.Fatalf("%+v", d)
	}
	if d := two[0]; d.Trigger != "GATE_FATAL" || d.PlanID != "plan-b" {
		t.Fatalf("%+v", d)
	}
	if d := h.Deployment.Decisions[1]; d.Trigger != "UNLOCK" || d.Accepted == nil || !*d.Accepted {
		t.Fatalf("%+v", d)
	}
	// the plan column is what it was before the history existed: the plan of
	// robot-1 had ended before the cancellation was written
	if f := ledgerFacet(t, c, "robot-1", "plan"); f.Value.State != "COMPLETED" {
		t.Fatalf("%+v", f)
	}
}

// T12: a record of a robot the source map does not declare is in no list.
func TestOpsviewDecisionsUndeclaredRobot(t *testing.T) {
	c, _ := ledgerFixture(t)
	history().ok(c)
	b, _ := json.Marshal(c.Decisions())
	if strings.Contains(string(b), "robot-9") || strings.Contains(string(b), "chain-z") || strings.Contains(string(b), "ERR_EXPIRED") || strings.Contains(string(b), `"record_seq":"13"`) {
		t.Fatal(string(b))
	}
	if strings.Contains(string(b), "free text") {
		t.Fatal("free text of a record is shown")
	}
	// the lists are bounded by the declaration: no list is kept for a robot
	// that is not declared, however many of them the ledger names
	w := &written{}
	for i := 0; i < 50; i++ {
		w.gate("stranger-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "chain-z", "BLOCK", "ERR_EXPIRED", false)
	}
	w.gate("robot-2", "chain-b", "BLOCK", "ERR_EXPIRED", false)
	w.ok(c)
	if n := len(c.ledger.fold.decisions); n != 1 || c.ledger.fold.decisions["robot-2"] == nil {
		t.Fatal("lists kept: ", n)
	}
}

// T12: nothing beyond the verified position; ledger_verified only for CHAIN_OK.
func TestOpsviewDecisionsVerifiedPrefixOnly(t *testing.T) {
	c, _ := ledgerFixture(t)
	w := history()
	n := int64(7)
	w.publish(c, LedgerVerdict{State: "chain_error", Code: "RECORD_HASH_MISMATCH", VerifiedSeq: n, Published: true})
	h := c.Decisions()
	if h.LedgerVerified || h.ChainState != "CHAIN_ERROR" || h.ErrorCode != "RECORD_HASH_MISMATCH" || h.VerifiedThrough != "7" {
		t.Fatalf("%+v", h)
	}
	if got := kinds(robotRows(t, h, "robot-2")); got != "7:GATE_DECISION:ESTOP 6:GATE_DECISION:BLOCK" {
		t.Fatal(got)
	}
	if got := kinds(robotRows(t, h, "robot-1")); got != "5:GATE_DECISION:PERMIT" {
		t.Fatal(got)
	}
	if len(h.Deployment.Decisions) != 0 {
		t.Fatal(kinds(h.Deployment.Decisions))
	}
	for _, v := range []LedgerVerdict{
		{State: "unverified", Code: "TORN_TAIL", VerifiedSeq: 0, Published: true},
		{State: "absent", Code: "SOURCE_ABSENT", Published: true},
		{State: "ok", VerifiedSeq: 16, Published: false},
	} {
		w.publish(c, v)
		h = c.Decisions()
		if h.LedgerVerified || h.VerifiedThrough != "0" || len(robotRows(t, h, "robot-1")) != 0 || len(robotRows(t, h, "robot-2")) != 0 || len(h.Deployment.Decisions) != 0 {
			t.Fatalf("%+v %+v", v, h)
		}
	}
	if h.ChainState != "INDEX_UNAVAILABLE" {
		t.Fatal(h.ChainState)
	}
}

// A verification that is too old to call the ledger column fresh does not
// call the history verified either; the clock going back verifies nothing.
func TestOpsviewDecisionsVerificationAge(t *testing.T) {
	c, now := ledgerFixture(t)
	history().ok(c)
	start := *now
	*now = start.Add(LedgerFreshness - time.Millisecond)
	if h := c.Decisions(); !h.LedgerVerified || *h.VerificationAge != LedgerFreshness.Milliseconds()-1 {
		t.Fatalf("%+v", h)
	}
	*now = start.Add(LedgerFreshness)
	h := c.Decisions()
	if h.LedgerVerified || h.ChainState != "CHAIN_OK" || len(robotRows(t, h, "robot-1")) != 3 {
		t.Fatalf("%+v", h)
	}
	*now = start.Add(-time.Second)
	if h := c.Decisions(); h.LedgerVerified || h.VerificationAge != nil {
		t.Fatalf("%+v", h)
	}
}

// A robot declared by two sources has one list.
func TestOpsviewDecisionsOneListPerRobot(t *testing.T) {
	second := provider("one-b", "robot-1", dep)
	second.Role = "secondary"
	c, _ := fixture(t, provider("two", "robot-2", dep), provider("one", "robot-1", dep), second, ledgerSource())
	history().ok(c)
	h := c.Decisions()
	if len(h.Robots) != 2 || h.Robots[0].Key.RobotID != "robot-1" || h.Robots[1].Key.RobotID != "robot-2" || len(h.Robots[0].Decisions) != 3 {
		t.Fatalf("%+v", h.Robots)
	}
}

// Before the first verification has ended nothing is listed.
func TestOpsviewDecisionsVerifying(t *testing.T) {
	c, _ := ledgerFixture(t)
	if h := c.Decisions(); h.LedgerVerified || h.ChainState != "INDEX_UNAVAILABLE" || len(h.Robots) != 2 {
		t.Fatalf("%+v", h)
	}
	c.LedgerVerifying()
	h := c.Decisions()
	if h.LedgerVerified || h.ChainState != "VERIFYING" || h.VerifiedAtMS != 0 || h.VerificationAge != nil || len(robotRows(t, h, "robot-1")) != 0 {
		t.Fatalf("%+v", h)
	}
}

// The list of a robot is bounded; the newest records are kept and the number
// of records that were dropped is stated.
func TestOpsviewDecisionsBounded(t *testing.T) {
	c, _ := ledgerFixture(t)
	w := &written{}
	for i := 0; i < MaxDecisions+25; i++ {
		// a different refusal every time: nothing to count together
		w.gate("robot-1", "chain-"+strconv.Itoa(i), "BLOCK", "ERR_ZONE_FORBIDDEN", false)
	}
	w.gate("robot-2", "chain-b", "BLOCK", "ERR_ZONE_FORBIDDEN", false)
	w.ok(c)
	h := c.Decisions()
	one := robotRows(t, h, "robot-1")
	if len(one) != MaxDecisions || one[0].Seq != "225" || one[MaxDecisions-1].Seq != "26" || h.Robots[0].Dropped != 25 || h.Limit != MaxDecisions {
		t.Fatal(len(one), one[0].Seq, one[len(one)-1].Seq, h.Robots[0].Dropped)
	}
	if len(robotRows(t, h, "robot-2")) != 1 || h.Robots[1].Dropped != 0 {
		t.Fatal("the bound of one robot touched another")
	}
}

// Reports of the permit of one running step are one row with their count; a
// block, a completion or another token ends the row.
func TestOpsviewDecisionsRepeatedPermit(t *testing.T) {
	c, _ := ledgerFixture(t)
	w := &written{}
	permit := func(robot, chain string, step int) {
		w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "robot_id": robot, "chain_id": chain, "token_id": tokenOf(chain, step), "decision": "PERMIT", "reason_code": "OK", "step_complete": false, "fatal": false, "chain_attributed": true})
	}
	for i := 0; i < 3; i++ {
		permit("robot-1", "chain-a", 1) // 1 2 3
	}
	permit("robot-2", "chain-b", 1)                                  // 4: another robot does not end the row of robot-1
	permit("robot-1", "chain-a", 1)                                  // 5
	w.gate("robot-1", "chain-a", "BLOCK", "ERR_SAFETY_STALE", false) // 6
	permit("robot-1", "chain-a", 1)                                  // 7
	permit("robot-1", "chain-a", 1)                                  // 8
	w.done("robot-1", "chain-a", 1)                                  // 9
	permit("robot-1", "chain-a", 2)                                  // 10
	for i := 0; i < 3*MaxDecisions; i++ {
		permit("robot-1", "chain-a", 3)
	}
	w.ok(c)
	h := c.Decisions()
	one := robotRows(t, h, "robot-1")
	if got := kinds(one); got != "610:GATE_DECISION:PERMIT 10:GATE_DECISION:PERMIT 9:GATE_DECISION:PERMIT 8:GATE_DECISION:PERMIT 6:GATE_DECISION:BLOCK 5:GATE_DECISION:PERMIT" {
		t.Fatal(got)
	}
	if one[0].Repeats != 3*MaxDecisions || one[0].FirstSeq != "11" || one[0].FirstMS != 1700000000011 || one[0].RecordMS != 1700000000610 || h.Robots[0].Dropped != 0 {
		t.Fatalf("%+v", one[0])
	}
	if one[1].Repeats != 0 || one[1].FirstSeq != "" || !*one[2].StepComplete || one[2].Repeats != 0 {
		t.Fatalf("%+v %+v", one[1], one[2])
	}
	if one[3].Repeats != 2 || one[3].FirstSeq != "7" || one[5].Repeats != 4 || one[5].FirstSeq != "1" {
		t.Fatalf("%+v %+v", one[3], one[5])
	}
	if two := robotRows(t, h, "robot-2"); len(two) != 1 || two[0].Repeats != 0 || two[0].Seq != "4" {
		t.Fatalf("%+v", two)
	}
	// a completion after a plain report, and a report with another reason, are rows of their own
	w = &written{}
	permit("robot-2", "chain-b", 1)
	// the completing report as the robot sends it: same token, same reason
	w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "robot_id": "robot-2", "chain_id": "chain-b", "token_id": tokenOf("chain-b", 1), "decision": "PERMIT", "reason_code": "OK", "step_complete": true, "fatal": false, "chain_attributed": true})
	permit("robot-2", "chain-b", 2)
	w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "robot_id": "robot-2", "chain_id": "chain-b", "token_id": tokenOf("chain-b", 2), "decision": "PERMIT", "reason_code": "OK_DEGRADED", "step_complete": false, "fatal": false, "chain_attributed": true})
	w.ok(c)
	if two := robotRows(t, c.Decisions(), "robot-2"); kinds(two) != "4:GATE_DECISION:PERMIT 3:GATE_DECISION:PERMIT 2:GATE_DECISION:PERMIT 1:GATE_DECISION:PERMIT" || two[0].ReasonCode != "OK_DEGRADED" || two[0].Repeats != 0 || !*two[2].StepComplete || *two[3].StepComplete {
		t.Fatalf("%+v", two)
	}
	// a refusal is reported as often as a permit: the reports of one refusal are one row,
	// another reason, another decision and a fatal report are rows of their own
	w = &written{}
	for i := 0; i < 100; i++ {
		w.gate("robot-2", "chain-b", "BLOCK", "ERR_SAFETY_STALE", false)
	}
	w.gate("robot-2", "chain-b", "BLOCK", "ERR_ZONE_FORBIDDEN", false)
	w.gate("robot-2", "chain-b", "ESTOP", "ERR_ZONE_FORBIDDEN", false)
	w.gate("robot-2", "chain-b", "ESTOP", "ERR_ZONE_FORBIDDEN", true)
	w.gate("robot-2", "chain-b", "ESTOP", "ERR_ZONE_FORBIDDEN", true)
	w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "robot_id": "robot-2", "decision": "BLOCK", "reason_code": "ERR_NO_TOKEN", "step_complete": false, "fatal": false, "chain_attributed": false})
	w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "robot_id": "robot-2", "decision": "BLOCK", "reason_code": "ERR_NO_TOKEN", "step_complete": false, "fatal": false, "chain_attributed": false})
	w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "robot_id": "robot-2", "decision": "BLOCK", "reason_code": "ERR_NO_TOKEN", "step_complete": false, "fatal": false, "chain_attributed": true})
	// 108 and 109: the same refusal without a token, reported for two chains
	w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "robot_id": "robot-2", "chain_id": "chain-x", "decision": "BLOCK", "reason_code": "ERR_NO_TOKEN", "step_complete": false, "fatal": false, "chain_attributed": false})
	w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "robot_id": "robot-2", "chain_id": "chain-y", "decision": "BLOCK", "reason_code": "ERR_NO_TOKEN", "step_complete": false, "fatal": false, "chain_attributed": false})
	w.ok(c)
	two := robotRows(t, c.Decisions(), "robot-2")
	if len(two) != 9 || two[0].ChainID != "chain-y" || two[1].ChainID != "chain-x" || two[0].Repeats != 0 || two[1].Repeats != 0 {
		t.Fatalf("%+v", two[:2])
	}
	two = two[2:]
	// 1..100 one refusal, 101 another reason, 102 another decision, 103 and 104 fatal,
	// 105 and 106 without a token and not attributed, 107 attributed
	if kinds(two) != "107:GATE_DECISION:BLOCK 106:GATE_DECISION:BLOCK 104:GATE_DECISION:ESTOP 103:GATE_DECISION:ESTOP 102:GATE_DECISION:ESTOP 101:GATE_DECISION:BLOCK 100:GATE_DECISION:BLOCK" {
		t.Fatal(kinds(two))
	}
	if two[6].Repeats != 100 || two[6].FirstSeq != "1" || two[6].ReasonCode != "ERR_SAFETY_STALE" || two[1].Repeats != 2 || two[1].FirstSeq != "105" || *two[1].Attributed || two[0].Repeats != 0 || !*two[0].Attributed {
		t.Fatalf("%+v", two)
	}
	for _, i := range []int{2, 3, 4, 5} {
		if two[i].Repeats != 0 || *two[i].Fatal != (i < 4) {
			t.Fatalf("%d %+v", i, two[i])
		}
	}
	w = &written{}
	for i := 0; i < 4; i++ {
		permit("robot-1", "chain-a", 1)
	}
	w.gate("robot-1", "chain-a", "BLOCK", "ERR_SAFETY_STALE", false)
	permit("robot-1", "chain-a", 1)
	permit("robot-1", "chain-a", 1)
	// a row is listed only when every report in it is verified
	w.publish(c, LedgerVerdict{State: "chain_error", Code: "RECORD_HASH_MISMATCH", VerifiedSeq: 6, Published: true})
	if got := kinds(robotRows(t, c.Decisions(), "robot-1")); got != "5:GATE_DECISION:BLOCK 4:GATE_DECISION:PERMIT" {
		t.Fatal(got)
	}
}

// Codes are shown only in the closed form; a decision value the collector
// does not know is UNKNOWN, never a permit.
func TestOpsviewDecisionsCodes(t *testing.T) {
	c, _ := ledgerFixture(t)
	w := &written{}
	w.gate("robot-1", "chain-a", "ALLOW_EVERYTHING", "<script>alert(1)</script>", false)
	w.add("OPERATOR_EVENT", fields{"kind": "not a code", "robot_id": "robot-1"})
	w.add("CHAIN_REVOKED", fields{"kind": "CHAIN_REVOKED", "trigger": "<i>why</i>", "robot_id": "robot-2", "chain_id": "chain-b"})
	w.add("GATE_DECISION", fields{"kind": "GATE_DECISION", "robot_id": "robot-1", "chain_id": "bad chain id", "plan_id": "<b>", "decision": "PERMIT"})
	w.ok(c)
	if two := robotRows(t, c.Decisions(), "robot-2"); len(two) != 1 || two[0].Trigger != "OTHER" || two[0].Kind != "CHAIN_REVOKED" {
		t.Fatalf("%+v", two)
	}
	rows := robotRows(t, c.Decisions(), "robot-1")
	if len(rows) != 3 || rows[2].Decision != "UNKNOWN" || rows[2].ReasonCode != "OTHER" || rows[1].Trigger != "OTHER" || rows[0].ChainID != "" || rows[0].PlanID != "" || rows[0].Decision != "PERMIT" || rows[0].Attributed != nil {
		t.Fatalf("%+v", rows)
	}
}

// T14 and §7.3: the capability document says what the status page may draw,
// and only where the ledger source is declared.
func TestOpsviewDecisionsCapabilities(t *testing.T) {
	read := func(c *Collector) (map[string]any, string) {
		w := httptest.NewRecorder()
		NewAPI(c).Capabilities(w, httptest.NewRequest("GET", "/v2/observation/capabilities", nil))
		var m map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &m) != nil {
			t.Fatal(w.Code, w.Body.String())
		}
		return m, w.Body.String()
	}
	c, _ := ledgerFixture(t)
	m, body := read(c)
	feeds := m["feeds"].(map[string]any)
	if feeds["ledger_decisions"] != true || feeds["signed_events"] != false || !strings.Contains(body, `"endpoints":["/v2/observation/robots","/v2/observation/decisions"]`) {
		t.Fatal(body)
	}
	burst := Provider{ProviderID: "burst", Kind: "legacy_burst", DeploymentID: dep, RobotID: "robot-1", Identity: "device-1", Allowed: []string{"gate"}, Trust: "verified_signature", Role: "primary"}
	c, _ = fixture(t, burst, ledgerSource())
	if m, body = read(c); m["feeds"].(map[string]any)["signed_events"] != true {
		t.Fatal(body)
	}
	mirror := Provider{ProviderID: "mirror", Kind: "legacy_permit", DeploymentID: dep, RobotID: "robot-1", Identity: "device-1", Allowed: []string{"permit"}, Trust: "verified_signature", Role: "primary"}
	c, _ = fixture(t, mirror, ledgerSource())
	if m, body = read(c); m["feeds"].(map[string]any)["signed_events"] != true {
		t.Fatal(body)
	}
	// without the ledger source the document has no new member
	c, _ = fixture(t, burst)
	if m, body = read(c); m["feeds"] != nil || !strings.Contains(body, `"endpoints":["/v2/observation/robots"]`) {
		t.Fatal(body)
	}
}

func TestOpsviewDecisionsHTTP(t *testing.T) {
	c, _ := ledgerFixture(t)
	history().ok(c)
	api := NewAPI(c)
	get := func(method, target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		api.Decisions(w, httptest.NewRequest(method, target, nil))
		return w
	}
	w := get("GET", DecisionsEndpoint)
	var h DecisionHistory
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &h) != nil || h.DocumentKind != "LedgerDecisionHistory" || h.SchemaVersion != 1 || len(h.Robots) != 2 || !h.LedgerVerified || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"seq"`) {
		t.Fatal("internal field in the answer")
	}
	w = get("GET", DecisionsEndpoint+"?robot_id=robot-2")
	h = DecisionHistory{}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &h) != nil || len(h.Robots) != 1 || h.Robots[0].Key.RobotID != "robot-2" || len(h.Robots[0].Decisions) != 4 || len(h.Deployment.Decisions) != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = get("GET", DecisionsEndpoint+"?robot_id=robot-9")
	h = DecisionHistory{}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &h) != nil || len(h.Robots) != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
	for target, want := range map[string]int{DecisionsEndpoint + "?limit=1": 400, DecisionsEndpoint + "?robot_id=a&robot_id=b": 400, DecisionsEndpoint + "?robot_id=%3Cb%3E": 400} {
		if w = get("GET", target); w.Code != want {
			t.Fatal(target, w.Code)
		}
	}
	if w = get("POST", DecisionsEndpoint); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w = get("HEAD", DecisionsEndpoint); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal(w.Code, w.Body.Len())
	}
	// not declared: the endpoint does not exist for this deployment
	plain, _ := fixture(t, provider("one", "robot-1", dep))
	w = httptest.NewRecorder()
	NewAPI(plain).Decisions(w, httptest.NewRequest("GET", DecisionsEndpoint, nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	NewAPI(nil).Decisions(w, httptest.NewRequest("GET", DecisionsEndpoint, nil))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
