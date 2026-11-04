// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/observability"
	"github.com/glowfly/pail/services/internal/signer"
)

// The fleet declares no signed event source: robots report by file, the
// ledger is the collector's own.
const decisionConfig = `{"schema_version":1,"source_map":{"schema_version":1,"source_id":"c68d3bdd-62b0-4721-9aec-9ea0d4ab0301","deployment_id":"5e8b24a0-2319-4a53-b5cf-a03afc977301","providers":[
 {"provider_id":"file-1","kind":"normalized_jsonl","expected_deployment_id":"5e8b24a0-2319-4a53-b5cf-a03afc977301","expected_robot_id":"robot-1","expected_identity":"robot-1","path_ref":"/observations/one/observation.jsonl","endpoint_ref":"","allowed_event_kinds":["gate","permit"],"expected_owner":"owner","expected_run_id":"c68d3bdd-62b0-4721-9aec-9ea0d4ab0302","expected_stream_id":"c68d3bdd-62b0-4721-9aec-9ea0d4ab0303","trust_basis":"local_self_report","role":"primary"},
 {"provider_id":"file-2","kind":"normalized_jsonl","expected_deployment_id":"5e8b24a0-2319-4a53-b5cf-a03afc977301","expected_robot_id":"robot-2","expected_identity":"robot-2","path_ref":"/observations/two/observation.jsonl","endpoint_ref":"","allowed_event_kinds":["gate","permit"],"expected_owner":"owner","expected_run_id":"c68d3bdd-62b0-4721-9aec-9ea0d4ab0302","expected_stream_id":"c68d3bdd-62b0-4721-9aec-9ea0d4ab0304","trust_basis":"local_self_report","role":"primary"},
 {"provider_id":"ledger","kind":"collector_ledger","expected_deployment_id":"","expected_robot_id":"","expected_identity":"","path_ref":"","endpoint_ref":"","allowed_event_kinds":["plan","ledger"],"expected_owner":"","expected_run_id":"","expected_stream_id":"","trust_basis":"collector_verified","role":"primary"}]}}`

// decisionLedger writes, through the production writer, a ledger in which
// every record has the same length, so that a byte offset names a record.
// Records 1..4 belong to robot-1, 5..8 to robot-2, 9 to a robot that is not
// declared, 10..12 to robot-1 again.
func decisionLedger(t *testing.T) (dir string, recordBytes int64) {
	t.Helper()
	bb := filepath.Join(t.TempDir(), "bb")
	if err := os.MkdirAll(bb, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := blackbox.OpenDir(bb, blackbox.Config{Signer: signer.NewLocal(&devcrypto.Keypair{Public: pub, Private: priv, KeyID: "k"}), IdleFlushAfter: -1})
	if err != nil {
		t.Fatal(err)
	}
	ms := uint64(1_700_000_000_000)
	length := -1
	put := func(robot, decision, reason string) {
		t.Helper()
		ms++
		// every record is a refusal of its own (another token): nothing is counted together
		b, _ := json.Marshal(map[string]any{"kind": "GATE_DECISION", "journal_v": 6, "robot_id": robot, "chain_id": "chain-0", "token_id": "token-" + string(rune('a'+int(ms%26))), "decision": decision, "reason_code": reason, "step_complete": false, "fatal": false, "chain_attributed": false, "unix_ms": ms})
		if length >= 0 && len(b) != length {
			t.Fatalf("record lengths differ: %d %d", length, len(b))
		}
		length = len(b)
		if err := w.Append(blackbox.RecordGateDecision, ms, b); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		put("robot-1", "BLOCK", "ERR_ZONE_A")
	}
	for i := 0; i < 4; i++ {
		put("robot-2", "BLOCK", "ERR_ZONE_B")
	}
	put("robot-9", "BLOCK", "ERR_ZONE_C")
	for i := 0; i < 3; i++ {
		put("robot-1", "ESTOP", "ERR_ZONE_D")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var first, second int64 = -1, -1
	if _, err := blackbox.WalkDir(bb, func(rec blackbox.Record) error {
		if rec.Type != blackbox.RecordGateDecision {
			return nil
		}
		if first < 0 {
			first = rec.Offset
		} else if second < 0 {
			second = rec.Offset
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if first < 0 || second <= first {
		t.Fatal("record offsets: ", first, second)
	}
	return bb, second - first
}

func readDecisions(t *testing.T, api *observability.API) (observability.DecisionHistory, string) {
	t.Helper()
	w := httptest.NewRecorder()
	api.Decisions(w, httptest.NewRequest("GET", observability.DecisionsEndpoint, nil))
	var h observability.DecisionHistory
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &h) != nil || len(h.Robots) != 2 {
		t.Fatal(w.Code, w.Body.String())
	}
	return h, w.Body.String()
}
func seqs(rows []observability.Decision) string {
	out := []string{}
	for _, d := range rows {
		out = append(out, d.Seq)
	}
	return strings.Join(out, ",")
}

// T12 through the real writer, the real verification walk and the HTTP
// answer. One byte of the ledger damaged: the history is no longer called
// verified and lists nothing at or beyond the damaged record.
func TestOpsviewDecisionHistoryEndToEnd(t *testing.T) {
	bb, size := decisionLedger(t)
	_, c, err := parseObservationConfig([]byte(decisionConfig))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := ledgerq.Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	api := observability.NewAPI(c)
	connectLedger(idx, c)
	var walks atomic.Int64
	walker := idx.ChainWalker
	idx.ChainWalker = func() ledgerq.ChainWalk { walks.Add(1); return walker() }
	if h, _ := readDecisions(t, api); h.LedgerVerified || h.ChainState != "VERIFYING" || len(h.Robots[0].Decisions) != 0 {
		t.Fatalf("%+v", h)
	}
	if cs, err := idx.IngestChain(bb, time.Now()); err != nil || cs.State != "ok" {
		t.Fatal(cs, err)
	}
	h, body := readDecisions(t, api)
	records, _ := idx.Stats()
	if !h.LedgerVerified || h.ChainState != "CHAIN_OK" || h.VerifiedThrough == "0" {
		t.Fatalf("%+v %+v", h, records)
	}
	one, two := h.Robots[0], h.Robots[1]
	if one.Key.RobotID != "robot-1" || two.Key.RobotID != "robot-2" || len(one.Decisions) != 7 || len(two.Decisions) != 4 {
		t.Fatal(body)
	}
	for _, d := range one.Decisions {
		if d.Kind != "GATE_DECISION" || (d.ReasonCode != "ERR_ZONE_A" && d.ReasonCode != "ERR_ZONE_D") || d.Attributed == nil || *d.Attributed {
			t.Fatalf("%+v", d)
		}
	}
	for _, d := range two.Decisions {
		if d.ReasonCode != "ERR_ZONE_B" || d.Decision != "BLOCK" {
			t.Fatalf("%+v", d)
		}
	}
	if strings.Contains(body, "robot-9") || strings.Contains(body, "ERR_ZONE_C") {
		t.Fatal("a record of an undeclared robot is listed: ", body)
	}
	whole := seqs(one.Decisions) + "|" + seqs(two.Decisions)

	// the first record of robot-2 is damaged by one byte
	seg := filepath.Join(bb, "pail_blackbox.00000001.seg")
	original, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	var offset int64 = -1
	n := 0
	if _, err := blackbox.WalkDir(bb, func(rec blackbox.Record) error {
		if rec.Type == blackbox.RecordGateDecision {
			if n++; n == 5 {
				offset = rec.Offset
			}
		}
		return nil
	}); err != nil || offset < 0 {
		t.Fatal(err, offset)
	}
	damaged := append([]byte{}, original...)
	damaged[offset+size/2] ^= 0x01
	if err := os.WriteFile(seg, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	if cs, err := idx.IngestChain(bb, time.Now()); err != nil || cs.State != "chain_error" {
		t.Fatal(cs, err)
	}
	h, body = readDecisions(t, api)
	if h.LedgerVerified || h.ChainState != "CHAIN_ERROR" || h.ErrorCode == "" {
		t.Fatal(body)
	}
	if len(h.Robots[1].Decisions) != 0 {
		t.Fatal("records at or beyond the damaged record are listed: ", body)
	}
	if got := seqs(h.Robots[0].Decisions); len(h.Robots[0].Decisions) != 4 || !strings.HasSuffix(whole, got+"|"+seqs(two.Decisions)) {
		t.Fatal(got, " of ", whole)
	}
	for _, d := range h.Robots[0].Decisions {
		if d.ReasonCode != "ERR_ZONE_A" {
			t.Fatalf("a record beyond the verified position is listed: %+v", d)
		}
	}

	// restored: the collector does not take the ledger back on its word; the
	// verdict is whatever the verification says, and the list follows it
	if err := os.WriteFile(seg, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cs, err := idx.IngestChain(bb, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h, body = readDecisions(t, api)
	if (cs.State == "ok") != h.LedgerVerified {
		t.Fatal(cs, body)
	}
	if cs.State == "ok" && seqs(h.Robots[0].Decisions)+"|"+seqs(h.Robots[1].Decisions) != whole {
		t.Fatal(body)
	}

	// a request reads memory: with the index closed and the ledger gone the
	// answer is the same and no walk starts
	before := walks.Load()
	if err := os.Rename(bb, bb+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := idx.Close(); err != nil {
		t.Fatal(err)
	}
	strip := func(s string) string {
		var m map[string]any
		json.Unmarshal([]byte(s), &m)
		delete(m, "generated_at_ms")
		delete(m, "verification_age_ms")
		b, _ := json.Marshal(m)
		return string(b)
	}
	for i := 0; i < 50; i++ {
		if _, again := readDecisions(t, api); strip(again) != strip(body) {
			t.Fatalf("request %d differs:\n%s\n%s", i, again, body)
		}
	}
	if walks.Load() != before {
		t.Fatalf("requests started %d ledger walks", walks.Load()-before)
	}
}

// The page and its new script are served; the endpoint is mounted.
func TestOpsviewDecisionAssets(t *testing.T) {
	w := httptest.NewRecorder()
	serveDashboard(w, httptest.NewRequest("GET", "/dashboard/status_ledger.js", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "javascript") || !strings.Contains(w.Body.String(), "PAIL_STATUS_LEDGER") {
		t.Fatal(w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	serveDashboard(w, httptest.NewRequest("GET", "/dashboard/", nil))
	if !strings.Contains(w.Body.String(), `src="status_ledger.js"`) || !strings.Contains(w.Body.String(), `id="ledger-decisions"`) {
		t.Fatal("status tab does not load the ledger decision table")
	}
}

var decisionScreenLedger = flag.String("opsview-decision-ledger", "", "directory that receives the ledger of the screen check (tests/tools/opsview_decisions_browser.py)")

// Not a test of the collector: it writes, through the production writer and
// with the present time, the ledger the screen check shows in a browser.
func TestOpsviewDecisionScreenLedger(t *testing.T) {
	if *decisionScreenLedger == "" {
		t.Skip("-opsview-decision-ledger not given")
	}
	if err := os.MkdirAll(*decisionScreenLedger, 0o755); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := blackbox.OpenDir(*decisionScreenLedger, blackbox.Config{Signer: signer.NewLocal(&devcrypto.Keypair{Public: pub, Private: priv, KeyID: "k"}), IdleFlushAfter: -1})
	if err != nil {
		t.Fatal(err)
	}
	ms := uint64(time.Now().UnixMilli()) - 60_000
	put := func(kind uint32, body map[string]any) {
		t.Helper()
		ms += 250
		body["unix_ms"] = ms
		b, _ := json.Marshal(body)
		if err := w.Append(kind, ms, b); err != nil {
			t.Fatal(err)
		}
	}
	gate := func(robot, chain, token, decision, reason string, complete, fatal bool) {
		put(blackbox.RecordGateDecision, map[string]any{"kind": "GATE_DECISION", "journal_v": 6, "robot_id": robot, "chain_id": chain, "token_id": token, "decision": decision, "reason_code": reason, "step_complete": complete, "fatal": fatal, "chain_attributed": true})
	}
	plan := func(robot, plan, chain string) {
		put(blackbox.RecordPlanAccepted, map[string]any{"kind": "PLAN_ACCEPTED", "v": 2, "robot_id": robot, "plan_id": plan, "chain_id": chain, "step_count": 1, "key_id": "k"})
		put(blackbox.RecordTokenIssued, map[string]any{"kind": "TOKEN_ISSUED", "journal_v": 8, "robot_id": robot, "plan_id": plan, "chain_id": chain, "token_id": chain + "-1", "sequence_index": 1, "step_id": "s"})
	}
	plan("robot-1", "plan-a", "chain-a")
	for i := 0; i < 40; i++ {
		gate("robot-1", "chain-a", "chain-a-1", "PERMIT", "OK", false, false)
	}
	gate("robot-1", "chain-a", "chain-a-1", "PERMIT", "OK", true, false)
	plan("robot-2", "plan-b", "chain-b")
	for i := 0; i < 12; i++ {
		gate("robot-2", "chain-b", "chain-b-1", "PERMIT", "OK", false, false)
	}
	gate("robot-2", "chain-b", "chain-b-1", "BLOCK", "ERR_SAFETY_STALE", false, false)
	gate("robot-2", "chain-b", "chain-b-1", "ESTOP", "ERR_SIGNATURE", false, true)
	put(blackbox.RecordSafeStop, map[string]any{"kind": "SAFE_STOP", "robot_id": "robot-2", "reason_code": "ERR_SIGNATURE", "forgery_count": 1, "state": "SAFE_STOP"})
	put(blackbox.RecordChainRevoked, map[string]any{"kind": "CHAIN_REVOKED", "trigger": "GATE_FATAL", "robot_id": "robot-2", "chain_id": "chain-b", "plan_id": "plan-b", "step_seq": 1, "reason_code": "ERR_SIGNATURE"})
	put(blackbox.RecordOperatorEvent, map[string]any{"kind": "UNLOCK", "accepted": true, "detail": "screen fixture", "operator_key_id": "op", "state": "NORMAL"})
	plan("robot-1", "plan-c", "chain-c")
	gate("robot-1", "chain-c", "chain-c-1", "PERMIT", "OK", false, false)
	put(blackbox.RecordChainRevoked, map[string]any{"kind": "CHAIN_CANCELLED", "trigger": "NORTHBOUND_CANCEL", "robot_id": "robot-1", "chain_id": "chain-c", "plan_id": "plan-c", "step_seq": 1})
	gate("robot-7", "chain-z", "chain-z-1", "BLOCK", "ERR_NOT_DECLARED", false, false)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(*decisionScreenLedger)
	for _, e := range entries {
		if err := os.Chmod(filepath.Join(*decisionScreenLedger, e.Name()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
