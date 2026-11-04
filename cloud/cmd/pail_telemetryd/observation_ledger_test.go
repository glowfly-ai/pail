// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/ledgerq"
	"github.com/glowfly/pail/services/internal/observability"
	"github.com/glowfly/pail/services/internal/signer"
)

const ledgerConfig = `{"schema_version":1,"source_map":{"schema_version":1,"source_id":"c68d3bdd-62b0-4721-9aec-9ea0d4ab0301","deployment_id":"5e8b24a0-2319-4a53-b5cf-a03afc977301","providers":[
 {"provider_id":"burst-1","kind":"legacy_burst","expected_deployment_id":"5e8b24a0-2319-4a53-b5cf-a03afc977301","expected_robot_id":"robot-1","expected_identity":"device-1","path_ref":"","endpoint_ref":"","allowed_event_kinds":["gate"],"expected_owner":"","expected_run_id":"","expected_stream_id":"","trust_basis":"verified_signature","role":"primary"},
 {"provider_id":"burst-2","kind":"legacy_burst","expected_deployment_id":"5e8b24a0-2319-4a53-b5cf-a03afc977301","expected_robot_id":"robot-2","expected_identity":"device-2","path_ref":"","endpoint_ref":"","allowed_event_kinds":["gate"],"expected_owner":"","expected_run_id":"","expected_stream_id":"","trust_basis":"verified_signature","role":"primary"},
 {"provider_id":"ledger","kind":"collector_ledger","expected_deployment_id":"","expected_robot_id":"","expected_identity":"","path_ref":"","endpoint_ref":"","allowed_event_kinds":["plan","ledger"],"expected_owner":"","expected_run_id":"","expected_stream_id":"","trust_basis":"collector_verified","role":"primary"}]}}`

// issuerLedger writes, through the production writer, what the issuer writes
// for: robot-1 a two-step plan run to its end; robot-2 a plan accepted, one
// step done, then cancelled, then a refused submission.
func issuerLedger(t *testing.T) string {
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
	put := func(kind uint32, body map[string]any) {
		t.Helper()
		ms++
		body["unix_ms"] = ms
		b, _ := json.Marshal(body)
		if err := w.Append(kind, ms, b); err != nil {
			t.Fatal(err)
		}
	}
	plan := func(robot, plan, chain string, steps int) {
		put(blackbox.RecordPlanAccepted, map[string]any{"kind": "PLAN_ACCEPTED", "v": 2, "robot_id": robot, "plan_id": plan, "chain_id": chain, "step_count": steps, "key_id": "k"})
		for i := 1; i <= steps; i++ {
			put(blackbox.RecordTokenIssued, map[string]any{"kind": "TOKEN_ISSUED", "journal_v": 8, "robot_id": robot, "plan_id": plan, "chain_id": chain, "token_id": chain + "-" + string(rune('0'+i)), "sequence_index": i, "step_id": "s"})
		}
	}
	done := func(robot, chain string, i int) {
		put(blackbox.RecordGateDecision, map[string]any{"kind": "GATE_DECISION", "journal_v": 10, "completion_result": "accepted", "completion_reason": "COMPLETION_SIGNAL_MATCHED", "consumed_sequence_index": i, "next_expected_index": i + 1, "lease_reported_at_after": 0, "robot_id": robot, "chain_id": chain, "token_id": chain + "-" + string(rune('0'+i)), "decision": "PERMIT", "reason_code": "", "step_complete": true, "fatal": false, "chain_attributed": true})
	}
	plan("robot-1", "plan-a", "chain-a", 2)
	plan("robot-2", "plan-b", "chain-b", 3)
	done("robot-1", "chain-a", 1)
	done("robot-2", "chain-b", 1)
	done("robot-1", "chain-a", 2)
	put(blackbox.RecordChainRevoked, map[string]any{"kind": "CHAIN_CANCELLED", "trigger": "NORTHBOUND_CANCEL", "robot_id": "robot-2", "chain_id": "chain-b", "plan_id": "plan-b", "step_seq": 2})
	if err := w.Append(blackbox.RecordChainRevoked, ms+1, []byte("ERR_BARE_STRING")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return bb
}

type ledgerView struct {
	Robots []struct {
		Key     observability.RobotKey `json:"robot_key"`
		Sources []struct {
			ProviderID string                         `json:"provider_id"`
			Health     string                         `json:"health"`
			Facets     map[string]observability.Facet `json:"facets"`
		} `json:"sources"`
	} `json:"robots"`
}

// ledgerHealth is the health of the ledger source in the last answer read.
var ledgerHealth string

func readLedgerView(t *testing.T, api *observability.API) (map[string]map[string]observability.Facet, string) {
	t.Helper()
	w := httptest.NewRecorder()
	api.Robots(w, httptest.NewRequest("GET", "/v2/observation/robots", nil))
	var v ledgerView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	out := map[string]map[string]observability.Facet{}
	for _, r := range v.Robots {
		for _, s := range r.Sources {
			if s.ProviderID == "ledger" {
				out[r.Key.RobotID] = s.Facets
				ledgerHealth = s.Health
			}
		}
	}
	if len(out) != 2 {
		t.Fatal("ledger source rows: ", w.Body.String())
	}
	return out, w.Body.String()
}

// T01 T04, through the real writer, the real verification walk and the HTTP
// answer; and §5.5: a request reads memory, not the index and not the ledger.
func TestOpsviewLedgerSourceEndToEnd(t *testing.T) {
	bb := issuerLedger(t)
	_, c, err := parseObservationConfig([]byte(ledgerConfig))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := ledgerq.Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	api := observability.NewAPI(c)
	if v, _ := readLedgerView(t, api); v["robot-1"]["ledger"].Reason != "INDEX_UNAVAILABLE" {
		t.Fatalf("%+v", v["robot-1"]["ledger"])
	}
	connectLedger(idx, c)
	var walks atomic.Int64
	walker := idx.ChainWalker
	idx.ChainWalker = func() ledgerq.ChainWalk { walks.Add(1); return walker() }
	if v, _ := readLedgerView(t, api); v["robot-1"]["ledger"].Value.State != "VERIFYING" || v["robot-1"]["plan"].Value.State != "UNKNOWN" {
		t.Fatalf("%+v", v["robot-1"])
	}
	if cs, err := idx.IngestChain(bb, time.Now()); err != nil || cs.State != "ok" {
		t.Fatal(cs, err)
	}
	v, body := readLedgerView(t, api)
	one, two := v["robot-1"], v["robot-2"]
	if f := one["plan"]; f.Value.State != "COMPLETED" || f.Plan.PlanID != "plan-a" || f.Plan.ChainID != "chain-a" || *f.Plan.StepsTotal != 2 || f.Plan.StepsIssued != 2 || f.Plan.StepsCompleted != 2 || f.Quality != "FRESH" || f.Trust != "collector_verified" || f.FreshnessBasis != "verified_frontier" {
		t.Fatalf("%+v %+v", f, f.Plan)
	}
	if f := two["plan"]; f.Value.State != "CANCELLED" || f.Plan.EndedBy != "CHAIN_CANCELLED" || *f.Plan.StepsTotal != 3 || f.Plan.StepsCompleted != 1 || f.Plan.RecordSeq != "11" {
		t.Fatalf("%+v %+v", f, f.Plan)
	}
	// twelve records (the last names no robot); one ledger for the deployment:
	// the chain state is the same on every row
	if a, b := one["ledger"], two["ledger"]; a.Value.State != "CHAIN_OK" || b.Value.State != "CHAIN_OK" || a.Ledger.VerifiedThrough != "12" || b.Ledger.VerifiedThrough != "12" || a.Ledger.LastRecord.Seq != "10" || a.Ledger.LastRecord.Kind != "GATE_DECISION" || b.Ledger.LastRecord.Seq != "11" || b.Ledger.LastRecord.Kind != "CHAIN_CANCELLED" || b.Ledger.LastRecord.MS != 1_700_000_000_011 {
		t.Fatalf("%+v %+v", a.Ledger.LastRecord, b.Ledger.LastRecord)
	}

	// §5.5: with the index closed and the ledger gone, requests answer the same.
	before := walks.Load()
	moved := bb + ".moved"
	if err := os.Rename(bb, moved); err != nil {
		t.Fatal(err)
	}
	if err := idx.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		_, again := readLedgerView(t, api)
		var a, b map[string]any
		json.Unmarshal([]byte(body), &a)
		json.Unmarshal([]byte(again), &b)
		for _, m := range []map[string]any{a, b} {
			for _, k := range []string{"generated_at_ms", "as_of_ms", "served_at_ms", "snapshot_age_ms"} {
				delete(m, k)
			}
		}
		x, _ := json.Marshal(stripAges(a))
		y, _ := json.Marshal(stripAges(b))
		if string(x) != string(y) {
			t.Fatalf("request %d differs:\n%s\n%s", i, x, y)
		}
	}
	if walks.Load() != before || before != 1 {
		t.Fatalf("requests started %d ledger walks", walks.Load()-before)
	}
}

func stripAges(v any) any {
	switch x := v.(type) {
	case map[string]any:
		delete(x, "age_ms")
		for k := range x {
			x[k] = stripAges(x[k])
		}
	case []any:
		for i := range x {
			x[i] = stripAges(x[i])
		}
	}
	return v
}

// T04: a damaged ledger is CHAIN_ERROR on every row and no plan is stated;
// a ledger that is not there is ABSENT.
func TestOpsviewLedgerSourceDamagedAndAbsent(t *testing.T) {
	bb := issuerLedger(t)
	_, c, err := parseObservationConfig([]byte(ledgerConfig))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := ledgerq.Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	connectLedger(idx, c)
	api := observability.NewAPI(c)
	if _, err := idx.IngestChain(bb, time.Now()); err != nil {
		t.Fatal(err)
	}
	if v, _ := readLedgerView(t, api); v["robot-1"]["plan"].Value.State != "COMPLETED" {
		t.Fatal(v["robot-1"]["plan"])
	}
	seg := filepath.Join(bb, "pail_blackbox.00000001.seg")
	b, _ := os.ReadFile(seg)
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(seg, b, 0600); err != nil {
		t.Fatal(err)
	}
	if cs, err := idx.IngestChain(bb, time.Now()); err != nil || cs.State != "chain_error" {
		t.Fatal(cs, err)
	}
	v, _ := readLedgerView(t, api)
	for _, robot := range []string{"robot-1", "robot-2"} {
		f := v[robot]["ledger"]
		if f.Value.State != "CHAIN_ERROR" || f.Quality != "UNKNOWN" || f.Reason != "CHAIN_ERROR" {
			t.Fatalf("%s %+v %+v", robot, f, f.Ledger)
		}
		// the fault is named by the index's closed code
		if code := f.Ledger.ErrorCode; code != "RECORD_HASH_MISMATCH" && code != "PREVIOUS_HASH_MISMATCH" && code != "CHAIN_FORMAT_ERROR" {
			t.Fatal(code)
		}
		if f := v[robot]["plan"]; f.Value.State != "UNKNOWN" || f.Quality != "UNKNOWN" || f.Reason != "CHAIN_ERROR" || f.Plan != nil {
			t.Fatalf("%s %+v", robot, f)
		}
	}
	if cs, err := idx.IngestChain(filepath.Join(bb, "none"), time.Now()); err != nil || cs.State != "absent" {
		t.Fatal(cs, err)
	}
	v, _ = readLedgerView(t, api)
	if f := v["robot-1"]["ledger"]; f.Value.State != "ABSENT" || f.Reason != "ABSENT" || f.Ledger.ErrorCode != "SOURCE_ABSENT" {
		t.Fatalf("%+v %+v", f, f.Ledger)
	}
	if f := v["robot-1"]["plan"]; f.Value.State != "UNKNOWN" || f.Plan != nil {
		t.Fatalf("%+v", f)
	}
}

// Without an index the source says so; without the declaration nothing is bound.
func TestOpsviewLedgerSourceBinding(t *testing.T) {
	_, c, err := parseObservationConfig([]byte(ledgerConfig))
	if err != nil {
		t.Fatal(err)
	}
	connectLedger(nil, c)
	v, _ := readLedgerView(t, observability.NewAPI(c))
	if ledgerHealth != "INDEX_UNAVAILABLE" {
		t.Fatal(ledgerHealth)
	}
	for _, kind := range []string{"plan", "ledger"} {
		if f := v["robot-1"][kind]; f.Value != nil || f.Quality != "UNKNOWN" || f.Reason != "INDEX_UNAVAILABLE" {
			t.Fatalf("%+v", f)
		}
	}
	_, plain, err := parseObservationConfig([]byte(`{"schema_version":1,"source_map":{"schema_version":1,"source_id":"c68d3bdd-62b0-4721-9aec-9ea0d4ab0301","deployment_id":"","providers":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := ledgerq.Open(filepath.Join(t.TempDir(), "ledger.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	connectLedger(idx, plain)
	connectLedger(idx, nil)
	if idx.ChainWalker != nil {
		t.Fatal("a source map without the ledger source bound the walk")
	}
	// T05 at the configuration file: a self-report source may not declare the ledger
	refused := `{"schema_version":1,"source_map":{"schema_version":1,"source_id":"c68d3bdd-62b0-4721-9aec-9ea0d4ab0301","deployment_id":"","providers":[{"provider_id":"one","kind":"normalized_jsonl","expected_deployment_id":"","expected_robot_id":"robot-1","expected_identity":"device-1","path_ref":"/state/one.jsonl","endpoint_ref":"","allowed_event_kinds":["gate","ledger"],"expected_owner":"actor","expected_run_id":"5e8b24a0-2319-4a53-b5cf-a03afc977301","expected_stream_id":"ec054792-0db0-4162-83c1-ce2b7c401782","trust_basis":"local_self_report","role":"primary"}]}}`
	if _, _, err := parseObservationConfig([]byte(refused)); err == nil || err.Error() != "SOURCE_MAP_VERIFIED_PROVIDER_REQUIRED" {
		t.Fatal(err)
	}
}

// §5.5: when the index cannot publish a pass, the columns say so; the reading
// of the pass before is not shown as the present one.
func TestOpsviewLedgerSourceIndexCannotPublish(t *testing.T) {
	bb := issuerLedger(t)
	_, c, err := parseObservationConfig([]byte(ledgerConfig))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	idx, err := ledgerq.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	connectLedger(idx, c)
	api := observability.NewAPI(c)
	if _, err := idx.IngestChain(bb, time.Now()); err != nil {
		t.Fatal(err)
	}
	if v, _ := readLedgerView(t, api); v["robot-1"]["plan"].Value.State != "COMPLETED" || ledgerHealth != "CONNECTED" {
		t.Fatal(v["robot-1"]["plan"], ledgerHealth)
	}
	raw, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Exec("UPDATE meta SET value='broken JSON' WHERE key='chain_trusted_frontier'"); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if _, err := idx.IngestChain(bb, time.Now()); err == nil {
		t.Fatal("the pass was published")
	}
	v, _ := readLedgerView(t, api)
	for _, robot := range []string{"robot-1", "robot-2"} {
		for _, kind := range []string{"plan", "ledger"} {
			if f := v[robot][kind]; f.Value != nil || f.Plan != nil || f.Ledger != nil || f.Quality != "UNKNOWN" || f.Reason != "INDEX_UNAVAILABLE" {
				t.Fatalf("%s %s %+v", robot, kind, f)
			}
		}
	}
	if ledgerHealth != "INDEX_UNAVAILABLE" {
		t.Fatal(ledgerHealth)
	}
}
