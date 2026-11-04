// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
)

// Fixtures are written with the real blackbox writer rather than hand-built
// bytes: a hand-built journal would let this test agree with itself while
// disagreeing with what the service actually writes.
func writeJournal(t *testing.T, recs []rec) string {
	t.Helper()
	dir := t.TempDir()
	kp, err := devcrypto.NewDevKeypair("uir-test-key")
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	w, err := blackbox.OpenDir(dir, blackbox.Config{Signer: signer.NewLocal(kp)})
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	for _, r := range recs {
		p, err := json.Marshal(r.payload)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := w.Append(r.typ, r.ms, p); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return dir
}

type rec struct {
	typ     uint32
	ms      uint64
	payload map[string]any
}

// gd builds a GATE_DECISION payload. Keys the caller does not set stay ABSENT
// rather than getting a zero value — the whole point of several assertions
// below is that an absent key and a present-but-false key are different facts.
func gd(ms uint64, kv map[string]any) rec {
	p := map[string]any{"kind": "GATE_DECISION", "journal_v": 6, "unix_ms": ms}
	for k, v := range kv {
		p[k] = v
	}
	return rec{typ: blackbox.RecordGateDecision, ms: ms, payload: p}
}

func observeDeny(ms uint64, chain, reason string) rec {
	return gd(ms, map[string]any{
		"decision": "BLOCK", "reason_code": reason, "chain_id": chain,
		"effective_mode": "observe", "chain_attributed": true, "step_complete": false,
	})
}

func observePermit(ms uint64, chain string) rec {
	return gd(ms, map[string]any{
		"decision": "PERMIT", "reason_code": "OK", "chain_id": chain,
		"effective_mode": "observe", "chain_attributed": true, "step_complete": false,
	})
}

func buildOK(t *testing.T, dir string) *report {
	t.Helper()
	rep, err := build(dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return rep
}

func observe(t *testing.T, rep *report) *modeStats {
	t.Helper()
	m := rep.Modes["observe"]
	if m == nil {
		t.Fatalf("no observe bucket; buckets=%v", rep.modeOrder)
	}
	return m
}

// A continuous stop is ONE interruption however many times the gate restated
// it. Ten denial records at 200ms are one episode, and the difference between
// 10 and 1 is exactly the difference between measuring the gate's decision
// frequency and measuring what the operator lived through.
func TestEpisodeIsNotTheRecordCount(t *testing.T) {
	var recs []rec
	for i := uint64(0); i < 10; i++ {
		recs = append(recs, observeDeny(1000+i*200, "chain-A", "ERR_SAFETY_STALE"))
	}
	m := observe(t, buildOK(t, writeJournal(t, recs)))
	if m.Denials != 10 {
		t.Fatalf("denials=%d, want 10", m.Denials)
	}
	if m.EpisodeN != 1 {
		t.Fatalf("episodes=%d, want 1 (a continuous stop is one interruption)", m.EpisodeN)
	}
	if m.ReasonRunN != 1 {
		t.Fatalf("reason runs=%d, want 1 (the reason never changed)", m.ReasonRunN)
	}
}

// A PERMIT between two denials means the robot moved in between: two separate
// interruptions, not one long one.
func TestPermitEndsAnEpisode(t *testing.T) {
	m := observe(t, buildOK(t, writeJournal(t, []rec{
		observeDeny(1000, "chain-A", "ERR_SAFETY_STALE"),
		observeDeny(1200, "chain-A", "ERR_SAFETY_STALE"),
		observePermit(1400, "chain-A"),
		observeDeny(1600, "chain-A", "ERR_SAFETY_STALE"),
	})))
	if m.EpisodeN != 2 {
		t.Fatalf("episodes=%d, want 2 (a PERMIT in between is motion)", m.EpisodeN)
	}
}

// A reason change inside one stop is one interruption to the operator and two
// causes to the engineer. Both counts are kept side by side; collapsing them
// into one number would hide which question the published rate answers.
func TestReasonChangeSplitsRunsButNotEpisodes(t *testing.T) {
	m := observe(t, buildOK(t, writeJournal(t, []rec{
		observeDeny(1000, "chain-A", "ERR_SAFETY_STALE"),
		observeDeny(1200, "chain-A", "ERR_SAFETY_STALE"),
		observeDeny(1400, "chain-A", "ERR_NO_EVIDENCE"),
		observeDeny(1600, "chain-A", "ERR_EXPIRED"),
	})))
	if m.EpisodeN != 1 {
		t.Fatalf("episodes=%d, want 1", m.EpisodeN)
	}
	if m.ReasonRunN != 3 {
		t.Fatalf("reason runs=%d, want 3", m.ReasonRunN)
	}
}

// Episodes are per action chain: two robots stopped at the same moment are two
// interruptions, and a chain boundary must not be crossed by a run.
func TestEpisodesDoNotSpanChains(t *testing.T) {
	m := observe(t, buildOK(t, writeJournal(t, []rec{
		observeDeny(1000, "chain-A", "ERR_SAFETY_STALE"),
		observeDeny(1100, "chain-B", "ERR_SAFETY_STALE"),
		observeDeny(1200, "chain-A", "ERR_SAFETY_STALE"),
		observeDeny(1300, "chain-B", "ERR_SAFETY_STALE"),
	})))
	if m.AttemptedActions != 2 {
		t.Fatalf("attempted actions=%d, want 2", m.AttemptedActions)
	}
	if m.EpisodeN != 2 {
		t.Fatalf("episodes=%d, want 2 (interleaved chains are not one run)", m.EpisodeN)
	}
}

// observe / enforce / absent are three buckets. Mixing them turns "what would
// have happened" into "what did happen" without any line saying so.
func TestModeBucketsAreNotMixed(t *testing.T) {
	// The observe bucket alone is 1 episode over 2 attempted actions = 0.500.
	// The two foreign records are shaped so that folding them in gives 3/4 =
	// 0.750 — a different number. An earlier draft of this test used counts
	// where mixing happened to produce the same value, so it would have passed
	// against a tool that mixed every bucket.
	rep := buildOK(t, writeJournal(t, []rec{
		observeDeny(1000, "chain-A", "ERR_SAFETY_STALE"),
		observePermit(1050, "chain-D"),
		gd(1100, map[string]any{"decision": "BLOCK", "reason_code": "ERR_EXPIRED",
			"chain_id": "chain-B", "effective_mode": "enforce", "chain_attributed": true}),
		gd(1200, map[string]any{"decision": "BLOCK", "reason_code": "ERR_EXPIRED",
			"chain_id": "chain-C", "chain_attributed": true}), // no effective_mode key
	}))
	if len(rep.Modes) != 3 {
		t.Fatalf("buckets=%d (%v), want 3", len(rep.Modes), rep.modeOrder)
	}
	if rep.Modes["enforce"] == nil || rep.Modes[modeUnknown] == nil {
		t.Fatalf("missing bucket: %v", rep.modeOrder)
	}
	if got := observe(t, rep).Records; got != 2 {
		t.Fatalf("observe records=%d, want 2 — other modes leaked in", got)
	}
	if rep.UIREpisodes == nil || *rep.UIREpisodes != 0.5 {
		t.Fatalf("uir=%v, want 0.500 over the observe bucket alone (mixing gives 0.750)", rep.UIREpisodes)
	}
}

// generated_server.go: an absent effective_mode is "a gate from before shadow
// mode", never enforce. Folding it into enforce would invent a declaration the
// gate never made.
func TestAbsentModeIsNotEnforce(t *testing.T) {
	rep := buildOK(t, writeJournal(t, []rec{
		gd(1000, map[string]any{"decision": "BLOCK", "reason_code": "ERR_EXPIRED",
			"chain_id": "chain-A", "chain_attributed": true}),
	}))
	if rep.Modes["enforce"] != nil {
		t.Fatal("an absent effective_mode was counted as enforce")
	}
	m := rep.Modes[modeUnknown]
	if m == nil || m.Records != 1 {
		t.Fatalf("unknown bucket=%v, want 1 record", m)
	}
}

// A denial the gate could not attribute to a chain has no denominator. Dropping
// it makes UIR look better — the dangerous direction — so it is counted into
// its own line and kept out of both numerator and denominator.
//
// The two unattributed records below are deliberately different shapes.
// generated_server.go refuses attribution on `!ok || c == nil || c.ChainID !=
// req.ChainId`, so a gate that names a stale or unknown chain produces
// chain_attributed=false with a NON-empty chain_id. An earlier version of this
// test used two empty-chain records only; the empty-string guard caught them
// both, so the chain_attributed judgment was never exercised and a deformation
// that ignored the flag entirely still passed.
func TestUnattributedDenialsAreSeparatedNotDropped(t *testing.T) {
	m := observe(t, buildOK(t, writeJournal(t, []rec{
		observeDeny(1000, "chain-A", "ERR_SAFETY_STALE"),
		gd(1100, map[string]any{"decision": "BLOCK", "reason_code": "ERR_NO_TOKEN",
			"chain_id": "", "effective_mode": "observe", "chain_attributed": false}),
		gd(1200, map[string]any{"decision": "BLOCK", "reason_code": "ERR_UNKNOWN_CHAIN",
			"chain_id": "chain-STALE", "effective_mode": "observe", "chain_attributed": false}),
	})))
	if m.UnattributedDenials != 2 {
		t.Fatalf("unattributed denials=%d, want 2", m.UnattributedDenials)
	}
	if m.Denials != 3 {
		t.Fatalf("denials=%d, want 3 — the unattributed ones must still be counted", m.Denials)
	}
	if m.AttemptedActions != 1 {
		t.Fatalf("attempted actions=%d, want 1 — an unattributed denial is not an action", m.AttemptedActions)
	}
	if m.EpisodeN != 1 {
		t.Fatalf("episodes=%d, want 1 — an unattributed denial has no chain to interrupt", m.EpisodeN)
	}
	if !strings.Contains(reportText(t, m), "귀속 불가 거부 2건") {
		t.Fatal("the report does not print the unattributed bucket; a silent drop reads as a better UIR")
	}
}

// A decision that names no chain is not an action, whatever it says about
// attribution. This is the one shape the empty-chain guard is alone in
// catching: chain_attributed absent (a gate from before shadow mode, which
// never answered the question) AND no chain_id. The current issuer cannot emit
// it, but this tool reads journals it did not write, and without the guard such
// a record would invent a nameless action in the denominator.
func TestChainlessDecisionIsNotAnAction(t *testing.T) {
	m := observe(t, buildOK(t, writeJournal(t, []rec{
		gd(1000, map[string]any{"decision": "BLOCK", "reason_code": "ERR_NO_TOKEN",
			"chain_id": "", "effective_mode": "observe"}), // no chain_attributed key
	})))
	if m.AttemptedActions != 0 {
		t.Fatalf("attempted actions=%d, want 0 — the record names no chain", m.AttemptedActions)
	}
	if m.EpisodeN != 0 {
		t.Fatalf("episodes=%d, want 0", m.EpisodeN)
	}
	if m.UnattributedDenials != 1 {
		t.Fatalf("unattributed denials=%d, want 1 — it must still be counted somewhere", m.UnattributedDenials)
	}
}

// An empty chain_id and a named-but-unattributable chain are two different
// refusals in generated_server.go and must not rest on one guard: if only the
// empty-string check did the work, a gate reporting a stale chain would have
// its denials folded into a real action's episode count.
func TestNamedButUnattributableChainIsNotAnAction(t *testing.T) {
	m := observe(t, buildOK(t, writeJournal(t, []rec{
		gd(1000, map[string]any{"decision": "BLOCK", "reason_code": "ERR_UNKNOWN_CHAIN",
			"chain_id": "chain-STALE", "effective_mode": "observe", "chain_attributed": false}),
	})))
	if m.AttemptedActions != 0 {
		t.Fatalf("attempted actions=%d, want 0 — the issuer could not attribute this chain", m.AttemptedActions)
	}
	if m.EpisodeN != 0 {
		t.Fatalf("episodes=%d, want 0", m.EpisodeN)
	}
	if m.UnattributedDenials != 1 {
		t.Fatalf("unattributed denials=%d, want 1", m.UnattributedDenials)
	}
}

func reportText(t *testing.T, m *modeStats) string {
	t.Helper()
	r := &report{Dir: "x", Modes: map[string]*modeStats{m.Mode: m}, modeOrder: []string{m.Mode}}
	r.computeRate()
	return r.text()
}

// implementation contract: no-token traffic in observe mode is entirely would-BLOCK, so
// a rate over it is worthless. The tool must say the rate is unavailable rather
// than print a number.
func TestNoObserveRecordsWithholdsTheRate(t *testing.T) {
	rep := buildOK(t, writeJournal(t, []rec{
		gd(1000, map[string]any{"decision": "BLOCK", "reason_code": "ERR_EXPIRED",
			"chain_id": "chain-A", "effective_mode": "enforce", "chain_attributed": true}),
	}))
	if rep.UIREpisodes != nil {
		t.Fatalf("a rate was emitted with no observe records: %v", *rep.UIREpisodes)
	}
	if rep.Incomputable == "" {
		t.Fatal("no reason given for the missing rate — silence reads as zero")
	}
	if !strings.Contains(rep.text(), "산출 불가") {
		t.Fatal("the text report does not mark the rate as unavailable")
	}
}

// Measured on deploy/.blackbox-m9: step_complete=true is 0 for every chain, so
// "interruptions per completed action" divides by zero. The tool states that
// instead of quietly falling back to another denominator.
func TestZeroCompletedActionsIsStatedNotSubstituted(t *testing.T) {
	rep := buildOK(t, writeJournal(t, []rec{
		observeDeny(1000, "chain-A", "ERR_SAFETY_STALE"),
	}))
	m := observe(t, rep)
	if m.CompletedActions != 0 {
		t.Fatalf("completed actions=%d, want 0", m.CompletedActions)
	}
	if !strings.Contains(rep.text(), "issuer-accepted completion = 0") {
		t.Fatal("the report is silent about the unusable denominator")
	}
}

func TestCompletedActionsCounted(t *testing.T) {
	rep := buildOK(t, writeJournal(t, []rec{
		observeDeny(1000, "chain-A", "ERR_SAFETY_STALE"),
		gd(1200, map[string]any{"decision": "PERMIT", "reason_code": "OK", "chain_id": "chain-A",
			"effective_mode": "observe", "chain_attributed": true, "step_complete": true, "journal_v": 10, "completion_result": "accepted", "completion_reason": "COMPLETION_SIGNAL_MATCHED", "consumed_sequence_index": 1, "next_expected_index": 2, "lease_reported_at_after": 0}),
	}))
	if got := observe(t, rep).CompletedActions; got != 1 {
		t.Fatalf("completed actions=%d, want 1", got)
	}
}

// A journal whose hash chain does not verify has no rate. The tool must fail
// before emitting counts, not emit counts from the part it managed to read.
func TestTamperedJournalEmitsNoCounts(t *testing.T) {
	dir := writeJournal(t, []rec{
		observeDeny(1000, "chain-A", "ERR_SAFETY_STALE"),
		observeDeny(1200, "chain-A", "ERR_SAFETY_STALE"),
	})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var seg string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".seg") {
			seg = filepath.Join(dir, e.Name())
		}
	}
	if seg == "" {
		t.Fatal("no segment written")
	}
	data, err := os.ReadFile(seg)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	data[56+20] ^= 0x01 // first payload byte of the first record
	if err := os.WriteFile(seg, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if rep, err := build(dir); err == nil {
		t.Fatalf("a tampered journal produced a report: gate decisions=%d", rep.GateDecisions)
	}
}

// An unknown argument must be refused before anything is read. Two tools in
// this repo have already started long tree-modifying runs from an argument they
// did not recognise.
func TestUnknownArgumentIsRefused(t *testing.T) {
	if err := validateArgs([]string{"--list"}, "/tmp/x"); err == nil {
		t.Fatal("an unrecognised argument was accepted")
	}
	if err := validateArgs(nil, ""); err == nil {
		t.Fatal("a missing -dir was accepted")
	}
	if err := validateArgs(nil, "/tmp/x"); err != nil {
		t.Fatalf("a well-formed invocation was refused: %v", err)
	}
}

// A GATE_DECISION this tool cannot parse is neither a permit nor a denial.
// Skipping it would shrink both numerator and denominator silently.
func TestUnparseableGateDecisionIsRefused(t *testing.T) {
	dir := t.TempDir()
	kp, err := devcrypto.NewDevKeypair("uir-test-key")
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	w, err := blackbox.OpenDir(dir, blackbox.Config{Signer: signer.NewLocal(kp)})
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	if err := w.Append(blackbox.RecordGateDecision, 1000, []byte("{not json")); err != nil {
		t.Fatalf("append: %v", err)
	}
	w.Close()
	if _, err := build(dir); err == nil {
		t.Fatal("an unparseable GATE_DECISION was absorbed instead of refused")
	}
}
