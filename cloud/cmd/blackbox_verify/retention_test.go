// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// G-EUC-01 (EC-1) — offline verifier side. The three policy answers are three
// words; the tests below give each word its own fixture so that folding any
// two together is seen by exactly one name (H-B9).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

const policyWithRetention = "human_safety:\n  enabled: true\nretention:\n  blackbox_years: 5\n  anchor_years: 7\n  lower_bound_years: 5\n"
const policyWithoutRetention = "human_safety:\n  enabled: true\n"

func shaOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sealRecord(t *testing.T, canonical string) record {
	t.Helper()
	ev, err := json.Marshal(map[string]any{"kind": "CONFIG_SEALED", "canonical": canonical})
	if err != nil {
		t.Fatal(err)
	}
	return record{recType: blackbox.RecordConfigSealed, payload: ev}
}

func TestRETV01_MatchedPolicyEvaluatesSegments(t *testing.T) {
	now := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	created := uint64(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	old := uint64(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli())
	rep, err := evaluateRetention(shaOf(policyWithRetention), []byte(policyWithRetention),
		[]segInfo{{Seq: 1, CreatedMs: old}, {Seq: 2, CreatedMs: created}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Policy != "matched" || rep.Retention != "declared" {
		t.Fatalf("policy=%s retention=%s", rep.Policy, rep.Retention)
	}
	if len(rep.Segments) != 2 || rep.Segments[0].State != "beyond" || rep.Segments[1].State != "within" {
		t.Fatalf("segments: %+v", rep.Segments)
	}
}

func TestRETV02_MismatchIsNotMatched(t *testing.T) {
	// A seal exists; the file in hand differs by one byte. The numbers in that
	// file must not be applied to this chain.
	other := policyWithRetention + "# edited after sealing\n"
	rep, err := evaluateRetention(shaOf(policyWithRetention), []byte(other), []segInfo{{Seq: 1, CreatedMs: 1}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Policy != "mismatched" {
		t.Fatalf("policy=%s — an edited file was read as the sealed one", rep.Policy)
	}
	if len(rep.Segments) != 0 || rep.Retention != "" {
		t.Fatalf("segments were evaluated under a mismatched policy: %+v", rep)
	}
	var out bytes.Buffer
	if rc := printRetention(&out, rep, 0); rc != 4 {
		t.Fatalf("rc=%d for mismatched, want 4\n%s", rc, out.String())
	}
}

func TestRETV03_UnsealedIsNotMatched(t *testing.T) {
	rep, err := evaluateRetention("", []byte(policyWithRetention), []segInfo{{Seq: 1, CreatedMs: 1}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Policy != "unsealed" || len(rep.Segments) != 0 {
		t.Fatalf("policy=%s segments=%d — no seal must not read as matched", rep.Policy, len(rep.Segments))
	}
	var out bytes.Buffer
	if rc := printRetention(&out, rep, 0); rc != 5 {
		t.Fatalf("rc=%d for unsealed, want 5\n%s", rc, out.String())
	}
}

func TestRETV04_MatchedButUndeclaredIsItsOwnWord(t *testing.T) {
	rep, err := evaluateRetention(shaOf(policyWithoutRetention), []byte(policyWithoutRetention), []segInfo{{Seq: 1, CreatedMs: 1}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Policy != "matched" || rep.Retention != "undeclared" || len(rep.Segments) != 0 {
		t.Fatalf("%+v — a sealed file without retention: must say undeclared, not within", rep)
	}
	var out bytes.Buffer
	printRetention(&out, rep, 0)
	if !strings.Contains(out.String(), "retention=undeclared") {
		t.Fatalf("output does not say undeclared:\n%s", out.String())
	}
}

func TestRETV05_NewestSealWinsAndUnreadableIsCounted(t *testing.T) {
	recs := []record{
		sealRecord(t, "pail-config-seal:v2\npolicy_file_sha256=aaaa\n"),
		{recType: blackbox.RecordConfigSealed, payload: []byte("not json")},
		sealRecord(t, "pail-config-seal:v2\npolicy_file_sha256=BBBB\n"),
		{recType: blackbox.RecordTokenIssued, payload: []byte(`{"policy_file_sha256":"cccc"}`)},
	}
	sha, skipped := sealedPolicySHA(recs)
	if sha != "bbbb" {
		t.Fatalf("sha=%q — want the newest CONFIG_SEALED hash, lower-cased", sha)
	}
	if skipped != 1 {
		t.Fatalf("skipped=%d — an unreadable seal must be counted, not folded into unsealed", skipped)
	}
	if sha, _ := sealedPolicySHA(recs[3:]); sha != "" {
		t.Fatalf("a non-seal record carrying the key name was read as a seal: %q", sha)
	}
}

// ---- EC-3 (G-EUC-03): class summary ---------------------------------------------

func TestIC04_ClassCountsKeepUnclassifiedApart(t *testing.T) {
	recs := []record{
		{recType: blackbox.RecordTokenIssued},
		{recType: blackbox.RecordPlanRejected},
		{recType: blackbox.RecordCheckpointV2},
		{recType: blackbox.RecordGateDecision},
		{recType: 99},
	}
	got := classCounts(recs)
	want := map[string]int{"legitimate": 1, "illegitimate": 1, "system": 1, "by_payload": 1, "unclassified": 1}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: got %d want %d (%v)", k, got[k], v, got)
		}
	}
	var out bytes.Buffer
	printClassCounts(&out, got)
	if !strings.Contains(out.String(), "unclassified=1") {
		t.Fatalf("summary must print the unclassified bucket: %s", out.String())
	}
}
