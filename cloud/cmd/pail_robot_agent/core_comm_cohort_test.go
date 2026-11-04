// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The guard alone: the first census decides startup; later censuses are a running fault.
func TestCohortGuardCensusClassification(t *testing.T) {
	var refusals []string
	g := &cohortGuard{refuse: func(e error) { refusals = append(refusals, e.Error()) }}
	g.censusAnswered(metadata.MD{}) // an Issuer older than the handshake: no header
	if len(refusals) != 1 || !strings.HasPrefix(refusals[0], "CORE_COMM_COHORT_MISMATCH") {
		t.Fatalf("first census without a v1 header must refuse startup (RefuseConfig adds the one prefix): %v", refusals)
	}
	g = &cohortGuard{refuse: func(e error) { refusals = append(refusals, e.Error()) }}
	g.censusAnswered(metadata.Pairs(cohortHeader, "v1"))
	if len(refusals) != 1 || g.mismatched() {
		t.Fatal("a matching Issuer must not refuse or fault")
	}
	g.censusAnswered(metadata.Pairs(cohortHeader, "legacy")) // the Issuer was rolled back while running (a pre-preview.40 release in its removed mode)
	if len(refusals) != 1 || !g.mismatched() {
		t.Fatal("a mismatch after the first census is a running fault, not a second startup refusal")
	}
	if g.rpcError(status.Error(codes.Unavailable, "dial")) || g.rpcError(nil) {
		t.Fatal("transport errors are not cohort mismatches")
	}
}

// The critical outbox's replay loop no longer discards delivery results: a report the Issuer cannot receive is
// logged (at most every 30 s) and, on a cohort mismatch, raises the fault.
func TestCriticalOutboxReplayFailureIsNotSilent(t *testing.T) {
	dir := t.TempDir()
	f := &legacyIssuerForC1{}
	q, err := newReportQueue(f, reportQueueOptions{RobotID: "robot-1", ReceiptVersion: 1, Dir: dir, RetryMax: time.Millisecond, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)
	r := coreFatal()
	if e := q.core.save(r); e != nil { // a pending critical report, as left by a crash before delivery
		t.Fatal(e)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (!q.cohort.mismatched() || f.received.Load() < 2) {
		time.Sleep(5 * time.Millisecond)
	}
	if !q.cohort.mismatched() {
		t.Fatal("a critical report the Issuer refuses as a cohort mismatch must enter the hold from the replay loop")
	}
	if !q.core.healthy() {
		t.Fatal("a cohort mismatch is a hold, not a storage fault (P37-M1)")
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "core-comm-critical", "*.pending")); len(files) != 1 {
		t.Fatalf("the pending critical report must be kept: %v", files)
	}
	if !strings.Contains(logs.String(), "CORE_COMM_COHORT_MISMATCH") {
		t.Fatalf("no warning: %s", logs.String())
	}
	_ = os.Remove
}
