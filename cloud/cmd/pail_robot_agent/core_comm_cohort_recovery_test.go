// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/glowfly/pail/services/proto/pailv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// lockedLog is a log sink the guard's workers write while the test reads (bytes.Buffer alone races).
type lockedLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func captureLog(t *testing.T) *lockedLog {
	t.Helper()
	logs := &lockedLog{}
	prev := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	return logs
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The transition in detail: the hold names itself on the authority path and in the probe state, the restore
// line is logged once with the other holds, and the storage fault is untouched.
func TestCohortHoldNamesItselfAndRestoresOnce(t *testing.T) {
	logs := captureLog(t)
	iss, tc := newCohortIssuer(t)
	q, m, p := cohortRig(t, tc, 0)
	wireCohortGuard(q, m, func(e error) { t.Fatalf("unexpected startup refusal: %v", e) })
	m.census()
	if s := reportStorageState(q); s != "LOCAL_DISK" {
		t.Fatalf("state before any mismatch: %s", s)
	}
	iss.set([]string{"legacy"}, 1, "OK")
	m.census()
	if err := authority(p); status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "CORE_COMM_COHORT_MISMATCH") {
		t.Fatalf("the hold must name itself: %v", err)
	}
	if s := reportStorageState(q); s != "COHORT_MISMATCH" {
		t.Fatalf("probe state during the hold: %s", s)
	}
	iss.set([]string{"v1"}, 1, "OK")
	m.census()
	if err := authority(p); err != nil {
		t.Fatal(err)
	}
	if s := reportStorageState(q); s != "LOCAL_DISK" {
		t.Fatalf("probe state after the restore: %s", s)
	}
	if n := strings.Count(logs.String(), "CORE_COMM_COHORT_RESTORED"); n != 1 {
		t.Fatalf("restore logged %d times: %s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "other holds: none") {
		t.Fatalf("the restore line must name the remaining holds: %s", logs.String())
	}
	if strings.Contains(logs.String(), "new authority is served") {
		t.Fatal("the restore line must not promise authority: other holds have their own rules")
	}
}

// A v1 answer that was in flight when a newer beacon connection was made belongs to the Issuer before the
// swap: it must not clear the hold the current connection established.
func TestLateV1AnswerFromOldConnectionDoesNotClear(t *testing.T) {
	logs := captureLog(t)
	iss, tc := newCohortIssuer(t)
	q, m, _ := cohortRig(t, tc, 0)
	wireCohortGuard(q, m, nil)
	m.census()
	iss.set([]string{"legacy"}, 1, "OK")
	m.census()
	if !q.cohort.mismatched() {
		t.Fatal("precondition: the hold must be in place")
	}
	gate, started := make(chan struct{}), make(chan struct{}, 1)
	iss.mu.Lock()
	iss.header, iss.gate, iss.started = []string{"v1"}, gate, started
	iss.mu.Unlock()
	done := make(chan struct{})
	go func() { m.census(); close(done) }()
	<-started         // the census is inside the Issuer
	m.noteReconnect() // a newer connection is made meanwhile
	close(gate)       // the old answer lands now
	<-done
	if !q.cohort.mismatched() {
		t.Fatal("a late v1 answer from an earlier connection must not clear the hold")
	}
	if !strings.Contains(logs.String(), "ignored for the cohort state") {
		t.Fatalf("the ignored answer must be logged: %s", logs.String())
	}
	iss.mu.Lock()
	iss.gate, iss.started = nil, nil
	iss.mu.Unlock()
	m.census() // the current connection's own answer clears it
	if q.cohort.mismatched() {
		t.Fatal("the current connection's v1 answer must clear the hold")
	}
}

// An answer below the seen epoch or without a verdict is not a verified census: it changes nothing.
func TestLowerEpochOrEmptyBodyDoesNotChangeCohort(t *testing.T) {
	logs := captureLog(t)
	iss, tc := newCohortIssuer(t)
	q, m, _ := cohortRig(t, tc, 0)
	wireCohortGuard(q, m, nil)
	iss.set([]string{"v1"}, 5, "OK")
	m.census() // epoch 5 seen
	iss.set([]string{"legacy"}, 5, "OK")
	m.census()
	if !q.cohort.mismatched() {
		t.Fatal("precondition: hold")
	}
	iss.set([]string{"v1"}, 3, "OK") // a regressed Issuer claiming v1
	m.census()
	if !q.cohort.mismatched() || strings.Contains(logs.String(), "CORE_COMM_COHORT_RESTORED") {
		t.Fatalf("a lower epoch must not clear the hold: %s", logs.String())
	}
	iss.set([]string{"v1"}, 5, "") // no verdict
	m.census()
	if !q.cohort.mismatched() {
		t.Fatal("an answer without a verdict must not clear the hold")
	}
	// the conservative direction on a bad answer is not taken either: clear, then a legacy header with no verdict
	iss.set([]string{"v1"}, 5, "OK")
	m.census()
	if q.cohort.mismatched() {
		t.Fatal("a verified v1 answer clears")
	}
	iss.set([]string{"legacy"}, 5, "")
	m.census()
	if q.cohort.mismatched() {
		t.Fatal("an unverified answer changes nothing — in either direction")
	}
	if !strings.Contains(logs.String(), "not applied to the cohort state") {
		t.Fatalf("unverified answers must be logged: %s", logs.String())
	}
}

// Report refusals and censuses race under -race; the state version only grows and the final verified answer wins.
func TestConcurrentRefusalAndCensus(t *testing.T) {
	iss, tc := newCohortIssuer(t)
	q, m, _ := cohortRig(t, tc, 0)
	wireCohortGuard(q, m, nil)
	m.census()
	iss.mu.Lock()
	iss.legacyC1 = true
	iss.mu.Unlock()
	for i := 0; i < 5; i++ {
		q.push(c1Report("obs-" + string(rune('a'+i))))
	}
	var wg sync.WaitGroup
	var versions []uint64
	var vmu sync.Mutex
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				iss.set([]string{"legacy"}, 1, "OK")
			} else {
				iss.set([]string{"v1"}, 1, "OK")
			}
			m.census()
			q.cohort.mu.Lock()
			v := q.cohort.version
			q.cohort.mu.Unlock()
			vmu.Lock()
			versions = append(versions, v)
			vmu.Unlock()
		}(i)
	}
	wg.Wait()
	waitFor(t, "a refused report", func() bool { return iss.reports.Load() > 0 })
	iss.mu.Lock()
	iss.legacyC1 = false
	iss.mu.Unlock()
	iss.set([]string{"v1"}, 1, "OK")
	m.census()
	// the version never moved backwards: every sampled value is <= the final one and the samples were produced
	// by monotone increments (a decrease would show as a later sample below an earlier maximum only if the lock
	// discipline were broken; -race covers the rest)
	q.cohort.mu.Lock()
	final := q.cohort.version
	q.cohort.mu.Unlock()
	for _, v := range versions {
		if v > final {
			t.Fatalf("version regressed: sample %d > final %d", v, final)
		}
	}
	if q.cohort.mismatched() {
		t.Fatal("the final verified v1 answer must clear the hold")
	}
}

// The storage fault stands until restart; a cohort restore names it and does not release authority.
func TestStorageFaultOutlivesCohortRestore(t *testing.T) {
	logs := captureLog(t)
	iss, tc := newCohortIssuer(t)
	q, m, p := cohortRig(t, tc, 0)
	wireCohortGuard(q, m, nil)
	m.census()
	q.core.raiseFault(errors.New("rejection quarantine full"))
	iss.set([]string{"legacy"}, 1, "OK")
	m.census()
	if s := reportStorageState(q); s != "FAULT" {
		t.Fatalf("the fault outranks the hold in the probe: %s", s)
	}
	iss.set([]string{"v1"}, 1, "OK")
	m.census()
	if q.cohort.mismatched() {
		t.Fatal("the hold clears")
	}
	if q.core.healthy() {
		t.Fatal("the storage fault must not be released by a cohort restore")
	}
	if err := authority(p); !strings.Contains(err.Error(), "CORE_REPORT_STORAGE_UNHEALTHY") {
		t.Fatalf("authority stays withheld by the fault: %v", err)
	}
	if !strings.Contains(logs.String(), "other holds: storage fault") {
		t.Fatalf("the restore line must name the storage fault: %s", logs.String())
	}
}

// The execution fence (restart pending) is another hold the restore leaves alone and names.
func TestExecutionFenceIsNotReleasedByRestore(t *testing.T) {
	logs := captureLog(t)
	iss, tc := newCohortIssuer(t)
	q, m, p := cohortRig(t, tc, 0)
	wireCohortGuard(q, m, nil)
	m.census()
	iss.set([]string{"legacy"}, 1, "OK")
	m.census()
	m.enableExecutionFence(false) // the Issuer never answers EXECUTION_RESET here: the fence stays
	iss.set([]string{"v1"}, 1, "OK")
	m.census()
	if q.cohort.mismatched() {
		t.Fatal("the hold clears")
	}
	if err := authority(p); !errors.Is(err, errExecutionPending) && status.Convert(err).Message() != "EXECUTION_RESTART_PENDING" {
		t.Fatalf("the execution fence must still withhold: %v", err)
	}
	if !strings.Contains(logs.String(), "other holds: execution restart pending") {
		t.Fatalf("the restore line must name the fence: %s", logs.String())
	}
}

// A census that both restores the cohort and ends the declared chain keeps ending the chain.
func TestEndedChainStaysEndedAcrossRestore(t *testing.T) {
	iss, tc := newCohortIssuer(t)
	q, m, _ := cohortRig(t, tc, time.Hour)
	wireCohortGuard(q, m, nil)
	m.setStream(true)
	m.census()
	iss.set([]string{"legacy"}, 1, "OK")
	m.census()
	m.mu.Lock()
	m.chainID, m.leaseMax, m.servingIdx = "chain-1", 1, 1
	m.lease = map[int32]*pb.SignedToken{1: {}}
	m.mu.Unlock()
	if !m.leaseHeld() {
		t.Fatal("precondition: a held window")
	}
	iss.set([]string{"v1"}, 1, censusChainEnded)
	m.census()
	if q.cohort.mismatched() {
		t.Fatal("the hold clears")
	}
	if m.leaseHeld() {
		t.Fatal("CHAIN_ENDED on the restoring census must still drop the window")
	}
}

// The warning is a timer: with no Issuer call at all it repeats every warnEvery.
func TestWarningRepeatsWithoutCalls(t *testing.T) {
	logs := captureLog(t)
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	stop := make(chan struct{})
	defer close(stop)
	g := &cohortGuard{warnEvery: 30 * time.Second, tick: time.Millisecond, clock: clock, stop: stop, held: func() (int, int) { return 2, 1 }}
	g.start()
	g.enter(errors.New("CORE_COMM_COHORT_MISMATCH: test"))
	count := func() int { return strings.Count(logs.String(), "CORE_COMM_COHORT_MISMATCH") }
	if count() != 1 {
		t.Fatalf("entering warns once: %d", count())
	}
	for i := 2; i <= 4; i++ {
		advance(30 * time.Second)
		want := i
		waitFor(t, "a timer warning", func() bool { return count() >= want })
		if count() != want {
			t.Fatalf("after %d periods: %d warnings", i-1, count())
		}
	}
	advance(10 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if count() != 4 {
		t.Fatalf("no warning inside a period: %d", count())
	}
	if !strings.Contains(logs.String(), "2 decision reports and 1 critical reports are held") {
		t.Fatalf("the timer warning counts the held reports: %s", logs.String())
	}
}

// The re-check worker re-declares the census with backoff 5,10,20,40,60 (scaled here) and stops when the hold clears.
func TestRecheckRetriesWithBackoffAndRecovers(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	var mu sync.Mutex
	var waits []time.Duration
	g := &cohortGuard{recheckBase: time.Millisecond, recheckMax: 4 * time.Millisecond, stop: stop}
	g.after = func(d time.Duration) <-chan time.Time {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}
	calls := 0
	g.recheck = func() {
		calls++
		if calls == 3 { // two transport failures (no state change), then the Issuer answers v1
			g.censusAnswered(metadata.Pairs(cohortHeader, "v1"))
		}
	}
	g.start()
	g.censusAnswered(metadata.Pairs(cohortHeader, "v1")) // first census fine
	g.censusAnswered(metadata.Pairs(cohortHeader, "legacy"))
	waitFor(t, "the recovery", func() bool { return !g.mismatched() })
	time.Sleep(5 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	want := []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond}
	if len(waits) != len(want) {
		t.Fatalf("waits=%v want %v", waits, want)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits=%v want %v", waits, want)
		}
	}
	g.mu.Lock()
	n := g.rechecks
	g.mu.Unlock()
	if n != 3 {
		t.Fatalf("rechecks=%d want 3", n)
	}
}

// Closing the report queue ends both workers.
func TestCohortWorkersStopWithQueue(t *testing.T) {
	_, tc := newCohortIssuer(t)
	q, m, _ := cohortRig(t, tc, 0)
	wireCohortGuard(q, m, nil)
	q.close()
	done := make(chan struct{})
	go func() { q.cohort.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the cohort workers did not stop with the queue")
	}
	q.close() // idempotent
}

// P37-N1: the refusal text carries the PAIL STARTUP REFUSED prefix once — RefuseConfig adds it, the guard does not.
func TestRefusalMessageHasOnePrefix(t *testing.T) {
	var refusals []string
	g := &cohortGuard{refuse: func(e error) { refusals = append(refusals, e.Error()) }}
	g.censusAnswered(metadata.MD{})
	if len(refusals) != 1 || !strings.HasPrefix(refusals[0], "CORE_COMM_COHORT_MISMATCH") || strings.Contains(refusals[0], "PAIL STARTUP REFUSED") {
		t.Fatalf("the guard's refusal must start with the code and carry no prefix of its own: %v", refusals)
	}
}

// Two or contradictory contract headers are not a v1 answer.
func TestDuplicateContractHeadersAreNotV1(t *testing.T) {
	iss, tc := newCohortIssuer(t)
	q, m, _ := cohortRig(t, tc, 0)
	wireCohortGuard(q, m, nil)
	m.census()
	iss.set([]string{"v1", "v1"}, 1, "OK")
	m.census()
	if !q.cohort.mismatched() {
		t.Fatal("two contract headers must not read as v1")
	}
}
