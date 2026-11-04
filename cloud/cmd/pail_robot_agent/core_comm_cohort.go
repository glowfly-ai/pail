// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// C1 cohort handshake (preview.36 hardware evaluation P36-M1; recovery model preview.38, P37-M1/L1/N1).
//
// A robot agent on the v1 contract against an Issuer that refused C1 reports started and moved normally while every
// decision report — the E-STOP included — stayed in its queue: the Issuer refused each C1 report with
// FailedPrecondition, the queue retried the head as a transport error, the critical outbox retried silently, and
// the census kept declaring last_consumed=0 so the Issuer retracted the lease window. Nothing told the operator.
//
// The Issuer answers every census with the response header `pail-core-comm-contract` (v1; absent on an Issuer
// older than the handshake). The agent reads it: a mismatch on the first successful census is a
// configuration refusal (exit 78, like every other PAIL startup refusal); a mismatch while running (the Issuer was
// replaced or rolled back) is a *cohort hold*: new authority is withheld (tokenProxy.GetActiveToken answers
// CORE_COMM_COHORT_MISMATCH), the health probe reports COHORT_MISMATCH, a warning repeats every 30 s with the number
// of reports held — from a timer, so it repeats even when nothing calls the Issuer — and the guard re-declares the
// census with a 5 s → 60 s backoff until the Issuer answers v1 again. Reports are never downgraded to the C0
// wire (the specification forbids a fabricated confirmation) and never dropped: they stay in the durable queue and
// the critical outbox until the cohort matches. Since 0.2.0-preview.40 the contract is v1 only: this guard is the
// version check against an older or downgraded Issuer, not a mode switch.
//
// The cohort hold is a separate state from the critical storage fault (coreOutbox.fault): the storage fault stands
// until restart by design, the cohort hold clears itself. The hold changes only on a *verified* census answer —
// lease.go applies the header after the body, the epoch and the call/connection generation were checked — or on
// the Issuer's FailedPrecondition refusal of a C1 report. A late answer from an earlier connection or a lower epoch
// never clears it.
const cohortHeader = "pail-core-comm-contract"

// cohortMismatchMsg is the Issuer's FailedPrecondition text for a C1 report it cannot receive (core_comm.go).
const cohortMismatchMsg = "core-comm receipt version unsupported"

const (
	cohortWarnEvery   = 30 * time.Second
	cohortRecheckBase = 5 * time.Second
	cohortRecheckMax  = 60 * time.Second
)

type cohortGuard struct {
	refuse func(error) // startup refusal; deploysec.RefuseConfig in main (it adds the "PAIL STARTUP REFUSED:" prefix itself), a recorder in tests
	held   func() (queued, criticalPending int)
	// recheck re-declares the census while the cohort is mismatched (main: tokenMirror.census). nil = no re-check worker.
	recheck func()
	// otherHolds names the holds that are not this guard's (storage fault, execution fence, ...) for the restore log.
	otherHolds func() []string
	// stop ends the two workers (the report queue's close signal).
	stop <-chan struct{}

	// test hooks (zero = production values)
	warnEvery, tick, recheckBase, recheckMax time.Duration
	clock                                    func() time.Time
	after                                    func(time.Duration) <-chan time.Time

	mu       sync.Mutex
	checked  bool   // a census has been answered at least once
	issuer   string // last header value seen ("" = none)
	mismatch bool
	version  uint64 // bumps on every state change; the restore log and tests read it
	since    time.Time
	nextWarn time.Time
	lastErr  error
	refused  int
	restored int
	rechecks int
	wake     chan struct{}
	workers  sync.WaitGroup
}

func (g *cohortGuard) now() time.Time {
	if g.clock != nil {
		return g.clock()
	}
	return time.Now()
}

func (g *cohortGuard) warnPeriod() time.Duration {
	if g.warnEvery > 0 {
		return g.warnEvery
	}
	return cohortWarnEvery
}

// censusAnswered classifies the Issuer's contract header of a successful, verified census (body, epoch and
// generation checked by the caller). It may enter the hold and may clear it.
func (g *cohortGuard) censusAnswered(md metadata.MD) { g.apply(md, true) }

// censusAnsweredStale classifies the header of a census whose answer landed after a newer connection or
// generation decided: it may still enter the hold (the conservative direction) but never clears it.
func (g *cohortGuard) censusAnsweredStale(md metadata.MD) { g.apply(md, false) }

func (g *cohortGuard) apply(md metadata.MD, mayClear bool) {
	if g == nil {
		return
	}
	vals := md.Get(cohortHeader)
	v := strings.Join(vals, ",")
	g.mu.Lock()
	first := !g.checked
	g.checked = true
	g.issuer = v
	g.mu.Unlock()
	if len(vals) == 1 && v == "v1" {
		if mayClear {
			g.clear()
		} else {
			log.Printf("robot-agent: census answer from an earlier connection or generation carried contract=v1 — ignored for the cohort state (the current connection decides)")
		}
		return
	}
	shown := v
	switch {
	case len(vals) == 0:
		shown = "no contract header (an Issuer older than the v1 handshake)"
	case len(vals) > 1:
		shown = fmt.Sprintf("%d contract headers (%s) — not a v1 answer", len(vals), v)
	}
	err := fmt.Errorf("CORE_COMM_COHORT_MISMATCH: this agent runs the v1 contract and the Issuer answered %s; upgrade the Issuer to a release with the v1 handshake and start it first", shown)
	if first {
		g.mu.Lock()
		g.refused++
		g.mu.Unlock()
		if g.refuse != nil {
			g.refuse(err) // does not return in production (RefuseConfig prints the one PAIL STARTUP REFUSED prefix)
		}
		return
	}
	g.enter(err)
}

// rpcError recognises an Issuer's refusal of a C1 report (an Issuer without C1) and enters the running hold.
// It returns true when the error was a cohort mismatch (the caller then keeps the report and backs off).
func (g *cohortGuard) rpcError(err error) bool {
	if g == nil || err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), cohortMismatchMsg) {
		return false
	}
	g.enter(fmt.Errorf("CORE_COMM_COHORT_MISMATCH: the Issuer refuses C1 reports (%s)", st.Message()))
	return true
}

// enter records the mismatch (state under the lock, logging outside it) and wakes the re-check worker.
func (g *cohortGuard) enter(err error) {
	now := g.now()
	g.mu.Lock()
	if !g.mismatch {
		g.mismatch = true
		g.since = now
		g.version++
	}
	g.lastErr = err
	due := g.nextWarn.IsZero() || !now.Before(g.nextWarn)
	if due {
		g.nextWarn = now.Add(g.warnPeriod())
	}
	wake := g.wake
	g.mu.Unlock()
	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	if due {
		g.warn(err)
	}
}

func (g *cohortGuard) warn(err error) {
	q, c := 0, 0
	if g.held != nil {
		q, c = g.held()
	}
	log.Printf("robot-agent: %v — new authority withheld; %d decision reports and %d critical reports are held durably until the cohort matches (nothing is downgraded to the C0 wire)", err, q, c)
}

// clear ends the hold — and only the hold: the storage fault, the execution fence and every other reason to
// withhold authority keep their own rules, which the restore line names.
func (g *cohortGuard) clear() {
	g.mu.Lock()
	if !g.mismatch {
		g.mu.Unlock()
		return
	}
	g.mismatch = false
	g.version++
	g.restored++
	g.nextWarn = time.Time{}
	held := g.now().Sub(g.since)
	g.mu.Unlock()
	others := "none"
	if g.otherHolds != nil {
		if h := g.otherHolds(); len(h) > 0 {
			others = strings.Join(h, ", ")
		}
	}
	log.Printf("robot-agent: CORE_COMM_COHORT_RESTORED: contract mismatch cleared after %s; other holds: %s", held.Round(time.Millisecond), others)
}

// mismatched reports the running hold (authority path, health probe, tests). nil-safe.
func (g *cohortGuard) mismatched() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.mismatch
}

// start launches the warning timer and the re-check worker; both end on stop. Idempotent per guard.
func (g *cohortGuard) start() {
	if g == nil || g.stop == nil {
		return
	}
	g.mu.Lock()
	if g.wake != nil {
		g.mu.Unlock()
		return
	}
	g.wake = make(chan struct{}, 1)
	mis := g.mismatch
	g.mu.Unlock()
	g.workers.Add(2)
	go g.warnLoop()
	go g.recheckLoop()
	if mis { // already holding when the workers start: re-check from now on
		g.wake <- struct{}{}
	}
}

// warnLoop repeats the hold warning every warnEvery from a timer — the P37-L1 cadence no longer depends on an
// Issuer call happening to fail inside the window.
func (g *cohortGuard) warnLoop() {
	defer g.workers.Done()
	tick := g.tick
	if tick <= 0 {
		tick = g.warnPeriod() / 2
	}
	if tick < 10*time.Millisecond {
		tick = 10 * time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-t.C:
			now := g.now()
			g.mu.Lock()
			due := g.mismatch && !now.Before(g.nextWarn)
			var err error
			if due {
				g.nextWarn = now.Add(g.warnPeriod())
				err = g.lastErr
			}
			g.mu.Unlock()
			if due {
				g.warn(err)
			}
		}
	}
}

// recheckLoop re-declares the census while the hold lasts (5 s, 10, 20, 40, 60, 60, ...). One re-check at a
// time; the backoff resets when the hold clears. A reconnect reconciles (and so re-declares) on its own.
func (g *cohortGuard) recheckLoop() {
	defer g.workers.Done()
	base, max := g.recheckBase, g.recheckMax
	if base <= 0 {
		base = cohortRecheckBase
	}
	if max <= 0 {
		max = cohortRecheckMax
	}
	after := g.after
	if after == nil {
		after = time.After
	}
	for {
		select {
		case <-g.stop:
			return
		case <-g.wake:
		}
		backoff := base
		for g.mismatched() {
			select {
			case <-g.stop:
				return
			case <-after(backoff):
			}
			if !g.mismatched() {
				break
			}
			if g.recheck != nil {
				g.mu.Lock()
				g.rechecks++
				g.mu.Unlock()
				g.recheck()
			}
			if backoff < max {
				backoff *= 2
				if backoff > max {
					backoff = max
				}
			}
		}
	}
}

// heldCounts is the guard's view of what waits for the cohort to match.
func (q *reportQueue) heldCounts() (int, int) {
	if q == nil {
		return 0, 0
	}
	q.mu.Lock()
	n := len(q.mem)
	if q.disk != nil {
		n = q.disk.records
	}
	q.mu.Unlock()
	return n, q.criticalPending()
}

// criticalPending counts the critical outbox entries still awaiting an Issuer receipt.
func (q *reportQueue) criticalPending() int {
	if q == nil || q.core == nil {
		return 0
	}
	return q.core.pendingCount()
}
