// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package anchor

// BA-3: tick jitter and store-attempt backoff. Rand and Now are seams, so the
// waits are computed, not slept, and the backoff window is crossed by moving
// the clock.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"
)

func (s *fakeStore) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func TestJitterBoundsAndPhase(t *testing.T) {
	a, _ := newAgent(t, &fakeStore{})
	a.Interval = 10 * time.Second
	// Jitter 0: the cadence is the interval, first wait included.
	if a.nextDelay() != 10*time.Second || a.initialDelay() != 10*time.Second {
		t.Fatalf("jitter 0 must be the fixed cadence: %v %v", a.nextDelay(), a.initialDelay())
	}
	a.Jitter = 0.2
	for _, u := range []float64{0, 0.25, 0.5, 0.75, 0.999} {
		a.Rand = func() float64 { return u }
		d := a.nextDelay()
		if d < 8*time.Second || d > 12*time.Second {
			t.Fatalf("u=%v: delay %v outside Interval*(1±0.2)", u, d)
		}
		want := time.Duration(float64(10*time.Second) * (1 + 0.2*(2*u-1)))
		if d != want {
			t.Fatalf("u=%v: delay %v, want %v", u, d, want)
		}
		if p := a.initialDelay(); p != time.Duration(float64(10*time.Second)*u) {
			t.Fatalf("u=%v: initial phase %v, want %v", u, p, time.Duration(float64(10*time.Second)*u))
		}
	}
	// The draw changes the wait: two different u give two different delays.
	a.Rand = func() float64 { return 0.1 }
	d1 := a.nextDelay()
	a.Rand = func() float64 { return 0.9 }
	if d2 := a.nextDelay(); d1 == d2 {
		t.Fatal("jitter must vary with the draw")
	}
}

// Store down: the first tick attempts and fails; while the backoff window is
// open further ticks do not touch the store but still queue their record;
// after the window an attempt happens again (and the window grows, capped);
// a success resets everything and the next tick attempts at once.
func TestBackoffSpacesStoreAttemptsAndKeepsQueueing(t *testing.T) {
	st := &fakeStore{fail: true}
	a, _ := newAgent(t, st)
	a.Interval = time.Second
	// 5 s is deliberately not a power-of-two multiple of the interval: the
	// doubling (1,2,4,8) overshoots it, so the clamp is what the test measures.
	a.BackoffMax = 5 * time.Second
	a.Rand = func() float64 { return 1 } // full jitter drawn at the cap: deterministic worst case
	clock := time.Unix(1_700_000_000, 0)
	a.Now = func() time.Time { return clock }
	src := a.Source.(*fakeSource)

	a.Tick() // attempt 1 fails -> streak 1, wait = interval*1 = 1s
	if st.attemptCount() != 1 {
		t.Fatalf("first tick must attempt: %d", st.attemptCount())
	}
	streak, retryAt := a.BackoffState()
	if streak != 1 || !retryAt.Equal(clock.Add(time.Second)) {
		t.Fatalf("after one failure: streak=%d retryAt=%v", streak, retryAt)
	}
	clock = clock.Add(500 * time.Millisecond)
	src.count++
	a.Tick() // inside the window: no attempt, record queued
	if st.attemptCount() != 1 {
		t.Fatalf("tick inside the backoff window must not touch the store: %d", st.attemptCount())
	}
	if n := queued(t, a); n != 2 {
		t.Fatalf("both records must be queued locally: %d", n)
	}
	clock = clock.Add(600 * time.Millisecond) // past retryAt
	src.count++
	a.Tick() // attempt 2 (drain tries the oldest queued record) fails -> streak 2, cap 2s
	if st.attemptCount() != 2 {
		t.Fatalf("after the window an attempt must happen: %d", st.attemptCount())
	}
	if streak, retryAt = a.BackoffState(); streak != 2 || !retryAt.Equal(clock.Add(2*time.Second)) {
		t.Fatalf("after two failures: streak=%d wait=%v", streak, retryAt.Sub(clock))
	}
	for i := 0; i < 4; i++ { // keep failing: the cap holds at BackoffMax
		clock = retryAt
		src.count++
		a.Tick()
		streak, retryAt = a.BackoffState()
	}
	if streak != 6 || retryAt.Sub(clock) != 5*time.Second {
		t.Fatalf("cap: streak=%d wait=%v want 5s (clamped from 8s)", streak, retryAt.Sub(clock))
	}
	if n := queued(t, a); n != 7 {
		t.Fatalf("every tick queued its record: %d", n)
	}
	// Store recovers; at the next allowed attempt the queue drains in order,
	// the backoff resets, and the following tick attempts without waiting.
	st.setFail(false)
	clock = retryAt
	src.count++
	a.Tick()
	if streak, _ = a.BackoffState(); streak != 0 {
		t.Fatalf("success must reset the backoff: streak=%d", streak)
	}
	if n := queued(t, a); n != 0 || st.count() != 8 {
		t.Fatalf("queue must drain and the current record upload: queued=%d stored=%d", n, st.count())
	}
	before := st.attemptCount()
	clock = clock.Add(time.Second)
	src.count++
	a.Tick()
	if st.attemptCount() != before+1 || st.count() != 9 {
		t.Fatalf("after reset every tick attempts again: attempts=%d stored=%d", st.attemptCount(), st.count())
	}
	if len(st.order) != 9 || st.order[0] >= st.order[8] {
		t.Fatalf("order preserved oldest-first: %v", st.order)
	}
}

// BackoffMax 0 is the legacy behavior: every tick attempts the store.
func TestBackoffZeroAttemptsEveryTick(t *testing.T) {
	st := &fakeStore{fail: true}
	a, _ := newAgent(t, st)
	a.Interval = time.Second
	clock := time.Unix(1_700_000_000, 0)
	a.Now = func() time.Time { return clock }
	for i := 0; i < 3; i++ {
		a.Tick()
		clock = clock.Add(time.Second)
	}
	if st.attemptCount() != 3 {
		t.Fatalf("without backoff every tick attempts: %d", st.attemptCount())
	}
	if streak, _ := a.BackoffState(); streak != 0 {
		t.Fatalf("no backoff state without BackoffMax: %d", streak)
	}
}

// Full jitter: the wait is uniform in [0, cap], so a fleet does not retry in
// lockstep; u=0 is an immediate retry, u=1 the whole cap.
func TestBackoffFullJitter(t *testing.T) {
	for _, u := range []float64{0, 0.5, 1} {
		st := &fakeStore{fail: true}
		a, _ := newAgent(t, st)
		a.Interval, a.BackoffMax = time.Second, 8*time.Second
		a.Rand = func() float64 { return u }
		clock := time.Unix(1_700_000_000, 0)
		a.Now = func() time.Time { return clock }
		a.Tick()
		_, retryAt := a.BackoffState()
		clock = retryAt // the first window is over
		a.Tick()        // streak 2 -> cap 2s
		_, retryAt = a.BackoffState()
		if want := time.Duration(float64(2*time.Second) * u); retryAt.Sub(clock) != want {
			t.Fatalf("u=%v: wait %v, want %v", u, retryAt.Sub(clock), want)
		}
	}
}

// Run honours the seams: with a tiny interval and jitter it keeps ticking
// until the context ends (a smoke test that the timer is re-armed).
func TestRunReArmsTimerWithJitter(t *testing.T) {
	st := &fakeStore{}
	a, _ := newAgent(t, st)
	a.Interval, a.Jitter = 5*time.Millisecond, 0.5
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	a.Run(ctx)
	if st.count() < 3 {
		t.Fatalf("Run must keep ticking with jitter: %d uploads", st.count())
	}
}

func queued(t *testing.T, a *Agent) int {
	t.Helper()
	entries, err := os.ReadDir(a.QueueDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0
		}
		t.Fatal(err)
	}
	return len(entries)
}
