// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"errors"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/ledgerq"
)

type scriptedLedger struct {
	t      *testing.T
	script []ledgerq.ChainStatus
	fail   error
	calls  int
	stamps []time.Time
	dirs   []string
}

func (s *scriptedLedger) IngestChain(dir string, now time.Time) (ledgerq.ChainStatus, error) {
	s.calls++
	s.stamps = append(s.stamps, now)
	s.dirs = append(s.dirs, dir)
	if s.calls > 10 {
		s.t.Fatal("the cycle does not end")
	}
	// a pass that failed still says what it had found before it failed
	if s.calls > len(s.script) {
		return s.script[len(s.script)-1], s.fail
	}
	return s.script[s.calls-1], s.fail
}

var (
	passOK       = ledgerq.ChainStatus{State: "ok", Records: 5, CheckedToSeq: 5}
	passUnstable = ledgerq.ChainStatus{State: "unverified", Error: "SOURCE_UNSTABLE"}
)

// A pass that collided with a change of the ledger is read again, at most
// three passes in a cycle; a verdict about the ledger itself is kept.
func TestOpsviewLedgerCycle(t *testing.T) {
	for name, x := range map[string]struct {
		script []ledgerq.ChainStatus
		fail   error
		passes int
		state  string
	}{
		"sound":                    {[]ledgerq.ChainStatus{passOK}, nil, 1, "ok"},
		"changed once":             {[]ledgerq.ChainStatus{passUnstable, passOK}, nil, 2, "ok"},
		"changed twice":            {[]ledgerq.ChainStatus{passUnstable, passUnstable, passOK}, nil, 3, "ok"},
		"changed every time":       {[]ledgerq.ChainStatus{passUnstable}, nil, 3, "unverified"},
		"changed, then damaged":    {[]ledgerq.ChainStatus{passUnstable, {State: "chain_error", Error: "this_hash mismatch"}, passOK}, nil, 2, "chain_error"},
		"damaged":                  {[]ledgerq.ChainStatus{{State: "chain_error", Error: "this_hash mismatch"}, passOK}, nil, 1, "chain_error"},
		"absent":                   {[]ledgerq.ChainStatus{{State: "absent", Error: "SOURCE_ABSENT"}, passOK}, nil, 1, "absent"},
		"end cut off":              {[]ledgerq.ChainStatus{{State: "unverified", Error: "TORN_TAIL"}, passOK}, nil, 1, "unverified"},
		"segments missing":         {[]ledgerq.ChainStatus{{State: "unverified", Error: "SEGMENT_SET_INCOMPLETE"}, passOK}, nil, 1, "unverified"},
		"beyond the budget":        {[]ledgerq.ChainStatus{{State: "unverified", Error: "VERIFY_BUDGET_EXCEEDED"}, passOK}, nil, 1, "unverified"},
		"another state, same code": {[]ledgerq.ChainStatus{{State: "chain_error", Error: "SOURCE_UNSTABLE"}, passOK}, nil, 1, "chain_error"},
		"index cannot publish":     {[]ledgerq.ChainStatus{passUnstable}, errors.New("INDEX_METADATA_INVALID"), 1, "unverified"},
	} {
		t.Run(name, func(t *testing.T) {
			s := &scriptedLedger{t: t, script: x.script, fail: x.fail}
			at := time.Unix(1800000000, 0)
			var paused []time.Duration
			cs, passes, err := verifyLedger(s, "/ledger", func() time.Time { at = at.Add(time.Second); return at }, func(d time.Duration) { paused = append(paused, d) })
			if passes != x.passes || s.calls != x.passes || cs.State != x.state || (err != nil) != (x.fail != nil) {
				t.Fatalf("passes=%d calls=%d state=%q err=%v", passes, s.calls, cs.State, err)
			}
			if len(paused) != x.passes-1 {
				t.Fatalf("pauses: %v", paused)
			}
			for _, d := range paused {
				if d != 250*time.Millisecond {
					t.Fatal(d)
				}
			}
			// every pass is stamped with its own time and reads the same ledger
			for i := range s.stamps {
				if s.dirs[i] != "/ledger" || (i > 0 && !s.stamps[i].After(s.stamps[i-1])) {
					t.Fatalf("%v %v", s.stamps, s.dirs)
				}
			}
		})
	}
	if ledgerPasses != 3 {
		t.Fatal(ledgerPasses)
	}
}
