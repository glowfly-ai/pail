// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"runtime"
	"testing"

	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

// The runtime guard summary is a snapshot: it reports EMPTY only when no
// lease and no cached OK answer exist, never mutates the mirror, and is
// UNKNOWN when no mirror is attached.
func TestGuardSummaryReflectsLeaseWithoutMutation(t *testing.T) {
	if runtime.GOOS != "linux" {
		// The summary stamps a Linux monotonic reading and reports
		// "monotonic clock unavailable" elsewhere; skip rather than fail.
		t.Skip("guard summary reads the Linux monotonic clock; not measurable on " + runtime.GOOS)
	}
	p := &selfProbe{robot: "robot-1"}
	if s := p.guardSummary(); s.AuthorityState != "UNKNOWN" {
		t.Fatal(s)
	}
	m := newTokenMirror(nil, "robot-1", 0)
	p.attachMirror(m)
	s := p.guardSummary()
	if s.AuthorityState != "EMPTY" || s.CachedAnswerPresent || s.MirrorRevision != 0 || s.SummaryMonoNs == "" {
		t.Fatal(s)
	}
	m.mu.Lock()
	m.lease = map[int32]*pb.SignedToken{3: {}, 5: {}}
	m.leaseMax = 5
	m.chainID = "chain-a"
	m.servingIdx = 3
	m.epoch = 7
	m.mu.Unlock()
	s = p.guardSummary()
	if s.AuthorityState != "HELD" || s.CachedChainId != "chain-a" || s.LeaseMinIndex != 3 || s.LeaseMaxIndex != 5 || s.ServingIndex != 3 || s.IssuerEpochSeen != 7 {
		t.Fatal(s)
	}
	m.mu.Lock()
	m.lease = nil
	m.resp = &tokenpb.GetActiveTokenResponse{Status: tokenpb.ActiveTokenStatus_OK}
	m.mu.Unlock()
	if s = p.guardSummary(); s.AuthorityState != "HELD" || !s.CachedAnswerPresent {
		t.Fatal("cached OK answer must count as held authority", s)
	}
	m.mu.Lock()
	m.resp = &tokenpb.GetActiveTokenResponse{Status: tokenpb.ActiveTokenStatus_NO_TOKEN}
	m.mu.Unlock()
	if s = p.guardSummary(); s.AuthorityState != "EMPTY" {
		t.Fatal("NO_TOKEN answer is not authority", s)
	}
	m.mu.Lock()
	still := len(m.lease) == 0 && m.resp != nil && m.gen == 0
	m.mu.Unlock()
	if !still {
		t.Fatal("summary mutated the mirror")
	}
}
