// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"testing"
)

func TestSupersededCompletionKeepsUnrelatedLease(t *testing.T) {
	c := newLeaseClient(1, "new-token")
	c.accept = false
	p, m := leasedProxy(t, c)
	first := serve(t, p)
	c.getDown.Store(true) // The fake issuer must not reissue authority after the report.
	if first.GetToken().GetToken().GetTokenId() != "new-token" {
		t.Fatal("positive control missing")
	}
	m.mu.Lock()
	generation := m.gen
	m.mu.Unlock()
	_, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{RobotId: "robot-1", ChainId: "old-chain", TokenId: "old-token", Decision: tokenpb.Decision_PERMIT, StepComplete: true})
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gen != generation || !m.leaseUsableLocked() {
		t.Fatalf("late old completion discarded NEW lease: gen=%d want=%d usable=%v", m.gen, generation, m.leaseUsableLocked())
	}
}

func TestSupersededFatalStillDropsCurrentLease(t *testing.T) {
	c := newLeaseClient(1, "new-token")
	p, m := leasedProxy(t, c)
	serve(t, p)
	c.getDown.Store(true) // Model the real issuer revoking, not endlessly regranting.
	_, err := p.ReportDecision(context.Background(), &tokenpb.ReportDecisionRequest{RobotId: "robot-1", ChainId: "old-chain", TokenId: "old-token", Decision: tokenpb.Decision_ESTOP, Fatal: true})
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.leaseUsableLocked() {
		t.Fatal("old-chain fatal retained live authority")
	}
}

func TestCompletionIdentityMustMatchCurrentLease(t *testing.T) {
	for _, change := range []string{"robot", "token", "decision", "chain", "empty-chain"} {
		t.Run(change, func(t *testing.T) {
			c := newLeaseClient(1, "new-token")
			p, m := leasedProxy(t, c)
			serve(t, p)
			req := &tokenpb.ReportDecisionRequest{RobotId: "robot-1", ChainId: "chain-1", TokenId: "new-token", Decision: tokenpb.Decision_PERMIT, StepComplete: true}
			switch change {
			case "robot":
				req.RobotId = "robot-2"
			case "token":
				req.TokenId = "old-token"
			case "decision":
				req.Decision = tokenpb.Decision_BLOCK
			case "chain":
				req.ChainId = "old-chain"
			case "empty-chain":
				req.ChainId = ""
			}
			if m.consumed(req) {
				t.Fatal("mismatched completion consumed current lease")
			}
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.servingIdx != 1 || len(m.pendingRep) != 0 {
				t.Fatal("invalid consumption mutated lease")
			}
		})
	}
}
