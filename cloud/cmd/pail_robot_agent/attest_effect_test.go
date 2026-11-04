// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"bytes"
	"context"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"sync/atomic"
	"testing"
	"time"
)

type effectClient struct {
	*leaseClient
	mode   string
	effect tp.AttestAuthorityEffect
	old    bool
	epoch  uint64
}

func (c *effectClient) Attest(ctx context.Context, r *tp.AttestRequest, _ ...grpc.CallOption) (*tp.AttestResponse, error) {
	if c.old {
		return &tp.AttestResponse{Status: "OK"}, nil
	}
	return &tp.AttestResponse{Status: "OK", EffectContractVersion: 1, EnforcementMode: c.mode, AuthorityEffect: c.effect, RobotId: r.RobotId, Component: r.Component, MeasurementSha256: r.MeasurementSha256, IssuerEpoch: c.epoch}, nil
}
func TestAttestPreserveDoesNotDropExistingLease(t *testing.T) {
	c := &effectClient{leaseClient: newLeaseClient(1, "token-1"), mode: "off", effect: tp.AttestAuthorityEffect_ATTEST_EFFECT_PRESERVE}
	m := newTokenMirror(c, "robot-1", time.Hour)
	m.setStream(true)
	p := &tokenProxy{c: c, m: m, f: newReportForwarder(c)}
	defer p.f.close()
	serve(t, p)
	m.mu.Lock()
	before := m.chainID
	had := m.leaseUsableLocked()
	m.mu.Unlock()
	if !had {
		t.Fatal("precondition: no lease")
	}
	_, e := p.Attest(context.Background(), &tp.AttestRequest{RobotId: "robot-1", Component: "pep_gate", MeasurementSha256: bytes.Repeat([]byte{1}, 32)})
	if e != nil {
		t.Fatal(e)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.leaseUsableLocked() || m.chainID != before {
		t.Fatal("unchanged attestation dropped lease")
	}
}

func TestAttestEffectFallbackAndRefresh(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		effect     tp.AttestAuthorityEffect
		old        bool
		keeps      bool
	}{
		{"log-preserve", "log", tp.AttestAuthorityEffect_ATTEST_EFFECT_PRESERVE, false, true},
		{"required-refresh", "required", tp.AttestAuthorityEffect_ATTEST_EFFECT_REFRESH_CACHE_ONLY, false, true},
		{"required-withhold", "required", tp.AttestAuthorityEffect_ATTEST_EFFECT_WITHHOLD, false, false},
		{"old", "", 0, true, false},
		{"unknown-mode", "unknown", tp.AttestAuthorityEffect_ATTEST_EFFECT_PRESERVE, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &effectClient{leaseClient: newLeaseClient(1, "token-1"), mode: tc.mode, effect: tc.effect, old: tc.old}
			m := newTokenMirror(c, "robot-1", time.Hour)
			m.setStream(true)
			p := &tokenProxy{c: c, m: m, f: newReportForwarder(c)}
			defer p.f.close()
			serve(t, p)
			// Prevent the normal background poller from immediately acquiring a NEW lease after invalidation.
			c.getDown.Store(true)
			_, _ = p.Attest(context.Background(), &tp.AttestRequest{RobotId: "robot-1", Component: "pep_gate", MeasurementSha256: bytes.Repeat([]byte{1}, 32)})
			m.mu.Lock()
			kept := m.leaseUsableLocked()
			m.mu.Unlock()
			if kept != tc.keeps {
				t.Fatalf("keeps=%v want %v", kept, tc.keeps)
			}
		})
	}
}

func TestAttestRejectsInvalidEffect(t *testing.T) {
	req := &tp.AttestRequest{RobotId: "robot-1", Component: "pep_gate", MeasurementSha256: bytes.Repeat([]byte{1}, 32)}
	for _, tc := range []struct {
		name   string
		change func(*tp.AttestResponse)
	}{
		{"missing-version", func(r *tp.AttestResponse) { r.EffectContractVersion = 0 }},
		{"future-version", func(r *tp.AttestResponse) { r.EffectContractVersion = 2 }},
		{"foreign-robot", func(r *tp.AttestResponse) { r.RobotId = "robot-2" }},
		{"foreign-component", func(r *tp.AttestResponse) { r.Component = "other" }},
		{"foreign-measurement", func(r *tp.AttestResponse) { r.MeasurementSha256 = bytes.Repeat([]byte{2}, 32) }},
		{"unknown-effect", func(r *tp.AttestResponse) { r.AuthorityEffect = 99 }},
		{"unknown-status", func(r *tp.AttestResponse) { r.Status = "NEW_STATUS" }},
		{"error-preserve", func(r *tp.AttestResponse) { r.Status = "ERROR" }},
		{"required-unknown-preserve", func(r *tp.AttestResponse) { r.EnforcementMode = "required"; r.Status = "UNKNOWN_MEASUREMENT" }},
		{"log-refresh", func(r *tp.AttestResponse) {
			r.AuthorityEffect = tp.AttestAuthorityEffect_ATTEST_EFFECT_REFRESH_CACHE_ONLY
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &tp.AttestResponse{Status: "OK", EffectContractVersion: 1, EnforcementMode: "log", AuthorityEffect: tp.AttestAuthorityEffect_ATTEST_EFFECT_PRESERVE, RobotId: req.RobotId, Component: req.Component, MeasurementSha256: req.MeasurementSha256}
			if !validAttestEffect(req, r) {
				t.Fatal("baseline")
			}
			tc.change(r)
			if validAttestEffect(req, r) {
				t.Fatal("invalid effect accepted")
			}
		})
	}
	if validAttestEffect(req, nil) {
		t.Fatal("nil accepted")
	}
}

type blockedAttestClient struct {
	*effectClient
	entered, release chan struct{}
}

func (c *blockedAttestClient) Attest(ctx context.Context, r *tp.AttestRequest, opts ...grpc.CallOption) (*tp.AttestResponse, error) {
	close(c.entered)
	select {
	case <-c.release:
		return c.effectClient.Attest(ctx, r, opts...)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestLateAttestDoesNotChangeNewMirrorGeneration(t *testing.T) {
	for _, effect := range []tp.AttestAuthorityEffect{tp.AttestAuthorityEffect_ATTEST_EFFECT_PRESERVE, tp.AttestAuthorityEffect_ATTEST_EFFECT_WITHHOLD} {
		t.Run(effect.String(), func(t *testing.T) {
			c := &blockedAttestClient{effectClient: &effectClient{leaseClient: newLeaseClient(1, "token-1"), mode: "required", effect: effect}, entered: make(chan struct{}), release: make(chan struct{})}
			m := newTokenMirror(c, "robot-1", time.Hour)
			m.setStream(true)
			p := &tokenProxy{c: c, m: m, f: newReportForwarder(c)}
			defer p.f.close()
			serve(t, p)
			c.getDown.Store(true)
			done := make(chan error, 1)
			go func() {
				_, e := p.Attest(context.Background(), &tp.AttestRequest{RobotId: "robot-1", Component: "pep_gate", MeasurementSha256: bytes.Repeat([]byte{1}, 32)})
				done <- e
			}()
			<-c.entered
			m.mu.Lock()
			m.gen++
			m.chainID = "new-chain"
			generation := m.gen
			count := len(m.lease)
			m.mu.Unlock()
			close(c.release)
			if e := <-done; e == nil {
				t.Fatal("late response presented as current")
			}
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.gen != generation || m.chainID != "new-chain" || len(m.lease) != count {
				t.Fatal("late result mutated newer state")
			}
		})
	}
}

func TestLateAttestNewIssuerEpochWithholdsEvenAfterMirrorRevision(t *testing.T) {
	c := &blockedAttestClient{effectClient: &effectClient{leaseClient: newLeaseClient(1, "token-1"), mode: "off", effect: tp.AttestAuthorityEffect_ATTEST_EFFECT_PRESERVE, epoch: 2}, entered: make(chan struct{}), release: make(chan struct{})}
	m := newTokenMirror(c, "robot-1", time.Hour)
	m.setStream(true)
	p := &tokenProxy{c: c, m: m, f: newReportForwarder(c)}
	defer p.f.close()
	serve(t, p)
	c.getDown.Store(true)
	done := make(chan error, 1)
	go func() {
		_, e := p.Attest(context.Background(), &tp.AttestRequest{RobotId: "robot-1", Component: "pep_gate", MeasurementSha256: bytes.Repeat([]byte{1}, 32)})
		done <- e
	}()
	<-c.entered
	m.mu.Lock()
	m.gen++
	m.chainID = "new-chain-in-old-issuer-epoch"
	m.mu.Unlock()
	close(c.release)
	<-done
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.epoch != 2 || m.leaseUsableLocked() {
		t.Fatal("new authenticated Issuer epoch left old-epoch authority usable")
	}
}

func TestHigherEpochFromStaleRouteCannotRewriteCurrentEpoch(t *testing.T) {
	c := &blockedAttestClient{effectClient: &effectClient{leaseClient: newLeaseClient(1, "token-1"), mode: "off", effect: tp.AttestAuthorityEffect_ATTEST_EFFECT_PRESERVE, epoch: 99}, entered: make(chan struct{}), release: make(chan struct{})}
	m := newTokenMirror(c, "robot-1", time.Hour)
	m.setStream(true)
	var route atomic.Uint64
	p := &tokenProxy{c: c, m: m, f: newReportForwarder(c), routeVersion: route.Load}
	defer p.f.close()
	serve(t, p)
	c.getDown.Store(true)
	done := make(chan error, 1)
	go func() {
		_, e := p.Attest(context.Background(), &tp.AttestRequest{RobotId: "robot-1", Component: "pep_gate", MeasurementSha256: bytes.Repeat([]byte{1}, 32)})
		done <- e
	}()
	<-c.entered
	route.Add(1)
	close(c.release)
	if e := <-done; e == nil {
		t.Fatal("stale route reported as current")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.epoch == 99 || m.leaseUsableLocked() {
		t.Fatal("stale route epoch accepted or captured authority not withheld")
	}
}
