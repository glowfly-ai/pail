// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"bytes"
	"context"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
)

func validAttestEffect(req *tp.AttestRequest, r *tp.AttestResponse) bool {
	if r == nil || r.EffectContractVersion != 1 || r.RobotId != req.RobotId || r.Component != req.Component || len(req.MeasurementSha256) != 32 || !bytes.Equal(req.MeasurementSha256, r.MeasurementSha256) {
		return false
	}
	if r.EnforcementMode != "off" && r.EnforcementMode != "log" && r.EnforcementMode != "required" {
		return false
	}
	if r.Status != "OK" && r.Status != "UNKNOWN_MEASUREMENT" && r.Status != "ERROR" {
		return false
	}
	switch r.AuthorityEffect {
	case tp.AttestAuthorityEffect_ATTEST_EFFECT_WITHHOLD:
		return true
	case tp.AttestAuthorityEffect_ATTEST_EFFECT_PRESERVE:
		return r.Status != "ERROR" && (r.EnforcementMode != "required" || r.Status == "OK")
	case tp.AttestAuthorityEffect_ATTEST_EFFECT_REFRESH_CACHE_ONLY:
		return r.EnforcementMode == "required" && r.Status == "OK"
	default:
		return false
	}
}

// The attestation outcome cannot create authority. Preserve/refresh only
// remove the old unconditional lease invalidation; every other hold remains.
func (p *tokenProxy) attestWithEffect(ctx context.Context, req *tp.AttestRequest) (*tp.AttestResponse, error) {
	if req == nil || req.RobotId == "" {
		return nil, status.Error(codes.InvalidArgument, "attestation robot required")
	}
	if p.m == nil {
		return p.c.Attest(ctx, req)
	}
	m := p.m
	if req.RobotId != m.robotID {
		return nil, status.Error(codes.PermissionDenied, "attestation robot mismatch")
	}
	m.mu.Lock()
	gen, connection, chain := m.gen, m.connGen, m.chainID
	m.mu.Unlock()
	route := uint64(0)
	if p.routeVersion != nil {
		route = p.routeVersion()
	}
	reply, err := p.c.Attest(ctx, req)
	currentRoute := route
	if p.routeVersion != nil {
		currentRoute = p.routeVersion()
	}
	wireValid := err == nil && currentRoute == route && validAttestEffect(req, reply)
	m.mu.Lock()
	if p.routeVersion != nil && p.routeVersion() != route {
		wireValid = false
	}
	// An authenticated newer Issuer epoch is a global authority boundary,
	// even when a concurrent request advanced this mirror's local revision.
	// It never grants authority and must not be discarded as an old-plan reply.
	if wireValid && reply.IssuerEpoch > m.epoch {
		m.epoch = reply.IssuerEpoch
		m.gen++
		dropped := m.dropLeaseLocked()
		m.invalidateCacheLocked()
		m.mu.Unlock()
		if dropped {
			go m.census()
		}
		return reply, nil
	}
	// A late response must not modify the state of a new plan/execution.
	if m.gen != gen || m.connGen != connection || m.chainID != chain {
		m.mu.Unlock()
		if err != nil {
			return reply, err
		}
		return nil, status.Error(codes.Unavailable, "ATTEST_OUTCOME_SUPERSEDED")
	}
	valid := wireValid && reply.IssuerEpoch >= m.epoch
	drop := !valid || reply.GetAuthorityEffect() == tp.AttestAuthorityEffect_ATTEST_EFFECT_WITHHOLD
	dropped := false
	if drop {
		m.gen++
		dropped = m.dropLeaseLocked()
		m.invalidateCacheLocked()
	} else if reply.AuthorityEffect == tp.AttestAuthorityEffect_ATTEST_EFFECT_REFRESH_CACHE_ONLY {
		m.gen++
		m.invalidateCacheLocked()
	}
	m.mu.Unlock()
	if dropped {
		go m.census()
	}
	if !valid {
		log.Printf("robot-agent: ATTEST_EFFECT_UNCONFIRMED: conservative invalidation; no authority granted")
		if err == nil && (reply == nil || reply.EffectContractVersion != 0 || currentRoute != route) {
			return nil, status.Error(codes.Unavailable, "ATTEST_EFFECT_INVALID_OR_STALE")
		}
	}
	return reply, err
}
