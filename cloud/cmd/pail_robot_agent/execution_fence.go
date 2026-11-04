// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"time"
)

const executionHeader = "pail-execution-instance"

var errExecutionPending = status.Error(codes.Unavailable, "EXECUTION_RESTART_PENDING")

// Enabled by the real process entrypoint before any token poll/listener starts.
// Component unit fixtures can test the mirror independently of process startup.
func (m *tokenMirror) enableExecutionFence(required bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.execEnabled = true
	m.execRequired = required
	m.execPending = true
	m.execSeq++
	m.gen++
	m.dropLeaseLocked()
	m.invalidateCacheLocked()
	m.startResetLocked()
}
func (m *tokenMirror) startResetLocked() {
	if !m.execPending || m.execBusy || time.Since(m.execRetry) < 250*time.Millisecond {
		return
	}
	m.execBusy = true
	m.execRetry = time.Now()
	seq, epoch := m.execSeq, m.epoch
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("pail-execution-reset", "v1"))
		r, err := m.c.ReportGatewayCensus(ctx, &tokenpb.GatewayCensusRequest{RobotId: m.robotID, SeenIssuerEpoch: epoch})
		m.mu.Lock()
		defer m.mu.Unlock()
		m.execBusy = false
		if seq != m.execSeq {
			return
		}
		if err != nil || r == nil || !r.Accepted || r.Verdict != "EXECUTION_RESET" || r.IssuerEpoch < m.epoch {
			log.Printf("robot-agent: execution restart remains fenced (err=%v verdict=%s)", err, r.GetVerdict())
			return
		}
		m.epoch = r.IssuerEpoch
		m.execPending = false
		m.invalidateCacheLocked()
		log.Printf("robot-agent: execution restart reconciled; prior delegated plan cannot resume")
	}()
}
func (m *tokenMirror) prepareExecution(ctx context.Context) (string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get(executionHeader)
	id := ""
	if len(v) > 0 {
		if len(v) != 1 {
			return "", status.Error(codes.InvalidArgument, "invalid execution identity")
		}
		if _, e := uuid.Parse(v[0]); e != nil {
			return "", status.Error(codes.InvalidArgument, "invalid execution identity")
		}
		id = v[0]
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.execEnabled {
		return "", nil
	}
	if m.execRequired && id == "" {
		return "", status.Error(codes.FailedPrecondition, "EXECUTION_INSTANCE_REQUIRED")
	}
	if id != "" {
		if m.execID != "" && m.execID != id {
			m.execSeq++
			m.execPending = true
			m.gen++
			m.dropLeaseLocked()
			m.invalidateCacheLocked()
			log.Printf("robot-agent: enforcement process changed; withholding prior execution")
		}
		m.execID = id
	}
	if m.execPending {
		m.startResetLocked()
		return "", errExecutionPending
	}
	return id, nil
}
func (m *tokenMirror) executionCurrent(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.execEnabled || (!m.execPending && (id == "" || id == m.execID))
}
