// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"sync/atomic"
	"testing"
	"time"
)

type fenceClient struct {
	fakeTokenClient
	resets  atomic.Int64
	old     bool
	release chan struct{}
}

func (f *fenceClient) ReportGatewayCensus(ctx context.Context, r *tokenpb.GatewayCensusRequest, o ...grpc.CallOption) (*tokenpb.GatewayCensusResponse, error) {
	md, _ := metadata.FromOutgoingContext(ctx)
	if v := md.Get("pail-execution-reset"); len(v) != 1 || v[0] != "v1" {
		return nil, status.Error(codes.InvalidArgument, "missing reset metadata")
	}
	f.resets.Add(1)
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	v := "EXECUTION_RESET"
	if f.old {
		v = "OK"
	}
	return &tokenpb.GatewayCensusResponse{Accepted: true, Verdict: v}, nil
}
func execContext(id string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(executionHeader, id))
}
func waitFence(t *testing.T, m *tokenMirror) {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if m.executionCurrent("") {
			return
		}
	}
	t.Fatal("fence did not clear")
}
func TestExecFenceOldPeer(t *testing.T) {
	f := &fenceClient{old: true}
	m := newTokenMirror(f, "robot-1", 200*time.Millisecond)
	m.enableExecutionFence(true)
	time.Sleep(30 * time.Millisecond)
	if m.executionCurrent("") {
		t.Fatal("old peer OK waived restart fence")
	}
	if _, e := m.prepareExecution(execContext(uuid.NewString())); e == nil {
		t.Fatal("old peer exposed authority")
	}
	if _, e := m.get(context.Background(), req()); e == nil || f.calls.Load() != 0 {
		t.Fatal("upstream read crossed pending fence")
	}
}
func TestExecFenceBootChange(t *testing.T) {
	f := &fenceClient{}
	m := newTokenMirror(f, "robot-1", 200*time.Millisecond)
	m.enableExecutionFence(true)
	waitFence(t, m)
	a, b := uuid.NewString(), uuid.NewString()
	if id, e := m.prepareExecution(execContext(a)); e != nil || id != a {
		t.Fatal(e)
	}
	before := f.resets.Load()
	for i := 0; i < 3; i++ {
		if _, e := m.prepareExecution(execContext(a)); e != nil {
			t.Fatal(e)
		}
	}
	if f.resets.Load() != before {
		t.Fatal("same process caused restart")
	}
	m.mu.Lock()
	m.execRetry = time.Time{}
	m.mu.Unlock()
	if _, e := m.prepareExecution(execContext(b)); e == nil {
		t.Fatal("new process did not fence")
	}
	waitFence(t, m)
	if m.executionCurrent(a) || !m.executionCurrent(b) {
		t.Fatal("old execution still current")
	}
	if f.resets.Load() != before+1 {
		t.Fatal("restart not declared")
	}
	if _, e := m.prepareExecution(context.Background()); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("missing identity accepted", e)
	}
}
func TestExecFenceLateAck(t *testing.T) {
	f := &fenceClient{release: make(chan struct{})}
	m := newTokenMirror(f, "robot-1", 200*time.Millisecond)
	m.enableExecutionFence(true)
	m.prepareExecution(execContext(uuid.NewString()))
	m.prepareExecution(execContext(uuid.NewString()))
	close(f.release)
	time.Sleep(30 * time.Millisecond)
	if m.executionCurrent("") {
		t.Fatal("old reset response cleared newer fence")
	}
}
