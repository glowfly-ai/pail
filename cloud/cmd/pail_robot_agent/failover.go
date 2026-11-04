// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"context"
	"strings"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// failoverConn implements grpc.ClientConnInterface over an ordered list of
// cloud addresses (HA LLD §5.2): every RPC goes to the current address; an
// UNAVAILABLE error (dial/transport failure) or a FAILED_PRECONDITION
// "STANDBY" refusal rotates to the next. No extra prober: the gate's permit
// rechecks, the token-mirror poller and the 500ms beacon reconnect loop are
// the traffic that drives rotation. The failed RPC itself still returns its
// error — fail-closed semantics at every caller are unchanged.
type failoverConn struct {
	addrs    []string
	conns    []*grpc.ClientConn
	idx      atomic.Int32
	routeGen atomic.Uint64
	logf     func(format string, args ...any)
}

func newFailoverConn(addrs []string, conns []*grpc.ClientConn, logf func(string, ...any)) *failoverConn {
	return &failoverConn{addrs: addrs, conns: conns, logf: logf}
}

func (f *failoverConn) index() int32 { return f.idx.Load() }
func (f *failoverConn) addr() string { return f.addrs[f.idx.Load()] }

// shouldFailover reports whether err means "this upstream cannot serve":
// transport-level UNAVAILABLE, or the standby's explicit STANDBY refusal.
// Any other error (including service-level FAILED_PRECONDITION like guard
// rejections) belongs to the current upstream and must NOT rotate.
func shouldFailover(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	return s.Code() == codes.Unavailable ||
		(s.Code() == codes.FailedPrecondition && strings.Contains(s.Message(), "STANDBY"))
}

// rotateIfCurrent advances to the next address only if `from` is still the
// active index (CAS): concurrent failures on the same upstream rotate once,
// never skip past the successor.
func (f *failoverConn) rotateIfCurrent(from int32, cause error) {
	if len(f.addrs) < 2 {
		return
	}
	next := (from + 1) % int32(len(f.addrs))
	if f.idx.CompareAndSwap(from, next) {
		f.routeGen.Add(1)
		f.logf("robot-agent: cloud failover %s -> %s (%v)", f.addrs[from], f.addrs[next], cause)
	}
}

// observe applies the rotation rule to an error seen OUTSIDE Invoke/NewStream
// (e.g. a stream Recv error), attributed to the index captured at call time.
func (f *failoverConn) observe(from int32, err error) {
	if shouldFailover(err) {
		f.rotateIfCurrent(from, err)
	}
}

func (f *failoverConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...grpc.CallOption) error {
	i := f.idx.Load()
	err := f.conns[i].Invoke(ctx, method, args, reply, opts...)
	f.observe(i, err)
	return err
}

func (f *failoverConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	i := f.idx.Load()
	cs, err := f.conns[i].NewStream(ctx, desc, method, opts...)
	f.observe(i, err)
	return cs, err
}
