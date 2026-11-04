// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"context"
	"errors"
	"net"
	"testing"

	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestShouldFailover(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{status.Error(codes.Unavailable, "connection refused"), true},
		{status.Error(codes.FailedPrecondition, "STANDBY"), true},
		{status.Error(codes.FailedPrecondition, "estop latched"), false},
		{status.Error(codes.Internal, "boom"), false},
		{status.Error(codes.PermissionDenied, "no"), false},
		{errors.New("not a status"), false},
	}
	for _, c := range cases {
		if got := shouldFailover(c.err); got != c.want {
			t.Errorf("shouldFailover(%v)=%v, want %v", c.err, got, c.want)
		}
	}
}

// Concurrent failures on the same upstream rotate ONCE (CAS): a stale index
// can never skip past the successor. A single address never rotates.
func TestRotateIfCurrentCAS(t *testing.T) {
	f := newFailoverConn([]string{"a", "b", "c"}, nil, t.Logf)
	cause := status.Error(codes.Unavailable, "down")
	f.rotateIfCurrent(0, cause)
	if f.index() != 1 {
		t.Fatalf("index=%d, want 1", f.index())
	}
	f.rotateIfCurrent(0, cause) // stale: another caller already rotated
	if f.index() != 1 {
		t.Fatalf("index=%d after stale rotate, want 1", f.index())
	}
	f.rotateIfCurrent(1, cause)
	f.rotateIfCurrent(2, cause) // wraps
	if f.index() != 0 {
		t.Fatalf("index=%d, want 0 (wrap)", f.index())
	}

	single := newFailoverConn([]string{"only"}, nil, t.Logf)
	single.rotateIfCurrent(0, cause)
	if single.index() != 0 {
		t.Fatal("single-address conn rotated")
	}
}

type stubToken struct {
	tokenpb.UnimplementedTokenServiceServer
	resp func() (*tokenpb.GetActiveTokenResponse, error)
}

func (s *stubToken) GetActiveToken(ctx context.Context, req *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	return s.resp()
}

func bufServer(t *testing.T, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	var gs *grpc.Server
	if register != nil {
		gs = grpc.NewServer()
		register(gs)
	} else {
		// standby shape: no services, everything refused STANDBY
		gs = grpc.NewServer(grpc.UnknownServiceHandler(
			func(srv interface{}, stream grpc.ServerStream) error {
				return status.Error(codes.FailedPrecondition, "STANDBY")
			}))
	}
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	conn, err := grpc.Dial("bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// End to end over two live servers: the STANDBY refusal on upstream 0 rotates
// to upstream 1, where the same typed client succeeds — and a service-level
// error there does NOT rotate away.
func TestFailoverConnRotatesOnStandby(t *testing.T) {
	standby := bufServer(t, nil)
	leaderStub := &stubToken{resp: func() (*tokenpb.GetActiveTokenResponse, error) {
		return &tokenpb.GetActiveTokenResponse{Status: tokenpb.ActiveTokenStatus_OK}, nil
	}}
	leader := bufServer(t, func(g *grpc.Server) { tokenpb.RegisterTokenServiceServer(g, leaderStub) })

	f := newFailoverConn([]string{"standby:1", "leader:1"}, []*grpc.ClientConn{standby, leader}, t.Logf)
	client := tokenpb.NewTokenServiceClient(f)

	_, err := client.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "r"})
	if status.Code(err) != codes.FailedPrecondition || f.index() != 1 {
		t.Fatalf("first call err=%v index=%d, want STANDBY refusal + rotation to 1", err, f.index())
	}
	resp, err := client.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "r"})
	if err != nil || resp.GetStatus() != tokenpb.ActiveTokenStatus_OK {
		t.Fatalf("post-rotation call: resp=%v err=%v", resp, err)
	}

	// Service-level FAILED_PRECONDITION on the leader must NOT rotate.
	leaderStub.resp = func() (*tokenpb.GetActiveTokenResponse, error) {
		return nil, status.Error(codes.FailedPrecondition, "estop latched")
	}
	_, err = client.GetActiveToken(context.Background(), &tokenpb.GetActiveTokenRequest{RobotId: "r"})
	if status.Code(err) != codes.FailedPrecondition || f.index() != 1 {
		t.Fatalf("service error err=%v index=%d, want no rotation (stay 1)", err, f.index())
	}
}
