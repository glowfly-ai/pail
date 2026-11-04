// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	"github.com/glowfly/pail/services/internal/grpclive"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type testIssuer struct {
	tokenpb.UnimplementedTokenServiceServer
	calls atomic.Int32
}

func (s *testIssuer) GetActiveToken(ctx context.Context, r *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	s.calls.Add(1)
	if err := grpclive.EchoFixtureExecution(ctx); err != nil {
		return nil, err
	}
	return &tokenpb.GetActiveTokenResponse{Status: tokenpb.ActiveTokenStatus_OK, Token: &pb.SignedToken{Token: &pb.ActionToken{TokenId: "pinned-test-token"}}}, nil
}
func testClient(t *testing.T, s tokenpb.TokenServiceServer) tokenpb.TokenServiceClient {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	tokenpb.RegisterTokenServiceServer(g, s)
	go g.Serve(l)
	c, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); g.Stop(); l.Close() })
	return tokenpb.NewTokenServiceClient(c)
}
func TestFrozenAck(t *testing.T) {
	up := &testIssuer{}
	client := testClient(t, &seam{up: testClient(t, up)})
	var first *tokenpb.GetActiveTokenResponse
	for _, id := range []string{"execution-a", "execution-b"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(grpclive.ExecutionHeader, id))
		var headers metadata.MD
		r, err := client.GetActiveToken(ctx, &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}, grpc.Header(&headers))
		cancel()
		values := headers.Get(grpclive.ExecutionHeader)
		if err != nil || len(values) != 1 || values[0] != "execution-a" {
			t.Fatalf("replay acknowledgement changed or missing: %v %v", headers, err)
		}
		if first == nil {
			first = r
		} else if !proto.Equal(first, r) {
			t.Fatal("pinned body changed")
		}
	}
	if up.calls.Load() != 1 {
		t.Fatal("replay performed a new upstream grant", up.calls.Load())
	}
}
