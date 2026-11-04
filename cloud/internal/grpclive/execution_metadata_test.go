// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package grpclive

import (
	"context"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"net"
	"testing"
	"time"
)

type wirePeer struct {
	tokenpb.UnimplementedTokenServiceServer
	mode string
	seen chan metadata.MD
}

func (s *wirePeer) GetActiveToken(ctx context.Context, r *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	s.seen <- md.Copy()
	if s.mode == "unavailable" {
		return nil, status.Error(codes.Unavailable, "injected")
	}
	if s.mode != "old-peer" {
		values := md.Get(ExecutionHeader)
		if s.mode == "duplicates" {
			values = append(values, values...)
		}
		grpc.SetHeader(ctx, metadata.MD{ExecutionHeader: values})
	}
	return &tokenpb.GetActiveTokenResponse{Status: tokenpb.ActiveTokenStatus_NO_TOKEN}, nil
}

type wireProxy struct {
	tokenpb.UnimplementedTokenServiceServer
	up      tokenpb.TokenServiceClient
	fixture bool
}

func (s *wireProxy) GetActiveToken(ctx context.Context, r *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	if s.fixture {
		if err := EchoFixtureExecution(ctx); err != nil {
			return nil, err
		}
		return &tokenpb.GetActiveTokenResponse{Status: tokenpb.ActiveTokenStatus_NO_TOKEN}, nil
	}
	resp, _, err := TokenCall(ctx, s.up, r)
	return resp, err
}
func wireClient(t *testing.T, s tokenpb.TokenServiceServer) tokenpb.TokenServiceClient {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	tokenpb.RegisterTokenServiceServer(server, s)
	go server.Serve(lis)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(); server.Stop(); lis.Close() })
	return tokenpb.NewTokenServiceClient(conn)
}
func TestForwardWire(t *testing.T) {
	for _, mode := range []string{"forward", "old-peer", "duplicates", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			peer := &wirePeer{mode: mode, seen: make(chan metadata.MD, 1)}
			client := wireClient(t, &wireProxy{up: wireClient(t, peer)})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(ExecutionHeader, "execution-a", "pail-grant-request-id", "request-a", "authorization", "not-forwarded"))
			var h metadata.MD
			r, err := client.GetActiveToken(ctx, &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}, grpc.Header(&h))
			if mode == "unavailable" {
				if status.Code(err) != codes.Unavailable {
					t.Fatal(err)
				}
			} else {
				if err != nil || r.GetStatus() != tokenpb.ActiveTokenStatus_NO_TOKEN {
					t.Fatal(r, err)
				}
			}
			got := h.Get(ExecutionHeader)
			want := 1
			if mode == "old-peer" || mode == "unavailable" {
				want = 0
			}
			if mode == "duplicates" {
				want = 2
			}
			if len(got) != want {
				t.Fatalf("ACK count %d want %d", len(got), want)
			}
			for _, v := range got {
				if v != "execution-a" {
					t.Fatal(v)
				}
			}
			md := <-peer.seen
			if len(md.Get("authorization")) != 0 || md.Get(ExecutionHeader)[0] != "execution-a" || md.Get("pail-grant-request-id")[0] != "request-a" {
				t.Fatal(md)
			}
		})
	}
}
func TestFixtureEcho(t *testing.T) {
	c := wireClient(t, &wireProxy{fixture: true})
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(ExecutionHeader, "fixture-execution"))
	var h metadata.MD
	_, err := c.GetActiveToken(ctx, &tokenpb.GetActiveTokenRequest{RobotId: "robot-1"}, grpc.Header(&h))
	if err != nil || len(h.Get(ExecutionHeader)) != 1 || h.Get(ExecutionHeader)[0] != "fixture-execution" {
		t.Fatal(h, err)
	}
}
