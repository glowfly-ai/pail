// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"bytes"
	"context"
	"github.com/glowfly/pail/services/internal/grpcauth"
	pb "github.com/glowfly/pail/services/proto/robotopsv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type probeUpstream struct {
	pb.UnimplementedRobotBindingProbeServer
	fail  atomic.Bool
	calls atomic.Int32
}

func (s *probeUpstream) ProbeBinding(ctx context.Context, q *pb.ProbeBindingRequest) (*pb.ProbeBindingResponse, error) {
	s.calls.Add(1)
	if s.fail.Load() {
		return nil, status.Error(codes.Unavailable, "injected")
	}
	return &pb.ProbeBindingResponse{Nonce: q.Nonce, DeploymentId: "5e8b24a0-2319-4a53-b5cf-a03afc977301", RobotId: q.RobotId, TlsClientFingerprintSha256: strings.Repeat("a", 64), Binding: pb.Binding_BOUND}, nil
}
func TestSelfProbeUDSDoesNotRotateOrTouchMirror(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live probe profile requires Linux peer/boot identity")
	}
	upstream := &probeUpstream{}
	lis, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	g := grpc.NewServer()
	pb.RegisterRobotBindingProbeServer(g, upstream)
	go g.Serve(lis)
	defer g.Stop()
	conn, e := grpc.Dial(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	fc := newFailoverConn([]string{"first", "second"}, []*grpc.ClientConn{conn, conn}, func(string, ...any) { t.Error("read probe rotated") })
	probe, e := newSelfProbe(fc, "robot-01", "5e8b24a0-2319-4a53-b5cf-a03afc977301", strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "probe.sock")
	local, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(path, 0600)
	server := grpc.NewServer(grpc.Creds(grpcauth.UDSCreds()))
	pb.RegisterRobotAgentSelfProbeServer(server, probe)
	go server.Serve(local)
	defer server.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn, e := grpc.DialContext(ctx, "unix:"+path, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if e != nil {
		t.Fatal(e)
	}
	defer clientConn.Close()
	client := pb.NewRobotAgentSelfProbeClient(clientConn)
	nonce := bytes.Repeat([]byte{3}, 32)
	v, e := client.ProbeSelf(ctx, &pb.ProbeSelfRequest{Nonce: nonce})
	if e != nil || v.Upstream == nil {
		t.Fatal(v, e)
	}
	upstream.fail.Store(true)
	v, e = client.ProbeSelf(ctx, &pb.ProbeSelfRequest{Nonce: nonce})
	if e != nil || v.Upstream != nil || v.UnavailableReason == "" || fc.index() != 0 || upstream.calls.Load() != 2 {
		t.Fatal(v, e)
	}
	if _, e = probe.ProbeSelf(context.Background(), &pb.ProbeSelfRequest{Nonce: nonce}); status.Code(e) != codes.Unauthenticated {
		t.Fatal("unverified local peer accepted")
	}
}

// The handler's peer check is not a reason to publish the management method on
// TCP. Pin the production registration boundary as well as the wire behavior.
func TestSelfProbeRegisteredOnlyOnUDS(t *testing.T) {
	source, e := os.ReadFile("main.go")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(string(source), "RegisterRobotAgentSelfProbeServer(") != 1 || !strings.Contains(string(source), "RegisterRobotAgentSelfProbeServer(udsServer, opsProbe)") {
		t.Fatal("self probe escaped local-only listener")
	}
}
