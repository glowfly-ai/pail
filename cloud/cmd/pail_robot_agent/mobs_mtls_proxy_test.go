// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Overlay into cmd/pail_robot_agent: production proxy and interceptors, real TLS
// on both hops. The tiny upstream models only plan-owner resolution; it is NOT
// the full issuer implementation or a fake-robot motion test.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/glowfly/pail/services/internal/corecomm"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/grpcauth"
	"github.com/glowfly/pail/services/internal/identity"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type mobsPlanOwner struct {
	pb.UnimplementedPailNorthboundServer
	mu        sync.Mutex
	cancelled bool
	callers   []string
}

func (s *mobsPlanOwner) authorize(ctx context.Context, plan string) error {
	if plan != "plan-robot-1" {
		return status.Error(codes.NotFound, "unknown plan")
	}
	kind, fp := grpcauth.CallerFromContext(ctx)
	s.callers = append(s.callers, kind+":"+fp)
	_, err := identity.AuthorizeResolvedRobot(ctx, "robot-1")
	return err
}
func (s *mobsPlanOwner) CancelPlan(ctx context.Context, r *pb.CancelPlanRequest) (*pb.CancelPlanResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.authorize(ctx, r.GetPlanId()); err != nil {
		return nil, err
	}
	s.cancelled = true
	// 0.2.0-preview.40: the proxy confirms every answer on its C1 receipt — the fake Issuer answers like a v1 one
	digest, err := corecomm.CancelDigest(r)
	if err != nil {
		return nil, err
	}
	id := r.GetOperationId()
	if id == "" {
		id = r.GetPlanId()
	}
	return &pb.CancelPlanResponse{PlanId: r.GetPlanId(), Cancelled: true, Receipt: &pb.OperationReceipt{ContractVersion: 1, OperationId: id, PlanId: r.GetPlanId(), RobotId: "robot-1",
		Method: pb.OperationKind_CANCEL, RequestDigest: digest, OperationState: pb.OperationState_COMMITTED, DurableRecordRef: "mobs-test-journal", CurrentAuthorityState: "WITHDRAWN"}}, nil
}
func (s *mobsPlanOwner) GetPlanStatus(ctx context.Context, r *pb.GetPlanStatusRequest) (*pb.GetPlanStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.authorize(ctx, r.GetPlanId()); err != nil {
		return nil, err
	}
	return &pb.GetPlanStatusResponse{PlanId: r.GetPlanId(), Detail: "private-owner-state"}, nil
}

type mobsProxyFixture struct {
	upstream                                       *mobsPlanOwner
	direct, own, wrong, unknown, expired, operator pb.PailNorthboundClient
	mirror                                         *tokenMirror
	mu                                             sync.Mutex
	inbound                                        []string
	ownFP, wrongFP                                 string
}

func mobsProxySetup(t *testing.T) *mobsProxyFixture {
	t.Helper()
	now := time.Now()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated MOBS proxy CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(serial int64, name string, expired bool) tls.Certificate {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		end := now.Add(time.Hour)
		if expired {
			end = now.Add(-time.Minute)
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		d, e := x509.CreateCertificate(rand.Reader, c, ca, p, key)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{d}, PrivateKey: k}
	}
	serverCert := leaf(2, "mobs.test", false)
	own := leaf(3, "robot-1", false)
	wrong := leaf(4, "robot-2", false)
	unknown := leaf(5, "unregistered", false)
	expired := leaf(6, "expired", true)
	operator := leaf(7, "operator", false)
	f := &mobsProxyFixture{upstream: &mobsPlanOwner{}, ownFP: fmt.Sprintf("%x", sha256.Sum256(own.Certificate[0])), wrongFP: fmt.Sprintf("%x", sha256.Sum256(wrong.Certificate[0]))}
	reg, err := identity.Parse([]byte(fmt.Sprintf("version: 1\nrobots:\n - robot_id: robot-1\n   role: robot\n   fingerprints: [%q]\n - robot_id: robot-2\n   role: robot\n   fingerprints: [%q]\n - robot_id: \"*\"\n   role: orchestrator\n   fingerprints: [%q]\n", f.ownFP, f.wrongFP, fmt.Sprintf("%x", sha256.Sum256(operator.Certificate[0])))))
	if err != nil {
		t.Fatal(err)
	}
	serve := func(service pb.PailNorthboundServer, proxy bool) *bufconn.Listener {
		ic := identity.NewInterceptor(reg)
		chain := []grpc.UnaryServerInterceptor{ic.Unary}
		if proxy {
			observe := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (interface{}, error) {
				kind, fp := grpcauth.CallerFromContext(ctx)
				f.mu.Lock()
				f.inbound = append(f.inbound, kind+":"+fp)
				f.mu.Unlock()
				return next(ctx, req)
			}
			chain = []grpc.UnaryServerInterceptor{observe, localRobotBinding("robot-1"), ic.Unary}
		}
		g := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12})), grpc.ChainUnaryInterceptor(chain...))
		pb.RegisterPailNorthboundServer(g, service)
		l := bufconn.Listen(1024 * 1024)
		go g.Serve(l)
		t.Cleanup(func() { g.Stop(); l.Close() })
		return l
	}
	dial := func(l *bufconn.Listener, cert tls.Certificate) pb.PailNorthboundClient {
		c, e := grpc.DialContext(context.Background(), "mobs.test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return l.Dial() }), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "mobs.test", MinVersion: tls.VersionTLS12})))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Close() })
		return pb.NewPailNorthboundClient(c)
	}
	upstream := serve(f.upstream, false)
	f.mirror = &tokenMirror{interval: time.Second}
	proxy := serve(&northProxy{c: dial(upstream, own), m: f.mirror}, true)
	f.direct = dial(upstream, wrong)
	f.own = dial(proxy, own)
	f.wrong = dial(proxy, wrong)
	f.unknown = dial(proxy, unknown)
	f.expired = dial(proxy, expired)
	f.operator = dial(proxy, operator)
	return f
}
func mobsContext(t *testing.T) context.Context {
	ctx, c := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(c)
	return ctx
}
func TestMOBSMTLSProxyOwnCancel(t *testing.T) {
	f := mobsProxySetup(t)
	r, e := f.own.CancelPlan(mobsContext(t), &pb.CancelPlanRequest{PlanId: "plan-robot-1"})
	if e != nil || !r.GetCancelled() {
		t.Fatalf("own positive control: %v %v", r, e)
	}
}
func TestMOBSMTLSDirectWrongCancelDenied(t *testing.T) {
	f := mobsProxySetup(t)
	r, e := f.direct.CancelPlan(mobsContext(t), &pb.CancelPlanRequest{PlanId: "plan-robot-1"})
	if status.Code(e) != codes.PermissionDenied || r.GetCancelled() || f.upstream.cancelled {
		t.Fatalf("direct control: %v %v", r, e)
	}
}
func TestMOBSMTLSProxyWrongScopedDenied(t *testing.T) {
	f := mobsProxySetup(t)
	_, e := f.wrong.SubmitActionPlan(mobsContext(t), &pb.SubmitActionPlanRequest{RobotId: "robot-1"})
	if status.Code(e) != codes.PermissionDenied {
		t.Fatalf("scoped wrong leaf control: %v", e)
	}
}
func TestMOBSMTLSProxyExpiredDenied(t *testing.T) {
	f := mobsProxySetup(t)
	r, e := f.expired.CancelPlan(mobsContext(t), &pb.CancelPlanRequest{PlanId: "plan-robot-1"})
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upstream.mu.Lock()
	defer f.upstream.mu.Unlock()
	if e == nil || r.GetCancelled() || len(f.inbound) != 0 || len(f.upstream.callers) != 0 {
		t.Fatalf("expired reached handler: %v %v", r, e)
	}
	t.Logf("expired rejected before application: %v", status.Code(e))
}
func TestMOBSMTLSProxyWrongCancelDenied(t *testing.T) {
	f := mobsProxySetup(t)
	r, e := f.wrong.CancelPlan(mobsContext(t), &pb.CancelPlanRequest{PlanId: "plan-robot-1"})
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upstream.mu.Lock()
	defer f.upstream.mu.Unlock()
	if status.Code(e) != codes.PermissionDenied || r.GetCancelled() || f.upstream.cancelled {
		t.Fatalf("PROXY_IDENTITY_BREACH: inbound=%v upstream=%v response=%v error=%v cancelled=%v; want PermissionDenied and no mutation", f.inbound, f.upstream.callers, r, e, f.upstream.cancelled)
	}
}
func TestMOBSMTLSProxyWrongStatusDenied(t *testing.T) {
	f := mobsProxySetup(t)
	r, e := f.wrong.GetPlanStatus(mobsContext(t), &pb.GetPlanStatusRequest{PlanId: "plan-robot-1"})
	if status.Code(e) != codes.PermissionDenied || r != nil {
		t.Fatalf("PROXY_STATUS_DISCLOSURE: response=%v error=%v; want PermissionDenied", r, e)
	}
}
func TestMOBSMTLSProxyUnregisteredCancelDenied(t *testing.T) {
	f := mobsProxySetup(t)
	r, e := f.unknown.CancelPlan(mobsContext(t), &pb.CancelPlanRequest{PlanId: "plan-robot-1"})
	if status.Code(e) != codes.PermissionDenied || r.GetCancelled() {
		t.Fatalf("UNREGISTERED_PROXY_BREACH: response=%v error=%v; want PermissionDenied", r, e)
	}
}

func TestMOBSMTLSProxyDelegatedOperator(t *testing.T) {
	f := mobsProxySetup(t)
	r, e := f.operator.CancelPlan(mobsContext(t), &pb.CancelPlanRequest{PlanId: "plan-robot-1"})
	if e != nil || !r.GetCancelled() {
		t.Fatalf("registered operator: %v %v", r, e)
	}
}
func TestMOBSMTLSProxyRefusalNeverReachesUpstreamOrInvalidates(t *testing.T) {
	f := mobsProxySetup(t)
	_, err := f.wrong.CancelPlan(mobsContext(t), &pb.CancelPlanRequest{PlanId: "plan-robot-1"})
	f.upstream.mu.Lock()
	defer f.upstream.mu.Unlock()
	f.mirror.mu.Lock()
	defer f.mirror.mu.Unlock()
	if status.Code(err) != codes.PermissionDenied || len(f.upstream.callers) != 0 || f.mirror.gen != 0 {
		t.Fatalf("denial side effects: upstream=%v gen=%v err=%v", f.upstream.callers, f.mirror.gen, err)
	}
}
