// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package identity

// Interceptor units (§2.4). The four verdicts are covered per interceptor
// shape; the stream side additionally pins the H-B2 edge — a stream judged
// before any RecvMsg must read as unjudged, never as a pass.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// scopedMsg stands in for a generated request with a robot_id field — the
// interceptor keys on the interface, not on any proto type.
type scopedMsg struct{ robotID string }

func (m *scopedMsg) GetRobotId() string { return m.robotID }

// plainMsg has no robot_id field.
type plainMsg struct{}

func mtlsContext(t *testing.T, rawCert []byte) (context.Context, string) {
	t.Helper()
	sum := sha256.Sum256(rawCert)
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{Raw: rawCert}},
		}},
	})
	return ctx, hex.EncodeToString(sum[:])
}

func testRegistry(t *testing.T, robotFP, orchFP string) *Registry {
	t.Helper()
	return mustParse(t, `version: 1
robots:
  - robot_id: robot-1
    role: robot
    fingerprints: ["`+robotFP+`"]
  - robot_id: "*"
    role: orchestrator
    fingerprints: ["`+orchFP+`"]
`)
}

func TestInterceptorUnary(t *testing.T) {
	robotCtx, robotFP := mtlsContext(t, []byte("robot-1 leaf DER"))
	orchCtx, orchFP := mtlsContext(t, []byte("orchestrator leaf DER"))
	strangerCtx, _ := mtlsContext(t, []byte("stranger leaf DER"))
	ic := NewInterceptor(testRegistry(t, robotFP, orchFP))

	call := func(ctx context.Context, req any) (Binding, error) {
		var seen Binding
		_, err := ic.Unary(ctx, req, &grpc.UnaryServerInfo{},
			func(ctx context.Context, _ any) (any, error) {
				seen = BindingFromContext(ctx)
				return nil, nil
			})
		return seen, err
	}

	if b, err := call(robotCtx, &scopedMsg{robotID: "robot-1"}); err != nil || b.Verdict != Bound {
		t.Fatalf("registered robot must pass bound, got %s / %v", b.Verdict, err)
	}
	if b, err := call(orchCtx, &scopedMsg{robotID: "robot-1"}); err != nil || b.Verdict != Delegated {
		t.Fatalf("orchestrator must pass delegated, got %s / %v", b.Verdict, err)
	}
	if b, err := call(robotCtx, &plainMsg{}); err != nil ||
		b.Verdict != Unchecked || b.Reason != "no_robot_id_field" {
		t.Fatalf("request without robot_id must pass unchecked, got %s (%s) / %v", b.Verdict, b.Reason, err)
	}

	// Refusals: unregistered fingerprint, and a registered robot claiming
	// another robot_id. Both must be PermissionDenied naming the reason code.
	for _, tc := range []struct {
		ctx  context.Context
		req  any
		hint string
	}{
		{strangerCtx, &scopedMsg{robotID: "robot-1"}, "unregistered fingerprint"},
		{robotCtx, &scopedMsg{robotID: "robot-2"}, "robot_id mismatch"},
	} {
		_, err := ic.Unary(tc.ctx, tc.req, &grpc.UnaryServerInfo{},
			func(context.Context, any) (any, error) {
				t.Fatalf("%s: handler must not run for unbound", tc.hint)
				return nil, nil
			})
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.PermissionDenied || st.Message() != "ERR_IDENTITY_UNBOUND" {
			t.Fatalf("%s: want PermissionDenied ERR_IDENTITY_UNBOUND, got %v", tc.hint, err)
		}
	}
}

// fakeStream drives judgedStream without a live transport. RecvMsg fills the
// caller's concrete pointer — exactly what gRPC does — because the type
// assertion under test only sees what RecvMsg was handed.
type fakeStream struct {
	grpc.ServerStream
	ctx  context.Context
	msgs []any
}

func (f *fakeStream) Context() context.Context { return f.ctx }

func (f *fakeStream) RecvMsg(m any) error {
	next := f.msgs[0]
	f.msgs = f.msgs[1:]
	switch dst := m.(type) {
	case *scopedMsg:
		*dst = *next.(*scopedMsg)
	case *plainMsg:
		*dst = *next.(*plainMsg)
	}
	return nil
}

func TestInterceptorStream(t *testing.T) {
	robotCtx, robotFP := mtlsContext(t, []byte("robot-1 leaf DER"))
	strangerCtx, _ := mtlsContext(t, []byte("stranger leaf DER"))
	_, orchFP := mtlsContext(t, []byte("orchestrator leaf DER"))
	ic := NewInterceptor(testRegistry(t, robotFP, orchFP))

	err := ic.Stream(nil, &fakeStream{
		ctx:  robotCtx,
		msgs: []any{&scopedMsg{robotID: "robot-1"}},
	}, &grpc.StreamServerInfo{}, func(_ any, ss grpc.ServerStream) error {
		// H-B2 edge: before the first RecvMsg nobody judged anything.
		if b := BindingFromContext(ss.Context()); b.Verdict.String() != "invalid" {
			t.Fatalf("pre-recv binding must read invalid, got %s", b.Verdict)
		}
		if err := ss.RecvMsg(&scopedMsg{}); err != nil {
			t.Fatalf("recv: %v", err)
		}
		if b := BindingFromContext(ss.Context()); b.Verdict != Bound {
			t.Fatalf("post-recv binding must be bound, got %s (%s)", b.Verdict, b.Reason)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("bound stream must pass: %v", err)
	}

	// Unbound arrives through RecvMsg — the refusal must come out of RecvMsg,
	// not out of stream open (the robot_id does not exist at open).
	err = ic.Stream(nil, &fakeStream{
		ctx:  strangerCtx,
		msgs: []any{&scopedMsg{robotID: "robot-1"}},
	}, &grpc.StreamServerInfo{}, func(_ any, ss grpc.ServerStream) error {
		return ss.RecvMsg(&scopedMsg{})
	})
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied || st.Message() != "ERR_IDENTITY_UNBOUND" {
		t.Fatalf("unbound stream recv: want PermissionDenied ERR_IDENTITY_UNBOUND, got %v", err)
	}

	// A message without robot_id (HA replication frames) stays unchecked.
	err = ic.Stream(nil, &fakeStream{
		ctx:  strangerCtx,
		msgs: []any{&plainMsg{}},
	}, &grpc.StreamServerInfo{}, func(_ any, ss grpc.ServerStream) error {
		if err := ss.RecvMsg(&plainMsg{}); err != nil {
			return err
		}
		if b := BindingFromContext(ss.Context()); b.Verdict != Unchecked {
			t.Fatalf("no-robot_id stream message must be unchecked, got %s", b.Verdict)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unchecked stream must pass: %v", err)
	}
}

func TestLoadFromEnvDefaultIsFixedPath(t *testing.T) {
	if DefaultRegistryPath != "/etc/pail/robot_registry.yaml" {
		t.Fatalf("default registry path moved: %s", DefaultRegistryPath)
	}
	t.Setenv("PAIL_ROBOT_REGISTRY", "/nonexistent/for-this-test.yaml")
	if _, err := LoadFromEnv(); err == nil {
		t.Fatalf("missing registry file must refuse (RG-4)")
	}
}

func TestResolvedRobotBindingReusesRegistryAndJournal(t *testing.T) {
	ctx, fp := mtlsContext(t, []byte("owner"))
	_, orch := mtlsContext(t, []byte("operator"))
	ic := NewInterceptor(testRegistry(t, fp, orch))
	j := &memJournal{}
	ic.SetJournal(j)
	_, err := ic.Unary(ctx, &plainMsg{}, &grpc.UnaryServerInfo{FullMethod: "/pail.v1.PailNorthbound/CancelPlan"}, func(ctx context.Context, _ any) (any, error) {
		bound, err := AuthorizeResolvedRobot(ctx, "robot-1")
		if err != nil || BindingFromContext(bound).Verdict != Bound {
			t.Fatalf("owner: %v", err)
		}
		_, err = AuthorizeResolvedRobot(ctx, "robot-2")
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("wrong owner: %v", err)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(j.payloads) != 1 {
		t.Fatalf("resolved refusal not journaled: %d", len(j.payloads))
	}
	if _, err := AuthorizeResolvedRobot(ctx, "robot-1"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("missing registry accepted: %v", err)
	}
	dev, err := AuthorizeResolvedRobot(context.Background(), "robot-1")
	if err != nil || BindingFromContext(dev).Verdict != Unchecked {
		t.Fatalf("dev compatibility: %v", err)
	}
}
