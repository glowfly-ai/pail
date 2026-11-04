// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package identity

// One definition, six registrations (implementation contract DC-6). The interceptor
// judges every server call against the robot registry; the structural check
// (RED-C2) watches the six grpc.NewServer sites, not this file — an orphan
// interceptor passes its units by direct call.

import (
	"context"
	"os"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/glowfly/pail/services/internal/grpcauth"
)

// DefaultRegistryPath is where deployments keep the registry when
// PAIL_ROBOT_REGISTRY is unset — same fixed-path convention as
// /etc/pail/policy.yaml.
const DefaultRegistryPath = "/etc/pail/robot_registry.yaml"

// LoadFromEnv loads the registry from PAIL_ROBOT_REGISTRY (default
// DefaultRegistryPath). An error is RG-4: the caller must refuse to start.
func LoadFromEnv() (*Registry, error) {
	path := os.Getenv("PAIL_ROBOT_REGISTRY")
	if path == "" {
		path = DefaultRegistryPath
	}
	return Load(path)
}

// robotScoped is satisfied by every generated request type that carries a
// robot_id field (§2.4 DC-5). A type assertion, not a method list: a new RPC
// with that field is enforced without its author doing anything — a method
// list works the other way around (doing nothing is a bypass).
type robotScoped interface{ GetRobotId() string }

type bindingKey struct{}
type resolverKey struct{}
type resolver struct {
	interceptor *Interceptor
	method      string
}
type resolvedRobot string

func (r resolvedRobot) GetRobotId() string { return string(r) }

// AuthorizeResolvedRobot applies the same registry policy after a handler has
// resolved a resource (such as a plan_id) to its owning robot. Call while the
// resource is locked, before returning its state or causing any side effect.
// The interceptor capability is local context state, never client metadata.
func AuthorizeResolvedRobot(ctx context.Context, robotID string) (context.Context, error) {
	if r, ok := ctx.Value(resolverKey{}).(resolver); ok && r.interceptor != nil {
		b, err := r.interceptor.judge(ctx, resolvedRobot(robotID), r.method)
		return WithBinding(ctx, b), err
	}
	kind, _ := grpcauth.CallerFromContext(ctx)
	// A certificate without the registry capability must never bypass binding.
	if kind != grpcauth.CallerUnknown && kind != grpcauth.CallerUDS {
		return ctx, status.Error(codes.PermissionDenied, "ERR_IDENTITY_UNBOUND")
	}
	// Preserve the existing explicitly unchecked dev/UDS plane. This is not a
	// certificate ownership assertion; production TCP still requires mTLS.
	return WithBinding(ctx, Binding{Verdict: Unchecked, Reason: "caller_kind=" + kind}), nil
}

// WithBinding records the identity judgment in the context for the handler
// and the journal (§2.8).
func WithBinding(ctx context.Context, b Binding) context.Context {
	return context.WithValue(ctx, bindingKey{}, b)
}

// BindingFromContext returns the judgment for this call. If nobody judged,
// the zero Binding comes back and its verdict reads "invalid" — never a pass
// (H-B2).
func BindingFromContext(ctx context.Context) Binding {
	b, _ := ctx.Value(bindingKey{}).(Binding)
	return b
}

// Interceptor carries the loaded registry into the gRPC option lists.
type Interceptor struct {
	registry *Registry

	// journal is the refusal sink (refusal_journal.go). nil where no journal
	// exists (robot-agent, cloud standby) — nil means "this process holds no
	// evidence store", never "do not record".
	jmu     sync.RWMutex
	journal Journal

	rmu      sync.Mutex
	refusals map[string]*refusalSeen
}

func NewInterceptor(r *Registry) *Interceptor { return &Interceptor{registry: r} }

// judge is the single judgment path for both interceptor shapes. The returned
// error is the refusal (already a gRPC status); a nil error means the call
// proceeds with the returned Binding in its context.
func (i *Interceptor) judge(ctx context.Context, msg any, method string) (Binding, error) {
	rs, scoped := msg.(robotScoped)
	if !scoped {
		// No robot_id field — unchecked by §2.5, and recorded as such: passing
		// is deliberate, passing under the same value as checked is what H-B2
		// forbids.
		return Binding{Verdict: Unchecked, Reason: "no_robot_id_field"}, nil
	}
	kind, id := grpcauth.CallerFromContext(ctx)
	b := i.registry.Bind(kind, id, rs.GetRobotId())
	if b.Verdict == Unbound {
		// §2.6: this refusal covers both "misconfiguration" and "intrusion";
		// the interceptor does not decide which — record 90 keeps caller_kind
		// and the fingerprint so the distinction survives to the post-incident
		// trace. Measured 2026-08-12: without that write the refusal left the
		// journal unchanged, and this comment was a promise nothing kept.
		i.journalRefusal(method, kind, id, rs.GetRobotId(), b.Reason)
		return b, status.Error(codes.PermissionDenied, "ERR_IDENTITY_UNBOUND")
	}
	return b, nil
}

// Unary judges the request message (§2.4).
func (i *Interceptor) Unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	b, err := i.judge(ctx, req, info.FullMethod)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, resolverKey{}, resolver{interceptor: i, method: info.FullMethod})
	return handler(WithBinding(ctx, b), req)
}

// Stream judges every received message. The robot_id of a streaming RPC
// (SubscribeBeaconsRequest) only exists inside RecvMsg — an interceptor that
// judges at stream open would wave every stream through as unchecked.
func (i *Interceptor) Stream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, &judgedStream{ServerStream: ss, i: i, method: info.FullMethod})
}

type judgedStream struct {
	grpc.ServerStream
	i      *Interceptor
	method string
	// binding is the latest judgment. Before the first RecvMsg it is the zero
	// Binding, whose verdict reads "invalid" — a stream that never received
	// anything was never judged, and must not read as judged (H-B2).
	binding Binding
}

func (s *judgedStream) RecvMsg(m any) error {
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	b, err := s.i.judge(s.ServerStream.Context(), m, s.method)
	if err != nil {
		return err
	}
	s.binding = b
	return nil
}

func (s *judgedStream) Context() context.Context {
	return WithBinding(s.ServerStream.Context(), s.binding)
}
