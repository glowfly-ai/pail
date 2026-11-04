// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package grpclive bounds how long a dead gRPC connection goes unnoticed. It
// is kept apart from grpcauth so that binaries which only authenticate (the
// telemetry daemon) do not link it.
package grpclive

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// Package grpclive bounds how long a dead gRPC connection goes unnoticed.
//
// Upstream liveness (0.2.0-preview.9, eighth evaluation P8-M1).
//
// Without keepalive the gateway learns that its Issuer connection is dead only
// from TCP. When the Issuer restarts while the gateway is cut off, the reset
// never arrives; after the network returns, the gateway keeps sending on a
// connection nobody holds and every RPC ends in DeadlineExceeded until the
// kernel gives up — one to three minutes measured, during which the gateway
// stays offline and serves the superseded plan's window. Pings bound that
// detection: a ping unanswered for UpstreamKeepaliveTimeout closes the
// transport, and the bounded reconnect backoff dials a fresh connection.
//
// Both ends must agree: a gRPC server refuses pings more frequent than its
// enforcement minimum (default five minutes) with GOAWAY too_many_pings, so
// every server a gateway dials installs ServerKeepalive.
const (
	UpstreamKeepaliveTime    = 10 * time.Second
	UpstreamKeepaliveTimeout = 5 * time.Second
	ServerKeepaliveMinTime   = 5 * time.Second
)

// UpstreamKeepalive is the dial option for a gateway's upstream channel.
func UpstreamKeepalive() grpc.DialOption {
	return grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                UpstreamKeepaliveTime,
		Timeout:             UpstreamKeepaliveTimeout,
		PermitWithoutStream: true,
	})
}

// ServerKeepalive lets clients ping at the UpstreamKeepalive rate.
func ServerKeepalive() grpc.ServerOption {
	return grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             ServerKeepaliveMinTime,
		PermitWithoutStream: true,
	})
}
