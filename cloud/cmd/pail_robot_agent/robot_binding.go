// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	"github.com/glowfly/pail/services/internal/grpcauth"
	"github.com/glowfly/pail/services/internal/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// localRobotBinding catches an adapter wired to the wrong agent before forwarding
// or consuming authority. It supplements (never substitutes for) issuer mTLS
// authorization. It also binds the local agent identity into server-owned context
// so plan-only proxies can authorize the original caller before credential substitution.
func localRobotBinding(robotID string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (interface{}, error) {
		if r, ok := req.(interface{ GetRobotId() string }); ok && r.GetRobotId() != robotID {
			return nil, status.Error(codes.PermissionDenied, "LOCAL_ROBOT_BINDING_MISMATCH")
		}
		return next(context.WithValue(ctx, localAgentRobotKey{}, robotID), req)
	}
}

// localAgentRobotKey cannot be supplied by incoming gRPC metadata.
type localAgentRobotKey struct{}

// authorizePlanProxy checks the original caller before using the agent's upstream
// certificate. The issuer separately resolves the plan owner against that agent.
func authorizePlanProxy(ctx context.Context) error {
	robotID, _ := ctx.Value(localAgentRobotKey{}).(string)
	if robotID == "" {
		kind, _ := grpcauth.CallerFromContext(ctx)
		if kind != grpcauth.CallerUnknown && kind != grpcauth.CallerUDS {
			return status.Error(codes.PermissionDenied, "LOCAL_ROBOT_BINDING_MISSING")
		}
		// Legacy in-process dev tests have no transport or local-agent context.
		return nil
	}
	_, err := identity.AuthorizeResolvedRobot(ctx, robotID)
	return err
}
