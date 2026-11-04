// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestMOBSLocalRobotBinding(t *testing.T) {
	guard := localRobotBinding("robot-A")
	calls := 0
	next := func(context.Context, interface{}) (interface{}, error) { calls++; return "forwarded", nil }
	for _, id := range []string{"robot-a", "robot-2", ""} {
		_, err := guard(context.Background(), &pb.SubmitActionPlanRequest{RobotId: id}, &grpc.UnaryServerInfo{}, next)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("wrong target %q forwarded: %v", id, err)
		}
	}
	if calls != 0 {
		t.Fatal("wrong target reached upstream")
	}
	got, err := guard(context.Background(), &pb.SubmitActionPlanRequest{RobotId: "robot-A"}, &grpc.UnaryServerInfo{}, next)
	if err != nil || got != "forwarded" || calls != 1 {
		t.Fatalf("own target refused: %v %v", got, err)
	}
	// No client robot_id exists here; only the issuer can resolve and authorize it.
	_, err = guard(context.Background(), &pb.CancelPlanRequest{PlanId: "p"}, &grpc.UnaryServerInfo{}, next)
	if err != nil || calls != 2 {
		t.Fatal("plan-only RPC contract changed")
	}
}
