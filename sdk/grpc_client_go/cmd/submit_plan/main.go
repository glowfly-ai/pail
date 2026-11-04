// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"context"
	"flag"
	"log"
	"time"

	"google.golang.org/grpc"

	// 생성 절차는 README. 경로는 이 모듈의 go.mod 경로 기준이어야 한다 —
	// `proto/pailv1` 은 표준도 모듈도 아니라 어느 트리에서도 해석되지 않았다.
	pb "github.com/glowfly/pail/tools/grpc_client_go/proto/pailv1"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "pail-services gRPC addr")
	robot := flag.String("robot", "robot-1", "robot_id")
	planID := flag.String("plan", "pvs-plan-1", "plan_id")
	target := flag.String("target", "880123", "target_object_id")
	flag.Parse()

	conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	c := pb.NewPailNorthboundClient(conn)

	req := &pb.SubmitActionPlanRequest{
		SessionId: "manual",
		RobotId:   *robot,
		Plan: &pb.ActionPlan{
			PlanId: *planID,
			Steps: []*pb.PlanStep{
				{StepId: "s1", Type: pb.StepType_STEP_TWIST, TargetObjectId: *target, Twist: &pb.TwistCommand{LinearX: 0.1, AngularZ: 0.0, DurationSec: 1.0}},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.SubmitActionPlan(ctx, req)
	if err != nil {
		log.Fatalf("SubmitActionPlan: %v", err)
	}
	log.Printf("status=%v chain_id=%s tokens=%d", resp.GetStatus(), resp.GetChainId(), len(resp.GetTokens()))

	// 거부의 계약면은 `Denial` 이다. `rejected_reason` 은 안정성 보장이 없는
	// 사람용 문자열이라 여기서 읽지 않는다 — 최소 예제가 그것을 읽으면 베껴
	// 가는 쪽은 틀린 계약을 배운다.
	if d := resp.GetDenial(); d != nil {
		log.Printf("denial reason=%s(%d) disposition=%v severity=%v epoch=%d",
			d.GetReasonCode(), d.GetReasonValue(), d.GetDisposition(),
			d.GetSeverity(), d.GetObservedEpoch())
		// 영값에서 뜻을 읽지 않는다: retry_after_ms=0 과 "필드가 오지 않았다" 는
		// proto3 에서 같은 바이트다. 금지인지 여부는 bool 이 말한다.
		if d.GetRetryForbidden() {
			log.Printf("  -> retry forbidden")
		} else {
			log.Printf("  -> minimum retry delay %v (a lower bound, not a schedule)",
				time.Duration(d.GetRetryAfterMs())*time.Millisecond)
		}
		// disposition 별 처리와 severity 기반 경보 라우팅은
		// cmd/fms_denial_example 가 끝까지 보여 준다.
	}
}
