// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"sync/atomic"
	"testing"
	"time"
)

type receiptAckClient struct {
	fakeTokenClient
	callsToReport atomic.Int64
	invalid       *tokenpb.ReportDecisionResponse
}

func (f *receiptAckClient) ReportDecision(ctx context.Context, r *tokenpb.ReportDecisionRequest, o ...grpc.CallOption) (*tokenpb.ReportDecisionResponse, error) {
	if f.callsToReport.Add(1) == 1 {
		return f.invalid, nil
	}
	return &tokenpb.ReportDecisionResponse{Accepted: true}, nil
}
func TestCoreCommQueueRequiresAcceptedResponse(t *testing.T) {
	// Neither answer is delivery. A nil answer is retried (the wire said nothing); a legacy accepted=false is
	// the Issuer's definitive refusal — retained, never confirmed, and the queue moves on (see
	// TestLegacyRefusalDoesNotBlockTheQueue for the head-of-line case found in the preview.35 pre-seal).
	for _, tc := range []struct {
		name     string
		response *tokenpb.ReportDecisionResponse
		retried  bool
	}{{"rejected", &tokenpb.ReportDecisionResponse{Accepted: false}, false}, {"nil", nil, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &receiptAckClient{invalid: tc.response}
			q, err := newReportQueue(f, reportQueueOptions{RobotID: "robot-1", RetryMax: time.Millisecond, NoJitter: true})
			if err != nil {
				t.Fatal(err)
			}
			defer q.close()
			q.push(blockReport(1))
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) && f.callsToReport.Load() < 1 {
				time.Sleep(time.Millisecond)
			}
			if tc.retried {
				for time.Now().Before(deadline) && f.callsToReport.Load() < 2 {
					time.Sleep(time.Millisecond)
				}
				if f.callsToReport.Load() < 2 {
					t.Fatal("invalid application ACK was discarded rather than retried")
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
			if n := f.callsToReport.Load(); n != 1 {
				t.Fatalf("a definitive legacy refusal was retried (%d calls)", n)
			}
			if q.sent.Load() != 0 || q.refused.Load() != 1 {
				t.Fatalf("sent=%d refused=%d: a refused report is neither delivered nor silently dropped", q.sent.Load(), q.refused.Load())
			}
		})
	}
}
func TestCoreCommFatalInvalidACKCannotConfirm(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response *tokenpb.ReportDecisionResponse
	}{{"rejected", &tokenpb.ReportDecisionResponse{Accepted: false}}, {"nil", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &receiptAckClient{invalid: tc.response}
			q, err := newReportQueue(f, reportQueueOptions{RobotID: "robot-1"})
			if err != nil {
				t.Fatal(err)
			}
			defer q.close()
			p := &tokenProxy{c: f, m: newTokenMirror(f, "robot-1", 0), f: q}
			r := fatalReq()
			resp, err := p.ReportDecision(context.Background(), r)
			if err == nil {
				t.Fatalf("invalid ACK must not confirm fatal: resp=%v", resp)
			}
		})
	}
}

func TestCoreCommFatalHandoffMemoryIsNotDurable(t *testing.T) {
	f := &fakeTokenClient{}
	f.reportFail.Store(true)
	q, err := newReportQueue(f, reportQueueOptions{RobotID: "robot-1"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	if q.pushFatalWithAck(fatalReq(), nil) {
		t.Fatal("memory-only queue claimed durable ownership")
	}
}

type legacyNorth struct{ pb.PailNorthboundClient }

func (*legacyNorth) SubmitActionPlan(context.Context, *pb.SubmitActionPlanRequest, ...grpc.CallOption) (*pb.SubmitActionPlanResponse, error) {
	return &pb.SubmitActionPlanResponse{Status: pb.SubmitStatus_ACCEPTED, ChainId: "legacy-chain"}, nil
}
func TestCoreCommProxyRejectsLegacySuccessWithoutReceipt(t *testing.T) {
	p := &northProxy{c: &legacyNorth{}, m: newTokenMirror(&fakeTokenClient{}, "robot-1", 0)}
	_, err := p.SubmitActionPlan(context.Background(), &pb.SubmitActionPlanRequest{RobotId: "robot-1", OperationId: "id", Plan: &pb.ActionPlan{PlanId: "plan"}})
	if err == nil {
		t.Fatal("a success without a receipt was promoted to C1")
	}
	// 0.2.0-preview.40: no C0 proxy mode remains — a submit without an operation id is still judged on its receipt
	if _, err = p.SubmitActionPlan(context.Background(), &pb.SubmitActionPlanRequest{RobotId: "robot-1", Plan: &pb.ActionPlan{PlanId: "plan"}}); err == nil {
		t.Fatal("a receipt-less success must not pass once the contract is v1 only")
	}
}
