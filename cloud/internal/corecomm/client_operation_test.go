// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package corecomm

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	"google.golang.org/protobuf/proto"
	"os"
	"strings"
	"testing"
)

func operationVector() *pb.SubmitActionPlanRequest {
	return &pb.SubmitActionPlanRequest{SessionId: "s", RobotId: "robot-1", OperationId: "op-39", Plan: &pb.ActionPlan{PlanId: "p39-vector", ContextJson: []byte(`{"lang":"ko"}`), Steps: []*pb.PlanStep{{StepId: "one", Type: pb.StepType_STEP_TWIST, Twist: &pb.TwistCommand{LinearX: .12, AngularZ: -.3, DurationSec: 2}}, {StepId: "two", Type: pb.StepType_STEP_CUSTOM, Action: &pb.ActionSpec{Name: "pose", Classes: []pb.ActionClass{pb.ActionClass_ACTION_CLASS_MOVE, pb.ActionClass_ACTION_CLASS_NONE}, ParamsJson: []byte(`{"n":1}`)}}}}}
}
func TestP39OperationDigestVector(t *testing.T) {
	r := operationVector()
	h, e := SubmitDigest(r)
	if e != nil {
		t.Fatal(e)
	}
	b, e := proto.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("P39_OPERATION_VECTOR %s %s\n", base64.StdEncoding.EncodeToString(b), hex.EncodeToString(h))
}
func TestP39OperationReceiptIsNotNewExecution(t *testing.T) {
	req := operationVector()
	h, _ := SubmitDigest(req)
	fresh := &pb.SubmitActionPlanResponse{Status: pb.SubmitStatus_ACCEPTED, ChainId: "chain", Tokens: []*pb.SignedToken{{}}, Receipt: &pb.OperationReceipt{ContractVersion: 1, OperationId: req.OperationId, Method: pb.OperationKind_SUBMIT, PlanId: req.Plan.PlanId, RobotId: req.RobotId, RequestDigest: h, OperationState: pb.OperationState_COMMITTED, OriginalChainId: "chain", CurrentAuthorityState: "ACTIVE", DurableRecordRef: "record"}}
	if outcome, e := SubmitOutcome(req, fresh); e != nil || outcome != OperationAuthorized {
		t.Fatal(outcome, e)
	}
	historic := proto.Clone(fresh).(*pb.SubmitActionPlanResponse)
	historic.Tokens = nil
	if outcome, e := SubmitOutcome(req, historic); e != nil || outcome != OperationHistorical {
		t.Fatal("historical receipt became new dispatch", outcome, e)
	}
	historic.Tokens = fresh.Tokens
	historic.Receipt.CurrentAuthorityState = "CANCELLED"
	if outcome, e := SubmitOutcome(req, historic); e != nil || outcome != OperationHistorical {
		t.Fatal("cancelled authority became dispatch", outcome, e)
	}
	for _, mutate := range []func(*pb.OperationReceipt){func(r *pb.OperationReceipt) { r.RobotId = "other" }, func(r *pb.OperationReceipt) { r.RequestDigest = []byte("wrong") }, func(r *pb.OperationReceipt) { r.DurableRecordRef = "" }, func(r *pb.OperationReceipt) { r.OperationId = "other" }} {
		r := proto.Clone(fresh).(*pb.SubmitActionPlanResponse)
		mutate(r.Receipt)
		if _, e := SubmitOutcome(req, r); e == nil {
			t.Fatal("unbound receipt accepted")
		}
	}
	old := proto.Clone(fresh).(*pb.SubmitActionPlanResponse)
	old.Receipt = nil
	if _, e := SubmitOutcome(req, old); e == nil {
		t.Fatal("implicit downgrade")
	}
}

// 0.2.0-preview.40: there is one communication contract and no setting that selects it — any value refuses by name.
// 0.2.0-preview.41 (P40-L2): the variable's presence refuses, an empty value included; only an absent variable starts.
func TestNoContractSetting(t *testing.T) {
	if CheckNoContractSetting("") != nil {
		t.Fatal("the pure value check accepts an empty value")
	}
	for _, v := range []string{"v1", "legacy", "v2", " "} {
		if e := CheckNoContractSetting(v); e != ErrContractSettingRemoved || !strings.HasPrefix(e.Error(), "CORE_COMM_CONTRACT_SETTING_REMOVED: ") {
			t.Fatalf("%q must refuse by name: %v", v, e)
		}
	}
	if CheckNoContractSettingPresent("", false) != nil {
		t.Fatal("absent is the only accepted state")
	}
	for _, v := range []string{"", "v1", "legacy"} {
		if e := CheckNoContractSettingPresent(v, true); e != ErrContractSettingRemoved {
			t.Fatalf("present with %q must refuse by name: %v", v, e)
		}
	}
	os.Unsetenv("PAIL_CORE_COMM_CONTRACT")
	if CheckNoContractSettingEnv() != nil {
		t.Fatal("absent variable must start")
	}
	t.Setenv("PAIL_CORE_COMM_CONTRACT", "")
	if CheckNoContractSettingEnv() != ErrContractSettingRemoved {
		t.Fatal("an empty value is a present variable and refuses (P40-L2)")
	}
}
