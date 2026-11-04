// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package corecomm

import (
	"errors"
	"os"

	pb "github.com/glowfly/pail/services/proto/pailv1"
)

const (
	OperationAuthorized         = "AUTHORIZED"
	OperationRejected           = "REJECTED"
	OperationHistorical         = "HISTORICAL_ONLY"
	OperationUnknown            = "UNKNOWN"
	OperationWithdrawalRecorded = "WITHDRAWAL_RECORDED"
)

// SubmitOutcome classifies evidence, not physical execution. In particular a
// historical result with no newly issued token list must not restart a demo's
// controller. An OEM with its own durable execution protocol decides separately.
func SubmitOutcome(req *pb.SubmitActionPlanRequest, r *pb.SubmitActionPlanResponse) (string, error) {
	if req == nil || req.Plan == nil || r == nil {
		return OperationUnknown, ErrReceipt
	}
	id := req.OperationId
	if id == "" {
		id = req.Plan.PlanId
	}
	digest, e := SubmitDigest(req)
	if e != nil {
		return OperationUnknown, e
	}
	if e = CheckOperationReceipt(r.Receipt, id, req.Plan.PlanId, req.RobotId, pb.OperationKind_SUBMIT, digest); e != nil {
		return OperationUnknown, e
	}
	switch r.Receipt.OperationState {
	case pb.OperationState_OP_REJECTED:
		if r.Status != pb.SubmitStatus_REJECTED {
			return OperationUnknown, ErrReceipt
		}
		return OperationRejected, nil
	case pb.OperationState_COMMITTED:
		if r.Status != pb.SubmitStatus_ACCEPTED || r.ChainId == "" || r.Receipt.OriginalChainId != r.ChainId {
			return OperationUnknown, ErrReceipt
		}
		if r.Receipt.CurrentAuthorityState != "ACTIVE" || len(r.Tokens) == 0 {
			return OperationHistorical, nil
		}
		return OperationAuthorized, nil
	default:
		return OperationUnknown, nil
	}
}

// A cancel receipt is authorization withdrawal, never physical-stop evidence.
func CancelOutcome(req *pb.CancelPlanRequest, r *pb.CancelPlanResponse, robot string) (string, error) {
	if req == nil || r == nil {
		return OperationUnknown, ErrReceipt
	}
	id := req.OperationId
	if id == "" {
		id = req.PlanId
	}
	digest, e := CancelDigest(req)
	if e != nil {
		return OperationUnknown, e
	}
	if e = CheckOperationReceipt(r.Receipt, id, req.PlanId, robot, pb.OperationKind_CANCEL, digest); e != nil {
		return OperationUnknown, e
	}
	if r.PlanId != req.PlanId {
		return OperationUnknown, ErrReceipt
	}
	if r.Receipt.OperationState == pb.OperationState_COMMITTED && r.Cancelled && r.Receipt.CurrentAuthorityState != "ACTIVE" {
		return OperationWithdrawalRecorded, nil
	}
	if r.Receipt.OperationState == pb.OperationState_OP_REJECTED && !r.Cancelled {
		return OperationRejected, nil
	}
	return OperationUnknown, nil
}

// There is one communication contract (0.2.0-preview.40). PAIL_CORE_COMM_CONTRACT used to select `legacy` (the C0 wire)
// or `v1`; the setting itself is gone — a value of any kind refuses startup with a message that says to unset it, never
// a silent interpretation. The same rule and the same message live in the gate (core_contract.hpp), the Python examples
// (core_operation_wire.py), the Microduck adapter and the hardware scripts; spec/CORE_COMM.md is the source of the
// wording. The wire keeps its version numbers (receipt contract_version 1, census header `v1`): those are protocol
// versions, not a mode.
var ErrContractSettingRemoved = errors.New(ContractSettingRemovedMessage)

const ContractSettingRemovedMessage = "CORE_COMM_CONTRACT_SETTING_REMOVED: PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); unset it"

// CheckNoContractSetting is the pure value check: a non-empty value refuses. Callers that read the environment use
// CheckNoContractSettingEnv (P40-L2: the variable's *presence* refuses, an empty value included).
func CheckNoContractSetting(value string) error {
	if value == "" {
		return nil
	}
	return ErrContractSettingRemoved
}

// CheckNoContractSettingPresent refuses when the variable is present at all — any value, including an empty one.
// `PAIL_CORE_COMM_CONTRACT=` left in an old deployment file is exactly the setting the message tells the operator to
// unset; giving the empty value a meaning would be a second interpretation of a variable that has none.
func CheckNoContractSettingPresent(value string, present bool) error {
	if present {
		return ErrContractSettingRemoved
	}
	return nil
}

// CheckNoContractSettingEnv reads PAIL_CORE_COMM_CONTRACT once with os.LookupEnv and applies the presence rule.
func CheckNoContractSettingEnv() error {
	return CheckNoContractSettingPresent(os.LookupEnv("PAIL_CORE_COMM_CONTRACT"))
}
