// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package corecomm

import (
	"bytes"
	"errors"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
)

var ErrRejected = errors.New("REPORT_ACK_NOT_ACCEPTED")
var ErrReceipt = errors.New("REPORT_RECEIPT_INVALID")
var ErrPending = errors.New("REPORT_RECEIPT_PENDING")

// TerminalRejected records a rejection, never confirms an authorization effect.
var ErrTerminalRejected = errors.New("REPORT_TERMINAL_REJECTED")

func CheckReportACK(req *tp.ReportDecisionRequest, r *tp.ReportDecisionResponse, issuer bool) error {
	if r == nil {
		return ErrReceipt
	}
	if req.GetReceiptContractVersion() == 0 {
		if !r.Accepted {
			return ErrRejected
		}
		return nil
	}
	if req.GetReceiptContractVersion() != 1 {
		return ErrReceipt
	}
	x := r.GetReceipt()
	if x == nil || x.ContractVersion != 1 || x.ReportId != req.ReportId || !bytes.Equal(x.ReportDigest, req.ReportDigest) || x.RobotId != req.RobotId || x.ReceiverInstanceId == "" {
		return ErrReceipt
	}
	if (issuer || req.Fatal) && (x.Storage != tp.StorageLevel_ISSUER_DURABLE || x.JournalRecordRef == "") {
		return ErrPending
	}
	if !r.Accepted {
		if x.Storage == tp.StorageLevel_ISSUER_DURABLE && (x.Effect == tp.EffectStatus_REJECTED || x.Effect == tp.EffectStatus_UNKNOWN) && x.Disposition == tp.ReceiptDisposition_TERMINAL_REJECTED && x.JournalRecordRef != "" {
			return ErrTerminalRejected
		}
		return ErrRejected
	}
	if x.Disposition != tp.ReceiptDisposition_NEW && x.Disposition != tp.ReceiptDisposition_DUPLICATE && !(!issuer && !req.Fatal && req.StepComplete && x.Storage == tp.StorageLevel_LOCAL_DURABLE && x.EffectScope == tp.EffectScope_LOCAL_LEASE && x.Disposition == tp.ReceiptDisposition_RETRYABLE) {
		return ErrReceipt
	}
	if x.Storage != tp.StorageLevel_LOCAL_BUFFERED && x.Storage != tp.StorageLevel_LOCAL_DURABLE && x.Storage != tp.StorageLevel_ISSUER_DURABLE {
		return ErrReceipt
	}
	if req.StepComplete && (x.Storage == tp.StorageLevel_LOCAL_BUFFERED || (x.EffectScope != tp.EffectScope_LOCAL_LEASE && x.EffectScope != tp.EffectScope_ISSUER_CHAIN)) {
		return ErrPending
	}
	if req.Fatal || req.StepComplete {
		if x.Effect != tp.EffectStatus_APPLIED {
			return ErrPending
		}
		if (issuer || req.Fatal) && x.EffectScope != tp.EffectScope_ISSUER_CHAIN {
			return ErrReceipt
		}
	} else if x.Effect != tp.EffectStatus_NOT_APPLICABLE && x.Effect != tp.EffectStatus_APPLIED {
		return ErrReceipt
	}
	return nil
}

// CheckOperationReceipt validates correlation, not current authority. UNKNOWN
// remains a valid *uncertain* outcome and never becomes an applied effect.
func CheckOperationReceipt(r *pb.OperationReceipt, id, plan, robot string, kind pb.OperationKind, digest []byte) error {
	if r == nil || r.ContractVersion != 1 || r.OperationId != id || r.PlanId != plan || r.Method != kind || r.RobotId == "" ||
		(robot != "" && r.RobotId != robot) || (digest != nil && !bytes.Equal(digest, r.RequestDigest)) {
		return ErrReceipt
	}
	switch r.OperationState {
	case pb.OperationState_IN_PROGRESS, pb.OperationState_OUTCOME_UNKNOWN:
		return nil
	case pb.OperationState_COMMITTED, pb.OperationState_OP_REJECTED, pb.OperationState_EXPIRED_RECEIPT:
		if r.DurableRecordRef == "" {
			return ErrReceipt
		}
		return nil
	default:
		return ErrReceipt
	}
}
