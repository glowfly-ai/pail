// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/glowfly/pail/services/internal/corecomm"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/glowfly/pail/services/internal/grpcauth"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "pail-services gRPC addr")
	robot := flag.String("robot", "robot-1", "robot_id")
	planID := flag.String("plan", "pvs-plan-1", "plan_id")
	target := flag.String("target", "880123", "target_object_id")
	contextJSON := flag.String("context", "", "AL-2 pass-through context_json bytes (sealed, never interpreted by the issuer)")
	actionSpec := flag.String("action", "", "AL-3 action spec `name[:CLASS,CLASS]` (classes MOVE|MANIPULATE|ACTUATE|NONE); empty = derived from step type")
	report := flag.Bool("report", false, "after accept, report a decision to TokenService (audit/burst demo)")
	decision := flag.String("decision", "PERMIT", "decision to report: PERMIT|BLOCK|ESTOP")
	fatal := flag.Bool("fatal", false, "report fatal=true (BLOCK/ESTOP revokes the chain)")
	reason := flag.String("reason", "OK", "reason code string for the reported decision")
	useTLS := flag.Bool("tls", grpcauth.TLSEnabled(), "use mTLS (default from PAIL_GRPC_TLS; ignored for unix: addr)")
	caPath := flag.String("ca", "", "CA cert path (default PAIL_GRPC_CA or /etc/pail/grpc_certs/ca.crt)")
	certPath := flag.String("cert", "", "client cert path (default PAIL_GRPC_CERT or /etc/pail/grpc_certs/client.crt)")
	keyPath := flag.String("key", "", "client key path (default PAIL_GRPC_KEY or /etc/pail/grpc_certs/client.key)")
	stepType := flag.String("step-type", "twist", "plan step type: twist|pick|place")
	steps := flag.Int("steps", 1, "number of identical steps in the plan")
	duration := flag.Float64("duration", 1.0, "per-step twist duration_sec")
	flag.Parse()

	var st pb.StepType
	switch *stepType {
	case "twist":
		st = pb.StepType_STEP_TWIST
	case "pick":
		st = pb.StepType_STEP_PICK
	case "place":
		st = pb.StepType_STEP_PLACE
	default:
		log.Fatalf("unknown -step-type %q (twist|pick|place)", *stepType)
	}

	dialOpts, err := grpcauth.ToolDialOptions(*addr, *useTLS, *caPath, *certPath, *keyPath)
	if err != nil {
		log.Fatalf("grpc credentials: %v", err)
	}
	conn, err := grpc.Dial(*addr, dialOpts...)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	c := pb.NewPailNorthboundClient(conn)

	var planSteps []*pb.PlanStep
	for i := 1; i <= *steps; i++ {
		planSteps = append(planSteps, &pb.PlanStep{
			StepId: fmt.Sprintf("s%d", i), Type: st, TargetObjectId: *target,
			Twist:  &pb.TwistCommand{LinearX: 0.1, AngularZ: 0.0, DurationSec: *duration},
			Action: parseActionSpec(*actionSpec),
		})
	}

	req := &pb.SubmitActionPlanRequest{
		SessionId: "manual",
		RobotId:   *robot,
		Plan: &pb.ActionPlan{
			PlanId:      *planID,
			Steps:       planSteps,
			ContextJson: []byte(*contextJSON),
		},
	}

	if modeErr := corecomm.CheckNoContractSettingEnv(); modeErr != nil {
		log.Fatal(modeErr)
	}
	req.OperationId = *planID
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.SubmitActionPlan(ctx, req)
	if err != nil {
		log.Fatalf("SubmitActionPlan: %v", err)
	}
	outcome, receiptErr := corecomm.SubmitOutcome(req, resp)
	if receiptErr != nil {
		log.Fatalf("OPERATION_RECEIPT_INVALID: %v", receiptErr)
	}
	log.Printf("operation_outcome=%s (authorization receipt, not physical execution)", outcome)
	firstTokenID := ""
	if len(resp.Tokens) > 0 && resp.Tokens[0] != nil {
		var token pb.ActionToken
		if len(resp.Tokens[0].ActionTokenBytes) == 0 || proto.Unmarshal(resp.Tokens[0].ActionTokenBytes, &token) != nil {
			log.Fatal("SIGNED_TOKEN_BYTES_INVALID")
		}
		firstTokenID = token.TokenId
	}
	log.Printf("status=%v chain_id=%s rejected=%s tokens=%d token_id=%s", resp.Status, resp.ChainId, resp.RejectedReason, len(resp.Tokens), firstTokenID)

	if *report && outcome == corecomm.OperationAuthorized && firstTokenID != "" {
		var dec tokenpb.Decision
		switch *decision {
		case "PERMIT":
			dec = tokenpb.Decision_PERMIT
		case "BLOCK":
			dec = tokenpb.Decision_BLOCK
		case "ESTOP":
			dec = tokenpb.Decision_ESTOP
		default:
			log.Fatalf("unknown -decision %q (PERMIT|BLOCK|ESTOP)", *decision)
		}
		tc := tokenpb.NewTokenServiceClient(conn)
		reportRequest := &tokenpb.ReportDecisionRequest{
			RobotId:    *robot,
			ChainId:    resp.ChainId,
			TokenId:    firstTokenID,
			Decision:   dec,
			ReasonCode: *reason,
			Fatal:      *fatal,
			Evidence: &tokenpb.EvidenceSummary{
				Source:     "BARCODE",
				ObjectId:   *target,
				Confidence: 0.95,
				UnixMs:     time.Now().UnixMilli(),
			},
		}
		reportRequest.EvidenceProvenance = "unenforced"
		reportRequest.ReportId = uuid.NewString()
		reportRequest.ReceiptContractVersion = 1
		reportRequest.ReportDigest, err = corecomm.ReportDigest(reportRequest)
		if err != nil {
			log.Fatal(err)
		}
		response, err := tc.ReportDecision(ctx, reportRequest)
		if err == nil {
			err = corecomm.CheckReportACK(reportRequest, response, false)
		}
		if err != nil {
			log.Printf("ReportDecision unconfirmed report_id=%s: %v", reportRequest.ReportId, err)
		} else {
			log.Printf("reported decision %s/%s fatal=%v", *decision, *reason, *fatal)
		}
	}
}

// parseActionSpec reads "name[:CLASS,CLASS]". Unknown class names are passed
// through as UNSPECIFIED so the issuer's refusal (ERR_UNKNOWN_ACTION_CLASS)
// can be exercised from the command line.
func parseActionSpec(v string) *pb.ActionSpec {
	if v == "" {
		return nil
	}
	name, classes, _ := strings.Cut(v, ":")
	spec := &pb.ActionSpec{Name: name}
	if classes == "" {
		return spec
	}
	for _, c := range strings.Split(classes, ",") {
		switch strings.TrimSpace(c) {
		case "MOVE":
			spec.Classes = append(spec.Classes, pb.ActionClass_ACTION_CLASS_MOVE)
		case "MANIPULATE":
			spec.Classes = append(spec.Classes, pb.ActionClass_ACTION_CLASS_MANIPULATE)
		case "ACTUATE":
			spec.Classes = append(spec.Classes, pb.ActionClass_ACTION_CLASS_ACTUATE)
		case "NONE":
			spec.Classes = append(spec.Classes, pb.ActionClass_ACTION_CLASS_NONE)
		default:
			spec.Classes = append(spec.Classes, pb.ActionClass(99))
		}
	}
	return spec
}
