// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// cge1_evidence drives a live pail-services instance over gRPC and prints a
// structured JSON evidence record for the CG-E1 §4.5 completion conditions.
//
// It is a reproducible evidence harness (not part of the runtime): it exercises
// SubmitActionPlan (northbound) and IngestContextEvent (operator) against a
// running issuer so the §4.5 behavior is proven end-to-end over the wire, on
// the real compiled binary, with a site model loaded from disk.
//
// Modes:
//
//	model   — issuer booted with a valid site model: baseline/determinism/
//	          maintenance/human-zone-isolation/unknown-agent/unknown-node.
//	corrupt — issuer booted with a corrupt model: fail-closed, refuses all.
//	nomodel — issuer booted with no model: CG1 ephemeral behavior preserved.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	operatorpb "github.com/glowfly/pail/services/proto/operatorv1"
	pb "github.com/glowfly/pail/services/proto/pailv1"
)

type planResult struct {
	Robot        string `json:"robot"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	Schema       uint32 `json:"schema_version,omitempty"`
	SnapshotHash string `json:"snapshot_hash,omitempty"`
	SnapshotLen  int    `json:"snapshot_len"`
}

type ackResult struct {
	Kind     string `json:"kind"`
	NodeID   string `json:"node_id"`
	Arg      string `json:"arg,omitempty"`
	Accepted bool   `json:"accepted"`
	Epoch    uint64 `json:"epoch"`
	Detail   string `json:"detail"`
}

type check struct {
	Name string `json:"name"`
	Pass bool   `json:"pass"`
	Note string `json:"note,omitempty"`
}

type evidence struct {
	Mode    string       `json:"mode"`
	Addr    string       `json:"addr"`
	UnixMs  int64        `json:"unix_ms"`
	Plans   []planResult `json:"plans"`
	Acks    []ackResult  `json:"acks"`
	Checks  []check      `json:"checks"`
	AllPass bool         `json:"all_pass"`
}

var (
	nb pb.PailNorthboundClient
	op operatorpb.OperatorServiceClient
	ev *evidence
)

func plan(robot string) planResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := nb.SubmitActionPlan(ctx, &pb.SubmitActionPlanRequest{
		RobotId: robot,
		Plan: &pb.ActionPlan{
			PlanId: "ev-" + robot,
			Steps: []*pb.PlanStep{{
				StepId: "s1", Type: pb.StepType_STEP_TWIST,
				Twist: &pb.TwistCommand{LinearX: 0.1, DurationSec: 1.0},
			}},
		},
	})
	if err != nil {
		log.Fatalf("SubmitActionPlan(%s): %v", robot, err)
	}
	pr := planResult{Robot: robot, Status: resp.Status.String(), Reason: resp.RejectedReason}
	if len(resp.Tokens) > 0 && resp.Tokens[0].GetToken() != nil {
		tok := resp.Tokens[0].GetToken()
		pr.Schema = tok.SchemaVersion
		pr.SnapshotLen = len(tok.SubgraphSnapshotHash)
		pr.SnapshotHash = hex.EncodeToString(tok.SubgraphSnapshotHash)
	}
	ev.Plans = append(ev.Plans, pr)
	return pr
}

func ingest(kind operatorpb.ContextEventKind, nodeID, arg string) ackResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ack, err := op.IngestContextEvent(ctx, &operatorpb.ContextEvent{NodeId: nodeID, Kind: kind, Arg: arg})
	if err != nil {
		log.Fatalf("IngestContextEvent(%v %s): %v", kind, nodeID, err)
	}
	ar := ackResult{Kind: kind.String(), NodeID: nodeID, Arg: arg, Accepted: ack.Accepted, Epoch: ack.Epoch, Detail: ack.Detail}
	ev.Acks = append(ev.Acks, ar)
	return ar
}

func add(name string, pass bool, note string) {
	ev.Checks = append(ev.Checks, check{Name: name, Pass: pass, Note: note})
	if !pass {
		ev.AllPass = false
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "pail-services gRPC addr (insecure)")
	mode := flag.String("mode", "model", "model | corrupt | nomodel")
	r1 := flag.String("robot", "robot-01", "primary robot (home z7)")
	r2 := flag.String("robot2", "robot-02", "secondary robot (home z8)")
	zone := flag.String("zone", "z7", "primary robot home zone")
	flag.Parse()

	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	nb = pb.NewPailNorthboundClient(conn)
	op = operatorpb.NewOperatorServiceClient(conn)

	ev = &evidence{Mode: *mode, Addr: *addr, UnixMs: time.Now().UnixMilli(), AllPass: true}

	switch *mode {
	case "model":
		runModel(*r1, *r2, *zone)
	case "corrupt":
		runCorrupt(*r1)
	case "nomodel":
		runNoModel(*r1)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}

	out, _ := json.MarshalIndent(ev, "", "  ")
	fmt.Println(string(out))
	if !ev.AllPass {
		os.Exit(1)
	}
}

func runModel(r1, r2, zone string) {
	// §4.5(1) baseline: schema v3 + 32B bound snapshot.
	b := plan(r1)
	add("§4.5(1) baseline schema=3 + 32B snapshot",
		b.Status == "ACCEPTED" && b.Schema == 3 && b.SnapshotLen == 32,
		fmt.Sprintf("status=%s schema=%d len=%d", b.Status, b.Schema, b.SnapshotLen))

	// §4.5(2) determinism: unchanged world => identical snapshot hash.
	h1 := plan(r1).SnapshotHash
	h2 := plan(r1).SnapshotHash
	add("§4.5(2) determinism identical snapshot",
		h1 != "" && h1 == h2, fmt.Sprintf("h1==h2: %v", h1 == h2))

	// §4.5(3) maintenance refuses then resumes; other robot unaffected; epoch monotonic.
	pre := plan(r1)
	on := ingest(operatorpb.ContextEventKind_MAINTENANCE_ON, "robot:"+r1, "")
	underMaint := plan(r1)
	other := plan(r2)
	off := ingest(operatorpb.ContextEventKind_MAINTENANCE_OFF, "robot:"+r1, "")
	resumed := plan(r1)
	add("§4.5(3) MAINTENANCE_ON refuses issuance",
		pre.Status == "ACCEPTED" && on.Accepted && underMaint.Status == "REJECTED",
		fmt.Sprintf("pre=%s on.acc=%v under=%s", pre.Status, on.Accepted, underMaint.Status))
	add("§4.5(3) other robot unaffected under maintenance",
		other.Status == "ACCEPTED", "robot2="+other.Status)
	add("§4.5(3) MAINTENANCE_OFF resumes + epoch monotonic",
		off.Accepted && off.Epoch > on.Epoch && resumed.Status == "ACCEPTED",
		fmt.Sprintf("epoch on=%d off=%d resumed=%s", on.Epoch, off.Epoch, resumed.Status))

	// §4.5(4) human zone isolation.
	enter := ingest(operatorpb.ContextEventKind_HUMAN_ENTER, "zone:"+zone, "h1")
	inZone := plan(r1)
	elsewhere := plan(r2)
	leave := ingest(operatorpb.ContextEventKind_HUMAN_LEAVE, "zone:"+zone, "h1")
	restored := plan(r1)
	add("§4.5(4) human in zone refuses home robot",
		enter.Accepted && inZone.Status == "REJECTED", "in-zone="+inZone.Status)
	add("§4.5(4) robot elsewhere unaffected",
		elsewhere.Status == "ACCEPTED", "elsewhere="+elsewhere.Status)
	add("§4.5(4) HUMAN_LEAVE restores issuance",
		leave.Accepted && restored.Status == "ACCEPTED", "restored="+restored.Status)

	// §4.5(6) unknown agent refused.
	unk := plan("robot-99")
	add("§4.5(6) unknown agent refused",
		unk.Status == "REJECTED", "status="+unk.Status)

	// unknown-node ingest is a fail-closed reject that does not advance the epoch.
	before := ingest(operatorpb.ContextEventKind_MAINTENANCE_ON, "robot:"+r1, "")
	ghost := ingest(operatorpb.ContextEventKind_MAINTENANCE_ON, "robot:ghost", "")
	_ = ingest(operatorpb.ContextEventKind_MAINTENANCE_OFF, "robot:"+r1, "") // restore
	add("ingest unknown node rejected, epoch unchanged",
		!ghost.Accepted && ghost.Epoch == before.Epoch,
		fmt.Sprintf("ghost.acc=%v epoch before=%d ghost=%d", ghost.Accepted, before.Epoch, ghost.Epoch))
}

func runCorrupt(r1 string) {
	// §4.5(5) corrupt model => issuer fail-closed, refuses ALL issuance.
	p := plan(r1)
	add("§4.5(5) corrupt model fail-closed refuses all issuance",
		p.Status == "REJECTED", "status="+p.Status+" reason="+p.Reason)
	// Ingest is also refused (no usable model).
	a := ingest(operatorpb.ContextEventKind_MAINTENANCE_ON, "robot:"+r1, "")
	add("§4.5(5) corrupt model refuses ingest",
		!a.Accepted, "detail="+a.Detail)
}

func runNoModel(r1 string) {
	// No site model => CG1 ephemeral behavior preserved (still bound snapshot).
	p := plan(r1)
	add("no model preserves CG1 issuance + 32B snapshot",
		p.Status == "ACCEPTED" && p.SnapshotLen == 32,
		fmt.Sprintf("status=%s len=%d", p.Status, p.SnapshotLen))
	a := ingest(operatorpb.ContextEventKind_MAINTENANCE_ON, "robot:"+r1, "")
	add("no model refuses ingest (nothing to mutate)",
		!a.Accepted, "detail="+a.Detail)
}
