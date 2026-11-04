// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// nb_evidence drives a live pail-services issuer over gRPC and proves the
// AG-7 (NB1/NB2) northbound cancel/status behavior end to end over the wire,
// on the real compiled binary, with the real UDP burst path listened to —
// specifically to prove the ABSENCE of incident evidence during a cancel.
//
// Reproducible evidence harness (cr_evidence precedent, not part of the
// runtime). Covered live:
//
//	N1  baseline           — 2-step plan ACCEPTED, token OK, status RUNNING.
//	N2  cancel             — CancelPlan answers cancelled=true.
//	N3  quiet stop signal  — GetActiveToken serves NO_TOKEN (NOT REVOKED):
//	                         the gate stops with ERR_NO_TOKEN, no incident.
//	N4  status honesty     — GetPlanStatus answers CANCELLED.
//	N5  idempotency        — re-cancel stays true.
//	N6  no incident bursts — ZERO burst packets during the entire run.
//	N7  path restored      — immediate resubmit ACCEPTED, fresh OK token,
//	                         status RUNNING again.
//	N8  unknown plan       — cancel of an unknown plan_id answers false.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/glowfly/pail/services/internal/burst"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

type check struct {
	Name string `json:"name"`
	Pass bool   `json:"pass"`
	Note string `json:"note,omitempty"`
}

type burstView struct {
	Event  string `json:"event"`
	Reason uint16 `json:"reason"`
	Seq    uint32 `json:"seq"`
}

type evidence struct {
	Addr    string      `json:"addr"`
	UnixMs  int64       `json:"unix_ms"`
	Views   []string    `json:"views"`
	Bursts  []burstView `json:"bursts"`
	Checks  []check     `json:"checks"`
	AllPass bool        `json:"all_pass"`
}

var (
	nb pb.PailNorthboundClient
	tk tokenpb.TokenServiceClient
	ev *evidence
	mu sync.Mutex
)

func add(name string, pass bool, note string) {
	ev.Checks = append(ev.Checks, check{Name: name, Pass: pass, Note: note})
	if !pass {
		ev.AllPass = false
	}
}

func view(label, s string) {
	ev.Views = append(ev.Views, label+": "+s)
}

func plan(robot, planID, target string) *pb.SubmitActionPlanResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := nb.SubmitActionPlan(ctx, &pb.SubmitActionPlanRequest{
		RobotId: robot,
		Plan: &pb.ActionPlan{
			PlanId: planID,
			Steps: []*pb.PlanStep{
				{StepId: "s1", Type: pb.StepType_STEP_TWIST, TargetObjectId: target,
					Twist: &pb.TwistCommand{LinearX: 0.1, DurationSec: 1.0}},
				{StepId: "s2", Type: pb.StepType_STEP_TWIST, TargetObjectId: target,
					Twist: &pb.TwistCommand{LinearX: 0.1, DurationSec: 1.0}},
			},
		},
	})
	if err != nil {
		log.Fatalf("SubmitActionPlan(%s): %v", planID, err)
	}
	return resp
}

func cancelPlan(planID string) *pb.CancelPlanResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := nb.CancelPlan(ctx, &pb.CancelPlanRequest{PlanId: planID})
	if err != nil {
		log.Fatalf("CancelPlan(%s): %v", planID, err)
	}
	return resp
}

func status(planID string) *pb.GetPlanStatusResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := nb.GetPlanStatus(ctx, &pb.GetPlanStatusRequest{PlanId: planID})
	if err != nil {
		log.Fatalf("GetPlanStatus(%s): %v", planID, err)
	}
	return resp
}

func active(robot string) *tokenpb.GetActiveTokenResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := tk.GetActiveToken(ctx, &tokenpb.GetActiveTokenRequest{RobotId: robot})
	if err != nil {
		log.Fatalf("GetActiveToken(%s): %v", robot, err)
	}
	return resp
}

func listenBursts(port int) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		log.Fatalf("burst listen :%d: %v", port, err)
	}
	go func() {
		buf := make([]byte, 256)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n != burst.V2PacketSize {
				continue
			}
			bv := burstView{
				Event:  burst.EventName(buf[5]),
				Reason: binary.LittleEndian.Uint16(buf[6:8]),
				Seq:    binary.LittleEndian.Uint32(buf[48:52]),
			}
			mu.Lock()
			ev.Bursts = append(ev.Bursts, bv)
			mu.Unlock()
		}
	}()
}

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "pail-services gRPC addr (insecure)")
	robot := flag.String("robot", "robot-01", "robot under test")
	object := flag.String("object", "box-12", "plan target object")
	burstPort := flag.Int("burst_port", 46000, "UDP burst listen port")
	flag.Parse()

	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	nb = pb.NewPailNorthboundClient(conn)
	tk = tokenpb.NewTokenServiceClient(conn)

	ev = &evidence{Addr: *addr, UnixMs: time.Now().UnixMilli(), AllPass: true}
	listenBursts(*burstPort)

	planID := "nb-ev-" + *robot

	// N1 — baseline: plan issued, token served, status RUNNING.
	p1 := plan(*robot, planID, *object)
	tv1 := active(*robot)
	st1 := status(planID)
	view("n1_token", tv1.Status.String()+" chain="+tv1.ChainId)
	view("n1_status", st1.State.String()+" "+st1.Detail)
	add("N1 plan accepted + token OK + status RUNNING",
		p1.Status == pb.SubmitStatus_ACCEPTED && tv1.Status == tokenpb.ActiveTokenStatus_OK &&
			st1.State == pb.PlanState_RUNNING && strings.Contains(st1.Detail, "expected_seq=1/2"),
		fmt.Sprintf("plan=%s token=%s status=%s detail=%q",
			p1.Status, tv1.Status, st1.State, st1.Detail))

	// N2 — cancel accepted.
	c1 := cancelPlan(planID)
	add("N2 CancelPlan cancelled=true", c1.Cancelled, fmt.Sprintf("cancelled=%v", c1.Cancelled))

	// N3 — the gate-visible signal is quiet NO_TOKEN, never REVOKED.
	tv2 := active(*robot)
	view("n3_token", tv2.Status.String())
	add("N3 post-cancel serving is NO_TOKEN (not REVOKED)",
		tv2.Status == tokenpb.ActiveTokenStatus_NO_TOKEN, "status="+tv2.Status.String())

	// N4 — status answers CANCELLED.
	st2 := status(planID)
	view("n4_status", st2.State.String()+" "+st2.Detail)
	add("N4 GetPlanStatus=CANCELLED", st2.State == pb.PlanState_CANCELLED,
		fmt.Sprintf("state=%s detail=%q", st2.State, st2.Detail))

	// N5 — idempotent re-cancel.
	c2 := cancelPlan(planID)
	add("N5 re-cancel idempotent true", c2.Cancelled, fmt.Sprintf("cancelled=%v", c2.Cancelled))

	// N8 — unknown plan refuses.
	c3 := cancelPlan("nb-ev-no-such-plan")
	add("N8 unknown plan_id cancelled=false", !c3.Cancelled, fmt.Sprintf("cancelled=%v", c3.Cancelled))

	// N7 — the path is restored immediately: fresh plan on the same robot.
	p2 := plan(*robot, planID+"-resubmit", *object)
	tv3 := active(*robot)
	st3 := status(planID + "-resubmit")
	view("n7_token", tv3.Status.String()+" chain="+tv3.ChainId)
	view("n7_status", st3.State.String()+" "+st3.Detail)
	add("N7 resubmit ACCEPTED + fresh OK token + RUNNING",
		p2.Status == pb.SubmitStatus_ACCEPTED && tv3.Status == tokenpb.ActiveTokenStatus_OK &&
			tv3.ChainId != tv1.ChainId && st3.State == pb.PlanState_RUNNING,
		fmt.Sprintf("plan=%s token=%s new_chain=%v status=%s",
			p2.Status, tv3.Status, tv3.ChainId != tv1.ChainId, st3.State))

	// N6 — the whole run must have produced ZERO burst packets (burst is the
	// incident broadcast channel; cancel is not an incident).
	time.Sleep(2 * time.Second) // any wrongly-emitted burst would retransmit here
	mu.Lock()
	nb6 := len(ev.Bursts)
	mu.Unlock()
	add("N6 zero incident bursts during cancel run", nb6 == 0, fmt.Sprintf("bursts=%d", nb6))

	out, _ := json.MarshalIndent(ev, "", "  ")
	fmt.Println(string(out))
	if !ev.AllPass {
		os.Exit(1)
	}
}
