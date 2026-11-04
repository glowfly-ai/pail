// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
// Reference client: uses generated mTLS credentials; prints metadata from signed token bytes.
//
//	-mode peek                          active token for robot-01
//	-mode submit [-duration S]          the reference one-step plan (0.05 m/s)
//	-mode submit -steps JSON            a plan of twist steps: [{"linear":0.1,"angular":0,"duration":10}, ...]
//	-mode cancel -plan ID               CancelPlan for a plan this client submitted (its "plan" field)
//	-mode unlock                        a signed operator unlock with the generated dev operator key
//
// A refused plan prints its denial, including every exceeded envelope bound.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	cfg "github.com/glowfly/pail/services/internal/config"
	"github.com/glowfly/pail/services/internal/corecomm"
	"github.com/glowfly/pail/services/internal/graph"
	"github.com/glowfly/pail/services/internal/skills"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"time"

	op "github.com/glowfly/pail/services/proto/operatorv1"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Defaults match the reference stack (inside the issuer container); flags point it elsewhere.
var (
	robotID     = "robot-01"
	operatorKey = "/etc/pail/keys/operator_ed25519.json"
)

func must(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func token(s *pb.SignedToken) interface{} {
	if s == nil {
		return nil
	}
	t := new(pb.ActionToken)
	must(proto.Unmarshal(s.ActionTokenBytes, t))
	b, e := protojson.Marshal(t.Constraints)
	must(e)
	var c interface{}
	must(json.Unmarshal(b, &c))
	h := sha256.Sum256(s.ActionTokenBytes)
	return map[string]interface{}{"id": t.TokenId, "schema": t.SchemaVersion, "skill": t.Skill, "slot": t.Slot, "constraints": c, "signed_bytes_sha256": hex.EncodeToString(h[:])}
}

// number keeps a non-finite value printable: JSON has no NaN or Inf.
func number(v float64) interface{} {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return strconv.FormatFloat(v, 'g', -1, 64)
	}
	return v
}

func denial(d *pb.Denial) interface{} {
	if d == nil {
		return nil
	}
	ex := []interface{}{}
	for _, e := range d.GetExceeded() {
		ex = append(ex, map[string]interface{}{"name": e.GetName(), "requested": number(e.GetRequested()), "max": number(e.GetMax())})
	}
	return map[string]interface{}{"code": d.GetReasonCode(), "detail": d.GetDetail(), "exceeded": ex}
}

type stepSpec struct {
	Linear   float64 `json:"linear"`
	Angular  float64 `json:"angular"`
	Duration float64 `json:"duration"`
}

func planSteps(stepsJSON, target string, duration float64) []*pb.PlanStep {
	if stepsJSON == "" {
		return []*pb.PlanStep{{StepId: "move", Type: pb.StepType_STEP_TWIST, TargetObjectId: target, Twist: &pb.TwistCommand{LinearX: .05, DurationSec: duration}}}
	}
	var specs []stepSpec
	must(json.Unmarshal([]byte(stepsJSON), &specs))
	if len(specs) == 0 {
		log.Fatal("-steps is empty")
	}
	out := make([]*pb.PlanStep, 0, len(specs))
	for i, s := range specs {
		out = append(out, &pb.PlanStep{StepId: fmt.Sprintf("s%d", i+1), Type: pb.StepType_STEP_TWIST, TargetObjectId: target,
			Twist: &pb.TwistCommand{LinearX: s.Linear, AngularZ: s.Angular, DurationSec: s.Duration}})
	}
	return out
}

// unlockRequest signs the operator unlock canon (pail-unlock:v2) with the dev operator key.
func unlockRequest() *op.UnlockRequest {
	raw, e := os.ReadFile(operatorKey)
	must(e)
	var k struct {
		KeyID string `json:"key_id"`
		Priv  string `json:"ed25519_private_key_base64"`
	}
	must(json.Unmarshal(raw, &k))
	priv, e := base64.StdEncoding.DecodeString(k.Priv)
	must(e)
	if len(priv) != ed25519.PrivateKeySize {
		log.Fatal("operator key has the wrong size")
	}
	nonce := make([]byte, 16)
	_, e = rand.Read(nonce)
	must(e)
	ms := time.Now().UnixMilli()
	msg := "pail-unlock:v2:" + robotID + ":" + strconv.FormatInt(ms, 10) + ":" + base64.StdEncoding.EncodeToString(nonce) + ":" + k.KeyID
	return &op.UnlockRequest{RobotId: robotID, UnixMs: ms, Nonce: nonce, OperatorSig: ed25519.Sign(ed25519.PrivateKey(priv), []byte(msg)), OperatorKeyId: k.KeyID}
}

// policyLimits reads the same policy, site and skill parsers as the issuer. It does not
// contact a server, grant a token or claim to attest a running issuer's configuration.
func policyLimits(dir, robot, target string) (interface{}, error) {
	p, raw, err := cfg.LoadPolicy(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		return nil, err
	}
	siteRaw, err := os.ReadFile(filepath.Join(dir, "site_model.yaml"))
	if err != nil {
		return nil, err
	}
	_, site, err := graph.Compile(siteRaw)
	if err != nil {
		return nil, err
	}
	class := site.RobotClass[robot]
	if class == "" {
		return nil, fmt.Errorf("no declared robot class for %s", robot)
	}
	zone, ok := site.ObjectZone[target]
	if !ok || zone == "" {
		return nil, fmt.Errorf("no declared target zone for %s", target)
	}
	regs, err := skills.LoadDir(dir)
	if err != nil {
		return nil, err
	}
	reg, ok := regs.ForClass(class)
	if !ok {
		return nil, fmt.Errorf("no registry for %s", class)
	}
	skill, ok := reg.Lookup("twist")
	if !ok {
		return nil, fmt.Errorf("no twist skill for %s", class)
	}
	env, missing := p.Guardrails.Envelope(skill.Envelope, zone)
	if len(missing) != 0 {
		return nil, fmt.Errorf("missing guardrail values: %v", missing)
	}
	for _, n := range []string{cfg.GuardrailLinear, cfg.GuardrailAngular, cfg.GuardrailDuration} {
		v, ok := env[n]
		if !ok || v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("invalid or missing twist limit %s", n)
		}
	}
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	return map[string]interface{}{"limits": env, "robot": robot, "robot_class": class, "target": target,
		"zone": zone, "skill": "twist", "basis": "local-config-not-live-attestation",
		"sha256": map[string]string{"policy.yaml": hash(raw), "site_model.yaml": hash(siteRaw), filepath.Base(reg.Path): reg.SHA256Hex}}, nil
}

func main() {
	mode := flag.String("mode", "peek", "peek|submit|cancel|unlock|limits")
	duration := flag.Float64("duration", 6, "step duration seconds (reference plan)")
	steps := flag.String("steps", "", "JSON list of twist steps; replaces the reference plan")
	plan := flag.String("plan", "", "plan id to cancel (cancel)")
	target := flag.String("target", "sample-box", "target object id for every step")
	addr := flag.String("addr", "127.0.0.1:50051", "issuer (or robot agent) gRPC address")
	caPath := flag.String("ca", "/etc/pail/grpc_certs/ca.crt", "CA certificate")
	certPath := flag.String("cert", "/etc/pail/grpc_certs/robot-01/client.crt", "client certificate")
	keyPath := flag.String("key", "/etc/pail/grpc_certs/robot-01/client.key", "client key")
	flag.StringVar(&robotID, "robot", robotID, "robot id")
	flag.StringVar(&operatorKey, "operator-key", operatorKey, "operator key JSON (unlock)")
	configDir := flag.String("config", "", "configuration directory for offline limits mode")
	flag.Parse()
	if *mode == "limits" {
		if *configDir == "" {
			log.Fatal("-mode limits needs -config")
		}
		out, err := policyLimits(*configDir, robotID, *target)
		must(err)
		b, err := json.Marshal(out)
		must(err)
		fmt.Println(string(b))
		return
	}
	ca, e := os.ReadFile(*caPath)
	must(e)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		log.Fatal("CA parse")
	}
	cert, e := tls.LoadX509KeyPair(*certPath, *keyPath)
	must(e)
	c, e := grpc.Dial(*addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})))
	must(e)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out interface{}
	must(corecomm.CheckNoContractSettingEnv()) // present at all — even empty — refuses (P40-L2)
	switch *mode {
	case "peek":
		r, e := tp.NewTokenServiceClient(c).GetActiveToken(ctx, &tp.GetActiveTokenRequest{RobotId: robotID})
		must(e)
		out = map[string]interface{}{"status": r.Status.String(), "token": token(r.Token)}
	case "submit":
		planID := *plan
		if planID == "" {
			planID = fmt.Sprintf("ref-%d", time.Now().UnixNano())
		}
		req := &pb.SubmitActionPlanRequest{RobotId: robotID, SessionId: "tb3-reference", Plan: &pb.ActionPlan{PlanId: planID, Steps: planSteps(*steps, *target, *duration)}, OperationId: planID}
		log.Printf("authorization request plan=%s operation=%s", planID, req.OperationId)
		r, e := pb.NewPailNorthboundClient(c).SubmitActionPlan(ctx, req, grpc.WaitForReady(true))
		must(e)
		outcome, e := corecomm.SubmitOutcome(req, r)
		must(e)
		ts := []interface{}{}
		for _, t := range r.Tokens {
			ts = append(ts, token(t))
		}
		out = map[string]interface{}{"status": r.Status.String(), "plan": planID, "chain": r.ChainId, "rejected": r.RejectedReason, "tokens": ts, "denial": denial(r.Denial), "operation_outcome": outcome, "dispatch_allowed": outcome == corecomm.OperationAuthorized, "operation_id": planID}
	case "cancel":
		// The issuer's own cancel: the chain ends (CHAIN_CANCELLED in the ledger) and the
		// remaining step window is no longer served, so a later plan cannot run on it.
		if *plan == "" {
			log.Fatal("-mode cancel needs -plan")
		}
		req := &pb.CancelPlanRequest{PlanId: *plan, OperationId: *plan}
		r, e := pb.NewPailNorthboundClient(c).CancelPlan(ctx, req)
		must(e)
		outcome, e := corecomm.CancelOutcome(req, r, robotID)
		must(e)
		out = map[string]interface{}{"plan": r.GetPlanId(), "cancelled": outcome == corecomm.OperationWithdrawalRecorded, "operation_outcome": outcome, "physical_stop": "NOT_OBSERVED"}
	case "unlock":
		r, e := op.NewOperatorServiceClient(c).Unlock(ctx, unlockRequest())
		must(e)
		out = map[string]interface{}{"accepted": r.GetAccepted(), "detail": r.GetDetail()}
	default:
		log.Fatal("unknown mode")
	}
	b, e := json.Marshal(out)
	must(e)
	fmt.Println(string(b))
}
