// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// cr_evidence drives a live pail-services issuer over gRPC and proves the
// AG-1/AG-2 (CR1~CR3) behavior end to end over the wire, on the real compiled
// binary, with a site model loaded from disk and the real UDP burst path.
//
// It is a reproducible evidence harness (cge1_evidence precedent, not part of
// the runtime). Covered live:
//
//	C1  serving parity      — GetActiveToken.current_subgraph_hash (32B) is
//	                          bit-identical to the token-embedded signed hash.
//	C2  DR-1 immunity       — a non-intersecting mutation leaves the served
//	                          hash bit-identical while graph_epoch advances.
//	C3  AG-1 revocation     — an intersecting mutation flips the chain to
//	                          REVOKED and emits a signed CHAIN_REVOKED burst
//	                          with reason 0x14 (ERR_WORLD_CHANGED).
//	C4  CR2 supersede       — a benign target move revokes + recompiles into a
//	                          fresh chain whose serving hash matches its own
//	                          embedded hash and differs from the old one.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"github.com/glowfly/pail/services/internal/burst"
	operatorpb "github.com/glowfly/pail/services/proto/operatorv1"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
)

type tokenView struct {
	Status       string `json:"status"`
	ChainID      string `json:"chain_id,omitempty"`
	TokenID      string `json:"token_id,omitempty"`
	EmbeddedHash string `json:"embedded_hash,omitempty"` // signed field 61
	CurrentHash  string `json:"current_hash,omitempty"`  // live serving re-derivation
	GraphEpoch   uint64 `json:"graph_epoch"`
}

type burstView struct {
	Event      string `json:"event"`
	Reason     uint16 `json:"reason"`
	Seq        uint32 `json:"seq"`
	SigOK      bool   `json:"sig_ok"`
	RobotMatch bool   `json:"robot_match"`
}

type check struct {
	Name string `json:"name"`
	Pass bool   `json:"pass"`
	Note string `json:"note,omitempty"`
}

type evidence struct {
	Addr    string               `json:"addr"`
	UnixMs  int64                `json:"unix_ms"`
	Views   map[string]tokenView `json:"views"`
	Acks    []map[string]any     `json:"acks"`
	Bursts  []burstView          `json:"bursts"`
	Checks  []check              `json:"checks"`
	AllPass bool                 `json:"all_pass"`
}

var (
	nb pb.PailNorthboundClient
	op operatorpb.OperatorServiceClient
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

func plan(robot, target string) *pb.SubmitActionPlanResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := nb.SubmitActionPlan(ctx, &pb.SubmitActionPlanRequest{
		RobotId: robot,
		Plan: &pb.ActionPlan{
			PlanId: "cr-ev-" + robot,
			Steps: []*pb.PlanStep{
				{StepId: "s1", Type: pb.StepType_STEP_TWIST, TargetObjectId: target,
					Twist: &pb.TwistCommand{LinearX: 0.1, DurationSec: 1.0}},
				{StepId: "s2", Type: pb.StepType_STEP_TWIST, TargetObjectId: target,
					Twist: &pb.TwistCommand{LinearX: 0.1, DurationSec: 1.0}},
			},
		},
	})
	if err != nil {
		log.Fatalf("SubmitActionPlan(%s): %v", robot, err)
	}
	return resp
}

func ingest(kind operatorpb.ContextEventKind, nodeID, arg string) *operatorpb.ContextEventAck {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ack, err := op.IngestContextEvent(ctx, &operatorpb.ContextEvent{NodeId: nodeID, Kind: kind, Arg: arg})
	if err != nil {
		log.Fatalf("IngestContextEvent(%v %s): %v", kind, nodeID, err)
	}
	ev.Acks = append(ev.Acks, map[string]any{
		"kind": kind.String(), "node_id": nodeID, "arg": arg,
		"accepted": ack.Accepted, "epoch": ack.Epoch, "detail": ack.Detail})
	return ack
}

func getActive(robot, label string) tokenView {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := tk.GetActiveToken(ctx, &tokenpb.GetActiveTokenRequest{RobotId: robot})
	if err != nil {
		log.Fatalf("GetActiveToken(%s): %v", robot, err)
	}
	v := tokenView{Status: resp.Status.String(), ChainID: resp.ChainId, GraphEpoch: resp.GraphEpoch,
		CurrentHash: hex.EncodeToString(resp.CurrentSubgraphHash)}
	if st := resp.Token; st != nil && len(st.ActionTokenBytes) > 0 {
		var tok pb.ActionToken
		if err := proto.Unmarshal(st.ActionTokenBytes, &tok); err == nil {
			v.TokenID = tok.TokenId
			v.EmbeddedHash = hex.EncodeToString(tok.SubgraphSnapshotHash)
		}
	}
	ev.Views[label] = v
	return v
}

func listenBursts(port int, pub ed25519.PublicKey, robot string) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		log.Fatalf("burst listen :%d: %v", port, err)
	}
	rh := sha256.Sum256([]byte(robot))
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
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			bv := burstView{
				Event:      burst.EventName(pkt[5]),
				Reason:     binary.LittleEndian.Uint16(pkt[6:8]),
				Seq:        binary.LittleEndian.Uint32(pkt[48:52]),
				SigOK:      burst.VerifyPacketV2(pub, pkt),
				RobotMatch: string(pkt[16:32]) == string(rh[:16]),
			}
			mu.Lock()
			ev.Bursts = append(ev.Bursts, bv)
			mu.Unlock()
		}
	}()
}

func revokedBurstCount() int {
	mu.Lock()
	defer mu.Unlock()
	seen := map[uint32]bool{}
	n := 0
	for _, b := range ev.Bursts {
		if b.Event == "CHAIN_REVOKED" && b.Reason == 0x14 && b.SigOK && b.RobotMatch && !seen[b.Seq] {
			seen[b.Seq] = true
			n++
		}
	}
	return n
}

func loadIssuerPub(path string) ed25519.PublicKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("issuer keyfile: %v", err)
	}
	var kf struct {
		PublicKeyB64 string `json:"ed25519_public_key_base64"`
	}
	if err := json.Unmarshal(raw, &kf); err != nil {
		log.Fatalf("issuer keyfile parse: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(kf.PublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		log.Fatalf("issuer pubkey decode: err=%v len=%d", err, len(pub))
	}
	return ed25519.PublicKey(pub)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:50051", "pail-services gRPC addr (insecure)")
	robot := flag.String("robot", "robot-01", "robot under test (home z7)")
	zone := flag.String("zone", "z7", "robot home zone (intersecting)")
	zone2 := flag.String("zone2", "z8", "non-intersecting zone")
	object := flag.String("object", "box-12", "plan target object (benign move)")
	keyfile := flag.String("issuer_pub", "/etc/pail/keys/issuer_ed25519.json", "issuer keyfile (public part used)")
	burstPort := flag.Int("burst_port", 46000, "UDP burst listen port")
	flag.Parse()

	pub := loadIssuerPub(*keyfile)

	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	nb = pb.NewPailNorthboundClient(conn)
	op = operatorpb.NewOperatorServiceClient(conn)
	tk = tokenpb.NewTokenServiceClient(conn)

	ev = &evidence{Addr: *addr, UnixMs: time.Now().UnixMilli(), AllPass: true,
		Views: map[string]tokenView{}}
	listenBursts(*burstPort, pub, *robot)

	// C1 — serving parity in an unchanged world.
	p1 := plan(*robot, *object)
	v1 := getActive(*robot, "c1_baseline")
	add("C1 plan accepted", p1.Status == pb.SubmitStatus_ACCEPTED, "status="+p1.Status.String())
	add("C1 serving parity: 32B current == embedded (bit-identical)",
		v1.Status == "OK" && len(v1.CurrentHash) == 64 && v1.CurrentHash == v1.EmbeddedHash,
		fmt.Sprintf("status=%s current=%.16s… embedded=%.16s…", v1.Status, v1.CurrentHash, v1.EmbeddedHash))

	// C2 — non-intersecting mutation: hash immune, epoch advances.
	a1 := ingest(operatorpb.ContextEventKind_HUMAN_ENTER, "zone:"+*zone2, "h9")
	v2 := getActive(*robot, "c2_nonintersect")
	add("C2 DR-1 immunity: same token, identical hash, epoch advanced",
		a1.Accepted && v2.Status == "OK" && v2.TokenID == v1.TokenID &&
			v2.CurrentHash == v1.CurrentHash && v2.GraphEpoch > v1.GraphEpoch,
		fmt.Sprintf("token same=%v hash same=%v epoch %d->%d",
			v2.TokenID == v1.TokenID, v2.CurrentHash == v1.CurrentHash, v1.GraphEpoch, v2.GraphEpoch))
	ingest(operatorpb.ContextEventKind_HUMAN_LEAVE, "zone:"+*zone2, "h9")

	// C3 — intersecting mutation: chain REVOKED + signed burst 0x14.
	before := revokedBurstCount()
	a2 := ingest(operatorpb.ContextEventKind_HUMAN_ENTER, "zone:"+*zone, "h1")
	v3 := getActive(*robot, "c3_revoked")
	time.Sleep(2 * time.Second) // burst retransmission window
	after := revokedBurstCount()
	add("C3 AG-1: intersecting mutation revokes chain",
		a2.Accepted && v3.Status == "REVOKED", "status="+v3.Status)
	add("C3 burst CHAIN_REVOKED reason=0x14 signed + robot-bound",
		after > before, fmt.Sprintf("distinct revoked bursts %d->%d", before, after))
	ingest(operatorpb.ContextEventKind_HUMAN_LEAVE, "zone:"+*zone, "h1")

	// C4 — benign target move: revoke + recompile into a fresh chain.
	p2 := plan(*robot, *object)
	v4 := getActive(*robot, "c4_pre_move")
	before2 := revokedBurstCount()
	a3 := ingest(operatorpb.ContextEventKind_OBJECT_MOVE, "object:"+*object, *zone2)
	v5 := getActive(*robot, "c4_superseded")
	time.Sleep(2 * time.Second)
	after2 := revokedBurstCount()
	add("C4 pre-move chain healthy", p2.Status == pb.SubmitStatus_ACCEPTED && v4.Status == "OK",
		fmt.Sprintf("plan=%s status=%s", p2.Status.String(), v4.Status))
	add("C4 CR2 supersede: new chain, new hash, serving parity holds",
		a3.Accepted && v5.Status == "OK" && v5.ChainID != v4.ChainID &&
			v5.EmbeddedHash != v4.EmbeddedHash && v5.CurrentHash == v5.EmbeddedHash &&
			len(v5.CurrentHash) == 64,
		fmt.Sprintf("chain new=%v hash new=%v parity=%v",
			v5.ChainID != v4.ChainID, v5.EmbeddedHash != v4.EmbeddedHash, v5.CurrentHash == v5.EmbeddedHash))
	add("C4 revoke burst emitted for superseded chain", after2 > before2,
		fmt.Sprintf("distinct revoked bursts %d->%d", before2, after2))

	out, _ := json.MarshalIndent(ev, "", "  ")
	fmt.Println(string(out))
	if !ev.AllPass {
		os.Exit(1)
	}
}
