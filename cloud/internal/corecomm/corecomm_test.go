// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package corecomm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/glowfly/pail/services/internal/blackbox"
	devcrypto "github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/signer"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/protobuf/proto"
	"math"
	"os"
	"testing"
)

func TestReportCanonicalScope(t *testing.T) {
	a := &tp.ReportDecisionRequest{RobotId: "r", ReportId: "event", Decision: tp.Decision_BLOCK, ReasonCode: "NO_TOKEN"}
	h, e := ReportDigest(a)
	if e != nil {
		t.Fatal(e)
	}
	b := proto.Clone(a).(*tp.ReportDecisionRequest)
	b.AgentSeq = 99
	b.AgentRunId = "different"
	b.Delivery = "replayed"
	b.DecidedUnixMs = 5
	b.Attribution = &tp.ReportAttribution{ChainId: "new"}
	h2, e := ReportDigest(b)
	if e != nil || !bytes.Equal(h, h2) {
		t.Fatal("delivery changed event identity", e)
	}
	b.ReasonCode = "other"
	h2, _ = ReportDigest(b)
	if bytes.Equal(h, h2) {
		t.Fatal("event payload not bound")
	}
	b = proto.Clone(a).(*tp.ReportDecisionRequest)
	b.Evidence = &tp.EvidenceSummary{Confidence: float32(math.NaN())}
	if _, e = ReportDigest(b); e == nil {
		t.Fatal("NaN accepted")
	}
	a.ProtoReflect().SetUnknown([]byte{0xa0, 1, 1})
	if _, e = ReportDigest(a); e == nil {
		t.Fatal("unknown fields accepted")
	}
}
func TestOperationIDNotPayload(t *testing.T) {
	a := &pb.CancelPlanRequest{PlanId: "p", OperationId: "a"}
	h, _ := CancelDigest(a)
	a.OperationId = "b"
	h2, _ := CancelDigest(a)
	if !bytes.Equal(h, h2) {
		t.Fatal("logical key mixed into payload")
	}
}
func TestReceiptDoesNotConflateStorageAndEffect(t *testing.T) {
	q := &tp.ReportDecisionRequest{RobotId: "r", ReportId: "id", ReportDigest: make([]byte, 32), ReceiptContractVersion: 1, Fatal: true}
	r := &tp.ReportDecisionResponse{Accepted: true, Receipt: &tp.ReportReceipt{ContractVersion: 1, RobotId: "r", ReportId: "id", ReportDigest: make([]byte, 32), ReceiverInstanceId: "issuer", Storage: tp.StorageLevel_LOCAL_DURABLE, Effect: tp.EffectStatus_PENDING, Disposition: tp.ReceiptDisposition_NEW}}
	if CheckReportACK(q, r, true) == nil {
		t.Fatal("local persistence became issuer effect")
	}
	r.Receipt.Storage = tp.StorageLevel_ISSUER_DURABLE
	r.Receipt.JournalRecordRef = "record"
	r.Receipt.Effect = tp.EffectStatus_APPLIED
	r.Receipt.EffectScope = tp.EffectScope_ISSUER_CHAIN
	if e := CheckReportACK(q, r, true); e != nil {
		t.Fatal(e)
	}
	r.Accepted = false
	if CheckReportACK(q, r, true) == nil {
		t.Fatal("rejection accepted")
	}
	r.Receipt.Effect = tp.EffectStatus_REJECTED
	r.Receipt.Disposition = tp.ReceiptDisposition_TERMINAL_REJECTED
	if e := CheckReportACK(q, r, true); e != ErrTerminalRejected {
		t.Fatal(e)
	}
}
func TestJournalRecoveryNoReexecution(t *testing.T) {
	dir := t.TempDir()
	kp, err := devcrypto.NewDevKeypair("test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := blackbox.Config{Signer: signer.NewLocal(kp)}
	w, e := blackbox.OpenDir(dir, cfg)
	if e != nil {
		t.Fatal(e)
	}
	j, e := OpenJournal(w)
	if e != nil {
		t.Fatal(e)
	}
	entry := Entry{Scope: "caller", Robot: "robot", Plan: "p", Kind: "SUBMIT", ID: "op", Digest: make([]byte, 32)}
	first, leader, e := j.Begin(entry)
	if e != nil || !leader {
		t.Fatal(e)
	}
	if _, again, e := j.Begin(entry); e != nil || again {
		t.Fatal("duplicate starts operation", e)
	}
	changed := entry
	changed.Digest = bytes.Repeat([]byte{1}, 32)
	if _, _, e = j.Begin(changed); e != ErrConflict {
		t.Fatal("conflict not rejected", e)
	}
	w.Close()
	w, e = blackbox.OpenDir(dir, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	j, e = OpenJournal(w)
	if e != nil {
		t.Fatal(e)
	}
	if !j.Blocked("robot") {
		t.Fatal("prepared crash not fenced")
	}
	old, leader, e := j.Begin(entry)
	if e != nil || leader || !old.Recovered {
		t.Fatal("unknown recovered as absent", e)
	}
	if _, e = j.Finish(first, "COMMITTED", []byte("result")); e != nil {
		t.Fatal(e)
	}
	next, e := OpenJournal(w)
	if e != nil {
		t.Fatal(e)
	}
	done, leader, e := next.Begin(entry)
	if e != nil || leader || string(done.Response) != "result" || next.Blocked("robot") {
		t.Fatal("committed receipt not restored", e)
	}
}

func TestReportCanonicalGolden(t *testing.T) {
	b, e := os.ReadFile("testdata/report-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Wire   string `json:"wire_hex"`
		Digest string `json:"digest_hex"`
	}
	if e = json.Unmarshal(b, &cases); e != nil {
		t.Fatal(e)
	}
	for _, c := range cases {
		raw, e := hex.DecodeString(c.Wire)
		if e != nil {
			t.Fatal(e)
		}
		r := &tp.ReportDecisionRequest{}
		if e = proto.Unmarshal(raw, r); e != nil {
			t.Fatal(e)
		}
		h, e := ReportDigest(r)
		if e != nil || hex.EncodeToString(h) != c.Digest {
			t.Fatalf("golden mismatch: %x %v", h, e)
		}
	}
}

func TestAdmissionIndexMatchesRecoveryStates(t *testing.T) {
	j := &Journal{entries: map[string]Entry{}}
	e := Entry{Key: "a", Robot: "r", Kind: "SUBMIT", Phase: "IN_PROGRESS"}
	j.put(e)
	if !j.Blocked("r") || j.BlockedExcept("r", "a") {
		t.Fatal("prepare index")
	}
	e.Phase = "OUTCOME_UNKNOWN"
	j.put(e)
	if !j.Blocked("r") {
		t.Fatal("unknown forgotten")
	}
	e.ResolvedBy = "proof"
	j.put(e)
	if j.Blocked("r") {
		t.Fatal("resolved still blocks")
	}
	e.Key = "b"
	e.ResolvedBy = ""
	e.Phase = "COMMITTED"
	j.put(e)
	if j.Blocked("r") {
		t.Fatal("commit blocks")
	}
}
func BenchmarkAdmissionWith4096Receipts(b *testing.B) {
	j := &Journal{entries: map[string]Entry{}}
	for i := 0; i < 4096; i++ {
		j.put(Entry{Key: fmt.Sprint(i), Robot: "r", Kind: "SUBMIT", Phase: "COMMITTED"})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if j.Blocked("r") {
			b.Fatal("unexpected hold")
		}
	}
}
