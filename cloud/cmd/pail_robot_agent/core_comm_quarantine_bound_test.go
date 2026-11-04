// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/corecomm"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
)

// recordingReceiver answers a C1 observation the way the preview.36 Issuer does when no chain owns it:
// recorded (ISSUER_DURABLE, journal reference), no authority effect, NEW. Nothing to quarantine.
type recordingReceiver struct {
	fakeTokenClient
	received atomic.Int64
}

func (f *recordingReceiver) ReportDecision(ctx context.Context, r *tp.ReportDecisionRequest, o ...grpc.CallOption) (*tp.ReportDecisionResponse, error) {
	f.received.Add(1)
	return &tp.ReportDecisionResponse{Accepted: true, Receipt: &tp.ReportReceipt{ContractVersion: 1, ReportId: r.ReportId, ReportDigest: r.ReportDigest, RobotId: r.RobotId, ReceiverInstanceId: "server", Storage: tp.StorageLevel_ISSUER_DURABLE, Effect: tp.EffectStatus_NOT_APPLICABLE, EffectScope: tp.EffectScope_SCOPE_NONE, Disposition: tp.ReceiptDisposition_NEW, Reason: "recorded; no chain attributed; no authority effect", JournalRecordRef: "core-observation:x"}}, nil
}

func c1Observation(i int) *tp.ReportDecisionRequest {
	r := blockReport(i)
	r.ReportId = fmt.Sprintf("obs-%d", i)
	r.ReceiptContractVersion = 1
	r.ReportDigest, _ = corecomm.ReportDigest(r)
	return r
}

func waitCount(t *testing.T, what string, n int64, get func() int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && get() < n {
		time.Sleep(time.Millisecond)
	}
	if get() < n {
		t.Fatalf("%s: want %d, got %d", what, n, get())
	}
}

// preview.35 evaluation P35-L2, consumer side: a recorded observation receipt is a delivery, not a refusal.
// No rejected-*.json appears and the queue moves on.
func TestObservationReceiptDoesNotQuarantine(t *testing.T) {
	dir := t.TempDir()
	f := &recordingReceiver{}
	q, err := newReportQueue(f, reportQueueOptions{RobotID: "robot-1", ReceiptVersion: 1, Dir: dir, RetryMax: time.Millisecond, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	for i := 1; i <= 3; i++ {
		q.push(c1Observation(i))
	}
	waitCount(t, "observations delivered", 3, f.received.Load)
	waitCount(t, "sent", 3, func() int64 { return int64(q.sent.Load()) })
	if files, _ := filepath.Glob(filepath.Join(dir, "rejected-*.json")); len(files) != 0 || q.refused.Load() != 0 {
		t.Fatalf("a recorded observation must not be quarantined: files=%v refused=%d", files, q.refused.Load())
	}
}

// The rejection quarantine is bounded like the critical outbox (4096 entries / 16 MiB). Beyond the bound a
// refused observation is counted and not retained and the queue still advances; a refused effect report
// (step_complete) additionally raises the C1 critical fault. Before preview.36 every refusal became a file.
func TestRejectionQuarantineIsBounded(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < quarantineMaxFiles; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("rejected-%04d.json", i)), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f := &coreReceiver{}
	f.deny.Store(true)
	q, err := newReportQueue(f, reportQueueOptions{RobotID: "robot-1", ReceiptVersion: 1, Dir: dir, RetryMax: time.Millisecond, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	if q.core == nil {
		t.Fatal("C1 queue without a critical outbox")
	}
	q.push(c1Observation(1))
	waitCount(t, "refused observation presented", 1, f.received.Load)
	waitCount(t, "refusedNotRetained", 1, func() int64 { return int64(q.refusedNotRetained.Load()) })
	if files, _ := filepath.Glob(filepath.Join(dir, "rejected-*.json")); len(files) != quarantineMaxFiles {
		t.Fatalf("bound not enforced: %d files", len(files))
	}
	if !q.core.healthy() {
		t.Fatal("an unretained observation refusal is not a critical fault")
	}
	// the queue moved on: the next (accepted) report is delivered
	f.deny.Store(false)
	q.push(c1Observation(2))
	waitCount(t, "report after the unretained refusal", 2, f.received.Load)
	waitCount(t, "sent", 1, func() int64 { return int64(q.sent.Load()) })
	// a refused effect report beyond the bound raises the critical fault and the queue still advances
	f.deny.Store(true)
	done := c1Observation(3)
	done.Decision = tp.Decision_PERMIT
	done.StepComplete = true
	done.ReasonCode = ""
	done.ReportDigest, _ = corecomm.ReportDigest(done)
	q.push(done)
	waitCount(t, "refused effect report presented", 3, f.received.Load)
	waitCount(t, "refusedNotRetained", 2, func() int64 { return int64(q.refusedNotRetained.Load()) })
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && q.core.healthy() {
		time.Sleep(time.Millisecond)
	}
	if q.core.healthy() {
		t.Fatal("a refused effect report that could not be retained must raise the critical fault")
	}
	f.deny.Store(false)
	q.push(c1Observation(4))
	waitCount(t, "report after the unretained effect refusal", 4, f.received.Load)
	if files, _ := filepath.Glob(filepath.Join(dir, "rejected-*.json")); len(files) != quarantineMaxFiles {
		t.Fatalf("bound not enforced after the effect refusal: %d files", len(files))
	}
}
