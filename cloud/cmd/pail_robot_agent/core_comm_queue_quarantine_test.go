// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/corecomm"
)

// A durably rejected ordinary C1 report is quarantined and the queue moves on. The quarantine path must
// release the per-attempt context and clear the in-flight flag: the drain/health probe reads inFlight as
// "busy", so a stuck flag reports a busy queue forever after one rejection (found by go vet as a context
// leak in the preview.35 presweep, 2026-10-25). The next accepted report must still be delivered.
func TestCoreCommQueueQuarantineReleasesInFlight(t *testing.T) {
	f := &coreReceiver{}
	f.deny.Store(true)
	q, err := newReportQueue(f, reportQueueOptions{RobotID: "robot-1", ReceiptVersion: 1, Dir: t.TempDir(), RetryMax: time.Millisecond, NoJitter: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.close()
	r := blockReport(1)
	r.ReportId = "evt-rejected"
	r.ReceiptContractVersion = 1
	if r.ReportDigest, err = corecomm.ReportDigest(r); err != nil {
		t.Fatal(err)
	}
	q.push(r)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && f.received.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	if f.received.Load() < 1 {
		t.Fatal("report never reached the receiver")
	}
	for time.Now().Before(deadline) && q.inFlight.Load() {
		time.Sleep(time.Millisecond)
	}
	if q.inFlight.Load() {
		t.Fatal("quarantined report left the queue in flight")
	}
	f.deny.Store(false)
	r2 := blockReport(2)
	r2.ReportId = "evt-accepted"
	r2.ReceiptContractVersion = 1
	if r2.ReportDigest, err = corecomm.ReportDigest(r2); err != nil {
		t.Fatal(err)
	}
	q.push(r2)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && f.received.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	if f.received.Load() < 2 {
		t.Fatal("the report after a quarantine was not delivered")
	}
	for time.Now().Before(deadline) && q.inFlight.Load() {
		time.Sleep(time.Millisecond)
	}
	if q.inFlight.Load() {
		t.Fatal("queue still in flight after the accepted report")
	}
}
