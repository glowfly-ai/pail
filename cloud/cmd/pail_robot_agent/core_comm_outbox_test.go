// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"context"
	"errors"
	"github.com/glowfly/pail/services/internal/corecomm"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
	"google.golang.org/grpc"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type coreReceiver struct {
	fakeTokenClient
	down     atomic.Bool
	deny     atomic.Bool
	received atomic.Int64
}

func (f *coreReceiver) ReportDecision(ctx context.Context, r *tp.ReportDecisionRequest, o ...grpc.CallOption) (*tp.ReportDecisionResponse, error) {
	if f.down.Load() {
		return nil, errors.New("offline")
	}
	f.received.Add(1)
	eff := tp.EffectStatus_APPLIED
	disp := tp.ReceiptDisposition_NEW
	if f.deny.Load() {
		eff = tp.EffectStatus_REJECTED
		disp = tp.ReceiptDisposition_TERMINAL_REJECTED
	}
	return &tp.ReportDecisionResponse{Accepted: !f.deny.Load(), Receipt: &tp.ReportReceipt{ContractVersion: 1, ReportId: r.ReportId, ReportDigest: r.ReportDigest, RobotId: r.RobotId, ReceiverInstanceId: "server", Storage: tp.StorageLevel_ISSUER_DURABLE, Effect: eff, EffectScope: tp.EffectScope_ISSUER_CHAIN, Disposition: disp, JournalRecordRef: "journal"}}, nil
}
func coreFatal() *tp.ReportDecisionRequest {
	r := fatalReq()
	r.ReportId = "same-event"
	r.ReceiptContractVersion = 1
	r.ReportDigest, _ = corecomm.ReportDigest(r)
	return r
}
func TestCoreCommOutboxReplayAndOwnership(t *testing.T) {
	dir := t.TempDir()
	f := &coreReceiver{}
	f.down.Store(true)
	o, err := newCoreOutbox(dir, "robot-1", f)
	if err != nil {
		t.Fatal(err)
	}
	r := coreFatal()
	if e := o.save(r); e != nil {
		t.Fatal(e)
	}
	if _, e := o.deliver(context.Background(), r); e == nil {
		t.Fatal("offline acknowledged")
	}
	path := o.path(r)
	if _, e := os.Stat(path); e != nil {
		t.Fatal("pending evidence lost", e)
	}
	o.close()
	o2, err := newCoreOutbox(dir, "robot-1", f)
	if err != nil {
		t.Fatal(err)
	}
	defer o2.close()
	got, e := o2.read(path)
	if e != nil || got.ReportId != r.ReportId {
		t.Fatal("origin identity not preserved", e)
	}
	f.down.Store(false)
	resp, e := o2.deliver(context.Background(), got)
	if e != nil {
		t.Fatal(e)
	}
	if e = corecomm.CheckReportACK(r, resp, true); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("confirmed record not retired", e)
	}
}
func TestCoreCommOutboxRejectRetainsReceipt(t *testing.T) {
	f := &coreReceiver{}
	f.deny.Store(true)
	o, e := newCoreOutbox(t.TempDir(), "robot-1", f)
	if e != nil {
		t.Fatal(e)
	}
	defer o.close()
	r := coreFatal()
	if e = o.save(r); e != nil {
		t.Fatal(e)
	}
	_, e = o.deliver(context.Background(), r)
	if !errors.Is(e, corecomm.ErrTerminalRejected) {
		t.Fatal(e)
	}
	files, _ := filepath.Glob(filepath.Join(o.dir, "*.rejected"))
	if len(files) != 1 {
		t.Fatal("no rejected evidence", files)
	}
}
func TestCoreCommOutboxCannotClaimMemoryDurable(t *testing.T) {
	f := &coreReceiver{}
	q, e := newReportQueue(f, reportQueueOptions{RobotID: "robot-1", ReceiptVersion: 1})
	if q != nil {
		q.close()
	}
	if e == nil {
		t.Fatal("C1 started without durable storage")
	}
}
func TestCoreCommFatalLocalStoreDoesNotConfirmIssuer(t *testing.T) {
	f := &coreReceiver{}
	f.down.Store(true)
	q, e := newReportQueue(f, reportQueueOptions{RobotID: "robot-1", Dir: t.TempDir(), ReceiptVersion: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer q.close()
	p := &tokenProxy{c: f, m: newTokenMirror(f, "robot-1", 0), f: q}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, e := p.ReportDecision(ctx, coreFatal())
	if e != nil {
		t.Fatal(e)
	}
	if r.Accepted || r.GetReceipt().GetStorage() != tp.StorageLevel_LOCAL_DURABLE || r.GetReceipt().GetEffect() != tp.EffectStatus_PENDING {
		t.Fatal("local persisted report confirmed effect", r)
	}
}

func TestCoreCommOutboxSingleOwner(t *testing.T) {
	dir := t.TempDir()
	f := &coreReceiver{}
	f.down.Store(true)
	a, e := newCoreOutbox(dir, "robot-1", f)
	if e != nil {
		t.Fatal(e)
	}
	if b, e := newCoreOutbox(dir, "robot-1", f); e == nil {
		b.close()
		t.Fatal("second owner accepted")
	}
	a.close()
	b, e := newCoreOutbox(dir, "robot-1", f)
	if e != nil {
		t.Fatal(e)
	}
	b.close()
}
