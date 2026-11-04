// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/glowfly/pail/services/internal/corecomm"
	tp "github.com/glowfly/pail/services/proto/tokenv1"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Critical reports use an independent durable ownership log. Observation FIFO
// overflow cannot remove a critical report. C1 is explicit, never inferred from
// the presence of a local file or a successful TCP response.
type coreOutbox struct {
	stopOnce             sync.Once
	lockFile             *os.File
	done                 chan struct{}
	mu                   sync.Mutex
	dir, instance, robot string
	c                    tp.TokenServiceClient
	send                 chan struct{}
	stop                 chan struct{}
	maxBytes             int64
	fault                error
	onAck                func(*tp.ReportDecisionRequest)
	cohort               *cohortGuard // C1 cohort mismatch classification of delivery errors (P36-M1); nil-safe
	lastDeliverLog       time.Time    // the replay loop's delivery failures are logged at most every 30 s
}

// pendingCount is the number of critical reports still awaiting an Issuer receipt.
func (o *coreOutbox) pendingCount() int {
	if o == nil {
		return 0
	}
	files, e := os.ReadDir(o.dir)
	if e != nil {
		return 0
	}
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".pending") {
			n++
		}
	}
	return n
}

func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func atomicCoreFile(path string, b []byte) error {
	tmp := path + "." + uuid.NewString() + ".tmp"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer os.Remove(tmp)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	return syncDirectory(filepath.Dir(path))
}
func newCoreOutbox(dir, robot string, c tp.TokenServiceClient) (*coreOutbox, error) {
	path := filepath.Join(dir, "core-comm-critical")
	if e := os.MkdirAll(path, 0700); e != nil {
		return nil, e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("core outbox must be private directory")
	}
	if e = syncDirectory(path); e != nil {
		return nil, e
	}
	lockFile, e := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		lockFile.Close()
		return nil, errors.New("core outbox already owned")
	}
	owned := false
	defer func() {
		if !owned {
			unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
			lockFile.Close()
		}
	}()
	o := &coreOutbox{lockFile: lockFile, done: make(chan struct{}), dir: path, robot: robot, instance: uuid.NewString(), c: c, send: make(chan struct{}, 1), stop: make(chan struct{}), maxBytes: 16 << 20}
	// Validate every retained record before serving. Corrupt evidence is retained.
	entries, e := os.ReadDir(path)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pending") {
			if _, e = o.read(filepath.Join(path, entry.Name())); e != nil {
				return nil, e
			}
		}
	}
	owned = true
	go o.run()
	return o, nil
}
func (o *coreOutbox) path(r *tp.ReportDecisionRequest) string {
	h := sha256.Sum256([]byte(r.RobotId + "\x00" + r.ReportId))
	return filepath.Join(o.dir, hex.EncodeToString(h[:])+".pending")
}
func (o *coreOutbox) read(path string) (*tp.ReportDecisionRequest, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() > corecomm.MaxCanonicalBytes {
		return nil, errors.New("invalid outbox record")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	r := &tp.ReportDecisionRequest{}
	if e = proto.Unmarshal(b, r); e != nil {
		return nil, e
	}
	h, e := corecomm.ReportDigest(r)
	if e != nil || r.RobotId != o.robot || r.ReceiptContractVersion != 1 || !corecomm.ValidID(r.ReportId) || !bytes.Equal(h, r.ReportDigest) || o.path(r) != path {
		return nil, errors.New("outbox identity/digest mismatch")
	}
	return r, nil
}
func (o *coreOutbox) save(r *tp.ReportDecisionRequest) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fault != nil {
		return o.fault
	}
	path := o.path(r)
	if old, e := o.read(path); e == nil {
		if !bytes.Equal(old.ReportDigest, r.ReportDigest) {
			return corecomm.ErrConflict
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return e
		}
		return syncDirectory(o.dir)
	} else if !os.IsNotExist(e) {
		return e
	}
	entries, e := os.ReadDir(o.dir)
	if e != nil {
		return e
	}
	var size int64
	count := 0
	for _, x := range entries {
		if strings.HasSuffix(x.Name(), ".pending") || strings.HasSuffix(x.Name(), ".rejected") {
			i, e := x.Info()
			if e != nil {
				return e
			}
			size += i.Size()
			count++
		}
	}
	b, e := proto.Marshal(r)
	if e != nil {
		return e
	}
	if len(b) > corecomm.MaxCanonicalBytes || size+int64(len(b)) > o.maxBytes || count >= 4096 {
		return corecomm.ErrCapacity
	}
	return atomicCoreFile(path, b)
}
func (o *coreOutbox) deliver(ctx context.Context, r *tp.ReportDecisionRequest) (*tp.ReportDecisionResponse, error) {
	select {
	case o.send <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-o.send }()
	response, err := o.c.ReportDecision(ctx, r)
	if err != nil {
		return response, err
	}
	err = corecomm.CheckReportACK(r, response, true)
	if err != nil && !errors.Is(err, corecomm.ErrTerminalRejected) {
		return response, err
	}
	o.mu.Lock()
	if errors.Is(err, corecomm.ErrTerminalRejected) {
		record, _ := json.Marshal(struct {
			Request  *tp.ReportDecisionRequest  `json:"request"`
			Response *tp.ReportDecisionResponse `json:"response"`
		}{r, response})
		if e := atomicCoreFile(o.path(r)+".rejected", record); e != nil {
			o.mu.Unlock()
			return response, e
		}
	}
	// A durably recorded rejection is not an applied effect. Keep its receipt
	// in quarantine, then remove only the active delivery copy.
	if e := os.Remove(o.path(r)); e != nil && !os.IsNotExist(e) {
		o.mu.Unlock()
		return response, e
	}
	if e := syncDirectory(o.dir); e != nil {
		o.mu.Unlock()
		return response, e
	}
	callback := o.onAck
	o.mu.Unlock()
	if err == nil && callback != nil {
		callback(r)
	}
	return response, err
}
func (o *coreOutbox) close() {
	o.stopOnce.Do(func() { close(o.stop) })
	<-o.done
}
func (o *coreOutbox) run() {
	defer close(o.done)
	defer o.lockFile.Close()
	defer unix.Flock(int(o.lockFile.Fd()), unix.LOCK_UN)
	timer := time.NewTicker(250 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-o.stop:
			return
		case <-timer.C:
		}
		files, e := os.ReadDir(o.dir)
		if e != nil {
			o.mu.Lock()
			o.fault = e
			o.mu.Unlock()
			continue
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".pending") {
				continue
			}
			r, e := o.read(filepath.Join(o.dir, f.Name()))
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				o.mu.Lock()
				o.fault = e
				o.mu.Unlock()
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, e = o.deliver(ctx, r)
			cancel()
			// P36-M1: this loop used to discard every delivery result, so a critical report that the Issuer could
			// not receive was retried every 250 ms in silence until the outbox filled. A cohort mismatch enters the
			// guard's hold (not this outbox's fault: the hold clears itself when the Issuer answers v1 again); any
			// other repeated failure is logged at most every 30 s.
			if e != nil && !errors.Is(e, corecomm.ErrTerminalRejected) && !o.cohort.rpcError(e) {
				o.mu.Lock()
				due := time.Since(o.lastDeliverLog) >= cohortWarnEvery
				if due {
					o.lastDeliverLog = time.Now()
				}
				o.mu.Unlock()
				if due {
					log.Printf("robot-agent: critical report %s not confirmed by the Issuer: %v — retrying from the outbox (%d pending)", r.ReportId, e, o.pendingCount())
				}
			}
			select {
			case <-o.stop:
				return
			default:
			}
		}
	}
}
func (o *coreOutbox) healthy() bool { o.mu.Lock(); defer o.mu.Unlock(); return o.fault == nil }

// raiseFault records a critical fault the outbox did not detect itself (the rejection quarantine is full
// and a refused effect report could not be retained). The first fault stands until the process restarts.
// A cohort mismatch is not a storage fault and never comes here (cohortGuard owns that hold, P37-M1).
func (o *coreOutbox) raiseFault(e error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fault == nil {
		o.fault = e
	}
}
func (p *tokenProxy) reportCoreDecision(ctx context.Context, req *tp.ReportDecisionRequest) (*tp.ReportDecisionResponse, error) {
	if req.ReceiptContractVersion != 1 || !corecomm.ValidID(req.ReportId) {
		return nil, errors.New("CORE_REPORT_ID_OR_VERSION_INVALID")
	}
	h, e := corecomm.ReportDigest(req)
	if e != nil || !bytes.Equal(h, req.ReportDigest) {
		return nil, errors.New("CORE_REPORT_DIGEST_INVALID")
	}
	if req.RobotId != p.m.robotID {
		return nil, errors.New("CORE_REPORT_ROBOT_MISMATCH")
	}
	if p.f.core == nil {
		return nil, errors.New("CORE_REPORT_CONTRACT_UNAVAILABLE")
	}
	req = proto.Clone(req).(*tp.ReportDecisionRequest)
	p.f.stamp(req)
	if !req.Fatal && !req.StepComplete {
		p.m.expiredLeased(req)
		p.f.push(req)
		return &tp.ReportDecisionResponse{Accepted: true, Receipt: &tp.ReportReceipt{ContractVersion: 1, ReportId: req.ReportId, ReportDigest: h, RobotId: req.RobotId, ReceiverInstanceId: p.f.core.instance, Storage: tp.StorageLevel_LOCAL_BUFFERED, Effect: tp.EffectStatus_NOT_APPLICABLE, EffectScope: tp.EffectScope_SCOPE_NONE, Disposition: tp.ReceiptDisposition_NEW}}, nil
	}
	o := p.f.core
	o.mu.Lock()
	o.onAck = func(r *tp.ReportDecisionRequest) {
		if r.StepComplete {
			p.m.forwarded(r)
		}
	}
	o.mu.Unlock()
	// Do not let the replay sender confirm/remove a step before its local
	// lease bookkeeping has recorded the same event.
	select {
	case o.send <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	staged := true
	release := func() {
		if staged {
			<-o.send
			staged = false
		}
	}
	defer release()
	if req.Fatal && req.ChainId == "" {
		req.Attribution = &tp.ReportAttribution{ChainId: p.m.servedChain(), Basis: "gateway-served-chain", GatewayInstanceId: o.instance}
	}
	if e = o.save(req); e != nil {
		o.mu.Lock()
		o.fault = e
		o.mu.Unlock()
		return nil, fmt.Errorf("CORE_REPORT_NOT_DURABLE: %w", e)
	}
	// Retry uses the first persisted attribution, not whichever chain is active now.
	if saved, err := o.read(o.path(req)); err != nil {
		return nil, err
	} else {
		req = saved
	}
	leased := false
	if req.StepComplete {
		p.m.mu.Lock()
		for _, pending := range p.m.pendingRep {
			if pending.GetReportId() == req.ReportId && bytes.Equal(pending.GetReportDigest(), req.ReportDigest) {
				leased = true
				break
			}
		}
		p.m.mu.Unlock()
		if !leased {
			leased = p.m.consumed(req)
		}
		if leased {
			p.m.invalidateCache()
		} else {
			p.m.invalidateReportedChain(req.ChainId)
		}
	}
	if req.Fatal {
		p.m.Invalidate()
	}
	release()
	call := ctx
	cancel := func() {}
	if req.Fatal {
		call, cancel = context.WithTimeout(context.WithoutCancel(ctx), fatalForwardTimeout)
	}
	defer cancel()
	response, e := o.deliver(call, req)
	if e == nil || errors.Is(e, corecomm.ErrTerminalRejected) || (response != nil && corecomm.CheckReportACK(req, response, true) == nil) {
		return response, nil
	}
	effect := tp.EffectStatus_PENDING
	scope := tp.EffectScope_SCOPE_NONE
	if leased {
		effect = tp.EffectStatus_APPLIED
		scope = tp.EffectScope_LOCAL_LEASE
	}
	return &tp.ReportDecisionResponse{Accepted: leased, Receipt: &tp.ReportReceipt{ContractVersion: 1, ReportId: req.ReportId, ReportDigest: h, RobotId: req.RobotId, ReceiverInstanceId: o.instance, Storage: tp.StorageLevel_LOCAL_DURABLE, Effect: effect, EffectScope: scope, Disposition: tp.ReceiptDisposition_RETRYABLE, Reason: "upstream effect not confirmed"}}, nil
}

// Quarantine bound (preview.35 evaluation P35-L2): the critical outbox is bounded (4096 entries, 16 MiB)
// but the rejection quarantine beside the report log was not, and every refused observation became one
// more file for as long as the robot ran. The same bound applies here. Beyond it a refused observation is
// counted (refusedNotRetained) and not retained — the Issuer has journaled what it refused — and a refused
// effect report (fatal, step_complete) additionally raises the C1 critical fault, so new authority is not
// served until an operator looks. The queue advances in every case: a blocked head is the defect class
// preview.35 fixed. Registered in spec/DURABLE_STORES.tsv.
const quarantineMaxFiles = 4096
const quarantineMaxBytes int64 = 16 << 20

// quarantineUsageLocked counts the retained rejections once per process (they survive restarts), then
// maintains the counters. Caller holds q.mu.
func (q *reportQueue) quarantineUsageLocked() (int, int64) {
	if !q.quarantineCounted {
		files, _ := filepath.Glob(filepath.Join(q.disk.dir, "rejected-*.json"))
		var size int64
		for _, f := range files {
			if st, e := os.Stat(f); e == nil {
				size += st.Size()
			}
		}
		q.quarantineFiles, q.quarantineBytes, q.quarantineCounted = len(files), size, true
	}
	return q.quarantineFiles, q.quarantineBytes
}

// quarantine preserves rejected evidence before advancing the active queue.
// It never tells the fatal tracker that the report's requested effect applied.
func (q *reportQueue) quarantine(it queueItem, response *tp.ReportDecisionResponse) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.disk == nil {
		return errors.New("rejection quarantine storage unavailable")
	}
	b, e := json.Marshal(struct {
		Request  *tp.ReportDecisionRequest  `json:"request"`
		Response *tp.ReportDecisionResponse `json:"response"`
	}{it.req, response})
	if e != nil {
		return e
	}
	files, size := q.quarantineUsageLocked()
	if files >= quarantineMaxFiles || size+int64(len(b)) > quarantineMaxBytes {
		n := q.refusedNotRetained.Add(1)
		if it.req.Fatal || it.req.StepComplete {
			fault := fmt.Errorf("REJECTION_QUARANTINE_FULL: %d files, %d bytes; refused effect report %s not retained", files, size, it.req.ReportId)
			if q.core != nil {
				q.core.raiseFault(fault)
			}
			log.Printf("robot-agent: %v", fault)
		} else if n == 1 || n%1000 == 0 {
			log.Printf("robot-agent: rejection quarantine full (%d files, %d bytes): refused observations not retained so far: %d (decision=%v reason=%s)", files, size, n, it.req.Decision, it.req.ReasonCode)
		}
	} else {
		hash := sha256.Sum256([]byte(it.req.ReportId + "\x00" + it.req.RobotId))
		if e = atomicCoreFile(filepath.Join(q.disk.dir, "rejected-"+hex.EncodeToString(hash[:])+".json"), b); e != nil {
			return e
		}
		q.quarantineFiles++
		q.quarantineBytes += int64(len(b))
	}
	if it.isGap {
		return errors.New("gap receipt cannot be quarantined as ordinary event")
	}
	if _, e = q.disk.advance(); e != nil {
		return e
	}
	q.ackLocked(it.req, false)
	return nil
}

// C0 fatal handoff also requires a real sync, not merely the existence of a
// queue filename. Keep the original WAL if the queue falls back to memory,
// drops the record, or fails to sync.
func (q *reportQueue) pushFatalWithAck(req *tp.ReportDecisionRequest, ack func(bool)) bool {
	var outcome atomic.Int32
	q.pushWithAck(req, func(delivered bool) {
		if delivered {
			outcome.Store(1)
		} else {
			outcome.Store(-1)
		}
		if ack != nil {
			ack(delivered)
		}
	})
	q.mu.Lock()
	defer q.mu.Unlock()
	if outcome.Load() == 1 {
		return true
	}
	if outcome.Load() < 0 || q.disk == nil || !q.durable {
		return false
	}
	if err := q.disk.f.Sync(); err != nil {
		return false
	}
	return syncDirectory(q.disk.dir) == nil
}
