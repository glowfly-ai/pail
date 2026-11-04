// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// reportQueue (OI-01, 2026-10-01): the non-mutating decision reports the gate
// hands this agent (per-command BLOCKs, recheck BLOCKs, mid-step PERMITs) are
// acknowledged locally — D3: the WAN round trip must not starve the 20 Hz
// permit heartbeat — and forwarded by one background sender. Before OI-01 a
// failed forward was logged and DROPPED, so every block the gate decided during
// a link outage was missing from the issuer's ledger. The robot was correct
// (it stood still); the audit record was not complete.
//
// Now a report stays at the head of the queue until the issuer acknowledges
// it: retried with bounded backoff, immediately on beacon-stream recovery,
// and — when a queue directory is configured — from a disk log that survives
// an agent restart. Every report carries delivery metadata (decided_unix_ms,
// agent_run_id, agent_seq, delivery live|replayed) so the issuer journals a
// late report as the late fact it is and can tell a duplicate from a second
// decision. When the queue overflows the OLDEST report is dropped and one
// summary report (ERR_REPORT_GAP) describing the dropped span is sent first —
// a record that something was lost is itself part of the ledger (H-B2).
//
// Order: reports are sent in agent_seq order. A mutating report (step
// complete / fatal) waits only for the attempt in flight, not for the queue
// to empty (a failing link must not hold the lease or a revocation hostage);
// readers restore order from agent_seq / decided_unix_ms.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glowfly/pail/services/internal/corecomm"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	reportDeliveryLive     = "live"
	reportDeliveryReplayed = "replayed"
	reportGapReason        = "ERR_REPORT_GAP"

	reportQueueMemCap     = 4096
	reportQueueDefaultCap = int64(64 << 20) // 64 MiB disk log
	reportAttemptTimeout  = 5 * time.Second
	reportRetryFloor      = 200 * time.Millisecond
	reportRetryMaxDefault = 5 * time.Second
	reportHeadPersistEach = time.Second

	reportLogFile  = "queue.log"
	reportHeadFile = "queue.head"
	reportGapFile  = "queue.gap"
)

// reportQueueOptions — zero values mean: memory only, defaults.
type reportQueueOptions struct {
	ReceiptVersion uint32 // explicit core-comm-v1; requires durable storage
	RobotID        string
	Dir            string        // "" = memory only
	MaxBytes       int64         // disk log bound; <= 0 with Dir set = default 64 MiB
	RetryMax       time.Duration // backoff ceiling; 0 = 5 s
	Attempt        time.Duration // per-attempt timeout; 0 = 5 s
	MemCap         int           // memory FIFO bound; 0 = 4096
	NoJitter       bool          // tests only: wait the full backoff instead of a random share of it
}

// gapSummary describes reports the queue had to drop. It is sent ahead of
// everything else, once, as a single ERR_REPORT_GAP report, and persisted
// beside the log so a restart does not lose the fact that something was lost.
type gapSummary struct {
	Dropped  uint64            `json:"dropped"`
	FirstSeq uint64            `json:"first_seq"`
	LastSeq  uint64            `json:"last_seq"`
	FirstMS  int64             `json:"first_ms"`
	LastMS   int64             `json:"last_ms"`
	Reasons  map[string]uint64 `json:"reasons"`
	Durable  bool              `json:"durable"`
}

func (g *gapSummary) add(req *tokenpb.ReportDecisionRequest) {
	if g.Reasons == nil {
		g.Reasons = map[string]uint64{}
	}
	g.Dropped++
	seq, ms := req.GetAgentSeq(), req.GetDecidedUnixMs()
	if g.FirstSeq == 0 || (seq != 0 && seq < g.FirstSeq) {
		g.FirstSeq = seq
	}
	if seq > g.LastSeq {
		g.LastSeq = seq
	}
	if g.FirstMS == 0 || (ms != 0 && ms < g.FirstMS) {
		g.FirstMS = ms
	}
	if ms > g.LastMS {
		g.LastMS = ms
	}
	code := req.GetReasonCode()
	if code == "" {
		code = "?"
	}
	g.Reasons[code]++
}

// detail is the wire form the issuer journals verbatim (gap: true).
func (g *gapSummary) detail() string {
	keys := make([]string, 0, len(g.Reasons))
	for k := range g.Reasons {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+":"+strconv.FormatUint(g.Reasons[k], 10))
	}
	return fmt.Sprintf("gap:dropped=%d;first_seq=%d;last_seq=%d;first_ms=%d;last_ms=%d;durable=%t;reasons=%s",
		g.Dropped, g.FirstSeq, g.LastSeq, g.FirstMS, g.LastMS, g.Durable, strings.Join(parts, ","))
}

type reportQueue struct {
	core    *coreOutbox
	cohort  *cohortGuard // C1 cohort mismatch classification (P36-M1); nil-safe
	c       tokenpb.TokenServiceClient
	robotID string
	runID   string
	seq     atomic.Uint64

	mu        sync.Mutex
	cond      *sync.Cond
	mem       []*tokenpb.ReportDecisionRequest // memory FIFO when disk == nil
	memCap    int
	disk      *reportLog // nil = memory only
	gap       *gapSummary
	attempted bool // the head was tried and failed → next attempt is "replayed"
	degraded  bool // a failure happened and the queue has not drained since: everything behind it waited through an outage
	closed    bool
	stopCh    chan struct{}                   // closed once by close(); the cohort guard's workers end on it
	acks      map[string]func(delivered bool) // P16-L1: callers that want to know when a queued report was confirmed (true) or dropped (false); keyed by fatalKey
	// rejection quarantine accounting (rejected-*.json beside the report log; bounded, P35-L2); under mu
	quarantineCounted bool
	quarantineFiles   int
	quarantineBytes   int64

	inFlight atomic.Bool
	kick     chan struct{}
	retryMax time.Duration
	attempt  time.Duration
	noJitter bool
	durable  bool

	// counters for logs/tests
	sent     atomic.Uint64
	replayed atomic.Uint64
	refused  atomic.Uint64 // definitive Issuer refusals retained locally (never confirmed, never retried)
	dropped  atomic.Uint64
	// definitive refusals beyond the quarantine bound: counted, logged, not retained (P35-L2)
	refusedNotRetained atomic.Uint64
}

// newReportForwarder keeps the pre-OI-01 constructor name: memory only, no
// run id configured, defaults — what the existing tests and the wire tests
// build. Production goes through newReportQueue.
func newReportForwarder(c tokenpb.TokenServiceClient) *reportQueue {
	q, _ := newReportQueue(c, reportQueueOptions{})
	return q
}

// newReportQueue opens the disk log when a directory is given.
//
// P25-M2 (preview.25 evaluation, 2026-10-21): a directory that cannot be used
// was a logged degradation to memory-only, and the fatal path then still logged
// "queued durably". The TB3 software demo ran that way from its first day, and an
// agent+gate crash after an E-STOP lost the ESTOP from the signed ledger (6 of 8
// runs). A store that claims durability refuses to start when it cannot be
// durable: the error is returned and the caller exits (REPORT_QUEUE_NOT_DURABLE).
// Memory-only is a configuration the operator states (PAIL_REPORT_QUEUE_BYTES=0,
// Dir == ""), never a fallback.
func newReportQueue(c tokenpb.TokenServiceClient, o reportQueueOptions) (*reportQueue, error) {
	q := &reportQueue{c: c, robotID: o.RobotID, runID: uuid.NewString(), kick: make(chan struct{}, 1), stopCh: make(chan struct{})}
	q.cond = sync.NewCond(&q.mu)
	q.memCap = o.MemCap
	if q.memCap <= 0 {
		q.memCap = reportQueueMemCap
	}
	q.retryMax = o.RetryMax
	if q.retryMax <= 0 {
		q.retryMax = reportRetryMaxDefault
	}
	q.attempt = o.Attempt
	if q.attempt <= 0 {
		q.attempt = reportAttemptTimeout
	}
	q.noJitter = o.NoJitter
	if o.Dir != "" {
		capBytes := o.MaxBytes
		if capBytes <= 0 {
			capBytes = reportQueueDefaultCap
		}
		d, err := openReportLog(o.Dir, capBytes)
		if err != nil {
			return nil, fmt.Errorf("REPORT_QUEUE_NOT_DURABLE: report queue directory %s unusable (%w); set PAIL_REPORT_QUEUE_DIR to a directory this user can write, or PAIL_REPORT_QUEUE_BYTES=0 to run memory only on purpose", o.Dir, err)
		}
		q.disk = d
		q.durable = true
		if g, err := d.loadGap(); err == nil && g != nil {
			q.gap = g
		}
		log.Printf("robot-agent: report queue: durable log %s (cap %d bytes, pending %d bytes, run=%s)",
			o.Dir, capBytes, d.liveBytes(), q.runID)
		q.replayFatalWAL()
	} else {
		log.Printf("robot-agent: report queue: memory only by configuration — a fatal report that has not reached the issuer is lost when this process ends")
	}
	if o.ReceiptVersion != 0 {
		if o.ReceiptVersion != 1 || o.Dir == "" {
			return nil, errors.New("CORE_REPORT_CONTRACT_REQUIRES_DURABLE_STORAGE")
		}
		var err error
		q.core, err = newCoreOutbox(o.Dir, o.RobotID, c)
		if err != nil {
			return nil, err
		}
		// C1 cohort guard (P36-M1): shared by this queue and the critical outbox; main adds the startup refusal,
		// the census re-check and starts its workers. Built here so every C1 queue has it, wired or not.
		q.cohort = &cohortGuard{held: q.heldCounts, stop: q.stopCh}
		q.core.cohort = q.cohort
	}
	go q.run()
	return q, nil
}

// isDurable reports whether reports pushed now survive a restart of this process.
func (q *reportQueue) isDurable() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.durable && q.disk != nil
}

// Write-ahead record of a fatal report (P25-M2). The fatal path used to push a
// fatal on the durable queue only AFTER its upstream attempt had failed (3 s);
// an agent that died inside that window, or on a non-durable queue, lost the
// E-STOP. Now the fatal is written to <dir>/fatal-<key>.wal BEFORE the attempt
// and removed once the issuer confirmed it or the queue log holds it; a restart
// replays every .wal into the queue (replayFatalWAL), so the ledger sees the
// E-STOP whatever happened to the process in between. The issuer revokes
// idempotently, so a duplicate delivery changes nothing.
const fatalWALPrefix = "fatal-"

func fatalWALName(req *tokenpb.ReportDecisionRequest) string {
	sum := sha256.Sum256([]byte(fatalKey(req)))
	return fatalWALPrefix + hex.EncodeToString(sum[:8]) + ".wal"
}

// writeAheadFatal records req durably before any upstream attempt. Returns
// false (and logs once per call) when there is no durable store.
func (q *reportQueue) writeAheadFatal(req *tokenpb.ReportDecisionRequest) bool {
	q.mu.Lock()
	d := q.disk
	q.mu.Unlock()
	if d == nil {
		return false
	}
	b, err := proto.Marshal(req)
	if err != nil {
		return false
	}
	path := filepath.Join(d.dir, fatalWALName(req))
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		log.Printf("robot-agent: fatal write-ahead failed (%v) — the report is NOT durable until the queue holds it", err)
		return false
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		log.Printf("robot-agent: fatal write-ahead failed (%v) — the report is NOT durable until the queue holds it", err)
		return false
	}
	if err = syncDirectory(d.dir); err != nil {
		log.Printf("fatal WAL directory sync failed: %v", err)
		return false
	}
	return true
}

// clearWriteAhead removes the write-ahead record once the issuer confirmed the
// fatal or the queue's own log holds it.
func (q *reportQueue) clearWriteAhead(req *tokenpb.ReportDecisionRequest) {
	q.mu.Lock()
	d := q.disk
	q.mu.Unlock()
	if d == nil {
		return
	}
	_ = os.Remove(filepath.Join(d.dir, fatalWALName(req)))
}

// replayFatalWAL pushes every write-ahead fatal left by a previous run on the
// queue (delivery=replayed through the run id) and removes the records.
func (q *reportQueue) replayFatalWAL() {
	entries, err := os.ReadDir(q.disk.dir)
	if err != nil {
		return
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, fatalWALPrefix) || !strings.HasSuffix(name, ".wal") {
			continue
		}
		path := filepath.Join(q.disk.dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		req := &tokenpb.ReportDecisionRequest{}
		if proto.Unmarshal(b, req) != nil {
			log.Printf("robot-agent: fatal write-ahead %s unreadable — evidence retained", name)
			_ = os.Rename(path, path+".corrupt")
			_ = syncDirectory(q.disk.dir)
			continue
		}
		if q.pushFatalWithAck(req, nil) {
			_ = os.Remove(path)
			_ = syncDirectory(q.disk.dir)
			n++
		} else {
			log.Printf("fatal write-ahead %s remains owned by WAL (handoff not durable)", name)
		}
	}
	if n > 0 {
		log.Printf("robot-agent: report queue: %d fatal report(s) written ahead by a previous run re-queued for the issuer", n)
	}
}

func (q *reportQueue) RunID() string { return q.runID }

// stamp fills the delivery metadata on a report the gate just handed us. The
// decided time is this agent's receipt time: gate and agent share the robot
// and its clock, and changing three adapters to send their own time is not
// worth milliseconds.
func (q *reportQueue) stamp(req *tokenpb.ReportDecisionRequest) {
	if req.GetAgentRunId() != "" && req.GetAgentSeq() != 0 {
		return
	}
	if req.GetDecidedUnixMs() == 0 {
		req.DecidedUnixMs = time.Now().UnixMilli()
	}
	req.AgentRunId = q.runID
	req.AgentSeq = q.seq.Add(1)
	req.Delivery = reportDeliveryLive
}

// push enqueues a non-mutating report. Never blocks the caller: the memory
// FIFO or the disk log takes it, and overflow drops the OLDEST report into
// the gap summary.
func (q *reportQueue) push(req *tokenpb.ReportDecisionRequest) {
	q.stamp(req)
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.disk != nil {
		b, err := proto.Marshal(req)
		if err == nil {
			err = q.disk.append(b)
		}
		if err != nil {
			// The log broke under us: keep serving from memory and say so in the
			// next gap summary (durable=false means "a restart may lose these").
			log.Printf("robot-agent: report queue: disk append failed (%v) — switching to memory only", err)
			q.disk = nil
			q.durable = false
			q.mem = append(q.mem, req)
		} else {
			for q.disk.liveBytes() > q.disk.capBytes {
				old, err := q.disk.dropOldest()
				if err != nil {
					break
				}
				q.recordDropLocked(old)
			}
		}
	} else {
		q.mem = append(q.mem, req)
		for len(q.mem) > q.memCap {
			q.recordDropLocked(q.mem[0])
			q.mem[0] = nil
			q.mem = q.mem[1:]
		}
	}
	q.cond.Signal()
}

// pushWithAck is push plus a one-shot callback: ack(true) once the issuer
// confirmed this report from the queue, ack(false) if the queue had to drop it
// (overflow or an unreadable record). Used by the fatal path so a repeat of
// the same fatal is not forwarded while its copy is still queued (P16-L1).
// Memory records are matched by pointer, disk records by fatalKey (the record
// is re-decoded on the way out).
func (q *reportQueue) pushWithAck(req *tokenpb.ReportDecisionRequest, ack func(delivered bool)) {
	if ack != nil {
		q.mu.Lock()
		if q.acks == nil {
			q.acks = map[string]func(bool){}
		}
		q.acks[fatalKey(req)] = ack
		q.mu.Unlock()
	}
	q.push(req)
}

// ackLocked fires and forgets the callback registered for req, if any.
func (q *reportQueue) ackLocked(req *tokenpb.ReportDecisionRequest, delivered bool) {
	if q.acks == nil || req == nil {
		return
	}
	key := fatalKey(req)
	ack, ok := q.acks[key]
	if !ok {
		return
	}
	delete(q.acks, key)
	ack(delivered)
}

func (q *reportQueue) recordDropLocked(old *tokenpb.ReportDecisionRequest) {
	q.ackLocked(old, false)
	if q.gap == nil {
		q.gap = &gapSummary{}
	}
	q.gap.Durable = q.durable
	q.gap.add(old)
	q.dropped.Add(1)
	if q.disk != nil {
		_ = q.disk.saveGap(q.gap)
	}
}

// drain keeps the pre-OI-01 promise on a live link — a mutating report never
// overtakes queued telemetry (ledger order = decision order) — and bounds it
// on a dead one: the wait ends as soon as an attempt has failed (the queue
// will not empty until the link returns) or after one attempt timeout. A
// mutating report must reach the issuer, or fail honestly, within that bound;
// readers restore order across an outage from agent_seq.
func (q *reportQueue) drain() {
	deadline := time.Now().Add(q.attempt)
	for time.Now().Before(deadline) {
		q.mu.Lock()
		busy := q.inFlight.Load() || len(q.mem) > 0 || q.gap != nil || (q.disk != nil && q.disk.records > 0)
		failing := q.attempted
		q.mu.Unlock()
		if !busy || failing {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// kickNow is the reconcile hook: the beacon stream came back, so retry at
// once instead of waiting out the backoff.
func (q *reportQueue) kickNow() {
	select {
	case q.kick <- struct{}{}:
	default:
	}
}

// pending reports not yet acknowledged (gap summary counts as one).
func (q *reportQueue) pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := len(q.mem)
	if q.disk != nil {
		n = q.disk.records
	}
	if q.gap != nil {
		n++
	}
	return n
}

type queueItem struct {
	req   *tokenpb.ReportDecisionRequest
	isGap bool
}

// next blocks until there is something to send and returns the head. The
// request returned is the one to put on the wire: a copy for disk records
// (so the stored bytes keep their original delivery stamp), the gap summary
// freshly built, or the memory head itself.
func (q *reportQueue) next() (queueItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if q.closed {
			return queueItem{}, false
		}
		if q.gap != nil {
			g := *q.gap
			req := &tokenpb.ReportDecisionRequest{
				RobotId: q.robotID, Decision: tokenpb.Decision_BLOCK, ReasonCode: reportGapReason,
				Detail: g.detail(), DecidedUnixMs: time.Now().UnixMilli(),
				AgentRunId: q.runID, AgentSeq: q.seq.Add(1), Delivery: reportDeliveryReplayed,
			}
			return queueItem{req: req, isGap: true}, true
		}
		if q.disk != nil {
			b, err := q.disk.peek()
			if err == nil && b != nil {
				req := &tokenpb.ReportDecisionRequest{}
				if proto.Unmarshal(b, req) != nil {
					// Unreadable head: skip it and account for it — never stall on it.
					_, _ = q.disk.dropOldest()
					q.recordDropLocked(&tokenpb.ReportDecisionRequest{ReasonCode: "?corrupt"})
					continue
				}
				if q.replayedLocked(req) {
					req.Delivery = reportDeliveryReplayed
				}
				return queueItem{req: req}, true
			}
			if err != nil {
				// Torn/corrupt tail at the head: drop what cannot be read, say so.
				_, _ = q.disk.dropOldest()
				q.recordDropLocked(&tokenpb.ReportDecisionRequest{ReasonCode: "?corrupt"})
				continue
			}
		} else if len(q.mem) > 0 {
			req := q.mem[0]
			if q.replayedLocked(req) {
				req.Delivery = reportDeliveryReplayed
			}
			return queueItem{req: req}, true
		}
		q.cond.Wait()
	}
}

// replayedLocked: a report is "replayed" when it is sent again after its own
// failed attempt, when it waited in the queue through an outage (a failure
// happened and the queue has not drained since — the issuer receives it long
// after it was decided), or when it comes from the disk log of a previous run.
func (q *reportQueue) replayedLocked(req *tokenpb.ReportDecisionRequest) bool {
	return q.attempted || q.degraded || req.GetAgentRunId() != q.runID
}

func (q *reportQueue) emptyLocked() bool {
	if q.gap != nil || len(q.mem) > 0 {
		return false
	}
	return q.disk == nil || q.disk.records == 0
}

func (q *reportQueue) pop(it queueItem) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.attempted = false
	defer func() {
		if q.emptyLocked() {
			q.degraded = false // the outage is behind us: the next report is live again
		}
	}()
	if it.isGap {
		q.gap = nil
		if q.disk != nil {
			_ = q.disk.clearGap()
		}
		return
	}
	q.ackLocked(it.req, true)
	if q.disk != nil {
		_, _ = q.disk.advance()
		return
	}
	if len(q.mem) > 0 && q.mem[0] == it.req {
		q.mem[0] = nil
		q.mem = q.mem[1:]
	}
}

func (q *reportQueue) failed() {
	q.mu.Lock()
	q.attempted = true
	q.degraded = true
	q.mu.Unlock()
}

// discardRefused drops the head of a memory-only queue after the Issuer's definitive refusal: the
// waiting acknowledgement (a fatal hand-off) learns "not delivered", nothing is confirmed, and the
// reports behind it are not held hostage. A durable queue retains the refusal instead (quarantine).
func (q *reportQueue) discardRefused(it queueItem) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.ackLocked(it.req, false)
	if len(q.mem) > 0 && q.mem[0] == it.req {
		q.mem[0] = nil
		q.mem = q.mem[1:]
	}
}

func (q *reportQueue) run() {
	backoff := time.Duration(0)
	for {
		it, ok := q.next()
		if !ok {
			return
		}
		q.inFlight.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), q.attempt)
		response, err := q.c.ReportDecision(ctx, it.req)
		if err == nil {
			err = corecomm.CheckReportACK(it.req, response, true)
		}
		// A definitive refusal is retained, never confirmed, and never retried: identical bytes cannot flip
		// it, and this queue is a FIFO — retrying the head blocks every later report. C1 says so with a
		// TERMINAL_REJECTED receipt. On the C0 wire a successful RPC that answers accepted=false IS the
		// Issuer's definitive refusal (unknown chain, single-use, invalid completion signal), and the Issuer
		// has already journaled what it refused, unattributed. preview.35 pre-seal on the built images: the
		// readiness probe's BLOCK ERR_NO_TOKEN was refused, the agent retried it for the whole run, and no later
		// decision reached the journal (test-supersede 2/8, every B-* precondition unmet).
		terminal := errors.Is(err, corecomm.ErrTerminalRejected) ||
			(errors.Is(err, corecomm.ErrRejected) && it.req.GetReceiptContractVersion() == 0 && !it.isGap)
		if terminal {
			retained := q.quarantine(it, response) == nil
			if !retained && it.req.GetReceiptContractVersion() == 0 && !it.isGap {
				// memory-only queue (PAIL_REPORT_QUEUE_BYTES=0, the operator's explicit opt-out of durability):
				// nothing to retain the refusal in; say so and move on rather than stall the stream.
				log.Printf("robot-agent: ReportDecision refused by the Issuer and NOT retained (memory-only queue): decision=%v reason=%s token=%s seq=%d — not confirmed, dropped",
					it.req.Decision, it.req.ReasonCode, it.req.TokenId, it.req.AgentSeq)
				q.discardRefused(it)
				retained = true
			}
			if retained {
				q.refused.Add(1)
				log.Printf("robot-agent: ReportDecision refused by the Issuer (decision=%v reason=%s token=%s seq=%d): %v — retained as rejected, not confirmed, queue continues",
					it.req.Decision, it.req.ReasonCode, it.req.TokenId, it.req.AgentSeq, err)
				// release this attempt's context and the in-flight flag here too, or the drain/health probe
				// reads a busy queue forever after one refusal (go vet context leak, preview.35 presweep)
				cancel()
				q.inFlight.Store(false)
				backoff = 0
				continue
			}
		}
		cancel()
		q.inFlight.Store(false)
		if err == nil {
			q.sent.Add(1)
			if it.req.GetDelivery() == reportDeliveryReplayed {
				q.replayed.Add(1)
			}
			q.pop(it)
			backoff = 0
			continue
		}
		q.failed()
		if q.cohort.rpcError(err) {
			// P36-M1: an Issuer refusing this C1 report is a cohort mismatch, not a transport failure. The guard
			// raised the critical fault and warns every 30 s; the head stays (it is never downgraded to the C0 wire
			// and is not dropped) and the retry backs off to the ceiling instead of hammering the Issuer.
			backoff = q.retryMax
		} else if backoff == 0 {
			log.Printf("robot-agent: ReportDecision forward failed (decision=%v reason=%s token=%s seq=%d): %v — queued for retry",
				it.req.Decision, it.req.ReasonCode, it.req.TokenId, it.req.AgentSeq, err)
			backoff = reportRetryFloor
		} else {
			backoff *= 2
			if backoff > q.retryMax {
				backoff = q.retryMax
			}
		}
		// Full jitter, and a kick (beacon stream recovery) ends the wait early.
		wait := backoff
		if !q.noJitter {
			wait = time.Duration(rand.Int63n(int64(backoff)) + 1)
		}
		select {
		case <-q.kick:
			backoff = 0
		case <-time.After(wait):
		}
	}
}

// close stops the sender (tests). Pending reports stay on disk.
func (q *reportQueue) close() {
	if q.core != nil {
		q.core.close()
	}
	q.mu.Lock()
	if !q.closed && q.stopCh != nil {
		close(q.stopCh) // ends the cohort guard's warning timer and re-check worker
	}
	q.closed = true
	if q.disk != nil {
		_ = q.disk.persistHead(true)
	}
	q.mu.Unlock()
	q.cond.Broadcast()
}

// ---------------------------------------------------------------------------
// reportLog — an append-only record log with a persisted head offset.
//
// Record: u32 BE length ‖ bytes ‖ u32 BE crc32(bytes). The head offset lives
// in queue.head (written atomically, at most once a second and when the log
// empties). On restart everything from the persisted head is sent again — a
// report acknowledged after the last head write is therefore sent twice, and
// the issuer's duplicate window turns the second into a `duplicate: true`
// record rather than a second decision. When the live span exceeds the cap
// the oldest record is dropped (accounted by the caller); when dead bytes in
// front of the head exceed the cap the live tail is rewritten into a fresh
// file so the file itself stays bounded.
// ---------------------------------------------------------------------------
type reportLog struct {
	dir       string
	capBytes  int64
	f         *os.File
	size      int64
	head      int64
	records   int // live records (counted from head on open, then maintained)
	lastSave  time.Time
	headDirty bool
}

func openReportLog(dir string, capBytes int64) (*reportLog, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, reportLogFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	l := &reportLog{dir: dir, capBytes: capBytes, f: f, size: st.Size()}
	if b, err := os.ReadFile(filepath.Join(dir, reportHeadFile)); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n >= 0 && n <= l.size {
			l.head = n
		}
	}
	// Count live records; stop at the first unreadable one (a torn tail from a
	// crash mid-append) and cut the file there.
	off := l.head
	for off < l.size {
		n, err := l.recordLenAt(off)
		if err != nil {
			_ = f.Truncate(off)
			l.size = off
			break
		}
		off += n
		l.records++
	}
	if l.head >= l.size {
		_ = l.reset()
	}
	return l, nil
}

func (l *reportLog) liveBytes() int64 { return l.size - l.head }

func (l *reportLog) recordLenAt(off int64) (int64, error) {
	var hdr [4]byte
	if _, err := l.f.ReadAt(hdr[:], off); err != nil {
		return 0, err
	}
	n := int64(binary.BigEndian.Uint32(hdr[:]))
	if n == 0 || n > 1<<20 || off+4+n+4 > l.size {
		return 0, errors.New("torn record")
	}
	return 4 + n + 4, nil
}

func (l *reportLog) append(b []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	var crc [4]byte
	binary.BigEndian.PutUint32(crc[:], crc32.ChecksumIEEE(b))
	buf := make([]byte, 0, len(b)+8)
	buf = append(buf, hdr[:]...)
	buf = append(buf, b...)
	buf = append(buf, crc[:]...)
	if _, err := l.f.WriteAt(buf, l.size); err != nil {
		return err
	}
	l.size += int64(len(buf))
	l.records++
	return nil
}

// peek returns the record bytes at the head, nil when empty, or an error when
// the head record cannot be read (caller drops it).
func (l *reportLog) peek() ([]byte, error) {
	if l.head >= l.size {
		return nil, nil
	}
	var hdr [4]byte
	if _, err := l.f.ReadAt(hdr[:], l.head); err != nil {
		return nil, err
	}
	n := int64(binary.BigEndian.Uint32(hdr[:]))
	if n == 0 || n > 1<<20 || l.head+4+n+4 > l.size {
		return nil, errors.New("torn record at head")
	}
	b := make([]byte, n)
	if _, err := l.f.ReadAt(b, l.head+4); err != nil {
		return nil, err
	}
	var crc [4]byte
	if _, err := l.f.ReadAt(crc[:], l.head+4+n); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(crc[:]) != crc32.ChecksumIEEE(b) {
		return nil, errors.New("crc mismatch at head")
	}
	return b, nil
}

// advance moves the head past the current record (after a successful send).
func (l *reportLog) advance() (int64, error) {
	n, err := l.recordLenAt(l.head)
	if err != nil {
		// Cannot measure it: drop everything up to the end rather than stall.
		n = l.size - l.head
	}
	l.head += n
	if l.records > 0 {
		l.records--
	}
	l.headDirty = true
	if l.head >= l.size {
		return n, l.reset()
	}
	if l.head > l.capBytes {
		return n, l.compact()
	}
	return n, l.persistHead(false)
}

// dropOldest removes the head record (overflow) and returns it for the gap
// summary. The decoded request may be nil when the bytes are unreadable.
func (l *reportLog) dropOldest() (*tokenpb.ReportDecisionRequest, error) {
	if l.head >= l.size {
		return nil, io.EOF
	}
	b, _ := l.peek()
	req := &tokenpb.ReportDecisionRequest{}
	if b == nil || proto.Unmarshal(b, req) != nil {
		req = &tokenpb.ReportDecisionRequest{ReasonCode: "?corrupt"}
	}
	if _, err := l.advance(); err != nil {
		return req, err
	}
	return req, nil
}

// reset — the log is empty: truncate so the file does not grow forever.
func (l *reportLog) reset() error {
	if err := l.f.Truncate(0); err != nil {
		return err
	}
	l.size, l.head, l.records = 0, 0, 0
	return l.persistHead(true)
}

// compact rewrites the live tail into a fresh file (dead bytes exceeded the cap).
func (l *reportLog) compact() error {
	tmp := filepath.Join(l.dir, reportLogFile+".tmp")
	out, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := out.ReadFrom(io.NewSectionReader(l.f, l.head, l.size-l.head)); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := os.Rename(tmp, filepath.Join(l.dir, reportLogFile)); err != nil {
		out.Close()
		return err
	}
	l.f.Close()
	l.f = out
	l.size -= l.head
	l.head = 0
	return l.persistHead(true)
}

func (l *reportLog) persistHead(force bool) error {
	if !force && (!l.headDirty || time.Since(l.lastSave) < reportHeadPersistEach) {
		return nil
	}
	tmp := filepath.Join(l.dir, reportHeadFile+".tmp")
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(l.head, 10)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(l.dir, reportHeadFile)); err != nil {
		return err
	}
	l.lastSave = time.Now()
	l.headDirty = false
	return nil
}

func (l *reportLog) saveGap(g *gapSummary) error {
	b, err := json.Marshal(g)
	if err != nil {
		return err
	}
	tmp := filepath.Join(l.dir, reportGapFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(l.dir, reportGapFile))
}

func (l *reportLog) loadGap() (*gapSummary, error) {
	b, err := os.ReadFile(filepath.Join(l.dir, reportGapFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	g := &gapSummary{}
	if err := json.Unmarshal(b, g); err != nil {
		return nil, err
	}
	if g.Dropped == 0 {
		return nil, nil
	}
	return g, nil
}

func (l *reportLog) clearGap() error {
	err := os.Remove(filepath.Join(l.dir, reportGapFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// reportQueueOptionsFromEnv reads PAIL_REPORT_QUEUE_DIR / _BYTES / PAIL_REPORT_RETRY_MAX_MS.
// The queue directory defaults to the directory of PAIL_GRPC_UDS_PATH when
// that is set (the agent already owns a state directory there), otherwise
// /var/lib/pail_robot_agent. PAIL_REPORT_QUEUE_BYTES=0 disables the disk log.
func reportQueueOptionsFromEnv(robotID string) (reportQueueOptions, error) {
	o := reportQueueOptions{RobotID: robotID, MaxBytes: reportQueueDefaultCap}
	// One communication contract (0.2.0-preview.40): the selecting variable is gone; its presence — any value, even an
	// empty one (P40-L2) — refuses by name.
	if err := corecomm.CheckNoContractSettingEnv(); err != nil {
		return o, err
	}
	o.ReceiptVersion = 1

	if v := os.Getenv("PAIL_REPORT_QUEUE_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return o, fmt.Errorf("PAIL_REPORT_QUEUE_BYTES: invalid value %q", v)
		}
		o.MaxBytes = n
	}
	if v := os.Getenv("PAIL_REPORT_RETRY_MAX_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return o, fmt.Errorf("PAIL_REPORT_RETRY_MAX_MS: invalid value %q", v)
		}
		o.RetryMax = time.Duration(n) * time.Millisecond
	}
	if o.MaxBytes == 0 {
		if o.ReceiptVersion != 0 {
			return o, errors.New("core-comm-v1 requires durable report storage")
		}
		return o, nil // memory only, by configuration
	}
	o.Dir = os.Getenv("PAIL_REPORT_QUEUE_DIR")
	if o.Dir == "" {
		if uds := os.Getenv("PAIL_GRPC_UDS_PATH"); uds != "" {
			o.Dir = filepath.Join(filepath.Dir(uds), "report_queue")
		} else {
			o.Dir = "/var/lib/pail_robot_agent/report_queue"
		}
	}
	return o, nil
}
