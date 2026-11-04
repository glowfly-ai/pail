// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// pail_robot_agent (D1 split, 배치형상 §7.3): the robot-side half of
// pail_services and the single front door on :50051.
//
// It proxies the three control-plane services (PailNorthbound, TokenService,
// OperatorService) to cloud-services unchanged — the PEP gate, PVS and demos
// keep their existing :50051 endpoints — and it owns the UDP burst socket:
// BeaconEvents subscribed from the cloud AgentRelay stream are signed and
// transmitted here with the single burst_seq counter receivers dedup on.
package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/glowfly/pail/services/internal/corecomm"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glowfly/pail/services/internal/burst"
	"github.com/glowfly/pail/services/internal/crypto"
	"github.com/glowfly/pail/services/internal/deploysec"
	"github.com/glowfly/pail/services/internal/grpcauth"
	"github.com/glowfly/pail/services/internal/grpclive"
	"github.com/glowfly/pail/services/internal/identity"
	agentpb "github.com/glowfly/pail/services/proto/agentv1"
	operatorpb "github.com/glowfly/pail/services/proto/operatorv1"
	pb "github.com/glowfly/pail/services/proto/pailv1"
	robotopspb "github.com/glowfly/pail/services/proto/robotopsv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// tokenMirror (D3, 배치형상 §7.3): local mirror of the cloud's active-token
// state so the PEP gate's 20Hz permit recheck (a synchronous GetActiveToken
// with no deadline) never blocks on a WAN round trip — over a ~100ms RTT the
// permit loop otherwise collapses below the 20Hz/2 rate floor (found by the
// D3 fake-WAN PVS run).
//
// Safety argument (fail-closed):
//   - the mirror is served ONLY while the beacon stream is connected — every
//     revocation/ESTOP emits a BeaconEvent, and each event invalidates the
//     mirror, so staleness after a revocation is one WAN one-way + refresh;
//   - every state-mutating call through this proxy (plan submit/cancel,
//     ReportDecision, unlock, key revoke) also invalidates it;
//   - stream down ⇒ mirror off ⇒ every recheck goes synchronously to the
//     cloud; if the WAN is gone those calls fail and the gate BLOCKs;
//   - a hard age cap (3× refresh interval) bounds staleness even if the
//     poller wedges — an over-age mirror is never served;
//   - token expiry needs no invalidation here: the gate validates
//     not_before/not_after on the signed token bytes locally.
type tokenMirror struct {
	execEnabled, execRequired, execPending, execBusy bool // guarded by mu
	execID                                           string
	execSeq                                          uint64
	execRetry                                        time.Time

	c        tokenpb.TokenServiceClient
	cohort   *cohortGuard // C1 cohort handshake on the census (P36-M1); nil-safe
	robotID  string
	interval time.Duration // refresh period; 0 disables the mirror entirely
	streamUp atomic.Bool

	mu         sync.Mutex
	resp       *tokenpb.GetActiveTokenResponse
	at         time.Time
	lastRead   time.Time
	polling    bool
	refreshErr error // AV1: last refresh failure; does NOT invalidate the cache
	kick       chan struct{}
	nowFn      func() time.Time // gateway clock for lease expiry only (lease.go now); nil = time.Now

	// AV2 (AV LLD §3.1): the edge lease. Unlike the mirror above — a cache of
	// an answer, valid only while the stream proves it fresh — this is an
	// explicit issuer grant to serve offline, so stream loss does NOT drop it.
	// Everything else that invalidates still purges it (see Invalidate).
	// Serving logic lives in lease.go.
	lease      map[int32]*pb.SignedToken // sequence index -> issuer-signed token
	leaseMax   int32                     // authorized to serve up to this index
	servingIdx int32                     // index currently handed to the gate
	chainID    string
	worldHash  []byte // last current_subgraph_hash the cloud computed (§3.2)
	epoch      uint64 // highest issuer_epoch seen (fencing, §3.3)
	pendingRep []*tokenpb.ReportDecisionRequest

	// AV2 §3.5 (HLD D-11): at most one upstream GetActiveToken in flight.
	inflight *upstreamCall
	// gen counts Invalidate calls. An upstream call remembers the generation it
	// started in; a reply that lands in a later one was computed before the
	// revocation, plan change or unlock that Invalidate stands for (HW-A1).
	gen uint64
	// connGen counts beacon-stream (re)connections (noteReconnect). A census answer that lands after a newer
	// connection was made is from an Issuer that may since have been replaced: it never clears the cohort hold.
	connGen uint64
}

// wireCohortGuard connects the report queue's C1 cohort guard to the mirror's
// census, names the other holds for its restore line and starts its workers. One function so that the process
// and the integration tests wire the same thing.
func wireCohortGuard(rq *reportQueue, m *tokenMirror, refuse func(error)) {
	if rq == nil || rq.cohort == nil {
		return
	}
	rq.cohort.refuse = refuse
	rq.cohort.recheck = m.census
	rq.cohort.otherHolds = func() []string {
		var h []string
		if rq.core != nil && !rq.core.healthy() {
			h = append(h, "storage fault (CORE_REPORT_STORAGE_UNHEALTHY, stands until restart)")
		}
		m.mu.Lock()
		pending := m.execEnabled && m.execPending
		m.mu.Unlock()
		if pending {
			h = append(h, "execution restart pending (EXECUTION_RESTART_PENDING)")
		}
		return h
	}
	m.cohort = rq.cohort
	rq.cohort.start()
}

// noteReconnect records a beacon-stream (re)connection; subscribeBeacons calls it before the reconcile.
func (m *tokenMirror) noteReconnect() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.connGen++
	m.mu.Unlock()
}

// upstreamCall is one outstanding GetActiveToken, shared by everyone who asked
// while it was out (AV LLD §3.5). Deduplication here is a safety measure, not
// an optimization: D-5 reads a second call inside a live window as "the window
// is spent", so two concurrent requests make the issuer delegate twice the
// policy depth while the gateway can only serve one window.
type upstreamCall struct {
	done        chan struct{}
	gen         uint64 // tokenMirror.gen when the call started
	censusGen   uint64 // latest generation consisting only of chain-scoped census endings
	endedChains map[string]bool
	resp        *tokenpb.GetActiveTokenResponse
	err         error
}

// beginUpstreamLocked must be called holding m.mu. The leader (second return
// true) performs the RPC and calls finishUpstream; everyone else waits on
// call.done and takes the leader's result verbatim — sharing the failure too,
// so a joiner can never fall back to serving something staler.
func (m *tokenMirror) beginUpstreamLocked() (*upstreamCall, bool) {
	if m.inflight != nil {
		return m.inflight, false
	}
	call := &upstreamCall{done: make(chan struct{}), gen: m.gen}
	m.inflight = call
	return call, true
}

// finishUpstream absorbs the leader's result, publishes it to the joiners and
// closes the window. The next request goes upstream normally: this dedups
// concurrent calls, not repeated ones.
//
// A failed refresh records refreshErr but keeps the cache (AV1 §1.3) — only
// Invalidate or an explicit negative answer drops it.
func (m *tokenMirror) finishUpstream(call *upstreamCall, resp *tokenpb.GetActiveTokenResponse, err error) {
	m.mu.Lock()
	declare := false
	if err == nil && call.gen != m.gen && !(call.censusGen == m.gen && len(call.endedChains) > 0 && resp.GetChainId() != "" && !call.endedChains[resp.GetChainId()]) {
		// HW-A1: the call outlived an Invalidate. Its answer predates whatever
		// Invalidate stood for, so it must not restore the cache or the window.
		// It is still read — the chain it names is what the census has to
		// declare, or the grant the issuer recorded for this reply stays open
		// under D-5 with no gateway that can walk it back (AV7). Waiters get an
		// error: the gate BLOCKs once and the next ask goes upstream afresh.
		if aerr := m.absorbLocked(resp); aerr == nil {
			declare = m.dropLeaseLocked()
		}
		m.resp = nil
		err, resp = errInvalidatedInFlight, nil
		m.refreshErr = err
	} else if err == nil {
		if aerr := m.absorbLocked(resp); aerr != nil {
			err, resp = aerr, nil
		} else {
			m.resp, m.at, m.refreshErr = resp, time.Now(), nil
		}
	} else {
		m.refreshErr = err

	}
	call.resp, call.err = resp, err
	m.inflight = nil
	m.mu.Unlock()
	close(call.done)
	if declare {
		go m.census()
	}
}

// errInvalidatedInFlight is what waiters on a call that outlived an Invalidate
// receive: the reply existed, but it describes the state before the event.
var errInvalidatedInFlight = errors.New("upstream reply predates an invalidation: discarded")

// upstreamCallTimeout bounds one upstream GetActiveToken on its own clock,
// independent of whoever asked (HW-A1). The census declaration uses the same
// bound; nothing on this path is worth waiting longer for, and a call that
// never returns would otherwise pin the single-flight slot forever.
const upstreamCallTimeout = 5 * time.Second

// upstream runs one GetActiveToken under the single-flight rule (§3.5). It must
// be called holding m.mu and releases it before returning.
//
// HW-A1 (TB3 hardware, 2026-09-14): the RPC runs on its OWN context, detached
// from the caller's. The gate asks with a 50 ms deadline; the first reply over
// TLS/WAN is slower. Run on the gate's context, the RPC was cancelled and the
// reply discarded — but the issuer records a lease grant before the reply
// leaves (record-first), and under D-5 the next call reads that unreported
// window as spent and serves past it. For a one-step chain that is NO_TOKEN
// for good, and the gateway cannot declare its way out: it never learned the
// chain. A grant the issuer has recorded is the gateway's to receive, so the
// call finishes and finishUpstream absorbs it whether or not the first asker
// is still waiting.
//
// Every waiter — leader included — still returns on its own deadline. Nobody
// starts a second call while one is out (D-11): a waiter that gives up leaves
// the call in flight, and the next asker joins it or finds its result.
func (m *tokenMirror) upstream(ctx context.Context, req *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	if m.execEnabled && m.execPending {
		m.startResetLocked()
		m.mu.Unlock()
		return nil, errExecutionPending
	}
	call, leader := m.beginUpstreamLocked()
	m.mu.Unlock()
	if leader {
		callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), upstreamCallTimeout)
		go func() {
			defer cancel()
			resp, err := m.getWithRetry(callCtx, req)
			m.finishUpstream(call, resp, err)
		}()
	}
	select {
	case <-call.done:
		return call.resp, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// upstreamFresh drains the outstanding call before reconciliation. If that
// call installed unspent authority, preserve it; local completion has already
// advanced servingIdx. Only an exhausted/invalidated window needs a fresh RPC.
func (m *tokenMirror) upstreamFresh(ctx context.Context, req *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	m.mu.Lock()
	for m.inflight != nil {
		call := m.inflight
		m.mu.Unlock()
		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		m.mu.Lock()
	}
	// A command can install a new grant while reconciliation drains an older
	// call. Never fetch over an unspent window: D-5 treats that as spent.
	// Local consumption already advanced servingIdx, and invalidation/restart
	// already dropped the window, so this cannot revive consumed authority.
	if !m.execPending {
		if resp := m.serveLeaseLocked(); resp != nil {
			m.mu.Unlock()
			return resp, nil
		}
	}
	return m.upstream(ctx, req) // releases m.mu
}

func newTokenMirror(c tokenpb.TokenServiceClient, robotID string, interval time.Duration) *tokenMirror {
	return &tokenMirror{c: c, robotID: robotID, interval: interval, kick: make(chan struct{}, 1)}
}

// Invalidate drops everything the gateway is serving from — cache AND lease.
// Every pre-AV2 caller keeps this meaning: a beacon (revocation, ESTOP), a plan
// change, an unlock or a world mutation must not be survivable by an
// outstanding grant.
//
// AV7 (§9.3): dropping a window the gateway never spent leaves the issuer
// serving past steps nobody executed, and its walk-back cannot happen on
// silence (D-5). So the drop is declared. The declaration is asynchronous —
// Invalidate is called from beacon and stream paths that must not block on a
// cloud round trip — and it says only where this gateway is; what that means
// for the issuer's window is the issuer's judgement.
//
// The cache purge stays synchronous and stays FIRST. Deferring it behind the
// declaration would let a revocation beacon's own call still be answered from
// the mirrored token, and Invalidate exists precisely so that cannot happen.
// The cost is a race the declaration cannot win every time: the poller may
// reach the issuer before the retraction lands and cache one NO_TOKEN. That
// answer is fail-closed and ages out on its own (3×interval), so it is the
// side of this trade worth being on.
func (m *tokenMirror) Invalidate() { m.invalidateReportedChain("") }

// Nonfatal completion of an old chain cannot release a different, current grant.
// Empty scope and fatal/robot-wide events retain the existing global invalidation.
func (m *tokenMirror) invalidateReportedChain(chain string) {
	if m == nil || m.interval == 0 {
		return
	}
	m.mu.Lock()
	if chain != "" && m.chainID != "" && chain != m.chainID {
		m.mu.Unlock()
		return
	}
	m.gen++
	dropped := m.dropLeaseLocked()
	m.invalidateCacheLocked()
	m.mu.Unlock()
	if dropped {
		go m.census()
	}
}

// invalidateCache drops the mirrored answer but keeps the lease (AV2 §3.3).
// Only two callers may use it: stream loss — which is precisely what the lease
// exists to survive — and a step advance inside the window.
func (m *tokenMirror) invalidateCache() {
	if m == nil || m.interval == 0 {
		return
	}
	m.mu.Lock()
	m.invalidateCacheLocked()
	m.mu.Unlock()
}

func (m *tokenMirror) invalidateCacheLocked() {
	m.resp = nil
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

func (m *tokenMirror) setStream(up bool) {
	if m == nil || m.interval == 0 {
		return
	}
	m.streamUp.Store(up)
	if !up {
		m.invalidateCache()
	}
}

func (m *tokenMirror) get(ctx context.Context, req *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	if m.interval == 0 || req.GetRobotId() != m.robotID {
		return m.c.GetActiveToken(ctx, req)
	}
	m.mu.Lock()
	if m.execEnabled && m.execPending {
		m.startResetLocked()
		m.mu.Unlock()
		return nil, errExecutionPending
	}
	m.lastRead = time.Now()
	if !m.polling {
		m.polling = true
		go m.poll()
	}
	// AV2 §3.2: the lease outranks the mirror. It is an explicit grant rather
	// than a freshness bet, so it holds while the stream is down — and asking
	// the cloud again inside our own window would be read as "the window is
	// spent" (D-5) and skip past it.
	if resp := m.serveLeaseLocked(); resp != nil {
		m.mu.Unlock()
		return resp, nil
	}
	if m.streamUp.Load() && m.resp != nil && time.Since(m.at) < 3*m.interval {
		resp := m.resp
		m.mu.Unlock()
		return resp, nil
	}
	return m.upstream(ctx, req) // releases m.mu
}

// poll keeps the mirror warm while reads keep arriving; stops after 5s idle.
func (m *tokenMirror) poll() {
	for {
		m.mu.Lock()
		idle := time.Since(m.lastRead)
		m.mu.Unlock()
		if idle > 5*time.Second {
			m.mu.Lock()
			m.polling = false
			m.resp = nil
			m.mu.Unlock()
			return
		}
		// AV2 §3.2 (D-5 corollary): never refresh inside a live window. A poll
		// the issuer cannot distinguish from a real request would advance its
		// conservative serving position and burn the lease.
		m.mu.Lock()
		// A window whose current token is past not_after is released here too, so an idle gateway
		// does not wait for the next read to find out (lease.go expireLeaseLocked).
		m.expireLeaseLocked()
		if m.leaseUsableLocked() {
			m.mu.Unlock()
			select {
			case <-m.kick:
			case <-time.After(m.interval):
			}
			continue
		}

		// AV2 §3.5: the poller's first iteration runs the instant get() starts
		// it, so without single-flight it raced get()'s own call and the issuer
		// delegated two windows (HLD D-11). Joining costs nothing here — the
		// poller only wants the mirror warm, and finishUpstream does that.
		//
		// AV1 (AV LLD §1.3): a failed refresh no longer destroys the cache.
		// Dropping it here turned a single WAN hiccup into "no token at all"
		// even while the cached token was still signed, unexpired and unrevoked
		// (AV0-1: 28.9s of validity thrown away over a 600ms stall). Staleness
		// is still bounded — get() enforces the age cap, and the gate
		// independently enforces not_after on the signed bytes. The cache is
		// dropped only by Invalidate() (stream loss, mutating call) or by an
		// explicit negative answer.
		ctx, cancel := context.WithTimeout(context.Background(), m.interval*2)
		_, _ = m.upstream(ctx, &tokenpb.GetActiveTokenRequest{RobotId: m.robotID}) // releases m.mu
		cancel()

		select {
		case <-m.kick:
		case <-time.After(m.interval):
		}
	}
}

type northProxy struct {
	pb.UnimplementedPailNorthboundServer
	c pb.PailNorthboundClient
	m *tokenMirror
}

func (p *northProxy) SubmitActionPlan(ctx context.Context, req *pb.SubmitActionPlanRequest) (*pb.SubmitActionPlanResponse, error) {
	defer p.m.Invalidate()
	out, err := p.c.SubmitActionPlan(ctx, req)
	if err == nil {
		id := req.GetOperationId()
		if id == "" {
			id = req.GetPlan().GetPlanId()
		}
		digest, e := corecomm.SubmitDigest(req)
		if e != nil || out == nil || corecomm.CheckOperationReceipt(out.GetReceipt(), id, req.GetPlan().GetPlanId(), req.GetRobotId(), pb.OperationKind_SUBMIT, digest) != nil {
			return nil, status.Error(codes.Unavailable, "CORE_OPERATION_RECEIPT_UNCONFIRMED")
		}
		if out.Status == pb.SubmitStatus_ACCEPTED && (out.Receipt.OperationState != pb.OperationState_COMMITTED || out.ChainId != out.Receipt.OriginalChainId) {
			return nil, status.Error(codes.Unavailable, "CORE_OPERATION_EFFECT_UNCONFIRMED")
		}
	}
	return out, err
}
func (p *northProxy) SubmitTextCommand(ctx context.Context, req *pb.SubmitTextCommandRequest) (*pb.SubmitTextCommandResponse, error) {
	defer p.m.Invalidate()
	return p.c.SubmitTextCommand(ctx, req)
}
func (p *northProxy) GetPlanStatus(ctx context.Context, req *pb.GetPlanStatusRequest) (*pb.GetPlanStatusResponse, error) {
	if err := authorizePlanProxy(ctx); err != nil {
		return nil, err
	}
	out, err := p.c.GetPlanStatus(ctx, req)
	if err == nil && req.GetOperationId() != "" {
		if out == nil {
			return nil, status.Error(codes.Unavailable, "CORE_OPERATION_STATUS_UNCONFIRMED")
		}
		if out.Receipt == nil && out.State == pb.PlanState_PLAN_STATE_UNSPECIFIED {
			return out, nil
		}
		if corecomm.CheckOperationReceipt(out.Receipt, req.GetOperationId(), req.GetPlanId(), "", req.GetOperationKind(), nil) != nil {
			return nil, status.Error(codes.Unavailable, "CORE_OPERATION_STATUS_UNCONFIRMED")
		}
	}
	return out, err
}
func (p *northProxy) CancelPlan(ctx context.Context, req *pb.CancelPlanRequest) (*pb.CancelPlanResponse, error) {
	if err := authorizePlanProxy(ctx); err != nil {
		return nil, err
	}
	defer p.m.Invalidate()
	out, err := p.c.CancelPlan(ctx, req)
	if err == nil {
		id := req.GetOperationId()
		if id == "" {
			id = req.GetPlanId()
		}
		digest, e := corecomm.CancelDigest(req)
		if e != nil || out == nil || corecomm.CheckOperationReceipt(out.GetReceipt(), id, req.GetPlanId(), "", pb.OperationKind_CANCEL, digest) != nil {
			return nil, status.Error(codes.Unavailable, "CORE_OPERATION_RECEIPT_UNCONFIRMED")
		}
	}
	return out, err
}

// The non-mutating report path lives in reportqueue.go (OI-01): local ack,
// ordered forwarding, retry until acknowledged, durable across restarts.

type tokenProxy struct {
	routeVersion func() uint64
	tokenpb.UnimplementedTokenServiceServer
	c      tokenpb.TokenServiceClient
	m      *tokenMirror
	f      *reportQueue
	fatals fatalTracker // P16-L1: one fatal reaches the issuer at most twice
}

func (p *tokenProxy) GetActiveToken(ctx context.Context, req *tokenpb.GetActiveTokenRequest) (*tokenpb.GetActiveTokenResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "robot identity required")
	}
	if p.m.execEnabled && req.GetRobotId() != p.m.robotID {
		return nil, status.Error(codes.PermissionDenied, "robot identity mismatch")
	}
	if p.f != nil && p.f.core != nil && !p.f.core.healthy() {
		return nil, status.Error(codes.Unavailable, "CORE_REPORT_STORAGE_UNHEALTHY")
	}
	// P37-M1: the cohort hold is its own reason — it clears when the Issuer answers v1 again (the storage fault
	// above stands until restart). Each hold is named so the operator knows which rule is withholding.
	if p.f != nil && p.f.cohort.mismatched() {
		return nil, status.Error(codes.Unavailable, "CORE_COMM_COHORT_MISMATCH")
	}
	id, err := p.m.prepareExecution(ctx)
	if err != nil {
		return nil, err
	}
	r, err := p.m.get(ctx, req)
	if !p.m.executionCurrent(id) {
		return nil, errExecutionPending
	}
	if id != "" {
		if e := grpc.SetHeader(ctx, metadata.Pairs(executionHeader, id)); e != nil {
			return nil, e
		}
	}
	return r, err
}

// Attest forwards the existing RPC. The versioned, bound effect determines
// cache/lease invalidation; legacy or unconfirmed effects remain conservative.
func (p *tokenProxy) Attest(ctx context.Context, req *tokenpb.AttestRequest) (*tokenpb.AttestResponse, error) {
	return p.attestWithEffect(ctx, req)
}

// SealConfig (SD4) is a straight synchronous pass-through. It is a declaration
// about the gate itself, not a request for authority, so it neither touches the
// token mirror nor joins the decision queue: reordering it against decisions
// would say nothing, and caching it would report a configuration that is no
// longer the one running.
func (p *tokenProxy) SealConfig(ctx context.Context, req *tokenpb.SealConfigRequest) (*tokenpb.SealConfigResponse, error) {
	return p.c.SealConfig(ctx, req)
}

// fatalForwardTimeout bounds one upstream attempt of a fatal (chain-revoking)
// report. It is deliberately not the gate's command-path deadline: the stop is
// already out when the report is sent, nothing waits on it, and a revocation
// that misses a 50 ms window must still arrive.
const fatalForwardTimeout = 3 * time.Second

// reportFatal — P15-H1 (TB3 judge2 scene 8, 2026-10-16). A fatal report used to
// wait behind the telemetry queue's in-flight attempt, then go upstream under the
// gate's 50 ms context; when that single attempt failed, the error went back to a
// gate that discarded it, the issuer kept the chain active, and the robot resumed
// the interrupted plan on the same token once safety returned to OK. Now the fatal
// jumps the queue (ledger order is restored by readers from agent_seq), runs under
// its own timeout detached from the gate's context, and on failure is both
// returned to the gate (which keeps its local latch and retries) and pushed on the
// durable queue, so it reaches the issuer even if the gate process does not live
// to retry it. The issuer revokes idempotently (revokeOnFatal), so a duplicate
// delivery changes nothing.
//
// P16-L1 (preview.16 evaluation): the gate retries a fatal every 200 ms..2 s until it is
// confirmed and the agent queued the first failed copy durably, so one injected outage
// put the same ESTOP seven times in the Issuer ledger. The tracker below answers a repeat
// of a fatal that is already pending from the queue (no second upstream call, no second
// push) and a repeat of a fatal the Issuer already confirmed (accepted at once), so the
// ledger sees a fatal at most twice: a first attempt whose answer was lost, and the queued
// copy. Keyed by robot, chain, token, decision and reason.
//
// P17-L1 (preview.17 evaluation, 30 s Issuer pause): a repeat that arrived while the FIRST
// upstream attempt was still in flight (the agent's 3 s window is longer than the gate's
// 2 s retry) was forwarded too, and a paused Issuer delivers both once it resumes — three
// ledger lines. Repeats now join the in-flight attempt (single flight per key): they wait
// for its outcome or for their own deadline, and never open a second RPC.
//
// P18-H1 (preview.18 evaluation, 2026-10-18): a fatal the gate could not attribute (E-STOP
// with no live permit while the Issuer was unreachable: chain and token both empty) has
// the same key every time it happens, so the second such E-STOP was answered from the
// tracker as "already confirmed" and never reached the Issuer — which therefore never
// revoked the robot's current chain, and the interrupted plan resumed when the link came
// back. Two rules now: (1) the agent names the chain it is serving when the gate names
// none, so the Issuer attributes the report; (2) a report that still names nothing is
// never remembered as confirmed — every such E-STOP is carried upstream (single flight and
// the durable queue still apply while one is in progress).
func (p *tokenProxy) reportFatal(ctx context.Context, req *tokenpb.ReportDecisionRequest) (*tokenpb.ReportDecisionResponse, error) {
	if anonymousFatal(req) {
		if chain := p.m.servedChain(); chain != "" {
			log.Printf("robot-agent: fatal report (decision=%v reason=%s) names no chain — attributing it to the chain this agent serves (%s)",
				req.Decision, req.ReasonCode, chain)
			req.ChainId = chain
		}
	}
	anonymous := anonymousFatal(req)
	key := fatalKey(req)
	for {
		state, done := p.fatals.claim(key)
		switch state {
		case fatalConfirmed:
			return &tokenpb.ReportDecisionResponse{Accepted: true}, nil
		case fatalPending:
			return nil, errors.New("fatal report already queued for the issuer; retry later")
		case fatalInFlight:
			select {
			case <-done: // the leader finished: re-read its outcome
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("fatal report still in flight to the issuer; %w", ctx.Err())
			}
		}
		break // fatalLeader: this call carries the report upstream
	}
	defer p.fatals.finish(key)
	p.f.stamp(req)
	defer p.m.Invalidate()
	// P25-M2: write ahead before the attempt, so the E-STOP survives this process whatever the link does
	ahead := p.f.writeAheadFatal(req)
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fatalForwardTimeout)
	defer cancel()
	resp, err := p.c.ReportDecision(fctx, req)
	if err == nil && (resp == nil || !resp.GetAccepted()) {
		err = errors.New("REPORT_ACK_NOT_ACCEPTED")
	}
	if err != nil {
		how := "queued in memory only (NOT durable: a restart of this agent loses it) for retry"
		if p.f.isDurable() {
			how = "queued durably for retry"
		}
		log.Printf("robot-agent: FATAL ReportDecision not confirmed by the issuer (decision=%v reason=%s chain=%s token=%s): %v — %s; the gate keeps its local latch",
			req.Decision, req.ReasonCode, req.ChainId, req.TokenId, err, how)
		p.fatals.markPending(key)
		handedOff := p.f.pushFatalWithAck(req, func(delivered bool) {
			if delivered && !anonymous {
				p.fatals.markConfirmed(key)
			} else {
				p.fatals.clearPending(key) // dropped from the queue, or anonymous (P18-H1): the next one is forwarded again
			}
		})
		if ahead && handedOff {
			p.f.clearWriteAhead(req) // the queue sync/confirmed delivery now owns it
		}
		return nil, err
	}
	if ahead {
		p.f.clearWriteAhead(req)
	}
	if anonymous {
		p.fatals.forget(key) // P18-H1: the next E-STOP that names nothing is a new event, not a repeat
	} else {
		p.fatals.markConfirmed(key)
	}
	return resp, nil
}

func fatalKey(req *tokenpb.ReportDecisionRequest) string {
	return req.GetRobotId() + "|" + req.GetChainId() + "|" + req.GetTokenId() + "|" + req.GetDecision().String() + "|" + req.GetReasonCode()
}

// anonymousFatal: the gate named neither a chain nor a token (P18-H1).
func anonymousFatal(req *tokenpb.ReportDecisionRequest) bool {
	return req.GetChainId() == "" && req.GetTokenId() == ""
}

// servedChain is the chain the mirror or lease is currently serving to the gate, or "".
func (m *tokenMirror) servedChain() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.chainID
}

// fatalTracker remembers which fatal reports are in flight, queued and confirmed.
// Bounded: the newest fatalTrackerCap keys are kept; a key that falls out is simply
// forwarded again, which the issuer's idempotent revocation tolerates.
const fatalTrackerCap = 256

type fatalState int

const (
	fatalLeader    fatalState = iota // nothing known: the caller sends the report
	fatalInFlight                    // another call is sending it: wait on the channel
	fatalPending                     // queued durably after a failed attempt
	fatalConfirmed                   // the issuer accepted it
)

type fatalTracker struct {
	mu       sync.Mutex
	pendingM map[string]bool
	confirmM map[string]bool
	inflight map[string]chan struct{}
	order    []string
}

// claim decides, under one lock, what the caller does for key. For fatalInFlight the
// returned channel closes when the leader is done.
func (t *fatalTracker) claim(key string) (fatalState, chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.confirmM[key] {
		return fatalConfirmed, nil
	}
	if t.pendingM[key] {
		return fatalPending, nil
	}
	if ch, ok := t.inflight[key]; ok {
		return fatalInFlight, ch
	}
	if t.inflight == nil {
		t.inflight = map[string]chan struct{}{}
	}
	ch := make(chan struct{})
	t.inflight[key] = ch
	return fatalLeader, ch
}

func (t *fatalTracker) finish(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ch, ok := t.inflight[key]; ok {
		close(ch)
		delete(t.inflight, key)
	}
}

func (t *fatalTracker) pending(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pendingM[key]
}

func (t *fatalTracker) confirmed(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.confirmM[key]
}

func (t *fatalTracker) markPending(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pendingM == nil {
		t.pendingM = map[string]bool{}
	}
	t.pendingM[key] = true
	t.remember(key)
}

func (t *fatalTracker) clearPending(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pendingM, key)
}

// forget drops every memory of key (P18-H1: an anonymous fatal is never a repeat).
func (t *fatalTracker) forget(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pendingM, key)
	delete(t.confirmM, key)
}

func (t *fatalTracker) markConfirmed(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.confirmM == nil {
		t.confirmM = map[string]bool{}
	}
	delete(t.pendingM, key)
	t.confirmM[key] = true
	t.remember(key)
}

func (t *fatalTracker) remember(key string) {
	t.order = append(t.order, key)
	for len(t.order) > fatalTrackerCap {
		old := t.order[0]
		t.order = t.order[1:]
		delete(t.pendingM, old)
		delete(t.confirmM, old)
	}
}

func (p *tokenProxy) ReportDecision(ctx context.Context, req *tokenpb.ReportDecisionRequest) (*tokenpb.ReportDecisionResponse, error) {
	if req == nil {
		return nil, errors.New("report required")
	}
	if req.GetReceiptContractVersion() != 0 {
		return p.reportCoreDecision(ctx, req)
	}
	if req.GetFatal() {
		return p.reportFatal(ctx, req)
	}
	if req.GetStepComplete() {
		// Mutating: forward synchronously and drop the mirror. OI-01: it waits
		// only for the attempt in flight (reportqueue.go drain) — during an
		// outage the queue never empties, and the lease path must not hang on
		// it; readers restore order from agent_seq.
		p.f.stamp(req)
		// AV2 §3.3: a step advance inside the lease is applied locally FIRST
		// and survives a failed forward — that is the lease.
		leased := p.m.consumed(req)
		if leased {
			p.m.invalidateCache()
		} else {
			defer p.m.invalidateReportedChain(req.GetChainId())
		}
		// Record local progress before telemetry/WAN can delay this completion.
		p.f.drain()
		resp, err := p.c.ReportDecision(ctx, req)
		if err == nil && resp == nil {
			err = errors.New("REPORT_ACK_MISSING")
		}
		if err == nil && !resp.GetAccepted() {
			// Application refusal is an explicit response, not a transport
			// failure eligible for the leased-success fallback.
			p.m.invalidateReportedChain(req.GetChainId())
			return resp, nil
		}
		if err != nil {
			if leased {
				log.Printf("robot-agent: ReportDecision queued for reconcile (token=%s, serving from lease): %v", req.GetTokenId(), err)
				return &tokenpb.ReportDecisionResponse{Accepted: true}, nil
			}
			return resp, err
		}
		if leased {
			p.m.forwarded(req)
		}
		return resp, nil
	}
	// A non-mutating report never touches the lease — with one exception: the gate telling us that the
	// token we are serving from the lease has expired (lease.go expiredLeased). The report itself is
	// still forwarded through the queue like any other decision.
	p.m.expiredLeased(req)
	// OI-01: acknowledged locally, forwarded in order, retried until the
	// issuer acknowledges it; overflow drops the OLDEST into a gap summary
	// (never backpressure onto the gate, never a silent drop).
	p.f.push(req)
	return &tokenpb.ReportDecisionResponse{Accepted: true}, nil
}

type operatorProxy struct {
	operatorpb.UnimplementedOperatorServiceServer
	c operatorpb.OperatorServiceClient
	m *tokenMirror
}

func (p *operatorProxy) Unlock(ctx context.Context, req *operatorpb.UnlockRequest) (*operatorpb.UnlockResponse, error) {
	defer p.m.Invalidate()
	return p.c.Unlock(ctx, req)
}
func (p *operatorProxy) RevokeIssuerKey(ctx context.Context, req *operatorpb.RevokeKeyRequest) (*operatorpb.RevokeKeyResponse, error) {
	defer p.m.Invalidate()
	return p.c.RevokeIssuerKey(ctx, req)
}

// IngestContextEvent (CG-E1) is an ops-plane mutation of the issuer site graph.
// The front door forwards it upstream unchanged; the mirror is invalidated so the
// gate's next permit recheck reflects any world change that alters issuance.
func (p *operatorProxy) IngestContextEvent(ctx context.Context, req *operatorpb.ContextEvent) (*operatorpb.ContextEventAck, error) {
	defer p.m.Invalidate()
	return p.c.IngestContextEvent(ctx, req)
}

func main() {
	// BG (PAIL-BG-LLD-v1 §4): before anything binds a port.
	deploysec.Preflight("pail_robot_agent")
	// S19 : private key modes, beside Preflight and not
	// inside it — Preflight downgrades to a banner under PAIL_PROFILE=dev.
	deploysec.EnforceKeyModes("pail_robot_agent")

	port := os.Getenv("PAIL_NORTHBOUND_PORT")
	if port == "" {
		port = "50051"
	}
	// HA3 failover (HA LLD §5.2): PAIL_CLOUD_ADDR may be a comma-separated
	// ordered list. All RPCs go to the current address; UNAVAILABLE or a
	// STANDBY refusal rotates to the next (see failover.go).
	cloudAddr := os.Getenv("PAIL_CLOUD_ADDR")
	if cloudAddr == "" {
		cloudAddr = "127.0.0.1:50061"
	}
	var cloudAddrs []string
	for _, a := range strings.Split(cloudAddr, ",") {
		if a = strings.TrimSpace(a); a != "" {
			cloudAddrs = append(cloudAddrs, a)
		}
	}
	if len(cloudAddrs) == 0 {
		log.Fatalf("PAIL_CLOUD_ADDR: no usable address in %q", cloudAddr)
	}
	robotID := os.Getenv("PAIL_ROBOT_ID")
	if robotID == "" {
		robotID = "robot-1"
	}

	// Upstream dial: same trust policy as the front door (mTLS unless DEV off).
	var dialOpts []grpc.DialOption
	var loadedClientFingerprint string
	if grpcauth.TLSEnabled() {
		creds, fp, err := grpcauth.ClientTLSWithFingerprint("", "", "")
		if err != nil {
			log.Fatalf("grpc client mTLS init: %v", err)
		}
		loadedClientFingerprint = fp
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(creds))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	// AV2 (AV LLD §3.4 / HLD D-9): bound the reconnect backoff. The lease's
	// reconcile rides on beacon-stream recovery, and gRPC's default backoff
	// grows to 120s — after a 30s outage the gateway sat 11s past the issuer's
	// return before reporting what it had consumed offline (AV2 measurement).
	// An issuer whose world model is stale is exactly the hole AV3 closes, so
	// the term that dominates that staleness gets a designed ceiling.
	maxBackoffMs := 2000
	if v := os.Getenv("PAIL_RECONNECT_MAX_BACKOFF_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			log.Fatalf("PAIL_RECONNECT_MAX_BACKOFF_MS: invalid value %q", v)
		}
		maxBackoffMs = n
	}
	dialOpts = append(dialOpts, grpc.WithConnectParams(grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  500 * time.Millisecond,
			Multiplier: 1.6,
			Jitter:     0.2,
			MaxDelay:   time.Duration(maxBackoffMs) * time.Millisecond,
		},
	}))
	log.Printf("upstream reconnect backoff: max=%dms", maxBackoffMs)
	// P8-M1: a dead upstream connection is detected by ping, not by TCP —
	// see grpclive.UpstreamKeepalive.
	dialOpts = append(dialOpts, grpclive.UpstreamKeepalive())
	log.Printf("upstream keepalive: time=%s timeout=%s", grpclive.UpstreamKeepaliveTime, grpclive.UpstreamKeepaliveTimeout)

	conns := make([]*grpc.ClientConn, len(cloudAddrs))
	for i, a := range cloudAddrs {
		c, err := grpc.Dial(a, dialOpts...)
		if err != nil {
			log.Fatalf("dial cloud %s: %v", a, err)
		}
		conns[i] = c
	}
	conn := newFailoverConn(cloudAddrs, conns, log.Printf)
	var opsProbe *selfProbe
	if dep := os.Getenv("PAIL_OPS_DEPLOYMENT_ID"); dep != "" {
		if grpcauth.UDSPath() == "" {
			deploysec.RefuseConfig("pail_robot_agent", fmt.Errorf("robotops probe requires local UDS"))
		}
		var err error
		opsProbe, err = newSelfProbe(conn, robotID, dep, loadedClientFingerprint)
		if err != nil {
			deploysec.RefuseConfig("pail_robot_agent", err)
		}
	}

	// Burst sender (D2 key separation): signs with the robot-agent's OWN key —
	// the issuer private key never leaves the cloud side. Receivers pick the
	// verify key from keyring.json role=="burst" (agent-key-1).
	burstAddr := os.Getenv("PAIL_BURST_ADDR")
	if burstAddr == "" {
		burstAddr = "127.0.0.1:46000"
	}
	bs := burst.New(burstAddr)
	agentKeyPath := os.Getenv("PAIL_AGENT_KEY")
	if agentKeyPath == "" {
		agentKeyPath = deploysec.DefaultAgentKeyfile
	}
	agentKeyID := os.Getenv("PAIL_AGENT_KEY_ID")
	if agentKeyID == "" {
		agentKeyID = "agent-key-1"
	}
	keypair, err := crypto.LoadEd25519KeypairJSON(agentKeyPath, agentKeyID)
	if err != nil {
		log.Fatalf("burst sign key: %v", err)
	}
	log.Printf("burst sign key: %s (%s)", keypair.KeyID, agentKeyPath)
	// S8 check (5) on the key actually loaded: the path check in Preflight does
	// not see a keyfile this call created, nor one reached through a symlink.
	deploysec.EnforceTrustAnchors("pail_robot_agent",
		deploysec.TrustAnchorFromPub("burst signing key", keypair.KeyID, keypair.Public))

	// D3: local active-token mirror keeps the gate's 20Hz permit recheck off
	// the WAN round trip. PAIL_TOKEN_MIRROR_MS=0 disables it (pure passthrough).
	mirrorMs := 200
	if v := os.Getenv("PAIL_TOKEN_MIRROR_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			log.Fatalf("PAIL_TOKEN_MIRROR_MS: invalid value %q", v)
		}
		mirrorMs = n
	}
	tc := tokenpb.NewTokenServiceClient(conn)
	m := newTokenMirror(tc, robotID, time.Duration(mirrorMs)*time.Millisecond)
	if opsProbe != nil {
		opsProbe.attachMirror(m) // LLD §11.6 runtime guard summary (read-only)
	}
	log.Printf("token mirror: interval=%dms (0=disabled)", mirrorMs)

	// OI-01: durable, retried decision-report queue (reportqueue.go).
	qo, err := reportQueueOptionsFromEnv(robotID)
	if err != nil {
		deploysec.RefuseConfig("pail_robot_agent", err)
	}
	rq, err := newReportQueue(tc, qo)
	if err != nil {
		// P25-M2: a report queue that cannot be durable is a configuration refusal, not a degradation
		deploysec.RefuseConfig("pail_robot_agent", err)
	}
	if opsProbe != nil {
		opsProbe.reports = rq
	}
	log.Printf("report queue: dir=%q cap=%d bytes retry_max=%s run=%s durable=%t", qo.Dir, qo.MaxBytes, rq.retryMax, rq.RunID(), rq.isDurable())
	// C1 cohort handshake (P36-M1): the queue's guard (shared with the critical outbox) also reads the census
	// header; a mismatch on the first census is a configuration refusal (exit 78).
	// P37-M1: while running, a mismatch is a hold that clears itself — the guard re-declares the census with backoff
	// and warns from a timer; the restore line names the holds that remain (storage fault, execution fence).
	wireCohortGuard(rq, m, func(e error) { deploysec.RefuseConfig("pail_robot_agent", e) })

	m.enableExecutionFence(os.Getenv("PAIL_PROFILE") != "dev")
	go subscribeBeacons(conn, bs, keypair, robotID, m, rq)

	// KM2-2 (KM LLD §7.1): signed keyring bundle pull. Enabled only when a
	// root public key is configured — bundles are trusted on the offline root
	// signature alone, never on this transport.
	puller, err := newKeyringPullerFromEnv(agentpb.NewAgentRelayClient(conn), robotID)
	if err != nil {
		// §3.7: 폐기 도달 상한이 설정되지 않은 것은 코드가 아니라 설정이 틀린
		// 것이다 — `exit 78`. `log.Fatalf` 의 1 이면 오케스트레이터가 고쳐질 리
		// 없는 설정 오류에 재시작 루프를 돈다.
		deploysec.RefuseConfig("pail_robot_agent", fmt.Errorf("keyring pull: %w", err))
	}
	if puller != nil {
		go puller.run()
	} else {
		log.Printf("keyring pull: disabled (set PAIL_ROOT_PUBKEY_FILE to enable)")
	}

	np := &northProxy{c: pb.NewPailNorthboundClient(conn), m: m}
	tp := &tokenProxy{c: tc, m: m, f: rq, routeVersion: conn.routeGen.Load}
	op := &operatorProxy{c: operatorpb.NewOperatorServiceClient(conn), m: m}

	register := func(g *grpc.Server) {
		pb.RegisterPailNorthboundServer(g, np)
		tokenpb.RegisterTokenServiceServer(g, tp)
		operatorpb.RegisterOperatorServiceServer(g, op)
	}

	// C2-C3 : 신원 인터셉터. 레지스트리가 없으면 기동 거부
	// (RG-4) — 빈 채로 뜨면 모든 호출이 unbound 가 되고, 운영자는 그것을
	// "인터셉터가 고장났다"로 읽는다.
	robotReg, err := identity.LoadFromEnv()
	if err != nil {
		deploysec.RefuseConfig("pail_robot_agent", err)
	}
	ident := identity.NewInterceptor(robotReg)

	// Front door (LLD-v2 §3): mTLS on TCP by default, identical to the
	// pre-split pail_services listener so gate/PVS/demo configs are unchanged.
	var serverOpts []grpc.ServerOption
	if grpcauth.TLSEnabled() {
		creds, err := grpcauth.ServerTLS("", "", "")
		if err != nil {
			log.Fatalf("grpc mTLS init (run scripts/sros2_provision.sh; PAIL_GRPC_TLS=off is DEV ONLY): %v", err)
		}
		serverOpts = append(serverOpts, grpc.Creds(creds))
		log.Printf("robot-agent gRPC: mTLS enabled (client certificate required)")
	} else {
		log.Printf("WARNING: PAIL_GRPC_TLS=off — plaintext gRPC is DEV ONLY (LLD-v2 §3)")
	}
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	serverOpts = append(serverOpts, grpc.ChainUnaryInterceptor(localRobotBinding(robotID), ident.Unary), grpc.ChainStreamInterceptor(ident.Stream))
	grpcServer := grpc.NewServer(serverOpts...)
	register(grpcServer)

	// Same-host alternative to mTLS (LLD-v2 §3): UDS guarded by file perms.
	if udsPath := grpcauth.UDSPath(); udsPath != "" {
		if fi, err := os.Stat(udsPath); err == nil {
			if fi.Mode()&os.ModeSocket == 0 {
				log.Fatalf("uds: %s exists and is not a socket; refusing to remove", udsPath)
			}
			if err := os.Remove(udsPath); err != nil {
				log.Fatalf("uds: remove stale socket: %v", err)
			}
		}
		ul, err := net.Listen("unix", udsPath)
		if err != nil {
			log.Fatalf("uds listen: %v", err)
		}
		if err := os.Chmod(udsPath, 0o660); err != nil {
			log.Fatalf("uds chmod: %v", err)
		}
		udsServer := grpc.NewServer(grpc.Creds(grpcauth.UDSCreds()), grpc.ChainUnaryInterceptor(localRobotBinding(robotID), ident.Unary), grpc.ChainStreamInterceptor(ident.Stream))
		if opsProbe != nil {
			robotopspb.RegisterRobotAgentSelfProbeServer(udsServer, opsProbe)
		}
		register(udsServer)
		log.Printf("pail_robot_agent UDS listening on %s (mode 0660)", udsPath)
		go func() {
			if err := udsServer.Serve(ul); err != nil {
				log.Fatalf("uds serve: %v", err)
			}
		}()
	}

	log.Printf("pail_robot_agent listening on :%s (cloud=%v burst=%s)", port, cloudAddrs, burstAddr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// applyBeacon is what one relay event does to this gateway's state. It
// reports whether the event concerned this robot at all; a foreign event
// changes nothing and must not be re-broadcast under this robot's key.
//
// For an event that is ours: the mirror must not answer the next recheck
// from a pre-event cache, so every beacon drops the cached answer. Whether it
// also surrenders the DELEGATED WINDOW depends on what the beacon says
// (beaconRevokesAuthority): a revocation or an ESTOP does, a BLOCK does not.
// See that function for what the blanket drop cost.
func applyBeacon(m *tokenMirror, self string, ev *agentpb.BeaconEvent) bool {
	if !burst.BeaconAddresses(byte(ev.GetEvent()), ev.GetRobotId(), self) {
		return false
	}
	if beaconRevokesAuthority(byte(ev.GetEvent())) {
		m.Invalidate()
	} else {
		m.invalidateCache()
	}
	return true
}

// subscribeBeacons keeps a robot-initiated stream to the cloud relay and
// transmits every BeaconEvent as a signed burst v2 packet. Reconnects with
// backoff; the cloud hub backlogs events while no subscriber is attached.
// The 500ms reconnect cycle is also a failover driver (HA LLD §5.2): a
// STANDBY refusal or UNAVAILABLE on this stream rotates the upstream.
func subscribeBeacons(fc *failoverConn, bs *burst.Sender, keypair *crypto.Keypair, robotID string, m *tokenMirror, q *reportQueue) {
	client := agentpb.NewAgentRelayClient(fc)
	for {
		i := fc.index()
		ctx, cancel := context.WithCancel(context.Background())
		stream, err := client.SubscribeBeacons(ctx, &agentpb.SubscribeBeaconsRequest{RobotId: robotID})
		if err != nil {
			cancel()
			time.Sleep(500 * time.Millisecond)
			continue
		}
		log.Printf("robot-agent: beacon stream connected (cloud=%s)", fc.addr())
		m.noteReconnect()
		m.setStream(true)
		// OI-01: the link is back — retry the queued decision reports now.
		if q != nil {
			q.kickNow()
		}
		// AV2 §3.3: stream recovery is the reconcile point — replay what was
		// consumed offline, in order, then take a fresh window.
		m.reconcile()
		for {
			ev, err := stream.Recv()
			if err != nil {
				log.Printf("robot-agent: beacon stream error: %v — reconnecting", err)
				fc.observe(i, err)
				break
			}
			// OI-02: an event about another robot is not this gateway's to act
			// on or to re-sign. The relay filters the stream by robot id, but
			// an older relay forwards everything, so the agent judges too.
			if !applyBeacon(m, robotID, ev) {
				log.Printf("robot-agent: beacon %s for robot=%s ignored (this gateway is robot=%s)",
					burst.EventName(byte(ev.Event)), ev.RobotId, robotID)
				continue
			}
			var th [16]byte
			copy(th[:], ev.TokenHash16)
			bs.SendBurst(burst.BuildPacketV2(keypair.Private, byte(ev.Event), uint16(ev.Reason), ev.UnixMs, ev.RobotId, th, bs.NextSeq()))
			log.Printf("robot-agent: burst %s reason=0x%02x robot=%s", burst.EventName(byte(ev.Event)), ev.Reason, ev.RobotId)
		}
		m.setStream(false)
		cancel()
		time.Sleep(500 * time.Millisecond)
	}
}
