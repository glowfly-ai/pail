// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// AV2 (AV LLD §3): the robot-side half of the edge lease. The issuer
// pre-authorizes a window of steps; while the cloud is unreachable the gateway
// serves that window from local state instead of failing every permit recheck.
//
// The lease does NOT weaken any gate check: the gateway hands over the same
// issuer-signed bytes, and the gate independently verifies signature,
// not_before/not_after and the world hash. What the lease removes is the
// requirement that the cloud be reachable at the moment of the check.
//
// Two costs are deliberate and bounded (HLD §7-2):
//   - lease depth is the stopping distance: past lease_max_index the gateway
//     falls back to the cloud, and without it the gate blocks;
//   - current_subgraph_hash cannot be pre-computed, so ERR_WORLD_CHANGED
//     detection lags by up to the lease window (§3.2).

import (
	"bytes"
	"context"
	"errors"
	"github.com/glowfly/pail/services/internal/corecomm"
	"log"
	"time"

	"github.com/glowfly/pail/services/internal/burst"

	pb "github.com/glowfly/pail/services/proto/pailv1"
	tokenpb "github.com/glowfly/pail/services/proto/tokenv1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// errEpochRegression fences a stale issuer (AV LLD §3.3/§4.5): a response from
// a generation older than one already seen is refused and the cached
// authorization is dropped. Checking at the resource side is the point —
// the robot is the resource.
var errEpochRegression = errors.New("issuer epoch regression: response refused")

// errStalePosition: the answer describes a step of this chain the gateway already consumed.
var errStalePosition = errors.New("issuer answer predates a consumption report: discarded")

// leaseUsableLocked reports whether the window can answer the next recheck.
func (m *tokenMirror) leaseUsableLocked() bool {
	if len(m.lease) == 0 || m.servingIdx > m.leaseMax {
		return false
	}
	_, ok := m.lease[m.servingIdx]
	return ok
}

func (m *tokenMirror) leaseHeld() bool {
	if m == nil || m.interval == 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.leaseUsableLocked()
}

// leaseNotAfterMs reads the validity end of the token the window is about to hand out. It is read from the
// signed bytes (the same bytes the gate judges); the informational copy is used only when a token carries
// no signed bytes. 0 means unknown — the window then has no expiry of its own and the gate alone judges.
func leaseNotAfterMs(tok *pb.SignedToken) int64 {
	if raw := tok.GetActionTokenBytes(); len(raw) > 0 {
		var at pb.ActionToken
		if err := proto.Unmarshal(raw, &at); err == nil {
			return at.GetNotAfterUnixMs()
		}
	}
	return tok.GetToken().GetNotAfterUnixMs()
}

// expireLeaseLocked releases a window whose current token has outlived its own not_after on this
// gateway's clock, and says whether it did. A lease cannot outlive its tokens: past not_after every
// recheck served from it is refused by the gate anyway, while the issuer may already have accepted the
// next plan — which this gateway never asks about while it believes it holds a usable window.
//
// This is a liveness decision, not a validity judgement: the gate still judges not_before/not_after on
// the signed bytes and this gateway's clock cannot extend a token (a slow clock only delays the release,
// and expiredLeased below then releases on the gate's ERR_EXPIRED report; a fast clock only releases
// early and the next read goes to the cloud, which re-delegates whatever is still valid). The drop is
// declared like every other drop (AV7). Measured 2026-10-09 on the software rig before this existed: one
// command judged PERMIT with its step never completed, the plan expired, a new plan was ACCEPTED, and the
// gateway kept serving the old token (BLOCK ERR_EXPIRED) for 15 minutes — only a cancel beacon released it.
func (m *tokenMirror) expireLeaseLocked() bool {
	if !m.isLeaseExpiredLocked() {
		return false
	}
	notAfter, now := leaseNotAfterMs(m.lease[m.servingIdx]), m.now().UnixMilli()
	tokenID := m.lease[m.servingIdx].GetToken().GetTokenId()
	m.gen++
	m.dropLeaseLocked()
	m.invalidateCacheLocked()
	log.Printf("robot-agent: leased token=%s chain=%s not_after=%d is behind this gateway's clock (%d) — window spent, lease released; the next read asks the issuer", tokenID, m.chainID, notAfter, now)
	go m.census()
	return true
}

// isLeaseExpiredLocked: a usable window whose current token's not_after is behind this gateway's clock.
func (m *tokenMirror) isLeaseExpiredLocked() bool {
	if !m.leaseUsableLocked() {
		return false
	}
	notAfter := leaseNotAfterMs(m.lease[m.servingIdx])
	return notAfter != 0 && m.now().UnixMilli() > notAfter
}

// now is the gateway clock used only to stop serving an expired window (tests substitute it).
func (m *tokenMirror) now() time.Time {
	if m.nowFn != nil {
		return m.nowFn()
	}
	return time.Now()
}

// serveLeaseLocked rebuilds the response the gate expects (§3.2). The lease
// fields (7-9) are NOT carried: they are an issuer-gateway contract and the
// gate's stub does not know them. Validity is still judged once, by the gate,
// on the signed bytes; this gateway only stops serving a window whose current
// token is already past not_after on its own clock (expireLeaseLocked).
func (m *tokenMirror) serveLeaseLocked() *tokenpb.GetActiveTokenResponse {
	m.expireLeaseLocked()
	if !m.leaseUsableLocked() {
		return nil
	}
	return &tokenpb.GetActiveTokenResponse{
		Status:                tokenpb.ActiveTokenStatus_OK,
		ChainId:               m.chainID,
		ExpectedSequenceIndex: m.servingIdx,
		Token:                 m.lease[m.servingIdx],
		CurrentSubgraphHash:   m.worldHash,
	}
}

// dropLeaseLocked releases the delegated window and reports whether one was
// actually held. AV7 (§9.3): servingIdx is NOT cleared. It is the gateway's
// position, not part of the grant — zeroing it made the next census declare
// last_consumed = -1, i.e. the drop erased the very fact the issuer needs to
// walk its serving position back.
func (m *tokenMirror) dropLeaseLocked() bool {
	had := len(m.lease) > 0
	m.lease = nil
	m.leaseMax = 0
	return had
}

// absorbLocked takes the issuer's answer as the new truth: it fences the epoch,
// captures the delegated window, and records the world-derived values the lease
// cannot recompute. A non-OK answer purges the window — a revoked or exhausted
// chain must not keep driving off a stale grant.
func (m *tokenMirror) absorbLocked(resp *tokenpb.GetActiveTokenResponse) error {
	if e := resp.GetIssuerEpoch(); e < m.epoch {
		log.Printf("robot-agent: issuer epoch regression (saw=%d, response=%d) — refusing and dropping cache", m.epoch, e)
		m.dropLeaseLocked()
		m.resp = nil
		return errEpochRegression
	} else if e > m.epoch {
		m.epoch = e
	}

	if resp.GetStatus() != tokenpb.ActiveTokenStatus_OK {
		m.dropLeaseLocked()
		return nil
	}
	// M3 (TB3, 2026-09-15): for one chain the issuer never serves below a position this
	// gateway has already reported consumed. An answer that does was computed before our
	// report landed — a completion report kicks the poller before it is forwarded, and the
	// refresh can overtake it. Absorbing it rewound servingIdx and re-armed the consumed
	// step as a live lease, so the next plan's gate read ERR_TOKEN_CONSUMED until expiry.
	// The stale answer changes nothing; the caller asks again and meets the report.
	if resp.GetChainId() == m.chainID && m.chainID != "" && resp.GetExpectedSequenceIndex() < m.servingIdx {
		log.Printf("robot-agent: stale answer for chain=%s index=%d < consumed position %d — discarded", m.chainID, resp.GetExpectedSequenceIndex(), m.servingIdx)
		return errStalePosition
	}
	m.chainID = resp.GetChainId()
	m.worldHash = resp.GetCurrentSubgraphHash()
	m.servingIdx = resp.GetExpectedSequenceIndex()

	toks := resp.GetLeaseTokens()
	if len(toks) == 0 {
		m.dropLeaseLocked()
		return nil
	}
	first := resp.GetExpectedSequenceIndex()
	lease := make(map[int32]*pb.SignedToken, len(toks))
	for i, st := range toks {
		lease[first+int32(i)] = st
	}
	// The window can never reach past what we actually hold, whatever the
	// issuer's bookkeeping says.
	last := first + int32(len(toks)) - 1
	if max := resp.GetLeaseMaxIndex(); max < last {
		last = max
	}
	m.lease, m.leaseMax = lease, last
	return nil
}

// beaconRevokesAuthority answers whether a beacon takes the delegated window
// away, as opposed to merely making the cached answer stale.
//
// The distinction was missing until 2026-09-10 and cost a live permit. The
// beacon handler dropped the mirror wholesale on EVERY event, and the drop
// releases the lease; releasing it makes the mirror declare
// `held_lease_max=0` at the next census, and the issuer reads a declaration of
// "I hold no window" as its cue to retract (AV7). So a routine BLOCK — a
// decision, not a state transition — walked the whole chain: BLOCK beacon ->
// lease dropped -> census 0 -> LEASE_RETRACTED -> the gate's next recheck
// NO_TOKEN. Measured on the Viam rig: LEASE_GRANTED and LEASE_RETRACTED
// alternating a few seconds apart, and `CA-16` unmeasurable because the permit
// never survived long enough to end at its own deadline.
//
// What each event means for authority:
//
//	EventChainRevoked       the authorization is gone -> the window must go with it
//	EventEstop              motion is refused now -> offline authority must not outlive it
//	EventAuthorityWithheld  the issuer no longer serves this robot (its gate's
//	                        attestation is invalid or expired, OI-04) -> the
//	                        window it granted earlier must not outlive that
//	EventBlock              one command was refused; the token is untouched
//	EventCheckpoint         a ledger marker; not about authorization at all
//
// Unknown codes revoke: a build that does not recognise an event cannot argue
// that it left authority intact.
func beaconRevokesAuthority(event byte) bool {
	switch event {
	case burst.EventBlock, burst.EventCheckpoint:
		return false
	case burst.EventChainRevoked, burst.EventEstop, burst.EventAuthorityWithheld:
		return true
	default:
		return true
	}
}

// census declares where this gateway actually is: the highest index it
// consumed and the window it still holds (AV LLD §4.6.3). It is a claim, not
// evidence — the issuer only checks whether its own journal can explain it —
// so the gateway states its position and changes nothing on the strength of
// having stated it.
func (m *tokenMirror) census() {
	if m == nil || m.c == nil {
		return
	}
	req := &tokenpb.GatewayCensusRequest{RobotId: m.robotID}
	m.mu.Lock()
	req.SeenIssuerEpoch = m.epoch
	callGen, connGen := m.gen, m.connGen
	if m.chainID != "" {
		req.ChainId = m.chainID
		req.LastConsumedIndex = m.servingIdx - 1
		if m.leaseUsableLocked() && !m.isLeaseExpiredLocked() {
			req.HeldLeaseMaxIndex = m.leaseMax
		}
	}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var header metadata.MD
	resp, err := m.c.ReportGatewayCensus(ctx, req, grpc.Header(&header))
	cancel()
	if err != nil {
		log.Printf("robot-agent: census declaration failed: %v — a promoted issuer keeps withholding until it lands", err)
		return
	}
	// C1 cohort handshake (P36-M1; recovery P37-M1): the Issuer's contract travels in a response header of every
	// census. The header is applied only after the answer is verified — a body with a verdict, an epoch not below
	// the one already seen (a regressed answer never touches the cohort state) — and only clears the hold when no
	// newer connection or generation decided meanwhile: a late v1 answer from the connection before a rollback must
	// not erase the mismatch the current connection found. The conservative direction (entering the hold) is
	// still allowed on a stale-but-valid answer.
	m.mu.Lock()
	valid := resp != nil && resp.GetVerdict() != "" && resp.GetIssuerEpoch() >= m.epoch
	stale := m.gen != callGen || m.connGen != connGen
	m.mu.Unlock()
	switch {
	case !valid:
		log.Printf("robot-agent: census answer without a verdict or below the seen epoch (verdict=%q issuer_epoch=%d) — not applied to the cohort state", resp.GetVerdict(), resp.GetIssuerEpoch())
	case stale:
		m.cohort.censusAnsweredStale(header)
	default:
		m.cohort.censusAnswered(header)
	}
	log.Printf("robot-agent: census declared chain=%s last_consumed=%d held_lease_max=%d seen_epoch=%d -> verdict=%s issuer_epoch=%d",
		req.ChainId, req.LastConsumedIndex, req.HeldLeaseMaxIndex, req.SeenIssuerEpoch, resp.GetVerdict(), resp.GetIssuerEpoch())

	// The census answer carries the generation too, so a stale issuer is
	// fenced on this path exactly as it is on the serving path.
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := resp.GetIssuerEpoch(); e < m.epoch {
		log.Printf("robot-agent: issuer epoch regression on census (saw=%d, response=%d) — refusing and dropping cache", m.epoch, e)
		m.dropLeaseLocked()
		m.resp = nil
	} else if e > m.epoch {
		m.epoch = e
	}
	// P7-H1: the issuer says the chain we declared no longer authorizes motion — cancelled, revoked,
	// completed, or replaced by an accepted plan. Its beacon is how that normally arrives; this is
	// the path for a gateway that missed it (cut from the relay when it was sent: the relay keeps a
	// backlog only while nobody at all is subscribed). Without it the reconnect reconcile kept the
	// window — a refresh inside our own window reads as "spent" (D-5) — and the robot stayed on the
	// old plan until that token's not_after. Dropping a window only takes authority away; the next
	// read asks the issuer. Only the chain we declared, and only if we are still on it.
	if resp.GetVerdict() == censusChainEnded && req.ChainId != "" && req.ChainId == m.chainID {
		// This verdict revokes exactly the declared chain, not a concurrently
		// issued replacement. Preserve that scope for the in-flight reply.
		// Any intervening global/fatal/restart generation change prevents this
		// exception; the normal invalidated-in-flight refusal still applies.
		if call := m.inflight; call != nil && (call.gen == m.gen || (len(call.endedChains) > 0 && call.censusGen == m.gen)) {
			if call.endedChains == nil {
				call.endedChains = make(map[string]bool)
			}
			call.endedChains[req.ChainId] = true
			call.censusGen = m.gen + 1
		}
		m.gen++
		dropped := m.dropLeaseLocked()
		m.invalidateCacheLocked()
		if dropped {
			log.Printf("robot-agent: issuer answered the census CHAIN_ENDED for chain=%s — the window it still held is dropped; the next read asks the issuer", req.ChainId)
		}
	}
}

// censusChainEnded is the issuer's census verdict for a declared chain that no longer authorizes motion.
const censusChainEnded = "CHAIN_ENDED"

// consumed applies the local advance for a completing PERMIT (§3.3). It returns
// true when the lease is carrying the step, in which case the caller must treat
// a failed forward as survivable: the report is queued and replayed on
// reconnect, and the cloud reconciles the real consumption index there.
func (m *tokenMirror) consumed(req *tokenpb.ReportDecisionRequest) bool {
	if m == nil || m.interval == 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.leaseUsableLocked() {
		return false
	}
	// A late completion may describe the previous plan. It cannot consume a
	// token from the newly installed chain (nor advance on a duplicate token).
	if !req.GetStepComplete() || req.GetFatal() || req.GetDecision() != tokenpb.Decision_PERMIT ||
		req.GetTokenId() == "" || req.GetChainId() == "" || req.GetRobotId() != m.robotID || req.GetChainId() != m.chainID ||
		req.GetTokenId() != m.lease[m.servingIdx].GetToken().GetTokenId() {
		return false
	}
	m.servingIdx++
	m.pendingRep = append(m.pendingRep, req)
	return true
}

// expiredLeased releases the delegated window when the gate reports that the very token this gateway is
// serving from its lease has expired, and says whether it did.
//
// It is the backstop behind expireLeaseLocked: when this gateway's clock lags the gate's (or a token
// carries no readable not_after), the window is still released the moment the gate has judged the leased
// token ERR_EXPIRED — holding the grant past that only hands the same dead token to every later recheck.
// An expiry report for another chain, or for a token this gateway is not serving, changes nothing (a late
// report of a previous plan must not release the current grant). The drop is declared like every other
// drop (AV7), so the issuer can walk its serving position back.
func (m *tokenMirror) expiredLeased(req *tokenpb.ReportDecisionRequest) bool {
	if m == nil || m.interval == 0 || req.GetReasonCode() != "ERR_EXPIRED" || req.GetRobotId() != m.robotID {
		return false
	}
	m.mu.Lock()
	if !m.leaseUsableLocked() || req.GetChainId() == "" || req.GetChainId() != m.chainID ||
		req.GetTokenId() == "" || req.GetTokenId() != m.lease[m.servingIdx].GetToken().GetTokenId() {
		m.mu.Unlock()
		return false
	}
	m.gen++
	dropped := m.dropLeaseLocked()
	m.invalidateCacheLocked()
	m.mu.Unlock()
	if dropped {
		log.Printf("robot-agent: gate reported ERR_EXPIRED on the leased token=%s chain=%s — window spent, lease released", req.GetTokenId(), req.GetChainId())
		go m.census()
	}
	return dropped
}

// forwarded removes a report the cloud has acknowledged.
func (m *tokenMirror) forwarded(req *tokenpb.ReportDecisionRequest) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, p := range m.pendingRep {
		if p == req || (req.GetReceiptContractVersion() == 1 && req.GetReportId() != "" && p.GetReportId() == req.GetReportId() && p.GetRobotId() == req.GetRobotId() && bytes.Equal(p.GetReportDigest(), req.GetReportDigest())) {
			m.pendingRep = append(m.pendingRep[:i], m.pendingRep[i+1:]...)
			return
		}
	}
}

// reconcile runs on beacon-stream recovery (§3.3): replay every queued
// consumption report IN ORDER, then force one GetActiveToken so the issuer
// grants a fresh window from the reconciled position. Order matters — the
// issuer's over-lease check is what turns unexplainable progress into a
// revocation, and out-of-order reports would look exactly like that.
func (m *tokenMirror) reconcile() {
	if m == nil {
		return
	}
	// AV3 §4.6.3: declare our position FIRST. A promoted issuer withholds
	// issuance from every robot it cannot account for, and the cloud has no way
	// to dial us, so the declaration is what lifts the hold. A gateway with the
	// mirror off holds no offline authority — but it must still declare that,
	// truthfully and emptily, or a promoted issuer would hold it forever.
	m.census()
	if m.interval == 0 {
		return
	}
	replayed := false
	for {
		m.mu.Lock()
		if len(m.pendingRep) == 0 {
			m.mu.Unlock()
			break
		}
		req := m.pendingRep[0]
		m.mu.Unlock()

		// OI-01: a replay is journaled as a replay, not as a fresh decision.
		req.Delivery = reportDeliveryReplayed
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := m.c.ReportDecision(ctx, req)
		cancel()
		if err != nil {
			log.Printf("robot-agent: lease reconcile: replay of token=%s failed: %v — retrying on next reconnect", req.GetTokenId(), err)
			return
		}
		if req.GetReceiptContractVersion() == 1 {
			if ackErr := corecomm.CheckReportACK(req, resp, true); ackErr != nil {
				log.Printf("core-comm lease receipt not confirmed: %v", ackErr)
				return
			}
		}
		if !resp.GetAccepted() {
			// The issuer refused the offline progress (over-lease / revoked
			// chain). The refusal is its verdict to enforce; the gateway drops
			// the window so the next recheck asks the cloud.
			log.Printf("robot-agent: lease reconcile: issuer REFUSED token=%s — dropping the lease", req.GetTokenId())
			m.mu.Lock()
			m.dropLeaseLocked()
			m.resp = nil
			m.mu.Unlock()
		}
		m.forwarded(req)
		replayed = true
	}

	// D-5 corollary again: a flap with nothing consumed has nothing to
	// reconcile, and a refresh inside our own live window reads to the issuer
	// as "the window is spent" — it would serve past the steps we still hold.
	// Once a report has landed, upstreamFresh still rechecks remaining local
	// authority under the lock before it requests the next exhausted window.
	if !replayed && m.leaseHeld() {
		return
	}

	// §3.5: this one must not JOIN an outstanding call — a request issued before
	// the replay was answered from the issuer's pre-reconcile position, which is
	// exactly the state this refresh exists to leave behind. So it drains the
	// window first and then takes it, which still guarantees the one thing D-11
	// is about: never two calls in flight at once.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = m.upstreamFresh(ctx, &tokenpb.GetActiveTokenRequest{RobotId: m.robotID})
	cancel()
}
