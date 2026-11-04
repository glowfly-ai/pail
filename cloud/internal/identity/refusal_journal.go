// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package identity

// C2-C6 : an unbound refusal must leave a journal
// record, or "who was turned away" reads the same as "nobody" (H-B2). The
// pass verdicts already reach the journal through the Binding the handler
// carries into records 10/20 (§2.8); a refusal has no handler, so the
// interceptor writes record 90 itself.
//
// Live measurement first (2026-08-12): the refusal at 13:24:24 left the
// journal at six records before and six after — the §2.6 comment promised
// the journal keeps caller_kind and the fingerprint, and nothing did.
//
// Best-effort, not record-first strict: strictness exists so that authority
// is never granted without evidence. A refusal grants nothing — it stands
// whether or not it could be written, and making it strict would let a full
// disk turn "refuse and record" into "hang".
//
// The suppression window exists because the refusal rate is
// attacker-controlled. Every other record type is written at a rate the
// issuer itself decides; this one is written at the rate an unregistered
// caller decides, and the same live bring-up produced 404 refusals in
// minutes from one misconfigured dialer. Per-caller: one record per window,
// with the count of suppressed repeats carried in the next record so the
// journal still states how many were turned away, just not one line each.

import (
	"encoding/json"
	"log"
	"time"

	"github.com/glowfly/pail/services/internal/blackbox"
)

// Journal is the sink for refusal records — satisfied by *blackbox.Writer.
// An interface so the robot-agent (which has no journal) wires nothing and
// tests wire memory.
type Journal interface {
	Append(recordType uint32, unixMs uint64, payload []byte) error
}

const (
	// refusalWindowMs: one journaled refusal per caller per minute. Long
	// enough that a reconnect loop cannot flood the evidence store, short
	// enough that an ongoing probe stays visible line by line.
	refusalWindowMs = 60_000
	// refusalTrackCap bounds the suppression map. When the map is full,
	// untracked callers journal every time — when we cannot track, we write
	// rather than suppress (suppressing what we cannot see is H-B2).
	refusalTrackCap = 1024
)

type refusalSeen struct {
	lastMs     uint64
	suppressed uint64
}

// SetJournal wires the refusal sink. Late-bound on purpose: both issuers
// open the journal after the interceptor is constructed, and pail_cloud
// serves standby traffic before the writer exists — refusals in that window
// are not journaled, which is a statement about the standby (it holds no
// journal), not about the refusal.
func (i *Interceptor) SetJournal(j Journal) {
	i.jmu.Lock()
	i.journal = j
	i.jmu.Unlock()
}

// shouldJournal is the per-caller window. It returns whether to write now
// and how many refusals from this caller were suppressed since the last
// written record.
func (i *Interceptor) shouldJournal(caller string, nowMs uint64) (bool, uint64) {
	i.rmu.Lock()
	defer i.rmu.Unlock()
	s, ok := i.refusals[caller]
	if !ok {
		if len(i.refusals) >= refusalTrackCap {
			return true, 0
		}
		if i.refusals == nil {
			i.refusals = map[string]*refusalSeen{}
		}
		i.refusals[caller] = &refusalSeen{lastMs: nowMs}
		return true, 0
	}
	if nowMs < s.lastMs || nowMs-s.lastMs >= refusalWindowMs {
		n := s.suppressed
		s.lastMs, s.suppressed = nowMs, 0
		return true, n
	}
	s.suppressed++
	return false, 0
}

// journalRefusal writes record 90 for one unbound refusal. reason is the
// registry's journal vocabulary (Binding.Reason), never the gRPC status
// literal — the wire text is the interceptor's concern, the journal keeps
// the why.
func (i *Interceptor) journalRefusal(method, callerKind, callerID, robotID, reason string) {
	i.jmu.RLock()
	j := i.journal
	i.jmu.RUnlock()
	if j == nil {
		return
	}
	nowMs := uint64(time.Now().UnixMilli())
	write, suppressed := i.shouldJournal(callerKind+"/"+callerID, nowMs)
	if !write {
		return
	}
	ev := map[string]any{
		"kind":           "IDENTITY_REFUSED",
		"journal_v":      4,
		"unix_ms":        nowMs,
		"method":         method,
		"robot_id":       robotID,
		"caller_kind":    callerKind,
		"caller_id":      callerID,
		"robot_id_bound": Unbound.String(),
		"reason":         reason,
		"suppressed":     suppressed,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		log.Printf("identity: refusal record marshal: %v", err)
		return
	}
	if err := j.Append(blackbox.RecordIdentityRefused, nowMs, b); err != nil {
		log.Printf("identity: refusal record append: %v", err)
	}
}
