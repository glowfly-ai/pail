// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/glowfly/pail/services/internal/completion"
	"github.com/glowfly/pail/services/pkg/robotid"
)

// A plan and the ledger are states, not streams: their freshness is the age
// of the collector's last verification, never the age of a record.
const LedgerKind = "collector_ledger"
const LedgerTrust = "collector_verified"
const LedgerBasis = "verified_frontier"
const LedgerFreshness = 30 * time.Second

// LedgerRereadWindow is how long a reading that found the ledger changing
// under it waits before it is shown. The collector reads such a ledger again
// within the same cycle; the reading that ends the cycle replaces this one.
// Only when none arrives does the collector say that it verified nothing.
const LedgerRereadWindow = time.Second

var ledgerCode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// LedgerRecord is one record the collector's own verification walk verified.
type LedgerRecord struct {
	Seq     int64
	Kind    string // record type name of the index
	Ms      uint64
	Payload []byte
}

// LedgerVerdict is the outcome of the walk that produced the records.
type LedgerVerdict struct {
	State       string // ok | chain_error | absent | unverified
	Code        string
	VerifiedSeq int64
	TipSeq      *int64
	LagRecords  *int64
	Published   bool
}
type PlanDetail struct {
	PlanID         string `json:"plan_id,omitempty"`
	ChainID        string `json:"chain_id,omitempty"`
	StepsTotal     *int   `json:"steps_total"`
	StepsIssued    int    `json:"steps_issued"`
	StepsCompleted int    `json:"steps_completed"`
	RejectCode     string `json:"reject_code,omitempty"`
	EndedBy        string `json:"ended_by,omitempty"`
	RecordSeq      string `json:"record_seq"`
	RecordMS       int64  `json:"record_ms"`
}
type LedgerLast struct {
	Seq  string `json:"seq"`
	Kind string `json:"kind"`
	MS   int64  `json:"ms"`
}
type LedgerDetail struct {
	ChainState      string      `json:"chain_state"`
	ErrorCode       string      `json:"error_code,omitempty"`
	VerifiedThrough string      `json:"verified_through_seq"`
	VerifiedAtMS    int64       `json:"verified_at_ms"`
	LagRecords      *int64      `json:"index_lag_records"`
	LastRecord      *LedgerLast `json:"robot_last_record"`
}

type ledgerPayload struct {
	completion.Record
	Kind          string `json:"kind"`
	V             int    `json:"v"`
	RobotID       string `json:"robot_id"`
	PlanID        string `json:"plan_id"`
	ChainID       string `json:"chain_id"`
	TokenID       string `json:"token_id"`
	SequenceIndex int32  `json:"sequence_index"`
	StepCount     *int   `json:"step_count"`
	Decision      string `json:"decision"`
	StepComplete  bool   `json:"step_complete"`
	Fatal         bool   `json:"fatal"`
	Attributed    *bool  `json:"chain_attributed"`
	RejectCode    string `json:"reject_code"`
	Verdict       string `json:"verdict"`
	// decision history
	ReasonCode string   `json:"reason_code"`
	Trigger    string   `json:"trigger"`
	Robots     []string `json:"robots"`
	Accepted   *bool    `json:"accepted"`
	// OI-01 delivery metadata on GATE_DECISION (journal_v 9); absent = an old agent
	DecidedMS int64  `json:"decided_unix_ms"`
	Delivery  string `json:"delivery"`
	Duplicate bool   `json:"duplicate"`
	Gap       bool   `json:"gap"`
}
type planFold struct {
	state, planID, chainID string
	completionIssue        string
	rejectCode, endedBy    string
	total                  int // 0 = the ledger does not say
	tokens                 map[string]int32
	issued, completed      map[int32]bool
	seq                    int64
	ms                     uint64
	last                   LedgerLast
	lastSeq                int64
}

// LedgerFold is the per-robot reading of one verification walk. It keeps the
// latest plan of each declared robot only, so its size is bounded by the
// declared robots and the step limit, not by the length of the ledger.
type LedgerFold struct {
	declared  map[string]bool
	robots    map[string]*planFold
	unknown   map[string]bool
	overflow  bool
	decisions map[string]*decisionList
	fleet     *decisionList
}

// NewLedgerFold starts the reading of one walk for the robots this collector's
// source map declares.
func (c *Collector) NewLedgerFold() *LedgerFold {
	f := &LedgerFold{declared: map[string]bool{}, robots: map[string]*planFold{}, unknown: map[string]bool{}, decisions: map[string]*decisionList{}, fleet: &decisionList{}}
	for _, p := range c.config.Providers {
		if p.Kind != LedgerKind && p.DeploymentID == c.config.DeploymentID {
			f.declared[p.RobotID] = true
		}
	}
	return f
}
func (p *planFold) begin(state string, x ledgerPayload, r LedgerRecord) {
	p.state, p.planID, p.chainID = state, x.PlanID, x.ChainID
	p.rejectCode, p.endedBy, p.total = "", "", 0
	p.completionIssue = ""
	p.tokens, p.issued, p.completed = map[string]int32{}, map[int32]bool{}, map[int32]bool{}
	p.seq, p.ms = r.Seq, r.Ms
}

// complete is true only when the ledger itself says how many steps the plan
// has and holds the completion record of the last one.
func (p *planFold) complete() bool {
	return p.completionIssue == "" && p.state == "ACCEPTED" && p.total > 0 && p.completed[int32(p.total)]
}
func (p *planFold) end(by string, r LedgerRecord) {
	if p.state != "ACCEPTED" || p.complete() {
		return
	}
	p.state, p.endedBy, p.seq, p.ms = "CANCELLED", by, r.Seq, r.Ms
}

// Record reads one verified record. A record that names no robot, or whose
// body is not the JSON the issuer writes, changes no robot's state.
func (f *LedgerFold) Record(r LedgerRecord) {
	var x ledgerPayload
	if len(r.Payload) == 0 || r.Payload[0] != '{' || json.Unmarshal(r.Payload, &x) != nil {
		return
	}
	f.decide(r, x)
	if x.RobotID == "" {
		return
	}
	if !f.declared[x.RobotID] {
		if !identifier.MatchString(x.RobotID) {
			return
		}
		if len(f.unknown) >= MaxUnresolved && !f.unknown[x.RobotID] {
			f.overflow = true
			return
		}
		f.unknown[x.RobotID] = true
		return
	}
	p := f.robots[x.RobotID]
	if p == nil {
		p = &planFold{}
		f.robots[x.RobotID] = p
	}
	kind := r.Kind
	if r.Kind == "CHAIN_REVOKED" && ledgerCode.MatchString(x.Kind) {
		kind = x.Kind
	}
	p.last, p.lastSeq = LedgerLast{Seq: strconv.FormatInt(r.Seq, 10), Kind: kind, MS: int64(r.Ms)}, r.Seq
	current := x.ChainID != "" && x.ChainID == p.chainID
	switch r.Kind {
	case "PLAN_ACCEPTED":
		p.begin("ACCEPTED", x, r)
		if x.V >= 2 && x.StepCount != nil && *x.StepCount >= 1 && *x.StepCount <= MaxSteps {
			p.total = *x.StepCount
		}
	case "PLAN_REJECTED":
		p.begin("REJECTED", x, r)
		p.chainID = ""
		p.rejectCode = "UNKNOWN_CODE"
		if ledgerCode.MatchString(x.RejectCode) {
			p.rejectCode = x.RejectCode
		}
	case "TOKEN_ISSUED":
		if !current {
			// Steps of a chain whose acceptance the ledger does not hold:
			// an issued token is not an acceptance record.
			p.begin("UNKNOWN", x, r)
			p.endedBy = "ACCEPT_RECORD_MISSING"
		}
		if x.SequenceIndex < 1 || x.SequenceIndex > MaxSteps || x.TokenID == "" {
			return
		}
		p.tokens[x.TokenID] = x.SequenceIndex
		p.issued[x.SequenceIndex] = true
	case "GATE_DECISION":
		if !current || (x.Attributed != nil && !*x.Attributed) {
			return
		}
		if x.Fatal && (x.Decision == "BLOCK" || x.Decision == "ESTOP") {
			p.end("GATE_FATAL", r)
			return
		}
		accepted, err := x.Record.Validate(x.Decision, x.StepComplete, x.Fatal, x.Attributed)
		if err != nil {
			p.completionIssue = "COMPLETION_RECORD_UNSUPPORTED"
			return
		}
		if x.JournalV < completion.JournalVersion && x.Decision == "PERMIT" && x.StepComplete {
			if _, known := p.tokens[x.TokenID]; !known {
				return
			}
			p.completionIssue = "LEGACY_COMPLETION_UNDETERMINED"
			return
		}
		if accepted && p.state == "ACCEPTED" {
			index, ok := p.tokens[x.TokenID]
			if !ok || index != *x.ConsumedSequenceIndex {
				p.completionIssue = "COMPLETION_RECORD_INCONSISTENT"
				return
			}
			p.completed[index] = true
		}
	case "CHAIN_REVOKED":
		if current && (x.Kind == "CHAIN_CANCELLED" || x.Kind == "CHAIN_REVOKED") {
			p.end(x.Kind, r)
		}
	case "LEASE_RECONCILED":
		if current && x.Verdict == "OVER_LEASE" {
			p.end("OVER_LEASE", r)
		}
	}
}

type ledgerState struct {
	verdict  LedgerVerdict
	fold     *LedgerFold
	at       time.Time
	chain    string // CHAIN_OK | CHAIN_ERROR | VERIFYING | UNVERIFIED | ABSENT | "" (no index)
	overflow bool
}

func chainState(v LedgerVerdict) string {
	switch v.State {
	case "ok":
		return "CHAIN_OK"
	case "chain_error":
		return "CHAIN_ERROR"
	case "absent":
		return "ABSENT"
	}
	return "UNVERIFIED"
}

// LedgerVerifying says the index is open and its first verification has not
// ended. It never replaces a verdict that was already published.
func (c *Collector) LedgerVerifying() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ledger == nil || c.ledger.chain == "" {
		c.ledger = &ledgerState{chain: "VERIFYING", at: c.now()}
	}
}

// PublishLedger installs the reading of one finished walk. A walk whose index
// transaction did not commit leaves nothing to show: the earlier reading is
// dropped rather than presented as the present one.
func (c *Collector) PublishLedger(f *LedgerFold, v LedgerVerdict) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trackAll()
	defer c.trackAll()
	now := c.now()
	c.settleLedger(now)
	if v.Published && f != nil && v.State == "unverified" && v.Code == "SOURCE_UNSTABLE" && c.ledger != nil && c.ledger.chain != "" && c.ledger.chain != "VERIFYING" {
		if c.reread == nil {
			c.reread = &ledgerState{verdict: v, fold: f, at: now, chain: chainState(v), overflow: c.ledger.overflow}
		}
		return
	}
	c.reread = nil
	id := c.ledgerProvider()
	for k := range c.unresolved {
		if len(k) > 7 && k[:7] == "ledger:" {
			delete(c.unresolved, k)
		}
	}
	if !v.Published || f == nil {
		c.ledger = &ledgerState{at: now}
		return
	}
	if v.Code != "" && !ledgerCode.MatchString(v.Code) {
		v.Code = "CHAIN_ERROR_OTHER"
	}
	s := &ledgerState{verdict: v, fold: f, at: now, chain: chainState(v)}
	if c.ledger != nil {
		s.overflow = c.ledger.overflow
	}
	c.ledger = s
	if id == "" || s.chain != "CHAIN_OK" {
		return
	}
	names := make([]string, 0, len(f.unknown))
	for name := range f.unknown {
		names = append(names, name)
	}
	sort.Strings(names)
	over := f.overflow
	for _, name := range names {
		if len(c.unresolved) >= MaxUnresolved {
			over = true
			break
		}
		hash := robotid.Hash16(name)
		c.unresolved["ledger:"+hash] = unknown{Unresolved{id, hash, "LEDGER_ROBOT_NOT_DECLARED", now.UnixMilli()}, now}
	}
	if over && !s.overflow {
		c.overflow++
	}
	s.overflow = over
}

// settleLedger shows a reading that waited for its replacement in vain.
func (c *Collector) settleLedger(now time.Time) {
	if c.reread != nil && (now.Sub(c.reread.at) >= LedgerRereadWindow || now.Before(c.reread.at)) {
		c.ledger, c.reread = c.reread, nil
	}
}

// HasLedgerSource reports whether the source map declares the ledger source.
func (c *Collector) HasLedgerSource() bool { return c.ledgerProvider() != "" }
func (c *Collector) ledgerProvider() string {
	for _, p := range c.config.Providers {
		if p.Kind == LedgerKind {
			return p.ProviderID
		}
	}
	return ""
}

// ledgerFacets is what the ledger source says about one robot, read from
// memory only: a request never opens the index or the ledger.
func (c *Collector) ledgerFacets(p Provider, robot string, now time.Time) (string, map[string]Facet) {
	c.settleLedger(now)
	s := c.ledger
	health := "UNKNOWN"
	quality, reason, receipt := "UNKNOWN", "INDEX_UNAVAILABLE", "UNKNOWN"
	var age *int64
	if s != nil && s.chain != "" {
		elapsed := now.Sub(s.at)
		age = ptr(elapsed.Milliseconds())
		reason = s.chain
		switch {
		case elapsed < 0:
			reason = "CLOCK_UNCERTAIN"
		case s.chain == "VERIFYING":
		case elapsed >= LedgerFreshness:
			health, receipt = "STALE", "STALE"
			if s.chain == "CHAIN_OK" {
				quality, reason = "STALE", "VERIFICATION_OLD"
			}
		default:
			health, receipt = "CONNECTED", "FRESH"
			if s.chain == "CHAIN_OK" {
				quality, reason = "STALE", "INDEX_BEHIND"
				if s.verdict.LagRecords != nil && *s.verdict.LagRecords == 0 {
					quality, reason = "FRESH", "VERIFIED_FRONTIER_CURRENT"
				}
			}
		}
	} else if s != nil {
		health = "INDEX_UNAVAILABLE"
	}
	out := map[string]Facet{}
	for kind := range legacyKinds {
		out[kind] = Facet{SourceRef: p.ProviderID, Trust: p.Trust, FreshnessBasis: "receiver_only", Quality: "UNSUPPORTED", Reason: "NO_CONFIGURED_FEED", ReceiptQuality: "UNKNOWN"}
	}
	for _, kind := range p.Allowed {
		f := Facet{SourceRef: p.ProviderID, Trust: p.Trust, FreshnessBasis: LedgerBasis, Quality: quality, Reason: reason, AgeMS: age, ReceiptQuality: receipt}
		if s == nil || s.chain == "" {
			out[kind] = f
			continue
		}
		f.Received = ptr(s.at.UnixMilli())
		var fold *planFold
		// Only the verified prefix may be shown; a walk that was rolled back
		// verified nothing.
		if s.fold != nil && s.verdict.VerifiedSeq > 0 {
			if fold = s.fold.robots[robot]; fold != nil && fold.lastSeq > s.verdict.VerifiedSeq {
				fold = nil
			}
		}
		if kind == "ledger" {
			f.Value = &Value{State: s.chain}
			d := &LedgerDetail{ChainState: s.chain, ErrorCode: s.verdict.Code, VerifiedThrough: strconv.FormatInt(s.verdict.VerifiedSeq, 10), VerifiedAtMS: s.at.UnixMilli(), LagRecords: s.verdict.LagRecords}
			if s.chain == "VERIFYING" {
				d.VerifiedAtMS = 0
			}
			if fold != nil {
				last := fold.last
				d.LastRecord = &last
				f.Observed = ptr(last.MS)
			}
			f.Ledger = d
		} else {
			// An unverified ledger says nothing about a plan.
			f.Value = &Value{State: "UNKNOWN"}
			if s.chain == "CHAIN_OK" {
				if fold == nil || fold.state == "" {
					f.Reason = "NO_PLAN_RECORD"
					f.Quality = "UNKNOWN"
				} else {
					f.Value.State = fold.state
					if fold.complete() {
						f.Value.State = "COMPLETED"
					}
					d := &PlanDetail{StepsIssued: len(fold.issued), StepsCompleted: len(fold.completed), RejectCode: fold.rejectCode, EndedBy: fold.endedBy, RecordSeq: strconv.FormatInt(fold.seq, 10), RecordMS: int64(fold.ms)}
					if fold.total > 0 {
						d.StepsTotal = ptr(fold.total)
					}
					if identifier.MatchString(fold.planID) {
						d.PlanID = fold.planID
					}
					if identifier.MatchString(fold.chainID) {
						d.ChainID = fold.chainID
					}
					if fold.completionIssue != "" && fold.state == "ACCEPTED" {
						f.Value.State = "UNKNOWN"
						f.Reason, f.Quality = fold.completionIssue, "UNKNOWN"
					}
					if fold.state == "UNKNOWN" {
						f.Reason = fold.endedBy
						f.Quality = "UNKNOWN"
					}
					f.Observed = ptr(int64(fold.ms))
					f.Plan = d
				}
			}
		}
		out[kind] = f
	}
	return health, out
}
