// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/glowfly/pail/services/pkg/robotid"
	"github.com/google/uuid"
)

var ttls = map[string]time.Duration{"plan": 3 * time.Second, "gate": 3 * time.Second, "permit": 3 * time.Second, "motion": time.Second, "pose": time.Second, "ledger": 30 * time.Second, "management": 300 * time.Second, "liveness": 3 * time.Second}

// legacyKinds is the facet set every source row carries. A kind added later
// (liveness) appears only on a provider that declares it, so a source map
// written for the earlier record version keeps its exact response.
var legacyKinds = map[string]bool{"plan": true, "gate": true, "permit": true, "motion": true, "pose": true, "ledger": true, "management": true}

const MaxSteps = 1024

type RobotKey struct {
	DeploymentID string `json:"deployment_id"`
	RobotID      string `json:"robot_id"`
}
type Value struct {
	State              string   `json:"state"`
	LinearMPS          *float64 `json:"linear_mps,omitempty"`
	AngularRPS         *float64 `json:"angular_rps,omitempty"`
	X                  *float64 `json:"x_m,omitempty"`
	Y                  *float64 `json:"y_m,omitempty"`
	Yaw                *float64 `json:"yaw_rad,omitempty"`
	FrameID            string   `json:"frame_id,omitempty"`
	SourceKind         string   `json:"source_kind,omitempty"`
	Component          string   `json:"component,omitempty"`
	StepIndex          *int     `json:"step_index,omitempty"`
	StepCount          *int     `json:"step_count,omitempty"`
	PhysicalStopProven bool     `json:"physical_stop_proven"`
}

// Event is a closed, sanitized adapter contract, not arbitrary JSON payload.
// Trust and receipt times are assigned by the receiver, never by this body.
type Event struct {
	SchemaVersion int    `json:"schema_version"`
	DeploymentID  string `json:"deployment_id"`
	RobotID       string `json:"robot_id"`
	Identity      string `json:"identity"`
	Owner         string `json:"owner"`
	RunID         string `json:"run_id"`
	Kind          string `json:"kind"`
	Producer      string `json:"producer_instance_id"`
	Stream        string `json:"stream_id"`
	Seq           string `json:"producer_seq"`
	Observed      *int64 `json:"observed_at_ms"`
	ClockID       string `json:"clock_id"`
	MonoNS        string `json:"observed_mono_ns,omitempty"`
	Replayed      bool   `json:"replayed"`
	// Challenge (design 15.2): the value the collector gave this producer in the
	// answer to its last upload, echoed in a record made after it. Judged by the
	// collector's own clock; never by the time the robot wrote.
	Challenge string `json:"challenge,omitempty"`
	Value     Value  `json:"value"`
}
type Facet struct {
	SourceRef      string  `json:"source_ref"`
	Trust          string  `json:"trust"`
	FreshnessBasis string  `json:"freshness_basis"`
	Observed       *int64  `json:"observed_at_ms"`
	Received       *int64  `json:"received_at_ms"`
	ClockID        *string `json:"clock_id"`
	Producer       *string `json:"producer_instance_id"`
	Seq            *string `json:"producer_seq"`
	Quality        string  `json:"quality"`
	Reason         string  `json:"reason"`
	AgeMS          *int64  `json:"age_ms"`
	ProducerAgeMS  *int64  `json:"producer_age_ms,omitempty"`
	// AgeUpperMS (challenge_bound): the record was made after the collector issued
	// its challenge, so its age is at most now - issue time. An upper bound, not a
	// measurement of the producer's clock.
	AgeUpperMS     *int64 `json:"age_upper_ms,omitempty"`
	ReceiptQuality string `json:"receipt_quality"`
	Value          *Value `json:"last_observation"`
	Active         *Value `json:"active_observation"`
	// Set by the collector's own ledger source only; never read from a record.
	Plan   *PlanDetail   `json:"plan_detail,omitempty"`
	Ledger *LedgerDetail `json:"ledger_detail,omitempty"`
}
type SourceRow struct {
	ProviderID string           `json:"provider_id"`
	Role       string           `json:"role"`
	Identity   string           `json:"identity"`
	Health     string           `json:"health"`
	Errors     uint64           `json:"error_count"`
	LastError  string           `json:"last_error"`
	Facets     map[string]Facet `json:"facets"`
}
type Robot struct {
	Key             RobotKey    `json:"robot_key"`
	DeploymentKnown bool        `json:"deployment_known"`
	Registration    string      `json:"registration"`
	Quality         string      `json:"quality"`
	Sources         []SourceRow `json:"sources"`
	// Present only when the source map declares a kind the summary reads.
	Summary *Summary `json:"summary,omitempty"`
}
type Unresolved struct {
	ProviderID string `json:"provider_id"`
	RobotHash  string `json:"robot_hash"`
	Reason     string `json:"reason"`
	ReceivedMS int64  `json:"received_at_ms"`
}
type Snapshot struct {
	SchemaVersion   int          `json:"schema_version"`
	DocumentKind    string       `json:"document_kind"`
	SourceID        string       `json:"source_id"`
	Instance        string       `json:"collector_instance_id"`
	DeploymentID    string       `json:"deployment_id"`
	DeploymentKnown bool         `json:"deployment_known"`
	Revision        string       `json:"revision"`
	GeneratedMS     int64        `json:"generated_at_ms"`
	Complete        bool         `json:"complete"`
	Scope           string       `json:"scope"`
	Robots          []Robot      `json:"robots"`
	Unresolved      []Unresolved `json:"unresolved"`
	Overflow        uint64       `json:"unresolved_overflow"`
}
type slot struct {
	facet            Facet
	received         time.Time
	seq              uint64
	producer, stream string
	progress         int
	retired          map[string]bool
	mono             int64
	hasMono          bool
	// challenge_bound: when the collector issued the challenge this record echoed
	issued    time.Time
	hasIssued bool
}
type providerState struct {
	config    Provider
	slots     map[string]*slot
	health    string
	conflict  bool
	contact   time.Time
	errors    uint64
	lastError string
}
type unknown struct {
	row Unresolved
	at  time.Time
}
type Collector struct {
	// push (design 15): the challenges issued per robot, and the issue time of the
	// challenge of the record being observed (set by Push around one observeLocked)
	challenges map[string][]challenge
	pushIssued map[string]time.Time
	mu         sync.Mutex
	config     SourceMap
	instance   string
	providers  map[string]*providerState
	unresolved map[string]unknown
	overflow   uint64
	revision   uint64
	digest     string
	now        func() time.Time
	clockID    string
	clockOK    bool
	mono       func() (int64, bool)
	ledger     *ledgerState
	reread     *ledgerState          // a reading of a ledger that changed under it, not shown yet
	robots     map[RobotKey][]string // provider ids of each declared robot, sorted
	summary    bool
	waiting    map[RobotKey]time.Time // since when row 10's condition holds
}

func New(c SourceMap) (*Collector, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	// Detach installer-owned slices before accepting observations.
	raw, _ := json.Marshal(c)
	json.Unmarshal(raw, &c)
	x := &Collector{config: c, instance: uuid.NewString(), providers: map[string]*providerState{}, unresolved: map[string]unknown{}, now: time.Now, mono: monotonicNS, robots: map[RobotKey][]string{}, waiting: map[RobotKey]time.Time{}}
	x.clockID, x.clockOK = clockIdentityFrom(bootIDPath, timensOffsetsPath)
	for _, p := range c.Providers {
		if p.Kind == LedgerKind {
			continue // not a record stream: it has no slots and accepts no events
		}
		x.providers[p.ProviderID] = &providerState{config: p, slots: map[string]*slot{}, health: "UNKNOWN"}
		key := RobotKey{p.DeploymentID, p.RobotID}
		x.robots[key] = append(x.robots[key], p.ProviderID)
	}
	for _, ids := range x.robots {
		sort.Strings(ids)
	}
	x.summary = summaryDeclared(c)
	return x, nil
}
func ptr[T any](v T) *T { return &v }
func validateEvent(e Event) error {
	if (e.SchemaVersion != 1 && e.SchemaVersion != 2) || !validUUID(e.Producer) || !validUUID(e.Stream) || !identifier.MatchString(e.ClockID) {
		return errors.New("EVENT_SCHEMA")
	}
	n, err := strconv.ParseUint(e.Seq, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != e.Seq {
		return errors.New("EVENT_SEQUENCE")
	}
	if _, ok := ttls[e.Kind]; !ok {
		return errors.New("EVENT_KIND")
	}
	// Version 1 is the closed earlier contract: nothing version 2 added may
	// ride in on a record that calls itself version 1.
	if e.SchemaVersion == 1 && (e.MonoNS != "" || e.Kind == "liveness" || e.Value.Component != "" || e.Value.StepIndex != nil || e.Value.StepCount != nil) {
		return errors.New("EVENT_SCHEMA")
	}
	if e.MonoNS != "" {
		m, err := strconv.ParseUint(e.MonoNS, 10, 63)
		if err != nil || m == 0 || strconv.FormatUint(m, 10) != e.MonoNS {
			return errors.New("EVENT_MONOTONIC")
		}
	}
	allowed := map[string]string{"liveness": "|ALIVE|", "plan": "|ACCEPTED|REJECTED|CANCELLED|COMPLETED|UNKNOWN|", "gate": "|PERMIT|BLOCK|UNKNOWN|", "permit": "|RECEIVED|EXPIRED|UNKNOWN|", "motion": "|OBSERVED_MOVING|OBSERVED_ZERO|UNKNOWN|", "pose": "|OBSERVED|UNKNOWN|", "ledger": "|CHAIN_OK|CHAIN_ERROR|ABSENT|VERIFYING|UNVERIFIED|", "management": "|OBSERVED|UNKNOWN|"}
	if !containsState(allowed[e.Kind], e.Value.State) {
		return errors.New("EVENT_VALUE")
	}
	for _, v := range []*float64{e.Value.LinearMPS, e.Value.AngularRPS, e.Value.X, e.Value.Y, e.Value.Yaw} {
		if v != nil && (math.IsNaN(*v) || math.IsInf(*v, 0)) {
			return errors.New("EVENT_NONFINITE")
		}
	}
	if e.Value.PhysicalStopProven || len(e.Value.FrameID) > 128 || len(e.Value.SourceKind) > 64 || (e.Observed != nil && (*e.Observed < 0 || *e.Observed > 9007199254740991)) {
		return errors.New("EVENT_VALUE")
	}
	// A liveness record names who answered; there is no value for "not alive":
	// a component that stopped cannot say so, the missing record is the signal.
	if (e.Kind == "liveness") != (e.Value.Component != "") || (e.Kind == "liveness" && e.Value.Component != "adapter" && e.Value.Component != "observer") {
		return errors.New("EVENT_COMPONENT")
	}
	if (e.Value.StepIndex == nil) != (e.Value.StepCount == nil) {
		return errors.New("EVENT_STEP")
	}
	if e.Value.StepIndex != nil && ((e.Kind != "permit" && e.Kind != "plan") || *e.Value.StepCount < 1 || *e.Value.StepCount > MaxSteps || *e.Value.StepIndex < 1 || *e.Value.StepIndex > *e.Value.StepCount) {
		return errors.New("EVENT_STEP")
	}
	if e.Kind == "motion" || e.Kind == "pose" {
		if !identifier.MatchString(e.Value.FrameID) || (e.Value.SourceKind != "simulation_applied_velocity" && e.Value.SourceKind != "wheel_odometry" && e.Value.SourceKind != "map_localization") {
			return errors.New("EVENT_FRAME")
		}
	}
	return nil
}
func containsState(list, s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i+len(s)+2 <= len(list); i++ {
		if list[i:i+len(s)+2] == "|"+s+"|" {
			return true
		}
	}
	return false
}
func (c *Collector) Fault(id, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.providers[id]; p != nil {
		p.health = reason
		if reason != "LIVE_BARRIER_WAIT" {
			p.errors++
			p.lastError = reason
		}
	}
}
func (c *Collector) Observe(id string, e Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observeLocked(id, e, c.now())
}

func (c *Collector) observeLocked(id string, e Event, now time.Time) error {
	p := c.providers[id]
	if p == nil {
		return errors.New("UNKNOWN_PROVIDER")
	}
	key := RobotKey{p.config.DeploymentID, p.config.RobotID}
	c.track(key)
	defer c.track(key)
	if err := validateEvent(e); err != nil {
		p.health = "INVALID"
		return err
	}
	// Serialize once to detach all caller-owned pointers and enforce event bytes.
	b, err := json.Marshal(e)
	if err != nil || len(b) > MaxEvent {
		p.health = "INVALID"
		return errors.New("EVENT_OVERSIZE")
	}
	json.Unmarshal(b, &e)
	if e.Kind == "" && e.Challenge != "" {
		return errors.New("EVENT_SCHEMA")
	}
	if e.DeploymentID != p.config.DeploymentID || e.RobotID != p.config.RobotID || e.Identity != p.config.Identity || e.Owner != p.config.Owner || e.RunID != p.config.RunID || e.Stream != p.config.StreamID {
		p.conflict = true
		p.health = "CONFLICT"
		return errors.New("SOURCE_IDENTITY_CONFLICT")
	}
	permitted := false
	for _, k := range p.config.Allowed {
		if e.Kind == k {
			permitted = true
		}
	}
	if !permitted {
		p.health = "INVALID"
		return errors.New("EVENT_KIND_NOT_ALLOWED")
	}
	p.health = "CONNECTED"
	p.contact = now
	if e.Replayed {
		return nil
	}
	s := p.slots[e.Kind]
	if s == nil {
		s = &slot{retired: map[string]bool{}}
		p.slots[e.Kind] = s
	}
	n, _ := strconv.ParseUint(e.Seq, 10, 64)
	generation := e.Producer + "/" + e.Stream
	if s.retired[generation] {
		return errors.New("RETIRED_PRODUCER")
	}
	if s.producer == e.Producer && s.stream == e.Stream && s.progress > 0 && n <= s.seq {
		return nil
	}
	if s.producer != e.Producer || s.stream != e.Stream {
		if s.producer != "" {
			if len(s.retired) >= 64 {
				p.health = "GENERATION_LIMIT"
				return errors.New("GENERATION_LIMIT")
			}
			s.retired[s.producer+"/"+s.stream] = true
		}
		s.progress = 0
	}
	s.progress++
	s.seq = n
	s.producer = e.Producer
	s.stream = e.Stream
	s.received = now
	s.mono, s.hasMono = 0, false
	if m, err := strconv.ParseInt(e.MonoNS, 10, 64); err == nil && e.MonoNS != "" {
		s.mono, s.hasMono = m, true
	}
	// a challenge the collector itself issued binds this record to the moment of
	// issue; the caller (Push) verified it and passes the time through the event
	s.issued, s.hasIssued = time.Time{}, false
	if issued := c.issuedAt(e); !issued.IsZero() {
		s.issued, s.hasIssued = issued, true
	}
	s.facet = Facet{SourceRef: id, Trust: p.config.Trust, FreshnessBasis: "receiver_only", Observed: e.Observed, Received: ptr(now.UnixMilli()), ClockID: ptr(e.ClockID), Producer: ptr(e.Producer), Seq: ptr(e.Seq), Quality: "UNKNOWN", Reason: "PRODUCER_CLOCK_NOT_BOUND", Value: &e.Value}
	if e.Observed != nil && *e.Observed > now.UnixMilli() {
		s.facet.Reason = "CLOCK_UNCERTAIN"
	} else if e.Observed != nil && now.UnixMilli()-*e.Observed >= ttls[e.Kind].Milliseconds() {
		s.facet.Reason = "OBSERVATION_OLD"
	}
	return nil
}

// ObserveLegacy consumes the existing verified dispatcher, never reparses the
// wire. A role signature over a hash is NOT per-robot identity or producer age.
func (c *Collector) ObserveLegacy(kind, hash string, seq uint32, verified, duplicate bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	matched := false
	for id, p := range c.providers {
		if p.config.Kind != kind {
			continue
		}
		if robotid.Hash16(p.config.RobotID) != hash {
			continue
		}
		matched = true
		if !verified {
			p.health = "INVALID"
			continue
		}
		p.health = "CONNECTED"
		p.contact = now
		facet := p.config.Allowed[0]
		s := p.slots[facet]
		if s == nil {
			s = &slot{}
			p.slots[facet] = s
		}
		if duplicate || (s.progress > 0 && (uint32(seq-uint32(s.seq)) == 0 || uint32(seq-uint32(s.seq)) >= 1<<31)) {
			continue
		}
		s.progress++
		s.seq = uint64(seq)
		s.received = now
		s.facet = Facet{SourceRef: id, Trust: "verified_signature", FreshnessBasis: "receiver_only", Received: ptr(now.UnixMilli()), Quality: "UNKNOWN", Reason: "LEGACY_NO_PRODUCER_EPOCH_OR_ROBOT_KEY_BINDING", Value: &Value{State: "RECEIVED"}}
	}
	if !matched && verified {
		c.expireUnknown(now)
		if len(hash) != 32 {
			return
		}
		if _, e := hex.DecodeString(hash); e != nil {
			return
		}
		key := kind + ":" + hash
		if _, ok := c.unresolved[key]; !ok && len(c.unresolved) >= MaxUnresolved {
			c.overflow++
			return
		}
		c.unresolved[key] = unknown{Unresolved{kind, hash, "UNRESOLVED_HASH", now.UnixMilli()}, now}
	}
}
func (c *Collector) expireUnknown(now time.Time) {
	for k, v := range c.unresolved {
		if now.Sub(v.at) >= 24*time.Hour {
			delete(c.unresolved, k)
		}
	}
}
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.expireUnknown(now)
	out := Snapshot{SchemaVersion: 1, DocumentKind: "RobotObservationSnapshot", SourceID: c.config.SourceID, Instance: c.instance, DeploymentID: c.config.DeploymentID, DeploymentKnown: c.config.DeploymentID != "", GeneratedMS: now.UnixMilli(), Complete: true, Scope: "configured_collector_sources", Robots: []Robot{}, Unresolved: []Unresolved{}, Overflow: c.overflow}
	for key := range c.robots {
		r := c.robotRow(key, now)
		for _, source := range r.Sources {
			if source.Health != "CONNECTED" {
				out.Complete = false
			}
		}
		if r.Quality == "CONFLICT" {
			out.Complete = false
		}
		if c.summary {
			r.Summary = summarize(r, c.waited(key, r, now))
		}
		out.Robots = append(out.Robots, r)
	}
	sort.Slice(out.Robots, func(i, j int) bool {
		a, b := out.Robots[i].Key, out.Robots[j].Key
		if a.DeploymentID != b.DeploymentID {
			return a.DeploymentID < b.DeploymentID
		}
		return a.RobotID < b.RobotID
	})
	for _, v := range c.unresolved {
		out.Unresolved = append(out.Unresolved, v.row)
	}
	sort.Slice(out.Unresolved, func(i, j int) bool {
		return out.Unresolved[i].ProviderID+out.Unresolved[i].RobotHash < out.Unresolved[j].ProviderID+out.Unresolved[j].RobotHash
	})
	if out.Overflow > 0 {
		out.Complete = false
	}
	// ETags/revisions change on quality transitions, not on polling age alone.
	canonical := out
	canonical.GeneratedMS = 0
	b, _ := json.Marshal(canonical)
	var stable Snapshot
	json.Unmarshal(b, &stable)
	for i := range stable.Robots {
		for j := range stable.Robots[i].Sources {
			for k, f := range stable.Robots[i].Sources[j].Facets {
				f.AgeMS = nil
				f.ProducerAgeMS = nil
				f.AgeUpperMS = nil
				stable.Robots[i].Sources[j].Facets[k] = f
			}
		}
	}
	b, _ = json.Marshal(stable)
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	if c.digest != digest {
		c.revision++
		c.digest = digest
	}
	out.Revision = strconv.FormatUint(c.revision, 10)
	// Return a detached immutable view; callers cannot rewrite future snapshots.
	b, _ = json.Marshal(out)
	json.Unmarshal(b, &out)
	return out
}

// robotRow is everything the configured sources say about one declared robot
// at this moment. It reads memory only.
func (c *Collector) robotRow(key RobotKey, now time.Time) Robot {
	r := Robot{Key: key, DeploymentKnown: key.DeploymentID != "", Registration: "DECLARED_OBSERVATION_ONLY", Quality: "UNKNOWN", Sources: []SourceRow{}}
	identity := ""
	for i, id := range c.robots[key] {
		p := c.providers[id]
		if (i > 0 && identity != p.config.Identity) || p.conflict {
			r.Quality = "CONFLICT"
		}
		identity = p.config.Identity
		r.Sources = append(r.Sources, c.sourceRow(id, p, now))
	}
	for _, p := range c.config.Providers {
		if p.Kind != LedgerKind || key.DeploymentID != c.config.DeploymentID {
			continue
		}
		health, facets := c.ledgerFacets(p, key.RobotID, now)
		r.Sources = append(r.Sources, SourceRow{ProviderID: p.ProviderID, Role: p.Role, Health: health, Facets: facets})
		sort.SliceStable(r.Sources, func(i, j int) bool { return r.Sources[i].ProviderID < r.Sources[j].ProviderID })
	}
	if r.Quality == "CONFLICT" {
		for i := range r.Sources {
			for k, f := range r.Sources[i].Facets {
				f.Quality = "CONFLICT"
				f.Reason = "SOURCE_IDENTITY_CONFLICT"
				f.Active = nil
				r.Sources[i].Facets[k] = f
			}
		}
	}
	return r
}

// sourceRow judges every facet of one record source.
func (c *Collector) sourceRow(id string, p *providerState, now time.Time) SourceRow {
	health := p.health
	if health == "CONNECTED" && (now.Sub(p.contact) < 0 || now.Sub(p.contact) >= 5*time.Second) {
		health = "STALE"
	}
	source := SourceRow{ProviderID: id, Role: p.config.Role, Identity: p.config.Identity, Health: health, Errors: p.errors, LastError: p.lastError, Facets: map[string]Facet{}}
	for kind, ttl := range ttls {
		f := Facet{SourceRef: id, Trust: p.config.Trust, FreshnessBasis: "receiver_only", Quality: "UNSUPPORTED", Reason: "NO_CONFIGURED_FEED", ReceiptQuality: "UNKNOWN"}
		supported := false
		for _, k := range p.config.Allowed {
			if k == kind {
				supported = true
			}
		}
		if !supported && !legacyKinds[kind] {
			continue
		}
		if supported {
			f.Quality = "UNKNOWN"
			f.Reason = "NO_OBSERVATION"
		}
		if s := p.slots[kind]; s != nil {
			f = s.facet
			age := now.Sub(s.received)
			f.AgeMS = ptr(age.Milliseconds())
			f.ReceiptQuality = "FRESH"
			if age < 0 {
				f.Quality = "UNKNOWN"
				f.Reason = "CLOCK_UNCERTAIN"
				f.ReceiptQuality = "UNKNOWN"
			} else if age >= ttl {
				f.Quality = "STALE"
				f.Reason = "TTL_EXPIRED"
				f.ReceiptQuality = "STALE"
			} else if s.progress < 2 && p.config.Kind == "normalized_jsonl" {
				f.Quality = "UNKNOWN"
				f.Reason = "NEW_PRODUCER_BASELINE"
			} else if p.config.ClockBinding == ClockBindingShared {
				c.judgeClock(s, kind, ttl, &f)
			} else if s.hasIssued {
				judgeChallenge(s, kind, ttl, now, &f)
			} else if (p.config.Kind == "normalized_jsonl" || p.config.Kind == PushKind) && kind != "motion" && kind != "pose" && f.Reason != "CLOCK_UNCERTAIN" && f.Reason != "OBSERVATION_OLD" {
				f.Quality = "FRESH"
				f.Reason = "RECEIVER_PROGRESS_ONLY"
			}
			if p.health != "CONNECTED" {
				f.Quality = "UNKNOWN"
				f.Reason = p.health
			}
			if f.Quality == "FRESH" && kind != "plan" && kind != "ledger" {
				f.Active = f.Value
			}
		}
		if p.conflict {
			f.Quality = "CONFLICT"
			f.Reason = "SOURCE_IDENTITY_CONFLICT"
			f.Active = nil
		}
		source.Facets[kind] = f
	}
	return source
}

// judgeClock decides a record of a source that asked for clock binding. The
// request alone binds nothing: the record must name the collector's own clock
// and carry its monotonic time. Only then is its age the producer's age.
func (c *Collector) judgeClock(s *slot, kind string, ttl time.Duration, f *Facet) {
	wall := f.Reason == "CLOCK_UNCERTAIN" || f.Reason == "OBSERVATION_OLD"
	refused := ""
	var age int64
	if !c.clockOK || c.clockID == "" {
		refused = "CLOCK_BINDING_UNAVAILABLE"
	} else if f.ClockID == nil || *f.ClockID != c.clockID {
		refused = "CLOCK_BINDING_MISMATCH"
	} else if !s.hasMono {
		refused = "PRODUCER_CLOCK_NOT_BOUND"
	} else if now, ok := c.mono(); !ok {
		refused = "CLOCK_BINDING_UNAVAILABLE"
	} else {
		age = now - s.mono
		// A record from the future, or one far older than anything a live
		// producer sends, is not evidence of age: the binding is dropped.
		if age < 0 || age > 10*ttl.Nanoseconds() {
			f.Quality = "UNKNOWN"
			f.Reason = "CLOCK_UNCERTAIN"
			return
		}
	}
	if refused != "" {
		if kind == "motion" || kind == "pose" {
			if !wall {
				f.Reason = refused
			}
		} else if !wall {
			// exactly the judgement of a source that asked for nothing
			f.Quality = "FRESH"
			f.Reason = "RECEIVER_PROGRESS_ONLY"
		}
		return
	}
	if wall {
		return
	}
	f.FreshnessBasis = "producer_clock_bound"
	f.ProducerAgeMS = ptr(age / int64(time.Millisecond))
	if age >= ttl.Nanoseconds() {
		f.Quality = "STALE"
		f.Reason = "OBSERVATION_OLD"
		return
	}
	f.Quality = "FRESH"
	f.Reason = "PRODUCER_CLOCK_BOUND"
}

// facetKinds lists the kinds this collector can show: the fixed set, plus a
// later kind only when some configured provider declares it.
func (c *Collector) facetKinds() []string {
	out := []string{"plan", "gate", "permit", "motion", "pose", "ledger", "management"}
	for _, extra := range []string{"liveness"} {
		declared := false
		for _, p := range c.config.Providers {
			for _, k := range p.Allowed {
				if k == extra {
					declared = true
				}
			}
		}
		if declared {
			out = append(out, extra)
		}
	}
	return out
}
