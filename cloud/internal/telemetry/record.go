// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package telemetry is the testable core of pail_telemetryd (implementation contract D1):
// record shapes, the JSONL store, signature verdicts, duplicate marking, gap
// judgment and the query engine. cmd/pail_telemetryd is wiring only.
//
// Telemetry is observation material, never the canonical record — the verdict
// canon stays in the blackbox/anchor chain . Nothing in this
// package may feed an authorization decision.
package telemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Record is the superset read shape for one JSONL line. Writers emit the
// per-kind subset (a tick line carries no burst fields); readers parse into
// this and dispatch on Kind.
type Record struct {
	V    int    `json:"v"`
	Kind string `json:"kind"` // "tick" | "burst"
	Ms   uint64 `json:"ms"`

	// Burst-only fields. No omitempty: this shape is only ever marshalled as
	// a query-result row, which is always a burst, and seq 0 / reason 0 are
	// real values — dropping them would make "zero" and "absent" share bytes.
	// (Tick lines are written via MarshalTick, never via this struct.)
	Seq         uint32 `json:"seq"`
	Event       string `json:"event"`
	ReasonValue uint16 `json:"reason_value"`
	Robot       string `json:"robot"` // hex robot_id_hash[:16]
	Token       string `json:"token"` // hex bytes 32:48 (correlation hint only)
	Sig         string `json:"sig"`   // SigOK | SigBad | SigUnverifiable
	Dup         *bool  `json:"dup"`   // pointer: nil on ticks, always present on bursts
	Raw         string `json:"raw"`   // hex of the 120B packet, re-verification material

	// Permit-mirror-only fields (kind "permit", implementation contract D11). Same
	// no-omitempty rule, and here it carries weight: deadman_window_ms 0 means
	// "the bridge never reported its window" and tick_ms 0 means "the mirror
	// never declared its period" — both are statements, not absences.
	MirrorSeq   uint32 `json:"mirror_seq"`
	PermitSeq   uint32 `json:"permit_seq"`
	PermitAgeMs uint32 `json:"permit_age_ms"`     // PermitAgeNever = 부팅 후 무수신
	DeadmanMs   uint16 `json:"deadman_window_ms"` // 0 = 미관찰
	TickMs      uint16 `json:"tick_ms"`           // 0 = 미선언
	Mode        string `json:"mode"`              // "" 미관찰 | enforce | observe
}

const (
	KindTick   = "tick"
	KindBurst  = "burst"
	KindPermit = "permit"

	// Sig verdict is 3-valued (implementation contract D1): folding it to a bool makes
	// "could not check" arrive wearing the same value as "checked and fine"
	// (H-B2).
	SigOK           = "ok"
	SigBad          = "bad"
	SigUnverifiable = "unverifiable"
)

// ParseLine decodes one JSONL line. The version check runs before any field
// strictness (OB2 convention): a future-version line must fail as "unsupported
// version", not as "unknown field", or the migration hint is never printed.
func ParseLine(b []byte) (Record, error) {
	var probe struct {
		V *int `json:"v"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return Record{}, err
	}
	if probe.V == nil {
		return Record{}, errors.New("record missing v")
	}
	if *probe.V != 1 {
		return Record{}, fmt.Errorf("unsupported record version %d", *probe.V)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Record
	if err := dec.Decode(&r); err != nil {
		return Record{}, err
	}
	switch r.Kind {
	case KindTick, KindBurst, KindPermit:
	default:
		return Record{}, fmt.Errorf("unknown record kind %q", r.Kind)
	}
	return r, nil
}

// MarshalJSON makes a Record's JSON identical to its JSONL line — one wire
// shape per kind, chosen by Kind (DB-4, implementation contract D9). Without this the query
// API marshalled the whole struct, so a burst row carried
// `"deadman_window_ms":0,"mode":""` — bytes that on a permit row MEAN
// "unobserved". A field that has no meaning on this kind must not arrive
// wearing a value that means something on another (H-B2). Freezing v1 on the
// plain struct shape would have frozen that.
//
// Tick rows never reach the query surface (Query filters bursts; permits go
// through PermitStates), but the dispatch is total so a future caller cannot
// fall back to the mixed shape silently.
func (r Record) MarshalJSON() ([]byte, error) {
	switch r.Kind {
	case KindTick:
		return MarshalTick(r.Ms)
	case KindBurst:
		return r.MarshalBurst()
	case KindPermit:
		return r.MarshalPermit()
	}
	return nil, fmt.Errorf("MarshalJSON on unknown record kind %q", r.Kind)
}

// MarshalTick emits the minimal tick line: {"v":1,"kind":"tick","ms":N}.
func MarshalTick(ms uint64) ([]byte, error) {
	return json.Marshal(struct {
		V    int    `json:"v"`
		Kind string `json:"kind"`
		Ms   uint64 `json:"ms"`
	}{1, KindTick, ms})
}

// MarshalBurst emits a burst line. Dup is always present on burst lines
// ("dup":false is a statement, not a default — its absence would be
// indistinguishable from "nobody looked").
func (r Record) MarshalBurst() ([]byte, error) {
	if r.Kind != KindBurst {
		return nil, fmt.Errorf("MarshalBurst on kind %q", r.Kind)
	}
	if r.Dup == nil {
		return nil, errors.New("burst record without a dup statement")
	}
	return json.Marshal(struct {
		V           int    `json:"v"`
		Kind        string `json:"kind"`
		Ms          uint64 `json:"ms"`
		Seq         uint32 `json:"seq"`
		Event       string `json:"event"`
		ReasonValue uint16 `json:"reason_value"`
		Robot       string `json:"robot"`
		Token       string `json:"token"`
		Sig         string `json:"sig"`
		Dup         bool   `json:"dup"`
		Raw         string `json:"raw"`
	}{1, KindBurst, r.Ms, r.Seq, r.Event, r.ReasonValue, r.Robot, r.Token, r.Sig, *r.Dup, r.Raw})
}

// MarshalPermit emits a permit-mirror line. Sig is written like a burst's:
// the mirror's own attestation verdict travels with the row, so a reader can
// tell "this robot was allowed" from "someone unverified said so".
func (r Record) MarshalPermit() ([]byte, error) {
	if r.Kind != KindPermit {
		return nil, fmt.Errorf("MarshalPermit on kind %q", r.Kind)
	}
	return json.Marshal(struct {
		V           int    `json:"v"`
		Kind        string `json:"kind"`
		Ms          uint64 `json:"ms"`
		Robot       string `json:"robot"`
		Sig         string `json:"sig"`
		Mode        string `json:"mode"`
		TickMs      uint16 `json:"tick_ms"`
		PermitAgeMs uint32 `json:"permit_age_ms"`
		DeadmanMs   uint16 `json:"deadman_window_ms"`
		PermitSeq   uint32 `json:"permit_seq"`
		MirrorSeq   uint32 `json:"mirror_seq"`
		Raw         string `json:"raw"`
	}{1, KindPermit, r.Ms, r.Robot, r.Sig, r.Mode, r.TickMs, r.PermitAgeMs,
		r.DeadmanMs, r.PermitSeq, r.MirrorSeq, r.Raw})
}
