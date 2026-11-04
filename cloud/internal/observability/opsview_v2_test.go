// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func v2provider(kinds ...string) Provider {
	p := provider("one", "robot-1", dep)
	p.Allowed = kinds
	return p
}

// v2clock is the collector clock of the running test: a producer stamps its
// record with the present, as the observer does.
var v2clock *time.Time

func v2fixture(t *testing.T, p Provider) (*Collector, *time.Time) {
	c, now := fixture(t, p)
	v2clock = now
	return c, now
}
func v2event(p Provider, kind, state string, seq int) Event {
	ms := v2clock.UnixMilli()
	return Event{SchemaVersion: 2, DeploymentID: p.DeploymentID, RobotID: p.RobotID, Identity: p.Identity, Owner: p.Owner, RunID: p.RunID, Kind: kind, Producer: boot, Stream: p.StreamID, Seq: strconv.Itoa(seq), Observed: &ms, ClockID: boot, MonoNS: "1905336045613083", Value: Value{State: state}}
}
func alive(p Provider, seq int) Event {
	e := v2event(p, "liveness", "ALIVE", seq)
	e.Value.Component = "adapter"
	return e
}
func one(c *Collector, kind string) (Facet, bool) {
	f, ok := c.Snapshot().Robots[0].Sources[0].Facets[kind]
	return f, ok
}
func intp(v int) *int { return &v }

// T21: a version 1 record is accepted exactly as before, and cannot carry
// anything version 2 added.
func TestOpsviewVersion1StillAccepted(t *testing.T) {
	p := v2provider("gate", "permit", "liveness")
	c, _ := v2fixture(t, p)
	send(t, c, p, "1")
	send(t, c, p, "2")
	if f := facet(c); f.Quality != "FRESH" || f.Value.State != "PERMIT" {
		t.Fatal(f)
	}
	for name, change := range map[string]func(*Event){
		"mono":      func(e *Event) { e.MonoNS = "5" },
		"component": func(e *Event) { e.Value.Component = "adapter" },
		"steps": func(e *Event) {
			e.Kind = "permit"
			e.Value = Value{State: "RECEIVED", StepIndex: intp(1), StepCount: intp(2)}
		},
		"liveness": func(e *Event) { e.Kind = "liveness"; e.Value = Value{State: "ALIVE"} },
	} {
		e := event(p, "3")
		change(&e)
		if err := c.Observe(p.ProviderID, e); err == nil || err.Error() != "EVENT_SCHEMA" {
			t.Fatal(name, err)
		}
	}
	for _, version := range []int{0, 3, -1} {
		e := event(p, "3")
		e.SchemaVersion = version
		if err := c.Observe(p.ProviderID, e); err == nil || err.Error() != "EVENT_SCHEMA" {
			t.Fatal(version, err)
		}
	}
}

func TestOpsviewVersion2Record(t *testing.T) {
	p := v2provider("gate", "permit", "plan", "liveness")
	c, _ := v2fixture(t, p)
	for i := 1; i <= 2; i++ {
		if e := c.Observe(p.ProviderID, v2event(p, "gate", "PERMIT", i)); e != nil {
			t.Fatal(e)
		}
	}
	if f := facet(c); f.Quality != "FRESH" {
		t.Fatal(f)
	}
	// The monotonic value is optional; without it the record is still a record.
	e := v2event(p, "gate", "BLOCK", 3)
	e.MonoNS = ""
	if err := c.Observe(p.ProviderID, e); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"0", "-1", "01", "1.5", "0x10", " 1", "9223372036854775808", "abc"} {
		e := v2event(p, "gate", "PERMIT", 4)
		e.MonoNS = bad
		if err := c.Observe(p.ProviderID, e); err == nil || err.Error() != "EVENT_MONOTONIC" {
			t.Fatal(bad, err)
		}
	}
	if f := facet(c); f.Value.State != "BLOCK" {
		t.Fatal("a refused record changed the facet", f)
	}
	b, _ := json.Marshal(c.Snapshot())
	if strings.Contains(string(b), "observed_mono_ns") || strings.Contains(string(b), "1905336045613083") {
		t.Fatal("unverified producer clock value reached the response")
	}
}

func TestOpsviewSteps(t *testing.T) {
	p := v2provider("gate", "permit", "plan", "motion")
	c, _ := v2fixture(t, p)
	good := v2event(p, "permit", "RECEIVED", 1)
	good.Value.StepIndex, good.Value.StepCount = intp(2), intp(3)
	if e := c.Observe(p.ProviderID, good); e != nil {
		t.Fatal(e)
	}
	if f, _ := one(c, "permit"); f.Value.StepIndex == nil || *f.Value.StepIndex != 2 || *f.Value.StepCount != 3 {
		t.Fatal(f)
	}
	for name, v := range map[string][2]*int{"index only": {intp(1), nil}, "count only": {nil, intp(1)}, "zero index": {intp(0), intp(3)}, "past the end": {intp(4), intp(3)}, "negative": {intp(-1), intp(3)}, "no steps": {intp(1), intp(0)}, "too many": {intp(1), intp(MaxSteps + 1)}} {
		e := v2event(p, "permit", "RECEIVED", 2)
		e.Value.StepIndex, e.Value.StepCount = v[0], v[1]
		if err := c.Observe(p.ProviderID, e); err == nil || err.Error() != "EVENT_STEP" {
			t.Fatal(name, err)
		}
	}
	e := v2event(p, "gate", "PERMIT", 2)
	e.Value.StepIndex, e.Value.StepCount = intp(1), intp(2)
	if err := c.Observe(p.ProviderID, e); err == nil || err.Error() != "EVENT_STEP" {
		t.Fatal("steps on a gate record", err)
	}
	// A record without steps shows none: the reader must not invent progress.
	plain := v2event(p, "permit", "RECEIVED", 3)
	if e := c.Observe(p.ProviderID, plain); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(c.Snapshot().Robots[0].Sources[0].Facets["permit"])
	if strings.Contains(string(b), "step_") {
		t.Fatal(string(b))
	}
}

// T09 (collector side): ALIVE is the only liveness value. The absence of
// records, not a record, is what turns the facet STALE.
func TestOpsviewLivenessKind(t *testing.T) {
	p := v2provider("gate", "liveness")
	c, now := v2fixture(t, p)
	if f, ok := one(c, "liveness"); !ok || f.Quality != "UNKNOWN" || f.Reason != "NO_OBSERVATION" {
		t.Fatal(f, ok)
	}
	for _, state := range []string{"DEAD", "DOWN", "UNKNOWN", "STOPPED", "alive", "", "OBSERVED"} {
		e := alive(p, 1)
		e.Value.State = state
		if err := c.Observe(p.ProviderID, e); err == nil || err.Error() != "EVENT_VALUE" {
			t.Fatal(state, err)
		}
	}
	for _, component := range []string{"", "gate", "robot", "Adapter", "planner"} {
		e := alive(p, 1)
		e.Value.Component = component
		if err := c.Observe(p.ProviderID, e); err == nil || err.Error() != "EVENT_COMPONENT" {
			t.Fatal(component, err)
		}
	}
	e := v2event(p, "gate", "PERMIT", 1)
	e.Value.Component = "adapter"
	if err := c.Observe(p.ProviderID, e); err == nil || err.Error() != "EVENT_COMPONENT" {
		t.Fatal("component on a gate record", err)
	}
	e = alive(p, 1)
	e.Value.PhysicalStopProven = true
	if err := c.Observe(p.ProviderID, e); err == nil {
		t.Fatal("liveness claimed a physical stop")
	}
	if f, _ := one(c, "liveness"); f.Value != nil {
		t.Fatal("a refused record reached the facet", f)
	}
	for i := 1; i <= 5; i++ {
		if err := c.Observe(p.ProviderID, alive(p, i)); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(time.Second)
	}
	*now = now.Add(-time.Second)
	f, _ := one(c, "liveness")
	if f.Quality != "FRESH" || f.Active == nil || f.Active.State != "ALIVE" || f.Active.Component != "adapter" || f.Trust != "local_self_report" {
		t.Fatal(f)
	}
	*now = now.Add(2999 * time.Millisecond)
	if f, _ = one(c, "liveness"); f.Quality != "FRESH" {
		t.Fatal("before the limit", f)
	}
	*now = now.Add(time.Millisecond)
	if f, _ = one(c, "liveness"); f.Quality != "STALE" || f.Reason != "TTL_EXPIRED" || f.Active != nil || f.Value.State != "ALIVE" {
		t.Fatal("at the limit", f)
	}
	// The observer variant is accepted too.
	e = alive(p, 9)
	e.Value.Component = "observer"
	if err := c.Observe(p.ProviderID, e); err != nil {
		t.Fatal(err)
	}
}

func TestOpsviewLivenessOnlyWhereDeclared(t *testing.T) {
	p := v2provider("gate", "motion", "pose")
	c, _ := v2fixture(t, p)
	if err := c.Observe(p.ProviderID, alive(p, 1)); err == nil || err.Error() != "EVENT_KIND_NOT_ALLOWED" {
		t.Fatal(err)
	}
	if _, ok := one(c, "liveness"); ok {
		t.Fatal("undeclared kind has a facet")
	}
	if n := len(c.Snapshot().Robots[0].Sources[0].Facets); n != 7 {
		t.Fatal("facets", n)
	}
	caps := func(c *Collector) string {
		w := httptest.NewRecorder()
		NewAPI(c).Capabilities(w, httptest.NewRequest("GET", "/v2/observation/capabilities", nil))
		return w.Body.String()
	}
	if s := caps(c); strings.Contains(s, "liveness") {
		t.Fatal(s)
	}
	d, _ := v2fixture(t, v2provider("gate", "liveness"))
	if s := caps(d); !strings.Contains(s, `"management","liveness"]`) {
		t.Fatal(s)
	}
	if n := len(d.Snapshot().Robots[0].Sources[0].Facets); n != 8 {
		t.Fatal("facets", n)
	}
	// Signed legacy providers keep their single kind.
	for _, kind := range []string{"legacy_burst", "legacy_permit"} {
		q := Provider{ProviderID: "x", Kind: kind, DeploymentID: dep, RobotID: "robot-1", Identity: "robot-1", Allowed: []string{"liveness"}, Trust: "verified_signature", Role: "primary"}
		if _, e := New(SourceMap{1, source, dep, []Provider{q}}); e == nil || e.Error() != "SOURCE_MAP_LEGACY" {
			t.Fatal(kind, e)
		}
	}
	all := v2provider("plan", "gate", "permit", "motion", "pose", "liveness")
	if _, e := New(SourceMap{1, source, dep, []Provider{all}}); e != nil {
		t.Fatal(e)
	}
	twice := v2provider("gate", "liveness", "liveness")
	if _, e := New(SourceMap{1, source, dep, []Provider{twice}}); e == nil {
		t.Fatal("duplicate kind accepted")
	}
}

// T03: held, expired, and reports cut off.
func TestOpsviewPermitReport(t *testing.T) {
	p := v2provider("gate", "permit")
	c, now := v2fixture(t, p)
	seq := 0
	report := func(state string) {
		seq++
		e := v2event(p, "permit", state, seq)
		if state == "RECEIVED" {
			e.Value.StepIndex, e.Value.StepCount = intp(1), intp(2)
		}
		if err := c.Observe(p.ProviderID, e); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		report("RECEIVED")
		if i > 0 {
			if f, _ := one(c, "permit"); f.Quality != "FRESH" || f.Active == nil || f.Active.State != "RECEIVED" || f.Trust != "local_self_report" {
				t.Fatal(i, f)
			}
		}
		*now = now.Add(time.Second)
	}
	report("EXPIRED")
	if f, _ := one(c, "permit"); f.Quality != "FRESH" || f.Active.State != "EXPIRED" {
		t.Fatal(f)
	}
	// One EXPIRED record and then silence: after the limit it is an old
	// statement, not a current "no permit".
	*now = now.Add(3 * time.Second)
	if f, _ := one(c, "permit"); f.Quality != "STALE" || f.Active != nil || f.Value.State != "EXPIRED" {
		t.Fatal(f)
	}
	report("RECEIVED")
	*now = now.Add(time.Second)
	report("RECEIVED")
	*now = now.Add(2999 * time.Millisecond)
	if f, _ := one(c, "permit"); f.Quality != "FRESH" {
		t.Fatal("reports cut, before the limit", f)
	}
	*now = now.Add(time.Millisecond)
	if f, _ := one(c, "permit"); f.Quality != "STALE" || f.Reason != "TTL_EXPIRED" || f.Active != nil {
		t.Fatal("reports cut, at the limit", f)
	}
	if err := c.Observe(p.ProviderID, v2event(p, "permit", "HELD", 99)); err == nil || err.Error() != "EVENT_VALUE" {
		t.Fatal("a new permit value was accepted", err)
	}
}

// The file reader takes both record versions from one file.
func TestOpsviewTailReadsBothVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observation.jsonl")
	if e := os.WriteFile(path, nil, 0o644); e != nil {
		t.Fatal(e)
	}
	p := v2provider("gate", "liveness")
	p.PathRef = path
	c, _ := v2fixture(t, p)
	tail, e := NewTail(c, p)
	if e != nil {
		t.Fatal(e)
	}
	defer tail.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	defer f.Close()
	for i, ev := range []Event{event(p, "1"), v2event(p, "gate", "BLOCK", 2), alive(p, 3), alive(p, 4)} {
		if i == 3 {
			f.WriteString(`{"schema_version":2,"kind":"liveness","value":{"state":"ALIVE","component":"adapter","physical_stop_proven":false,"note":"x"}}` + "\n")
		}
		b, _ := json.Marshal(ev)
		f.Write(append(b, '\n'))
	}
	if e := tail.Poll(); e != nil {
		t.Fatal(e)
	}
	s := c.Snapshot().Robots[0].Sources[0]
	if s.Facets["gate"].Value.State != "BLOCK" || s.Facets["liveness"].Quality != "FRESH" {
		t.Fatal(s)
	}
	if s.Errors != 1 || s.LastError != "INVALID" {
		t.Fatal("unknown field was not refused", s.Errors, s.LastError)
	}
}
