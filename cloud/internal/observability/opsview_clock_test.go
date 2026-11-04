// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The same vector is asserted by the producer's contract test
// (tests/contract/test_opsview_clock_binding.py): both languages must name
// one clock with one string.
const vectorBoot = "0b4c7a3e-5d1f-4e8a-9c2b-7f6e5d4c3b2a"
const vectorZero = "mono-b6581a372205fd61b4421ee9355bba71b4d3fc2bae3f94e4f3a6750f04290892"
const vectorNegative = "mono-bbe95ebe93dae3f8d359a771d958289f102975030c057bcb8948469cc99539b7"
const hashOfUnavailable = "mono-ba691ba042bcedd9a61a36f5969026bc95859dccdc7e47f24e6bce35673baf2f"
const otherClock = "mono-0000000000000000000000000000000000000000000000000000000000000000"

const monoStart = int64(1905336045613083)

type boundClock struct {
	wall *time.Time
	mono int64
	ok   bool
}

func (b *boundClock) advance(d time.Duration) {
	*b.wall = b.wall.Add(d)
	b.mono += d.Nanoseconds()
}

// clockFixture is a collector whose own clock identity is vectorZero.
func clockFixture(t *testing.T, binding string, kinds ...string) (*Collector, Provider, *boundClock) {
	t.Helper()
	p := v2provider(kinds...)
	p.ClockBinding = binding
	c, now := v2fixture(t, p)
	b := &boundClock{wall: now, mono: monoStart, ok: true}
	c.clockID, c.clockOK = vectorZero, true
	c.mono = func() (int64, bool) { return b.mono, b.ok }
	return c, p, b
}

// produced is a record stamped `ago` before the collector's present, on the clock named `clock`.
func produced(p Provider, b *boundClock, kind string, seq int, clock string, ago time.Duration) Event {
	e := v2event(p, kind, "PERMIT", seq)
	switch kind {
	case "motion":
		e.Value = Value{State: "OBSERVED_ZERO", LinearMPS: ptr(0.0), AngularRPS: ptr(0.0), FrameID: "frame", SourceKind: "simulation_applied_velocity"}
	case "pose":
		e.Value = Value{State: "OBSERVED", X: ptr(0.0), Y: ptr(0.0), Yaw: ptr(0.0), FrameID: "frame", SourceKind: "simulation_applied_velocity"}
	}
	e.ClockID = clock
	e.MonoNS = strconv.FormatInt(b.mono-ago.Nanoseconds(), 10)
	return e
}
func observe(t *testing.T, c *Collector, p Provider, e Event) {
	t.Helper()
	if err := c.Observe(p.ProviderID, e); err != nil {
		t.Fatal(err)
	}
}

// two sends a baseline record and the record to be judged.
func two(t *testing.T, c *Collector, p Provider, b *boundClock, kind, clock string, ago time.Duration) Facet {
	t.Helper()
	observe(t, c, p, produced(p, b, kind, 1, clock, ago))
	observe(t, c, p, produced(p, b, kind, 2, clock, ago))
	f, ok := one(c, kind)
	if !ok {
		t.Fatal("no facet", kind)
	}
	return f
}
func unbound(f Facet) bool {
	return f.FreshnessBasis == "receiver_only" && f.ProducerAgeMS == nil
}

func TestOpsviewClockIdentity(t *testing.T) {
	dir := t.TempDir()
	file := func(name, text string) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, []byte(text), 0o600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	boot := file("boot", vectorBoot+"\n")
	for name, c := range map[string]struct{ offsets, want string }{
		"zero":     {"monotonic           0         0\nboottime            0         0\n", vectorZero},
		"negative": {"monotonic      -86400       250\nboottime       -86400       250\n", vectorNegative},
	} {
		got, ok := clockIdentityFrom(boot, file("offsets-"+name, c.offsets))
		if !ok || got != c.want {
			t.Fatal(name, got, ok)
		}
	}
	good := file("good", "monotonic 0 0\n")
	for name, paths := range map[string][2]string{
		"no boot file":       {filepath.Join(dir, "absent"), good},
		"empty boot":         {file("b-empty", "\n"), good},
		"boot is not an id":  {file("b-text", "unavailable\n"), good},
		"no offsets file":    {boot, filepath.Join(dir, "absent")},
		"no monotonic row":   {boot, file("o-none", "boottime 0 0\n")},
		"two monotonic rows": {boot, file("o-two", "monotonic 0 0\nmonotonic 0 0\n")},
		"two fields":         {boot, file("o-short", "monotonic 0\n")},
		"four fields":        {boot, file("o-long", "monotonic 0 0 0\n")},
		"not a number":       {boot, file("o-text", "monotonic zero 0\n")},
		"oversize":           {boot, file("o-big", "monotonic 0 0\n"+string(make([]byte, 5000)))},
	} {
		got, ok := clockIdentityFrom(paths[0], paths[1])
		if ok || got != "" {
			t.Fatal(name, got, ok)
		}
	}
}

// T07: the identity matches, so the age is the producer's age.
func TestOpsviewClockBound(t *testing.T) {
	c, p, b := clockFixture(t, ClockBindingShared, "motion", "pose", "gate")
	for _, kind := range []string{"motion", "pose", "gate"} {
		f := two(t, c, p, b, kind, vectorZero, 200*time.Millisecond)
		if f.Quality != "FRESH" || f.Reason != "PRODUCER_CLOCK_BOUND" || f.FreshnessBasis != "producer_clock_bound" || f.ProducerAgeMS == nil || *f.ProducerAgeMS != 200 || *f.AgeMS != 0 || f.Active == nil {
			t.Fatal(kind, f)
		}
	}
	// the record was already 0.2 s old when it arrived: 0.8 s later it is 1 s old
	b.advance(799 * time.Millisecond)
	if f, _ := one(c, "motion"); f.Quality != "FRESH" || *f.ProducerAgeMS != 999 {
		t.Fatal(f)
	}
	b.advance(time.Millisecond)
	if f, _ := one(c, "motion"); f.Quality != "STALE" || f.Reason != "OBSERVATION_OLD" || f.FreshnessBasis != "producer_clock_bound" || *f.ProducerAgeMS != 1000 || *f.AgeMS != 800 || f.Active != nil {
		t.Fatal("receipt was younger than the record", f)
	}
	if f, _ := one(c, "gate"); f.Quality != "FRESH" || *f.ProducerAgeMS != 1000 {
		t.Fatal("gate keeps its own 3 s", f)
	}
}

// T07: asking for the binding is not the binding.
func TestOpsviewClockDeclarationAloneDoesNotBind(t *testing.T) {
	c, p, b := clockFixture(t, ClockBindingShared, "motion", "pose", "gate")
	for _, kind := range []string{"motion", "pose"} {
		f := two(t, c, p, b, kind, otherClock, 200*time.Millisecond)
		if f.Quality != "UNKNOWN" || f.Reason != "CLOCK_BINDING_MISMATCH" || !unbound(f) || f.Active != nil {
			t.Fatal(kind, f)
		}
	}
	// a kind that was judged by receipt keeps exactly that judgement
	if f := two(t, c, p, b, "gate", otherClock, 200*time.Millisecond); f.Quality != "FRESH" || f.Reason != "RECEIVER_PROGRESS_ONLY" || !unbound(f) {
		t.Fatal(f)
	}
}

// T07: the collector could not read its own identity, or its own clock.
func TestOpsviewClockUnavailable(t *testing.T) {
	for name, breakIt := range map[string]func(*Collector, *boundClock) string{
		"identity unreadable": func(c *Collector, b *boundClock) string { c.clockID, c.clockOK = "", false; return vectorZero },
		"identity empty":      func(c *Collector, b *boundClock) string { c.clockID = ""; return vectorZero },
		// a producer that could not read its identity hashes the word it fell back to
		"both unreadable":  func(c *Collector, b *boundClock) string { c.clockID, c.clockOK = "", false; return hashOfUnavailable },
		"clock unreadable": func(c *Collector, b *boundClock) string { b.ok = false; return vectorZero },
	} {
		c, p, b := clockFixture(t, ClockBindingShared, "motion", "gate")
		clock := breakIt(c, b)
		if f := two(t, c, p, b, "motion", clock, 200*time.Millisecond); f.Quality != "UNKNOWN" || f.Reason != "CLOCK_BINDING_UNAVAILABLE" || !unbound(f) || f.Active != nil {
			t.Fatal(name, f)
		}
		if f := two(t, c, p, b, "gate", clock, 200*time.Millisecond); f.Quality != "FRESH" || f.Reason != "RECEIVER_PROGRESS_ONLY" || !unbound(f) {
			t.Fatal(name, f)
		}
	}
	// the real reader on a machine without the files
	if id, ok := clockIdentityFrom("/nonexistent/boot_id", "/nonexistent/timens_offsets"); ok || id != "" {
		t.Fatal(id, ok)
	}
}

// T07: no declaration, the answer of the earlier version, even for a record
// that names the collector's own clock.
func TestOpsviewClockNotDeclared(t *testing.T) {
	c, p, b := clockFixture(t, "", "motion", "gate")
	if f := two(t, c, p, b, "motion", vectorZero, 200*time.Millisecond); f.Quality != "UNKNOWN" || f.Reason != "PRODUCER_CLOCK_NOT_BOUND" || !unbound(f) || f.Active != nil {
		t.Fatal(f)
	}
	if f := two(t, c, p, b, "gate", vectorZero, 200*time.Millisecond); f.Quality != "FRESH" || f.Reason != "RECEIVER_PROGRESS_ONLY" || !unbound(f) {
		t.Fatal(f)
	}
}

// A record without a monotonic time (version 1, or version 2 without the
// field) has nothing to compare.
func TestOpsviewClockRecordWithoutMonotonicTime(t *testing.T) {
	c, p, b := clockFixture(t, ClockBindingShared, "motion")
	for seq, version := range []int{2, 2, 1, 1} {
		e := produced(p, b, "motion", seq+1, vectorZero, 0)
		e.MonoNS = ""
		e.SchemaVersion = version
		observe(t, c, p, e)
		if seq == 0 {
			continue
		}
		if f, _ := one(c, "motion"); f.Quality != "UNKNOWN" || f.Reason != "PRODUCER_CLOCK_NOT_BOUND" || !unbound(f) {
			t.Fatal(version, f)
		}
	}
	// and a bound record does not lend its time to the next one
	observe(t, c, p, produced(p, b, "motion", 10, vectorZero, 0))
	if f, _ := one(c, "motion"); f.Quality != "FRESH" {
		t.Fatal(f)
	}
	e := produced(p, b, "motion", 11, vectorZero, 0)
	e.MonoNS = ""
	observe(t, c, p, e)
	if f, _ := one(c, "motion"); f.Quality != "UNKNOWN" || !unbound(f) {
		t.Fatal("an earlier monotonic time was reused", f)
	}
}

// T08: a time from the future or from long ago drops the binding.
func TestOpsviewClockFutureAndPast(t *testing.T) {
	for _, kind := range []string{"motion", "pose", "gate"} {
		ttl := ttls[kind]
		for name, c := range map[string]struct {
			ago     time.Duration
			quality string
			reason  string
			bound   bool
		}{
			"one nanosecond ahead": {-time.Nanosecond, "UNKNOWN", "CLOCK_UNCERTAIN", false},
			"one hour ahead":       {-time.Hour, "UNKNOWN", "CLOCK_UNCERTAIN", false},
			"now":                  {0, "FRESH", "PRODUCER_CLOCK_BOUND", true},
			"just inside":          {ttl - time.Nanosecond, "FRESH", "PRODUCER_CLOCK_BOUND", true},
			"at the limit":         {ttl, "STALE", "OBSERVATION_OLD", true},
			"ten limits":           {10 * ttl, "STALE", "OBSERVATION_OLD", true},
			"beyond ten limits":    {10*ttl + time.Nanosecond, "UNKNOWN", "CLOCK_UNCERTAIN", false},
			"one hour old":         {time.Hour, "UNKNOWN", "CLOCK_UNCERTAIN", false},
		} {
			x, p, b := clockFixture(t, ClockBindingShared, "motion", "pose", "gate")
			f := two(t, x, p, b, kind, vectorZero, c.ago)
			if f.Quality != c.quality || f.Reason != c.reason || unbound(f) == c.bound || (f.Active != nil) != (c.quality == "FRESH") {
				t.Fatal(kind, name, f)
			}
		}
	}
}

// The clock the collector compares with never replaces the receipt rules.
func TestOpsviewClockKeepsReceiptRules(t *testing.T) {
	c, p, b := clockFixture(t, ClockBindingShared, "motion")
	observe(t, c, p, produced(p, b, "motion", 1, vectorZero, 0))
	if f, _ := one(c, "motion"); f.Quality != "UNKNOWN" || f.Reason != "NEW_PRODUCER_BASELINE" || !unbound(f) {
		t.Fatal("first record of a producer", f)
	}
	observe(t, c, p, produced(p, b, "motion", 2, vectorZero, 0))
	first := c.Snapshot().Revision
	b.advance(300 * time.Millisecond)
	if again := c.Snapshot().Revision; again != first {
		t.Fatal("age alone changed the revision", first, again)
	}
	// wall time of the record in the future: the earlier rule stays in force
	e := produced(p, b, "motion", 3, vectorZero, 0)
	e.Observed = ptr(b.wall.Add(time.Hour).UnixMilli())
	observe(t, c, p, e)
	if f, _ := one(c, "motion"); f.Quality != "UNKNOWN" || f.Reason != "CLOCK_UNCERTAIN" || !unbound(f) {
		t.Fatal(f)
	}
	observe(t, c, p, produced(p, b, "motion", 4, vectorZero, 0))
	// the collector's wall clock stepped, its monotonic clock did not: receipt age is what the
	// earlier rule measures, and it ends the record
	*b.wall = b.wall.Add(time.Second)
	if f, _ := one(c, "motion"); f.Quality != "STALE" || f.Reason != "TTL_EXPIRED" || !unbound(f) {
		t.Fatal(f)
	}
}

func TestOpsviewClockSourceMap(t *testing.T) {
	ok := v2provider("motion")
	ok.ClockBinding = ClockBindingShared
	if e := (SourceMap{1, source, dep, []Provider{ok}}).Validate(); e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{"shared_kernel", "SHARED_KERNEL_MONOTONIC", "true", " shared_kernel_monotonic", "ntp"} {
		p := v2provider("motion")
		p.ClockBinding = value
		if e := (SourceMap{1, source, dep, []Provider{p}}).Validate(); e == nil || e.Error() != "SOURCE_MAP_CLOCK_BINDING" {
			t.Fatal(value, e)
		}
	}
	for _, kind := range []string{"legacy_burst", "legacy_permit"} {
		facet := map[string]string{"legacy_burst": "gate", "legacy_permit": "permit"}[kind]
		p := Provider{ProviderID: "legacy", Kind: kind, DeploymentID: dep, RobotID: "robot-1", Identity: "device-1", Allowed: []string{facet}, Trust: "verified_signature", Role: "primary"}
		if e := (SourceMap{1, source, dep, []Provider{p}}).Validate(); e != nil {
			t.Fatal(kind, e)
		}
		p.ClockBinding = ClockBindingShared
		if e := (SourceMap{1, source, dep, []Provider{p}}).Validate(); e == nil || e.Error() != "SOURCE_MAP_CLOCK_BINDING" {
			t.Fatal(kind, e)
		}
	}
	text := `{"schema_version":1,"source_id":"` + source + `","deployment_id":"` + dep + `","providers":[{"provider_id":"one","kind":"normalized_jsonl","expected_deployment_id":"` + dep + `","expected_robot_id":"robot-1","expected_identity":"device-robot-1","path_ref":"/private/not-public.jsonl","endpoint_ref":"","allowed_event_kinds":["motion"],"expected_owner":"actor","expected_run_id":"` + dep + `","expected_stream_id":"` + stream + `","trust_basis":"local_self_report","role":"primary","clock_binding":"shared_kernel_monotonic"}]}`
	m, e := ParseSourceMap([]byte(text))
	if e != nil || m.Providers[0].ClockBinding != ClockBindingShared {
		t.Fatal(e, m)
	}
	c, e := New(m)
	if e != nil || c.config.Providers[0].ClockBinding != ClockBindingShared || c.providers["one"].config.ClockBinding != ClockBindingShared {
		t.Fatal("the declaration was lost on the way into the collector", e)
	}
}

// Design 4.4: the expiry table of the observation view is what it was.
func TestOpsviewClockLimitsUnchanged(t *testing.T) {
	want := map[string]time.Duration{"plan": 3 * time.Second, "gate": 3 * time.Second, "permit": 3 * time.Second, "motion": time.Second, "pose": time.Second, "ledger": 30 * time.Second, "management": 300 * time.Second, "liveness": 3 * time.Second}
	if len(ttls) != len(want) {
		t.Fatal(ttls)
	}
	for k, v := range want {
		if ttls[k] != v {
			t.Fatal(k, ttls[k])
		}
	}
}
