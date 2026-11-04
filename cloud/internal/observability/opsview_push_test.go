// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// OPSVIEW O7-01 (T32, T33, T34): observations pushed with a challenge, judged by
// the collector's clock alone.

func pushProvider(id, robot string) Provider {
	return Provider{ProviderID: id, Kind: PushKind, DeploymentID: dep, RobotID: robot, Identity: "device-" + robot, Allowed: []string{"motion", "pose", "gate", "liveness"},
		Owner: "actor", RunID: dep, StreamID: stream, Trust: PushTrust, Role: "primary"}
}

func pushFixture(t *testing.T) (*Collector, *time.Time, Provider, Provider) {
	t.Helper()
	a, b := pushProvider("push-1", "robot-1"), pushProvider("push-2", "robot-2")
	b.Identity = "device-robot-2"
	c, now := fixture(t, a, b)
	return c, now, a, b
}

func motion(p Provider, seq int, observed int64, challenge string) Event {
	v := 0.0
	return Event{SchemaVersion: 2, DeploymentID: p.DeploymentID, RobotID: p.RobotID, Identity: p.Identity, Owner: p.Owner, RunID: p.RunID, Kind: "motion", Producer: boot, Stream: p.StreamID,
		Seq: strconv.Itoa(seq), ClockID: "robot-clock", Observed: ptr(observed), Challenge: challenge, Value: Value{State: "OBSERVED_ZERO", LinearMPS: &v, AngularRPS: &v, FrameID: "run-a", SourceKind: "simulation_applied_velocity"}}
}

func facetOf(c *Collector, robot, kind string) Facet {
	for _, r := range c.Snapshot().Robots {
		if r.Key.RobotID == robot {
			return r.Sources[0].Facets[kind]
		}
	}
	return Facet{}
}

func push(t *testing.T, c *Collector, p Provider, events ...Event) PushResult {
	t.Helper()
	r, err := c.Push(p.ProviderID, boot, events)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// T32: a record that echoes the challenge is bound to the moment of issue.
func TestOpsviewPushChallengeBindsAge(t *testing.T) {
	c, now, a, _ := pushFixture(t)
	first := push(t, c, a, motion(a, 1, now.UnixMilli(), ""))
	if first.Accepted != 1 || len(first.Rejected) != 0 || len(first.Challenge) < 20 || first.ChallengeLifeMS != 10000 {
		t.Fatalf("first upload: %+v", first)
	}
	// without a challenge the record is what the receiver saw arrive: motion stays UNKNOWN
	if f := facetOf(c, "robot-1", "motion"); f.FreshnessBasis != "receiver_only" || f.Quality != "UNKNOWN" || f.AgeUpperMS != nil {
		t.Fatalf("receiver_only: %+v", f)
	}
	issued := *now
	*now = now.Add(400 * time.Millisecond)
	second := push(t, c, a, motion(a, 2, now.UnixMilli(), first.Challenge))
	if second.Accepted != 1 || len(second.Rejected) != 0 || second.Challenge == first.Challenge {
		t.Fatalf("second upload: %+v", second)
	}
	f := facetOf(c, "robot-1", "motion")
	if f.FreshnessBasis != "challenge_bound" || f.Quality != "FRESH" || f.Reason != "CHALLENGE_BOUND" || f.AgeUpperMS == nil || *f.AgeUpperMS != 400 || f.Active == nil {
		t.Fatalf("challenge_bound: %+v", f)
	}
	// the upper bound grows with the collector's clock, from the issue time, not from receipt
	*now = issued.Add(999 * time.Millisecond)
	if f = facetOf(c, "robot-1", "motion"); f.Quality != "FRESH" || *f.AgeUpperMS != 999 {
		t.Fatalf("at 999 ms: %+v", f)
	}
	*now = issued.Add(1000 * time.Millisecond)
	if f = facetOf(c, "robot-1", "motion"); f.Quality != "STALE" || f.Reason != "OBSERVATION_OLD" || *f.AgeUpperMS != 1000 || f.FreshnessBasis != "challenge_bound" {
		t.Fatalf("at 1000 ms: %+v", f)
	}
	// the summary counts a challenge-bound fresh motion as fresh
	*now = issued.Add(500 * time.Millisecond)
	if in := c.Snapshot().Robots[0].Summary.Inputs; in.Motion != "FRESH" || in.MotionState != "OBSERVED_ZERO" {
		t.Fatalf("summary inputs: %+v", in)
	}
}

// T34: what the robot wrote as its own time changes nothing.
func TestOpsviewPushRobotClockIgnored(t *testing.T) {
	c, now, a, _ := pushFixture(t)
	ch := push(t, c, a, motion(a, 1, now.UnixMilli(), "")).Challenge
	want := []string{}
	for i, skew := range []int64{0, +3600000, -3600000} {
		challenge := ch
		*now = now.Add(300 * time.Millisecond)
		r := push(t, c, a, motion(a, 2+i, now.UnixMilli()+skew, challenge))
		ch = r.Challenge
		if r.Accepted != 1 {
			t.Fatalf("skew %d: %+v", skew, r)
		}
		f := facetOf(c, "robot-1", "motion")
		if f.AgeUpperMS == nil {
			t.Fatalf("skew %d: no upper bound: %+v", skew, f)
		}
		want = append(want, f.Quality+"/"+f.Reason+"/"+f.FreshnessBasis+"/"+strconv.FormatInt(*f.AgeUpperMS, 10))
	}
	if want[0] != "FRESH/CHALLENGE_BOUND/challenge_bound/300" || want[1] != want[0] || want[2] != want[0] {
		t.Fatalf("judgements differ with the robot's clock: %v", want)
	}
}

// T33: the wrong challenge is refused and counted; no challenge is receiver_only.
func TestOpsviewPushChallengeRefusals(t *testing.T) {
	c, now, a, b := pushFixture(t)
	one := push(t, c, a, motion(a, 1, now.UnixMilli(), "")).Challenge
	two := push(t, c, b, motionB(b, 1, now.UnixMilli(), "")).Challenge
	*now = now.Add(200 * time.Millisecond)
	// used once: the whole upload shares it, the next upload may not
	r := push(t, c, a, motion(a, 20, now.UnixMilli(), one), motion(a, 21, now.UnixMilli(), one))
	if r.Accepted != 2 || len(r.Rejected) != 0 {
		t.Fatalf("shared within an upload: %+v", r)
	}
	current := r.Challenge
	r = push(t, c, a, motion(a, 22, now.UnixMilli(), one))
	if r.Accepted != 0 || len(r.Rejected) != 1 || r.Rejected[0].Reason != "CHALLENGE_USED" {
		t.Fatalf("used twice: %+v", r)
	}
	cases := []struct {
		name, challenge string
		at              time.Duration
		reason          string
	}{
		{"unknown", "AAAAAAAAAAAAAAAAAAAAAA", 0, "CHALLENGE_UNKNOWN"},
		{"another robot's", two, 0, "CHALLENGE_UNKNOWN"},
		{"expired", current, 10*time.Second + time.Millisecond, "CHALLENGE_EXPIRED"},
	}
	for i, tc := range cases {
		at := now.Add(tc.at)
		save := *now
		*now = at
		r, err := c.Push(a.ProviderID, boot, []Event{motion(a, 10+i, at.UnixMilli(), tc.challenge)})
		*now = save
		if err != nil || r.Accepted != 0 || len(r.Rejected) != 1 || r.Rejected[0].Reason != tc.reason || r.Rejected[0].Seq != strconv.Itoa(10+i) {
			t.Fatalf("%s: %+v %v", tc.name, r, err)
		}
	}
	// the refusals are counted on the source
	if row := c.Snapshot().Robots[0].Sources[0]; row.Errors != 4 || row.LastError != "CHALLENGE_EXPIRED" {
		t.Fatalf("errors: %d %s", row.Errors, row.LastError)
	}
	// another producer of the same robot may not echo it
	other := "3c1f7a2e-2b4a-4f0a-9f5e-0a1b2c3d4e5f"
	r = push(t, c, a, motion(a, 23, now.UnixMilli(), ""))
	e := motion(a, 24, now.UnixMilli(), r.Challenge)
	e.Producer = other
	rr, err := c.Push(a.ProviderID, other, []Event{e})
	if err != nil || len(rr.Rejected) != 1 || rr.Rejected[0].Reason != "CHALLENGE_OTHER_PRODUCER" {
		t.Fatalf("other producer: %+v %v", rr, err)
	}
	// no challenge: taken, receiver_only; replayed: taken as history, never current
	r = push(t, c, a, motion(a, 25, now.UnixMilli(), ""))
	if r.Accepted != 1 {
		t.Fatalf("no challenge: %+v", r)
	}
	if f := facetOf(c, "robot-1", "motion"); f.FreshnessBasis != "receiver_only" || f.Quality != "UNKNOWN" {
		t.Fatalf("receiver_only after a bound record: %+v", f)
	}
	rep := motion(a, 26, now.UnixMilli(), "")
	rep.Replayed = true
	if r = push(t, c, a, rep); r.Replayed != 1 || r.Accepted != 0 {
		t.Fatalf("replayed: %+v", r)
	}
	// a producer named in the upload that is not the records' producer
	rr, err = c.Push(a.ProviderID, other, []Event{motion(a, 27, now.UnixMilli(), "")})
	if err != nil || len(rr.Rejected) != 1 || rr.Rejected[0].Reason != "PUSH_PRODUCER_MISMATCH" {
		t.Fatalf("producer mismatch: %+v %v", rr, err)
	}
	// bounds
	if _, err = c.Push(a.ProviderID, boot, make([]Event, PushMaxRecords+1)); err == nil || err.Error() != "PUSH_TOO_MANY_RECORDS" {
		t.Fatal("too many records", err)
	}
	if _, err = c.Push("push-9", boot, nil); err == nil || err.Error() != "UNKNOWN_PROVIDER" {
		t.Fatal("unknown provider", err)
	}
	if _, err = c.Push(a.ProviderID, "not-a-uuid", nil); err == nil || err.Error() != "PUSH_PRODUCER" {
		t.Fatal("producer form", err)
	}
	// only the newest few challenges are kept
	for i := 0; i < ChallengesKept+2; i++ {
		push(t, c, a, motion(a, 30+i, now.UnixMilli(), ""))
	}
	if n := len(c.challenges["robot-1"]); n != ChallengesKept {
		t.Fatalf("kept %d", n)
	}
}

func motionB(p Provider, seq int, observed int64, challenge string) Event {
	e := motion(p, seq, observed, challenge)
	return e
}

// A push source in the source map: bound like a file source, without a path or an address.
func TestOpsviewPushSourceMap(t *testing.T) {
	good := pushProvider("push-1", "robot-1")
	if _, err := New(SourceMap{1, source, dep, []Provider{good}}); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(p *Provider){
		"trust":    func(p *Provider) { p.Trust = "local_self_report" },
		"path":     func(p *Provider) { p.PathRef = "/x" },
		"endpoint": func(p *Provider) { p.EndpointRef = "https://collector:8443" },
		"ledger":   func(p *Provider) { p.Allowed = []string{"ledger"} },
		"clock":    func(p *Provider) { p.ClockBinding = ClockBindingShared },
		"run":      func(p *Provider) { p.RunID = "x" },
		"stream":   func(p *Provider) { p.StreamID = "" },
		"owner":    func(p *Provider) { p.Owner = "" },
	}
	for name, change := range bad {
		p := good
		p.Allowed = append([]string{}, good.Allowed...)
		change(&p)
		if _, err := New(SourceMap{1, source, dep, []Provider{p}}); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// the capability document names the feed as a facet source like any other
	c, _ := fixture(t, good)
	if kinds := c.facetKinds(); !strings.Contains(strings.Join(kinds, ","), "liveness") {
		t.Fatal(kinds)
	}
	// the push source of a robot: this deployment's, of the push kind; a file source of the
	// same robot is not one, and an upload to it is refused
	file := provider("file-1", "robot-2", dep)
	file.Identity = "device-robot-2"
	c2, _ := fixture(t, good, file)
	if id, ok := c2.PushProvider("robot-1"); !ok || id != "push-1" {
		t.Fatalf("push provider of robot-1: %s %v", id, ok)
	}
	if id, ok := c2.PushProvider("robot-2"); ok {
		t.Fatalf("a file source taken as the push source: %s", id)
	}
	if _, err := c2.Push("file-1", boot, nil); err == nil || err.Error() != "UNKNOWN_PROVIDER" {
		t.Fatalf("upload to a file source: %v", err)
	}
	// a push source declared for another deployment is not the push source of this one's robot
	other := pushProvider("push-9", "robot-9")
	other.DeploymentID, other.Identity = dep2, "device-9"
	c3, _ := fixture(t, good, other)
	if id, ok := c3.PushProvider("robot-9"); ok {
		t.Fatalf("push source of another deployment: %s", id)
	}
}

// The collector's own clock going backwards is not a fresh record; and the age bound is
// not part of the revision (two readings of the same records have the same revision).
func TestOpsviewPushClockAndRevision(t *testing.T) {
	c, now, a, _ := pushFixture(t)
	r := push(t, c, a, motion(a, 1, now.UnixMilli(), ""))
	*now = now.Add(100 * time.Millisecond)
	push(t, c, a, motion(a, 2, now.UnixMilli(), r.Challenge))
	first := c.Snapshot()
	*now = now.Add(150 * time.Millisecond)
	second := c.Snapshot()
	f1, f2 := first.Robots[0].Sources[0].Facets["motion"], second.Robots[0].Sources[0].Facets["motion"]
	if f1.Quality != "FRESH" || f2.Quality != "FRESH" || *f1.AgeUpperMS == *f2.AgeUpperMS || first.Revision != second.Revision {
		t.Fatalf("revision moves with the age bound: %d %d %s %s", *f1.AgeUpperMS, *f2.AgeUpperMS, first.Revision, second.Revision)
	}
	*now = now.Add(-2 * time.Second) // before the challenge was issued: the collector's own clock is not to be trusted
	if f := facetOf(c, "robot-1", "motion"); f.Quality != "UNKNOWN" || f.Reason != "CLOCK_UNCERTAIN" || f.AgeUpperMS != nil {
		t.Fatalf("clock backwards: %+v", f)
	}
}

// A file source keeps its judgement when a record carries a challenge it cannot have.
func TestOpsviewPushChallengeOnFileSourceIsIgnored(t *testing.T) {
	c, now, _, _ := pushFixture(t)
	file := provider("file-1", "robot-3", dep)
	file.Identity = "device-robot-3"
	c2, now2 := fixture(t, file)
	_ = c
	_ = now
	e := motion(file, 1, now2.UnixMilli(), "AAAAAAAAAAAAAAAAAAAAAA")
	e.Kind = "motion"
	if err := c2.Observe(file.ProviderID, e); err != nil {
		t.Fatal(err)
	}
	if f := facetOf(c2, "robot-3", "motion"); f.FreshnessBasis != "receiver_only" || f.AgeUpperMS != nil {
		t.Fatalf("file source with a challenge: %+v", f)
	}
}
