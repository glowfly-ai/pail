// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const dep = "5e8b24a0-2319-4a53-b5cf-a03afc977301"
const dep2 = "5e8b24a0-2319-4a53-b5cf-a03afc977302"
const source = "c68d3bdd-62b0-4721-9aec-9ea0d4ab0301"
const boot = "2457dd0a-d7b1-42f6-b089-6ce0d5b2d8c3"
const boot2 = "2457dd0a-d7b1-42f6-b089-6ce0d5b2d8c4"
const stream = "ec054792-0db0-4162-83c1-ce2b7c401782"

func provider(id, robot, deployment string) Provider {
	return Provider{ProviderID: id, Kind: "normalized_jsonl", DeploymentID: deployment, RobotID: robot, Identity: "device-" + robot, PathRef: "/private/not-public.jsonl", Allowed: []string{"gate", "motion", "pose", "plan"}, Owner: "actor", RunID: dep, StreamID: stream, Trust: "local_self_report", Role: "primary"}
}
func fixture(t *testing.T, ps ...Provider) (*Collector, *time.Time) {
	t.Helper()
	c, e := New(SourceMap{1, source, dep, ps})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0)
	c.now = func() time.Time { return now }
	return c, &now
}
func event(p Provider, seq string) Event {
	return Event{SchemaVersion: 1, DeploymentID: p.DeploymentID, RobotID: p.RobotID, Identity: p.Identity, Owner: p.Owner, RunID: p.RunID, Kind: "gate", Producer: boot, Stream: p.StreamID, Seq: seq, ClockID: boot, Value: Value{State: "PERMIT"}}
}
func facet(c *Collector) Facet { return c.Snapshot().Robots[0].Sources[0].Facets["gate"] }
func send(t *testing.T, c *Collector, p Provider, seq string) {
	t.Helper()
	if e := c.Observe(p.ProviderID, event(p, seq)); e != nil {
		t.Fatal(e)
	}
}
func TestMOBSSourceIdentity(t *testing.T) {
	p := provider("one", "robot-1", dep)
	q := provider("two", "robot-1", dep2)
	c, _ := fixture(t, p, q)
	send(t, c, p, "1")
	send(t, c, q, "1")
	s := c.Snapshot()
	if len(s.Robots) != 2 || s.Robots[0].Key == s.Robots[1].Key {
		t.Fatal("cross-deployment merge", s)
	}
	for _, field := range []string{"deployment", "robot", "identity", "owner", "run", "stream"} {
		t.Run(field, func(t *testing.T) {
			c, _ := fixture(t, p)
			e := event(p, "1")
			switch field {
			case "deployment":
				e.DeploymentID = dep2
			case "robot":
				e.RobotID = "other"
			case "identity":
				e.Identity = "foreign"
			case "owner":
				e.Owner = "foreign"
			case "run":
				e.RunID = dep2
			case "stream":
				e.Stream = dep2
			}
			if c.Observe(p.ProviderID, e) == nil {
				t.Fatal("misbound feed accepted")
			}
			s := c.Snapshot()
			if len(s.Robots) != 1 || s.Robots[0].Key.RobotID != "robot-1" || s.Robots[0].Quality != "CONFLICT" {
				t.Fatal(s)
			}
		})
	}
	q = provider("two", "robot-1", dep)
	q.Identity = "different-device"
	c, _ = fixture(t, p, q)
	if c.Snapshot().Robots[0].Quality != "CONFLICT" {
		t.Fatal("duplicate machine hidden")
	}
	q.Identity = p.Identity
	q.Role = "secondary"
	c, _ = fixture(t, p, q)
	s = c.Snapshot()
	if len(s.Robots) != 1 || len(s.Robots[0].Sources) != 2 || s.Robots[0].Quality == "CONFLICT" {
		t.Fatal("multiple sources collapsed", s)
	}
	p.DeploymentID = ""
	c, _ = fixture(t, p)
	if c.Snapshot().Robots[0].DeploymentKnown {
		t.Fatal("invented deployment")
	}
}
func TestMOBSDuplicateAge(t *testing.T) {
	p := provider("one", "robot-1", dep)
	c, now := fixture(t, p)
	send(t, c, p, "1")
	send(t, c, p, "2")
	initial := facet(c)
	if initial.Quality != "FRESH" || initial.Active == nil {
		t.Fatal(initial)
	}
	*now = now.Add(4 * time.Second)
	send(t, c, p, "2")
	send(t, c, p, "1")
	f := facet(c)
	if f.Quality != "STALE" || *f.AgeMS != 4000 || *f.Received != *initial.Received || *f.Seq != "2" || f.Active != nil {
		t.Fatal("duplicate resurrected freshness", f)
	}
	send(t, c, p, "3")
	if facet(c).Quality != "FRESH" {
		t.Fatal("positive progression refused")
	}
}
func TestMOBSProducerRestart(t *testing.T) {
	p := provider("one", "robot-1", dep)
	c, now := fixture(t, p)
	send(t, c, p, "100")
	send(t, c, p, "101")
	*now = now.Add(4 * time.Second)
	e := event(p, "1")
	e.Producer = boot2
	e.ClockID = boot2
	if err := c.Observe("one", e); err != nil {
		t.Fatal(err)
	}
	if facet(c).Quality != "UNKNOWN" || *facet(c).Seq != "1" {
		t.Fatal("new epoch revived state")
	}
	e.Seq = "2"
	c.Observe("one", e)
	if facet(c).Quality != "FRESH" {
		t.Fatal("new epoch progression failed")
	}
	if c.Observe("one", event(p, "102")) == nil || *facet(c).Producer != boot2 {
		t.Fatal("retired epoch returned")
	}
	other, _ := fixture(t, p)
	if facet(other).Value != nil || facet(other).Quality != "UNKNOWN" || other.instance == c.instance {
		t.Fatal("collector restart carried live state")
	}
}
func TestMOBSReplayClockAndIndependentFacets(t *testing.T) {
	p := provider("one", "robot-1", dep)
	c, now := fixture(t, p)
	send(t, c, p, "1")
	send(t, c, p, "2")
	*now = now.Add(4 * time.Second)
	e := event(p, "3")
	e.Replayed = true
	c.Observe("one", e)
	if facet(c).Quality != "STALE" {
		t.Fatal("backfill promoted")
	}
	e.Replayed = false
	e.Observed = ptr(now.Add(time.Hour).UnixMilli())
	c.Observe("one", e)
	if facet(c).Quality != "UNKNOWN" || facet(c).Reason != "CLOCK_UNCERTAIN" {
		t.Fatal("future made fresh", facet(c))
	}
	e = event(p, "4")
	e.Kind = "plan"
	e.Value.State = "ACCEPTED"
	c.Observe("one", e)
	e.Seq = "5"
	c.Observe("one", e)
	s := c.Snapshot().Robots[0].Sources[0]
	if s.Facets["motion"].Value != nil || s.Facets["ledger"].Quality != "UNSUPPORTED" || s.Facets["plan"].Active != nil {
		t.Fatal("facet inferred from ACCEPTED", s)
	}
	e.Kind = "motion"
	e.Value = Value{State: "OBSERVED_ZERO", SourceKind: "simulation_applied_velocity", FrameID: "robot-1/local"}
	c.Observe("one", e)
	e.Seq = "6"
	c.Observe("one", e)
	f := c.Snapshot().Robots[0].Sources[0].Facets["motion"]
	if f.Quality != "UNKNOWN" || f.Active != nil || f.Value.PhysicalStopProven {
		t.Fatal("unbound fake promoted to physical fact", f)
	}
	*now = now.Add(-time.Hour)
	if facet(c).Reason != "CLOCK_UNCERTAIN" {
		t.Fatal("negative age clamped")
	}
}
func TestMOBSLegacyUnknownBound(t *testing.T) {
	p := Provider{ProviderID: "legacy", Kind: "legacy_burst", DeploymentID: dep, RobotID: "robot-1", Identity: "device-1", Allowed: []string{"gate"}, Trust: "verified_signature", Role: "primary"}
	c, now := fixture(t, p)
	for i := 0; i < MaxUnresolved+10; i++ {
		c.ObserveLegacy("legacy_burst", fmt.Sprintf("%032x", i), uint32(i), true, false)
	}
	s := c.Snapshot()
	if len(s.Unresolved) != 1000 || s.Overflow != 10 || len(s.Robots) != 1 || s.Complete {
		t.Fatal("unknown overflow", len(s.Unresolved), s.Overflow)
	}
	*now = now.Add(24 * time.Hour)
	if len(c.Snapshot().Unresolved) != 0 || len(c.Snapshot().Robots) != 1 {
		t.Fatal("unknown TTL evicted declaration")
	}
	// Independent known SHA-256/128 vector from the existing ledger identity helper.
	c.ObserveLegacy("legacy_burst", "not-a-hash", 1, true, false)
	if len(c.Snapshot().Unresolved) != 0 {
		t.Fatal("bad hash leaked")
	}
}
func TestMOBSSourceConfigStrict(t *testing.T) {
	p := provider("one", "robot-1", dep)
	base, _ := json.Marshal(SourceMap{1, source, dep, []Provider{p}})
	if _, e := ParseSourceMap(base); e != nil {
		t.Fatal(e)
	}
	for name, b := range map[string]string{"duplicate": strings.Replace(string(base), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1), "nested-duplicate": strings.Replace(string(base), `"role":"primary"`, `"role":"primary","role":"secondary"`, 1), "unknown": strings.Replace(string(base), `"role":"primary"`, `"role":"primary","secret":"hidden"`, 1), "null": "null", "version": strings.Replace(string(base), `"schema_version":1`, `"schema_version":2`, 1), "trailing": string(base) + "{}"} {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseSourceMap([]byte(b)); e == nil {
				t.Fatal("bad config accepted")
			}
		})
	}
	for name, change := range map[string]func(*Provider){"relative": func(p *Provider) { p.PathRef = "relative" }, "url": func(p *Provider) { p.EndpointRef = "http://metadata" }, "trust": func(p *Provider) { p.Trust = "verified_signature" }, "unknown-kind": func(p *Provider) { p.Allowed = []string{"drive"} }, "owner": func(p *Provider) { p.Owner = "" }} {
		t.Run(name, func(t *testing.T) {
			q := p
			change(&q)
			if _, e := New(SourceMap{1, source, dep, []Provider{q}}); e == nil {
				t.Fatal("bad provider accepted")
			}
		})
	}
}
func TestMOBSEventStrict(t *testing.T) {
	p := provider("one", "robot-1", dep)
	for _, seq := range []string{"-1", "01", "1.0", "18446744073709551616"} {
		c, _ := fixture(t, p)
		if c.Observe("one", event(p, seq)) == nil {
			t.Fatal(seq)
		}
	}
	c, _ := fixture(t, p)
	e := event(p, "18446744073709551615")
	if c.Observe("one", e) != nil || *facet(c).Seq != e.Seq {
		t.Fatal("uint64 wire precision")
	}
	e.Value.PhysicalStopProven = true
	if c.Observe("one", e) == nil {
		t.Fatal("physical stop assertion accepted")
	}
}
func TestMOBSImmutableAndConcurrent(t *testing.T) {
	p := provider("one", "robot-1", dep)
	c, _ := fixture(t, p)
	send(t, c, p, "1")
	s := c.Snapshot()
	s.Robots[0].Sources[0].Facets["gate"].Value.State = "BLOCK"
	if facet(c).Value.State != "PERMIT" {
		t.Fatal("snapshot alias")
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 2; n < 80; n++ {
				_ = c.Observe("one", event(p, fmt.Sprint(n)))
				_ = c.Snapshot()
			}
		}()
	}
	wg.Wait()
}
func request(h http.HandlerFunc, target, etag string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", target, nil)
	r.Header.Set("If-None-Match", etag)
	h(w, r)
	return w
}
func TestMOBSHTTP304TTL(t *testing.T) {
	p := provider("one", "robot-1", dep)
	c, now := fixture(t, p)
	send(t, c, p, "1")
	send(t, c, p, "2")
	a := NewAPI(c)
	a.now = func() time.Time { return *now }
	w := request(a.Robots, "/v2/observation/robots", "")
	tag := w.Header().Get("ETag")
	if w.Code != 200 || tag == "" {
		t.Fatal(w.Code)
	}
	w = request(a.Robots, "/v2/observation/robots", tag)
	if w.Code != 304 {
		t.Fatal(w.Code)
	}
	*now = now.Add(3 * time.Second)
	w = request(a.Robots, "/v2/observation/robots", tag)
	if w.Code != 200 || w.Header().Get("ETag") == tag || !strings.Contains(w.Body.String(), `"quality":"STALE"`) {
		t.Fatal("304 hid TTL", w.Code, w.Body.String())
	}
	old := facet(c)
	request(a.Robots, "/v2/observation/robots", w.Header().Get("ETag"))
	if *facet(c).Received != *old.Received {
		t.Fatal("HTTP refreshed producer")
	}
}
func TestMOBSPaginationAndScope(t *testing.T) {
	p := provider("one", "robot-1", dep)
	q := provider("two", "robot-2", dep)
	c, now := fixture(t, p, q)
	send(t, c, q, "1")
	send(t, c, q, "2")
	a := NewAPI(c)
	a.now = func() time.Time { return *now }
	w := request(a.Robots, "/v2/observation/robots?limit=1", "")
	var first page
	json.Unmarshal(w.Body.Bytes(), &first)
	if w.Code != 200 || len(first.Robots) != 1 || first.Total != 2 || first.Next == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	*now = now.Add(4 * time.Second)
	w = request(a.Robots, "/v2/observation/robots?cursor="+first.Next, "")
	var second page
	json.Unmarshal(w.Body.Bytes(), &second)
	if w.Code != 200 || second.Robots[0].Key.RobotID != "robot-2" || second.Robots[0].Sources[0].Facets["gate"].Quality != "STALE" || second.AsOfMS != first.AsOfMS {
		t.Fatal("cached fresh page", w.Code, w.Body.String())
	}
	for _, target := range []string{"?path=/etc/passwd", "?robot_id=a&robot_id=b", "?limit=1001", "?cursor=garbage", "?cursor=" + first.Next + "&robot_id=robot-2"} {
		if request(a.Robots, "/v2/observation/robots"+target, "").Code != 400 {
			t.Fatal(target)
		}
	}
	w = request(a.Robots, "/v2/observation/robots?source_id=foreign", "")
	json.Unmarshal(w.Body.Bytes(), &second)
	if second.Total != 0 {
		t.Fatal("foreign scope accepted")
	}
	for i := 0; i < 9; i++ {
		request(a.Robots, "/v2/observation/robots", "")
	}
	if len(a.cache) > 8 || a.bytes > cacheBytes || request(a.Robots, "/v2/observation/robots?cursor="+first.Next, "").Code != 409 {
		t.Fatal("cache eviction")
	}
	w = request(a.Robots, "/v2/observation/robots?limit=1", "")
	json.Unmarshal(w.Body.Bytes(), &first)
	*now = now.Add(30 * time.Second)
	if request(a.Robots, "/v2/observation/robots?cursor="+first.Next, "").Code != 409 {
		t.Fatal("cache TTL")
	}
	w = request(a.Capabilities, "/v2/observation/capabilities", "")
	if strings.Contains(w.Body.String(), "/private/") || strings.Contains(w.Body.String(), "path_ref") {
		t.Fatal("private path leak")
	}
	srv := httptest.NewServer(http.HandlerFunc(a.Robots))
	defer srv.Close()
	resp, e := http.Get(srv.URL)
	if e != nil || resp.StatusCode != 200 {
		t.Fatal(e)
	}
	resp.Body.Close()
}
func TestMOBSTailBarrierAndReplacement(t *testing.T) {
	p := provider("one", "robot-1", dep)
	p.PathRef = filepath.Join(t.TempDir(), "actor.jsonl")
	e := event(p, "1")
	b, _ := json.Marshal(e)
	os.WriteFile(p.PathRef, append(b, '\n'), 0600)
	c, _ := fixture(t, p)
	tail, err := NewTail(c, p)
	if err != nil {
		t.Fatal(err)
	}
	defer tail.Close()
	tail.Poll()
	if facet(c).Value != nil {
		t.Fatal("history became live")
	}
	appendEvent := func(seq string, newline bool) {
		e.Seq = seq
		b, _ := json.Marshal(e)
		if newline {
			b = append(b, '\n')
		}
		f, _ := os.OpenFile(p.PathRef, os.O_APPEND|os.O_WRONLY, 0600)
		f.Write(b)
		f.Close()
	}
	appendEvent("2", false)
	tail.Poll()
	if facet(c).Value != nil {
		t.Fatal("partial line became live")
	}
	f, _ := os.OpenFile(p.PathRef, os.O_APPEND|os.O_WRONLY, 0600)
	f.Write([]byte("\n"))
	f.Close()
	tail.Poll()
	appendEvent("3", true)
	tail.Poll()
	if facet(c).Quality != "FRESH" {
		t.Fatal("tail progression", facet(c))
	}
	replacement := p.PathRef + ".new"
	os.WriteFile(replacement, append(b, '\n'), 0600)
	os.Rename(replacement, p.PathRef)
	tail.Poll()
	if facet(c).Quality == "FRESH" {
		t.Fatal("replacement revived old values")
	}
	f, _ = os.OpenFile(p.PathRef, os.O_APPEND|os.O_WRONLY, 0600)
	f.Write([]byte(strings.Repeat("x", MaxEvent+1) + "\n"))
	f.Close()
	tail.Poll()
	if len(tail.pending) > MaxEvent {
		t.Fatal("unbounded line")
	}
	if c.Snapshot().Robots[0].Sources[0].Health != "PAYLOAD_OVERSIZE" {
		t.Fatal("oversize hidden")
	}
}

func TestMOBSDelayedProducerSamples(t *testing.T) {
	p := provider("one", "robot-1", dep)
	c, now := fixture(t, p)
	e := event(p, "1")
	e.Observed = ptr(now.Add(-time.Hour).UnixMilli())
	c.Observe("one", e)
	e.Seq = "2"
	c.Observe("one", e)
	if facet(c).Quality == "FRESH" || facet(c).Active != nil {
		t.Fatal("buffered historical observation became live", facet(c))
	}
	e.Seq = "3"
	e.Observed = ptr(now.UnixMilli())
	c.Observe("one", e)
	if facet(c).Quality != "FRESH" {
		t.Fatal("positive current observation rejected")
	}
}
func TestMOBSUnverifiedLedgerProviderRefused(t *testing.T) {
	p := provider("one", "robot-1", dep)
	p.Allowed = []string{"ledger"}
	if _, e := New(SourceMap{1, source, dep, []Provider{p}}); e == nil {
		t.Fatal("local JSON may forge chain verification")
	}
}
func TestMOBSLimitsAndDisconnection(t *testing.T) {
	ps := make([]Provider, MaxRobots)
	for i := range ps {
		ps[i] = provider(fmt.Sprint("p", i), fmt.Sprint("r", i), dep)
	}
	c, _ := fixture(t, ps...)
	if len(c.Snapshot().Robots) != 1024 {
		t.Fatal("declared inventory lost")
	}
	ps = append(ps, provider("overflow", "extra", dep))
	if _, e := New(SourceMap{1, source, dep, ps}); e == nil {
		t.Fatal("robot limit absent")
	}
	p := provider("one", "robot-1", dep)
	c, _ = fixture(t, p)
	send(t, c, p, "1")
	send(t, c, p, "2")
	c.Fault("one", "SOURCE_UNAVAILABLE")
	s := c.Snapshot()
	if len(s.Robots) != 1 || s.Complete || facet(c).Quality != "UNKNOWN" || facet(c).Active != nil || facet(c).Value == nil {
		t.Fatal("disconnection fabricated idle or lost last observation", s)
	}
}

func TestMOBSConnectionIsNotProducerProgress(t *testing.T) {
	p := provider("one", "robot-1", dep)
	c, now := fixture(t, p)
	send(t, c, p, "1")
	send(t, c, p, "2")
	*now = now.Add(6 * time.Second)
	s := c.Snapshot()
	if s.Robots[0].Sources[0].Health != "STALE" {
		t.Fatal("silent provider marked connected")
	}
	send(t, c, p, "2")
	s = c.Snapshot()
	if s.Robots[0].Sources[0].Health != "CONNECTED" || facet(c).Quality != "STALE" {
		t.Fatal("connection resurrected producer")
	}
	c.Fault("one", "PAYLOAD_OVERSIZE")
	send(t, c, p, "3")
	s = c.Snapshot()
	if s.Robots[0].Sources[0].Errors != 1 || s.Robots[0].Sources[0].LastError != "PAYLOAD_OVERSIZE" {
		t.Fatal("fault disappeared after valid sample")
	}
}
