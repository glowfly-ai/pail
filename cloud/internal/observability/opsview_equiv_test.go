// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"encoding/json"
	"flag"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// The file uses only what the record version 1 contract already had, so the
// same bytes compile against the earlier release and against this tree. The
// comparison tool runs it on both and compares the documents it writes.
var opsviewDump = flag.String("opsview-dump", "", "write the version 1 scenario documents to this file")
var opsviewDeclare = flag.String("opsview-declare", "", "control: also declare this kind on the file providers")

const equivDeployment = "7a1d3c52-90c1-4b7e-8f0e-5d2f6f1b0a01"
const equivSource = "7a1d3c52-90c1-4b7e-8f0e-5d2f6f1b0a02"
const equivProducer = "7a1d3c52-90c1-4b7e-8f0e-5d2f6f1b0a03"
const equivStream = "7a1d3c52-90c1-4b7e-8f0e-5d2f6f1b0a04"
const equivInstance = "7a1d3c52-90c1-4b7e-8f0e-5d2f6f1b0a05"

func equivProviders() []Provider {
	file := func(id, robot string) Provider {
		return Provider{ProviderID: id, Kind: "normalized_jsonl", DeploymentID: equivDeployment, RobotID: robot, Identity: robot, PathRef: "/observations/" + id + "/observation.jsonl", Allowed: []string{"motion", "pose", "gate"}, Owner: equivSource, RunID: equivSource, StreamID: equivStream, Trust: "local_self_report", Role: "primary"}
	}
	if *opsviewDeclare != "" {
		inner := file
		file = func(id, robot string) Provider {
			p := inner(id, robot)
			p.Allowed = append(p.Allowed, *opsviewDeclare)
			return p
		}
	}
	return []Provider{file("r-1", "robot-1"), file("r-2", "robot-2"),
		{ProviderID: "burst-1", Kind: "legacy_burst", DeploymentID: equivDeployment, RobotID: "robot-1", Identity: "robot-1", Allowed: []string{"gate"}, Trust: "verified_signature", Role: "secondary"},
		{ProviderID: "permit-1", Kind: "legacy_permit", DeploymentID: equivDeployment, RobotID: "robot-1", Identity: "robot-1", Allowed: []string{"permit"}, Trust: "verified_signature", Role: "secondary"}}
}

// equivScenario replays one fixed history and returns the documents a client
// would read at each step.
func equivScenario(t *testing.T) []json.RawMessage {
	t.Helper()
	ps := equivProviders()
	c, e := New(SourceMap{SchemaVersion: 1, SourceID: equivSource, DeploymentID: equivDeployment, Providers: ps})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0)
	c.now = func() time.Time { return now }
	c.instance = equivInstance
	api := NewAPI(c)
	api.now = c.now
	out := []json.RawMessage{}
	read := func() {
		for _, target := range []string{"/v2/observation/capabilities", "/v2/observation/robots"} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", target, nil)
			if target == "/v2/observation/capabilities" {
				api.Capabilities(w, r)
			} else {
				api.Robots(w, r)
			}
			if w.Code != 200 {
				t.Fatal(target, w.Code, w.Body.String())
			}
			out = append(out, json.RawMessage(w.Body.Bytes()))
		}
		b, _ := json.Marshal(c.Snapshot())
		out = append(out, b)
	}
	f := func(v float64) *float64 { return &v }
	seq := 0
	put := func(p Provider, kind string, v Value, wantError bool) {
		seq++
		ms := now.UnixMilli() - 20
		ev := Event{SchemaVersion: 1, DeploymentID: p.DeploymentID, RobotID: p.RobotID, Identity: p.Identity, Owner: p.Owner, RunID: p.RunID, Kind: kind, Producer: equivProducer, Stream: p.StreamID, Seq: jsonNumber(seq), Observed: &ms, ClockID: "mono-0123456789abcdef", Value: v}
		if e := c.Observe(p.ProviderID, ev); (e != nil) != wantError {
			t.Fatal(kind, v.State, e)
		}
	}
	read()
	frame := equivStream + "/" + equivProducer
	for i := 0; i < 3; i++ {
		for _, p := range ps[:2] {
			put(p, "motion", Value{State: "OBSERVED_MOVING", LinearMPS: f(0.2), AngularRPS: f(0), FrameID: frame, SourceKind: "simulation_applied_velocity"}, false)
			put(p, "pose", Value{State: "OBSERVED", X: f(1), Y: f(2), Yaw: f(0.5), FrameID: frame, SourceKind: "simulation_applied_velocity"}, false)
			put(p, "gate", Value{State: "PERMIT"}, false)
		}
		now = now.Add(200 * time.Millisecond)
	}
	put(ps[0], "permit", Value{State: "RECEIVED"}, true) // not declared by this provider
	put(ps[0], "gate", Value{State: "DEAD"}, true)
	c.ObserveLegacy("legacy_burst", hash16ForTest("robot-1"), 7, true, false)
	c.ObserveLegacy("legacy_permit", hash16ForTest("robot-1"), 9, true, false)
	read()
	now = now.Add(1500 * time.Millisecond)
	read()
	now = now.Add(4 * time.Second)
	read()
	return out
}
func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestOpsviewVersion1Scenario(t *testing.T) {
	docs := equivScenario(t)
	if len(docs) != 12 {
		t.Fatal("documents", len(docs))
	}
	if *opsviewDump != "" {
		b, _ := json.MarshalIndent(docs, "", " ")
		if e := os.WriteFile(*opsviewDump, append(b, '\n'), 0o644); e != nil {
			t.Fatal(e)
		}
	}
}
