// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

import (
	"os"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/testlayout"
)

const goodSite = `
site: warehouse-A
schema: v3
zones:
  - id: z6
    type: charge
    adjacent: [z7]
  - id: z7
    type: work_area
    adjacent: [z6, z8]
  - id: z8
    type: corridor
    adjacent: [z7]
objects:
  - id: box-12
    at: z7
robots:
  - id: robot-01
    capabilities: [move, grasp]
    schema: v3
    home: z7
  - id: robot-02
    capabilities: [move]
    schema: v3
    home: z8
constraints:
  - type: human_exclusion
    zone: "*"
  - type: exclusive
    object: box-12
`

func mustCompile(t *testing.T, src string) *Graph {
	t.Helper()
	g, sm, err := Compile([]byte(src))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if sm.Site != "warehouse-A" {
		t.Fatalf("site = %q", sm.Site)
	}
	return g
}

func TestCompileCountsAndHash(t *testing.T) {
	g := mustCompile(t, goodSite)

	// Nodes: 3 zones + 1 object + 2 robots + 2 executors
	//        + 3 human_excl constraints (one per zone) = 11.
	//        (speed_limit is refused since SK-1 — TestCompileRefusesSpeedLimit.)
	if got := len(g.Nodes); got != 11 {
		t.Errorf("node count = %d, want 11", got)
	}
	// exclusive marks the object node, does not add one.
	if n, ok := g.Nodes["object:box-12"]; !ok {
		t.Fatal("object:box-12 missing")
	} else if v, ok := n.Attrs["exclusive"]; !ok || v.Tag != TagBool || !v.B {
		t.Errorf("box-12 exclusive flag = %+v", v)
	}
	if g.Epoch != 0 {
		t.Errorf("initial epoch = %d, want 0", g.Epoch)
	}
	h, err := GraphHash(g)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	t.Logf("graph nodes=%d edges=%d hash=%x", len(g.Nodes), len(g.Edges), h)
}

func TestCompileDeterministic(t *testing.T) {
	g1 := mustCompile(t, goodSite)
	g2 := mustCompile(t, goodSite)
	h1, err := GraphHash(g1)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := GraphHash(g2)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("same YAML produced different hashes: %x != %x", h1, h2)
	}
}

// Reordering YAML sections/keys must not change the compiled graph hash.
func TestCompileOrderIndependent(t *testing.T) {
	reordered := `
schema: v3
site: warehouse-A
constraints:
  - type: exclusive
    object: box-12
  - type: human_exclusion
    zone: "*"
robots:
  - id: robot-02
    home: z8
    schema: v3
    capabilities: [move]
  - id: robot-01
    home: z7
    capabilities: [grasp, move]
    schema: v3
objects:
  - id: box-12
    at: z7
zones:
  - id: z8
    adjacent: [z7]
    type: corridor
  - id: z7
    adjacent: [z8, z6]
    type: work_area
  - id: z6
    adjacent: [z7]
    type: charge
`
	g1 := mustCompile(t, goodSite)
	g2 := mustCompile(t, reordered)
	h1, _ := GraphHash(g1)
	h2, _ := GraphHash(g2)
	if h1 != h2 {
		t.Fatalf("reordered YAML changed hash: %x != %x", h1, h2)
	}
}

func TestCompileRejectsUnknownConstraint(t *testing.T) {
	src := `
site: s
zones: [{id: z1}]
constraints:
  - type: no_such_rule
    zone: z1
`
	if _, _, err := Compile([]byte(src)); err == nil {
		t.Fatal("expected error for unknown constraint type")
	}
}

func TestCompileRejectsDanglingRefs(t *testing.T) {
	cases := map[string]string{
		"object at missing zone": `
site: s
zones: [{id: z1}]
objects: [{id: o1, at: zX}]
`,
		"robot home missing zone": `
site: s
zones: [{id: z1}]
robots: [{id: r1, home: zX}]
`,
		"constraint zone missing": `
site: s
zones: [{id: z1}]
constraints: [{type: human_exclusion, zone: zX}]
`,
		"adjacent missing zone": `
site: s
zones: [{id: z1, adjacent: [zX]}]
`,
	}
	for name, src := range cases {
		if _, _, err := Compile([]byte(src)); err == nil {
			t.Errorf("%s: expected compile error", name)
		}
	}
}

func TestCompileRejectsUnknownTopLevelField(t *testing.T) {
	src := `
site: s
zzones: [{id: z1}]
`
	if _, _, err := Compile([]byte(src)); err == nil {
		t.Fatal("expected error for unknown top-level key")
	}
}

func TestCompileRejectsUnexpectedConstraintField(t *testing.T) {
	// human_exclusion does not accept `object`.
	src := `
site: s
zones: [{id: z1}]
constraints: [{type: human_exclusion, zone: z1, object: o1}]
`
	if _, _, err := Compile([]byte(src)); err == nil {
		t.Fatal("expected error for unexpected constraint field")
	}
}

// PAIL-CASE: compile_refuses_speed_limit
// G-POL-11 (SK-1): a site-model speed_limit is refused, not silently carried.
// Its numbers never reached the gate; letting the file load read as a limit
// that holds. The bound now lives in policy.yaml guardrails.zones.
func TestCompileRefusesSpeedLimit(t *testing.T) {
	src := `
site: s
zones: [{id: z1}]
constraints: [{type: speed_limit, zone: z1, max_linear_speed_mps: 0.5}]
`
	_, _, err := Compile([]byte(src))
	if err == nil {
		t.Fatal("speed_limit accepted — it never enforced anything")
	}
	if !strings.Contains(err.Error(), "guardrails.zones") {
		t.Fatalf("refusal must point at the replacement: %v", err)
	}
}

func TestCompileRobotClass(t *testing.T) {
	src := `
site: s
zones: [{id: z1}]
robots:
  - {id: r1, home: z1, robot_class: diff_drive_amr}
  - {id: r2, home: z1}
`
	g, sm, err := Compile([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if sm.RobotClass["r1"] != "diff_drive_amr" {
		t.Fatalf("RobotClass: %+v", sm.RobotClass)
	}
	if _, ok := sm.RobotClass["r2"]; ok {
		t.Fatal("r2 has no robot_class and must be absent, not defaulted")
	}
	if _, ok := g.Nodes["robot:r2"].Attrs["robot_class"]; ok {
		t.Fatal("undeclared robot_class must not enter the graph")
	}
}

func TestCompileRejectsMissingSite(t *testing.T) {
	if _, _, err := Compile([]byte("zones: [{id: z1}]\n")); err == nil {
		t.Fatal("expected error for missing site")
	}
}

func TestCompileRejectsCorruptYAML(t *testing.T) {
	if _, _, err := Compile([]byte("site: s\nzones: [ {id: :::\n")); err == nil {
		t.Fatal("expected parse error for corrupt YAML")
	}
}

// After compilation the graph carries enough structure that Evaluate reproduces
// the fixed predicates: a maintenance/cordoned robot and a human sharing the
// robot's zone both forbid issuance.
func TestCompiledGraphEvaluateSemantics(t *testing.T) {
	g := mustCompile(t, goodSite)

	sg, err := BuildSubgraph(ActionRequest{SubgraphID: "t1", RobotID: "robot-01", TargetObjectID: "box-12"}, g)
	if err != nil {
		t.Fatal(err)
	}
	if v, r := Evaluate(sg); v {
		t.Fatalf("baseline should be OK, got violation %q", r)
	}

	// Maintenance → refuse.
	g.Nodes["robot:robot-01"].State = StateMaintenance
	sg, _ = BuildSubgraph(ActionRequest{SubgraphID: "t2", RobotID: "robot-01"}, g)
	if v, r := Evaluate(sg); !v || r != ReasonMaintenance {
		t.Fatalf("maintenance should refuse with %q, got v=%v r=%q", ReasonMaintenance, v, r)
	}
	g.Nodes["robot:robot-01"].State = StateActive

	// Human in robot-01's home zone (z7) → refuse; robot-02 (z8) still OK.
	g.Nodes["human:h1"] = &Node{ID: "human:h1", Kind: KindHuman, State: StateActive}
	g.Edges = append(g.Edges, Edge{From: "human:h1", To: "zone:z7", Rel: RelLocatedIn})

	sg7, _ := BuildSubgraph(ActionRequest{SubgraphID: "t3", RobotID: "robot-01"}, g)
	if v, r := Evaluate(sg7); !v || r != ReasonHumanInZone {
		t.Fatalf("human in z7 should refuse robot-01, got v=%v r=%q", v, r)
	}
	sg8, _ := BuildSubgraph(ActionRequest{SubgraphID: "t4", RobotID: "robot-02"}, g)
	if v, r := Evaluate(sg8); v {
		t.Fatalf("robot-02 in z8 should be OK, got violation %q", r)
	}
}

// The shipped example YAML must always compile (guards against doc/code drift).
func TestExampleFileCompiles(t *testing.T) {
	// internal/graph -> up 4 to PAIL-v2 root, then config/.
	path := testlayout.Path(t, "config/site_model.example.yaml")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("required example unreadable (%v)", err)
	}
	if _, _, err := Compile(src); err != nil {
		t.Fatalf("example site model failed to compile: %v", err)
	}
}
