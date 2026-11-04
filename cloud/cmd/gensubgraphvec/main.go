// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Command gensubgraphvec emits the frozen conformance vector set for the
// execution-authorization subgraph snapshot hash (spec/SUBGRAPH_HASH.md).
//
// Why this exists. ActionToken.subgraph_snapshot_hash (field 61) is covered by
// the token signature, and the gate refuses motion when the issuer's live
// re-derivation of it disagrees with the token. Until this set existed the only
// public statement of how that number is computed was the issuer's own source,
// which the public split places under a different licence from the gate and
// the verifier. A number that is signed but cannot be recomputed from the
// specification is not evidence; it is a claim. This set, together with the
// document and the independent Python checker, turns it back into evidence.
//
// Three planes, three files:
//
//	cases.json      canonical encoding + SHA-256 of hand-built subgraphs, and
//	                the inputs the encoder must refuse
//	selection.json  which slice of a world a request selects, and the hash of
//	                that slice (standing site graphs and the ephemeral world)
//	world.json      how a site declaration compiles into a graph and how
//	                context events mutate it — the world cut a verifier rebuilds
//
// Generation and verification do not share code. This generator runs the
// issuer's implementation; the checker (scripts/spec_subgraph_check.py)
// re-derives every byte from the document's rules alone. If the two agree, the
// document is sufficient; if they disagree, one of them is wrong and the
// checker says which case.
//
// Self-verification before any write: the legacy golden subgraph (G1 in
// internal/graph/GOLDEN_VECTORS.md) must still hash to its frozen value, and
// every accept case must round-trip through the package's own encoder. If any
// of that fails, nothing is written and the exit code is 1.
//
//	gensubgraphvec -dest oss/spec/vectors/subgraph
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/glowfly/pail/services/internal/graph"
)

// GoldenG1SHA256 is the hash of the legacy golden subgraph G1
// (internal/graph/GOLDEN_VECTORS.md). The set carries it as SG-01 so the
// continuity between the old single vector and this set is measurable.
const GoldenG1SHA256 = "58b631c03edf4600000aec54715c022b0c5505d29b1639af021abf79d1474aa1"

// Format constants restated for the checker's K-style source pin (internal).
const (
	FormatMagic   = "PAILSG"
	FormatVersion = 1
)

// ---------------------------------------------------------------- JSON shapes

type jAttr struct {
	T string `json:"t"`
	V any    `json:"v,omitempty"`
	// Tag is only present for the unknown-tag reject case.
	Tag int `json:"tag,omitempty"`
}

type jNode struct {
	ID      string           `json:"id"`
	Kind    int              `json:"kind"`
	State   int              `json:"state"`
	Version uint64           `json:"version"`
	Attrs   map[string]jAttr `json:"attrs"`
}

type jEdge struct {
	From string `json:"from"`
	Rel  int    `json:"rel"`
	To   string `json:"to"`
}

type jSubgraph struct {
	Epoch uint64  `json:"epoch"`
	Nodes []jNode `json:"nodes"`
	Edges []jEdge `json:"edges"`
}

type jCase struct {
	ID           string     `json:"id"`
	Title        string     `json:"title"`
	Expect       string     `json:"expect"` // accept | reject
	Reason       string     `json:"reason,omitempty"`
	Subgraph     *jSubgraph `json:"subgraph"`
	CanonicalHex string     `json:"canonical_hex,omitempty"`
	SHA256       string     `json:"sha256,omitempty"`
}

type jCases struct {
	Format        string  `json:"format"`
	FormatVersion int     `json:"format_version"`
	Cases         []jCase `json:"cases"`
}

type jRequest struct {
	RobotID        string `json:"robot_id"`
	TargetObjectID string `json:"target_object_id"`
}

type jEphemeral struct {
	RobotID            string  `json:"robot_id"`
	TargetObjectID     string  `json:"target_object_id"`
	MaxLinearSpeedMps  float64 `json:"max_linear_speed_mps"`
	MaxAngularSpeedRps float64 `json:"max_angular_speed_rps"`
	MaxDurationSec     float64 `json:"max_duration_sec"`
}

type jSelected struct {
	NodeIDs []string `json:"node_ids"`
	Edges   []jEdge  `json:"edges"`
}

type jEvaluate struct {
	Violated bool   `json:"violated"`
	Reason   string `json:"reason"`
}

type jSelCase struct {
	ID           string      `json:"id"`
	Title        string      `json:"title"`
	Mode         string      `json:"mode"` // site | ephemeral
	Ephemeral    *jEphemeral `json:"ephemeral,omitempty"`
	World        *jSubgraph  `json:"world"`
	Request      jRequest    `json:"request"`
	Selected     jSelected   `json:"selected"`
	Evaluate     jEvaluate   `json:"evaluate"`
	CanonicalHex string      `json:"canonical_hex"`
	SHA256       string      `json:"sha256"`
}

type jSelection struct {
	Cases []jSelCase `json:"cases"`
}

type jEvent struct {
	Kind       string `json:"kind"`
	NodeID     string `json:"node_id"`
	Arg        string `json:"arg"`
	Epoch      uint64 `json:"epoch"`
	OldVersion uint64 `json:"old_version"`
	NewVersion uint64 `json:"new_version"`
}

type jWorldRequest struct {
	RobotID        string   `json:"robot_id"`
	TargetObjectID string   `json:"target_object_id"`
	NodeIDs        []string `json:"node_ids"`
	SHA256         string   `json:"sha256"`
}

type jWorldCase struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Expect      string          `json:"expect"` // accept | reject
	Reason      string          `json:"reason,omitempty"`
	SiteYAML    string          `json:"site_yaml"`
	Site        any             `json:"site,omitempty"`
	Events      []jEvent        `json:"events"`
	Graph       *jSubgraph      `json:"graph,omitempty"`
	GraphSHA256 string          `json:"graph_sha256,omitempty"`
	Requests    []jWorldRequest `json:"requests"`
}

type jWorld struct {
	Cases []jWorldCase `json:"cases"`
}

// ------------------------------------------------------------- conversions

func attrToJSON(v graph.AttrVal) jAttr {
	switch v.Tag {
	case graph.TagString:
		return jAttr{T: "string", V: v.S}
	case graph.TagInt64:
		return jAttr{T: "int64", V: v.I}
	case graph.TagDouble:
		// Doubles travel as strings so that -0.0, NaN and the infinities survive
		// JSON (JSON has no NaN, and "-0" would decode as the integer 0).
		return jAttr{T: "double", V: strconv.FormatFloat(v.F, 'g', -1, 64)}
	case graph.TagBool:
		return jAttr{T: "bool", V: v.B}
	default:
		return jAttr{T: "unknown", Tag: int(v.Tag)}
	}
}

func nodeToJSON(n *graph.Node) jNode {
	attrs := map[string]jAttr{}
	for k, v := range n.Attrs {
		attrs[k] = attrToJSON(v)
	}
	return jNode{ID: n.ID, Kind: int(n.Kind), State: int(n.State), Version: n.Version, Attrs: attrs}
}

func edgeToJSON(e graph.Edge) jEdge { return jEdge{From: e.From, Rel: int(e.Rel), To: e.To} }

func subgraphToJSON(sg *graph.Subgraph) *jSubgraph {
	out := &jSubgraph{Epoch: sg.GraphEpoch, Nodes: []jNode{}, Edges: []jEdge{}}
	for _, n := range sg.Nodes {
		out.Nodes = append(out.Nodes, nodeToJSON(n))
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].ID < out.Nodes[j].ID })
	for _, e := range sg.Edges {
		out.Edges = append(out.Edges, edgeToJSON(e))
	}
	sortEdges(out.Edges)
	return out
}

func graphToJSON(g *graph.Graph) *jSubgraph {
	nodes := make([]*graph.Node, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		nodes = append(nodes, n)
	}
	return subgraphToJSON(&graph.Subgraph{GraphEpoch: g.Epoch, Nodes: nodes, Edges: g.Edges})
}

func sortEdges(es []jEdge) {
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.Rel != b.Rel {
			return a.Rel < b.Rel
		}
		return a.To < b.To
	})
}

func sortedNodeIDs(sg *graph.Subgraph) []string {
	ids := make([]string, 0, len(sg.Nodes))
	for _, n := range sg.Nodes {
		ids = append(ids, n.ID)
	}
	sort.Strings(ids)
	return ids
}

func hashHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ------------------------------------------------------------ cases.json

func n(id string, kind graph.NodeKind, state graph.NodeState, ver uint64, attrs map[string]graph.AttrVal) *graph.Node {
	return &graph.Node{ID: id, Kind: kind, State: state, Version: ver, Attrs: attrs}
}

func e(from string, rel graph.EdgeRel, to string) graph.Edge {
	return graph.Edge{From: from, To: to, Rel: rel}
}

func A(kv ...any) map[string]graph.AttrVal {
	m := map[string]graph.AttrVal{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1].(graph.AttrVal)
	}
	return m
}

type encCase struct {
	id, title, expect, reason string
	sg                        *graph.Subgraph
	rawAttrs                  map[string]map[string]jAttr // for the unknown-tag case: JSON we cannot build from AttrVal
}

func goldenG1() *graph.Subgraph {
	return &graph.Subgraph{
		GraphEpoch: 7,
		Nodes: []*graph.Node{
			n("robot:tb1", graph.KindAgent, graph.StateActive, 3, nil),
			n("zone:z7", graph.KindZone, graph.StateActive, 1, A("type", graph.AString("work_area"), "adjacent_count", graph.AInt(2))),
			n("constraint:speed@z7", graph.KindConstraint, graph.StateActive, 1, A("max_linear_speed_mps", graph.ADouble(0.5), "hard", graph.ABool(true))),
		},
		Edges: []graph.Edge{
			e("robot:tb1", graph.RelLocatedIn, "zone:z7"),
			e("constraint:speed@z7", graph.RelConstrains, "zone:z7"),
		},
	}
}

func encodingCases() []encCase {
	composed := "zone:café"    // U+00E9
	decomposed := "zone:café" // e + U+0301
	return []encCase{
		{id: "SG-01", title: "legacy golden G1: three nodes, two edges, four attribute types", expect: "accept", sg: goldenG1()},
		{id: "SG-02", title: "empty subgraph at epoch 0", expect: "accept", sg: &graph.Subgraph{GraphEpoch: 0}},
		{id: "SG-03", title: "one node, every attribute tag; keys sorted by NFC bytes; negative int64; negative zero; false",
			expect: "accept", sg: &graph.Subgraph{GraphEpoch: 1, Nodes: []*graph.Node{
				n("zone:z1", graph.KindZone, graph.StateActive, 1, A(
					"s", graph.AString("héllo"), "i", graph.AInt(-5), "d", graph.ADouble(math.Copysign(0, -1)), "b", graph.ABool(false),
					"é", graph.AString("last"), "a", graph.AString("first"))),
			}}},
		{id: "SG-04a", title: "NFC: decomposed identifier input", expect: "accept", sg: &graph.Subgraph{GraphEpoch: 2, Nodes: []*graph.Node{
			n(decomposed, graph.KindZone, graph.StateActive, 1, A("café", graph.AString("café"))),
		}}},
		{id: "SG-04b", title: "NFC: composed identifier input (same bytes as SG-04a)", expect: "accept", sg: &graph.Subgraph{GraphEpoch: 2, Nodes: []*graph.Node{
			n(composed, graph.KindZone, graph.StateActive, 1, A("café", graph.AString("café"))),
		}}},
		{id: "SG-05", title: "ordering is over encoded bytes: length-major (zone:b before zone:aa); edges likewise",
			expect: "accept", sg: &graph.Subgraph{GraphEpoch: 3, Nodes: []*graph.Node{
				n("zone:aa", graph.KindZone, graph.StateActive, 1, nil),
				n("zone:b", graph.KindZone, graph.StateActive, 1, nil),
				n("robot:r", graph.KindAgent, graph.StateActive, 1, nil),
			}, Edges: []graph.Edge{
				e("robot:r", graph.RelLocatedIn, "zone:aa"),
				e("robot:r", graph.RelLocatedIn, "zone:b"),
			}}},
		{id: "SG-06", title: "identical duplicate edges are both kept (edge count 2)", expect: "accept", sg: &graph.Subgraph{GraphEpoch: 4, Nodes: []*graph.Node{
			n("robot:r", graph.KindAgent, graph.StateActive, 1, nil), n("zone:z", graph.KindZone, graph.StateActive, 1, nil),
		}, Edges: []graph.Edge{
			e("robot:r", graph.RelLocatedIn, "zone:z"), e("robot:r", graph.RelLocatedIn, "zone:z"),
		}}},
		{id: "SG-07", title: "every node kind and every node state; every edge relation", expect: "accept", sg: &graph.Subgraph{GraphEpoch: 5, Nodes: []*graph.Node{
			n("robot:a", graph.KindAgent, graph.StateMaintenance, 2, nil),
			n("executor:a", graph.KindExecutor, graph.StateActive, 0, nil),
			n("object:o", graph.KindObject, graph.StateCordoned, 9, A("exclusive", graph.ABool(true))),
			n("zone:z", graph.KindZone, graph.StateActive, 0, A("adjacent", graph.AString("y,z"))),
			n("human:h", graph.KindHuman, graph.StateActive, 1, nil),
			n("constraint:c", graph.KindConstraint, graph.StateActive, 0, A("ctype", graph.AString("human_exclusion"))),
		}, Edges: []graph.Edge{
			e("robot:a", graph.RelLocatedIn, "zone:z"), e("robot:a", graph.RelTargets, "object:o"),
			e("constraint:c", graph.RelConstrains, "zone:z"), e("robot:a", graph.RelOperates, "executor:a"),
			e("robot:a", graph.RelOccupies, "object:o"), e("human:h", graph.RelLocatedIn, "zone:z"),
		}}},
		{id: "SG-08", title: "extreme values: epoch and version 2^64-1; int64 min and max; large and subnormal doubles",
			expect: "accept", sg: &graph.Subgraph{GraphEpoch: math.MaxUint64, Nodes: []*graph.Node{
				n("zone:x", graph.KindZone, graph.StateActive, math.MaxUint64, A(
					"min", graph.AInt(math.MinInt64), "max", graph.AInt(math.MaxInt64),
					"big", graph.ADouble(1e308), "tiny", graph.ADouble(5e-324), "half", graph.ADouble(0.5))),
			}}},
		{id: "SG-09", title: "an edge may reference an id that is not a node of the subgraph; the encoder does not resolve ids",
			expect: "accept", sg: &graph.Subgraph{GraphEpoch: 6, Nodes: []*graph.Node{
				n("robot:r", graph.KindAgent, graph.StateActive, 1, nil),
			}, Edges: []graph.Edge{e("robot:r", graph.RelTargets, "object:nowhere")}}},
		{id: "SG-10", title: "attribute count 0: absent map and empty map encode identically", expect: "accept", sg: &graph.Subgraph{GraphEpoch: 6, Nodes: []*graph.Node{
			n("zone:p", graph.KindZone, graph.StateActive, 1, map[string]graph.AttrVal{}),
			n("zone:q", graph.KindZone, graph.StateActive, 1, nil),
		}}},
		// rejects
		{id: "SG-90", title: "reject: node kind 0 (unspecified)", expect: "reject", reason: "kind_unspecified", sg: &graph.Subgraph{Nodes: []*graph.Node{
			n("x", graph.KindUnspecified, graph.StateActive, 0, nil)}}},
		{id: "SG-91", title: "reject: double attribute NaN", expect: "reject", reason: "non_finite_double", sg: &graph.Subgraph{Nodes: []*graph.Node{
			n("zone:z", graph.KindZone, graph.StateActive, 0, A("v", graph.ADouble(math.NaN())))}}},
		{id: "SG-92", title: "reject: double attribute +Inf", expect: "reject", reason: "non_finite_double", sg: &graph.Subgraph{Nodes: []*graph.Node{
			n("zone:z", graph.KindZone, graph.StateActive, 0, A("v", graph.ADouble(math.Inf(1))))}}},
		{id: "SG-93", title: "reject: double attribute -Inf", expect: "reject", reason: "non_finite_double", sg: &graph.Subgraph{Nodes: []*graph.Node{
			n("zone:z", graph.KindZone, graph.StateActive, 0, A("v", graph.ADouble(math.Inf(-1))))}}},
		{id: "SG-94", title: "reject: duplicate node id", expect: "reject", reason: "duplicate_node_id", sg: &graph.Subgraph{Nodes: []*graph.Node{
			n("zone:dup", graph.KindZone, graph.StateActive, 0, nil), n("zone:dup", graph.KindZone, graph.StateActive, 1, nil)}}},
		{id: "SG-95", title: "reject: duplicate node id after NFC (composed and decomposed spellings of one id)", expect: "reject", reason: "duplicate_node_id",
			sg: &graph.Subgraph{Nodes: []*graph.Node{
				n(composed, graph.KindZone, graph.StateActive, 0, nil), n(decomposed, graph.KindZone, graph.StateActive, 0, nil)}}},
		{id: "SG-96", title: "reject: unknown attribute tag 0x09", expect: "reject", reason: "unknown_attr_tag", sg: &graph.Subgraph{Nodes: []*graph.Node{
			n("zone:z", graph.KindZone, graph.StateActive, 0, map[string]graph.AttrVal{"v": {Tag: graph.AttrTag(0x09)}})}}},
	}
}

func reasonOf(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "KindUnspecified"):
		return "kind_unspecified"
	case strings.Contains(s, "NaN or Inf"):
		return "non_finite_double"
	case strings.Contains(s, "duplicate node_id"):
		return "duplicate_node_id"
	case strings.Contains(s, "unknown attribute tag"):
		return "unknown_attr_tag"
	}
	return "other:" + s
}

func buildCases() (*jCases, error) {
	out := &jCases{Format: FormatMagic, FormatVersion: FormatVersion}
	for _, c := range encodingCases() {
		jc := jCase{ID: c.id, Title: c.title, Expect: c.expect, Subgraph: subgraphToJSON(c.sg)}
		b, err := graph.CanonicalSubgraph(c.sg)
		switch c.expect {
		case "accept":
			if err != nil {
				return nil, fmt.Errorf("%s: unexpected encode error: %v", c.id, err)
			}
			jc.CanonicalHex = hex.EncodeToString(b)
			jc.SHA256 = hashHex(b)
			if c.id == "SG-01" && jc.SHA256 != GoldenG1SHA256 {
				return nil, fmt.Errorf("SG-01 hash %s differs from the frozen golden %s — the encoder changed", jc.SHA256, GoldenG1SHA256)
			}
		case "reject":
			if err == nil {
				return nil, fmt.Errorf("%s: expected the encoder to refuse", c.id)
			}
			if got := reasonOf(err); got != c.reason {
				return nil, fmt.Errorf("%s: reason %s, want %s (%v)", c.id, got, c.reason, err)
			}
			jc.Reason = c.reason
		}
		out.Cases = append(out.Cases, jc)
	}
	// SG-04a and SG-04b must agree byte for byte — that is the NFC claim.
	var a, b string
	for _, c := range out.Cases {
		if c.ID == "SG-04a" {
			a = c.CanonicalHex
		}
		if c.ID == "SG-04b" {
			b = c.CanonicalHex
		}
	}
	if a == "" || a != b {
		return nil, fmt.Errorf("SG-04a/b differ: NFC normalization is not in effect")
	}
	return out, nil
}

// --------------------------------------------------------- selection.json

func siteWorldW1() *graph.Graph {
	g := graph.NewGraph()
	g.Epoch = 12
	add := func(nd *graph.Node) { g.Nodes[nd.ID] = nd }
	add(n("robot:tb1", graph.KindAgent, graph.StateActive, 3, A("capabilities", graph.AString("drive,lift"))))
	add(n("executor:tb1", graph.KindExecutor, graph.StateActive, 0, nil))
	add(n("robot:tb2", graph.KindAgent, graph.StateActive, 0, nil))
	add(n("executor:tb2", graph.KindExecutor, graph.StateActive, 0, nil))
	add(n("zone:z7", graph.KindZone, graph.StateActive, 0, A("type", graph.AString("work_area"))))
	add(n("zone:z8", graph.KindZone, graph.StateActive, 0, A("type", graph.AString("dock"))))
	add(n("constraint:human_excl@z7", graph.KindConstraint, graph.StateActive, 0, A("ctype", graph.AString("human_exclusion"))))
	add(n("constraint:human_excl@z8", graph.KindConstraint, graph.StateActive, 0, A("ctype", graph.AString("human_exclusion"))))
	add(n("constraint:payload@tb1", graph.KindConstraint, graph.StateActive, 0, A("ctype", graph.AString("payload"), "max_kg", graph.ADouble(20))))
	add(n("object:box1", graph.KindObject, graph.StateActive, 1, A("exclusive", graph.ABool(true))))
	add(n("object:box2", graph.KindObject, graph.StateActive, 0, nil))
	add(n("human:h1", graph.KindHuman, graph.StateActive, 0, nil))
	g.Edges = []graph.Edge{
		e("robot:tb1", graph.RelLocatedIn, "zone:z7"),
		e("robot:tb1", graph.RelOperates, "executor:tb1"),
		e("robot:tb2", graph.RelLocatedIn, "zone:z8"),
		e("robot:tb2", graph.RelOperates, "executor:tb2"),
		e("constraint:human_excl@z7", graph.RelConstrains, "zone:z7"),
		e("constraint:human_excl@z8", graph.RelConstrains, "zone:z8"),
		e("constraint:payload@tb1", graph.RelConstrains, "robot:tb1"),
		e("object:box1", graph.RelLocatedIn, "zone:z8"),
		e("human:h1", graph.RelLocatedIn, "zone:z8"),
	}
	return g
}

type selSpec struct {
	id, title string
	world     *graph.Graph
	eph       *jEphemeral
	req       jRequest
}

func selectionSpecs() []selSpec {
	w := siteWorldW1
	return []selSpec{
		{id: "SEL-01", title: "agent only: its zone, executor, and the constraints on the agent and the zone", world: w(), req: jRequest{RobotID: "tb1"}},
		{id: "SEL-02", title: "with a target object: the object, the synthetic TARGETS edge, and the object's zone — but not the humans in that zone", world: w(), req: jRequest{RobotID: "tb1", TargetObjectID: "box1"}},
		{id: "SEL-03", title: "a human in the agent's zone is selected, and Evaluate reports HUMAN_IN_ZONE", world: w(), req: jRequest{RobotID: "tb2"}},
		{id: "SEL-04", title: "unknown agent: nothing is selected (the issuer refuses with AGENT_NOT_IN_MODEL); the hash is still defined", world: w(), req: jRequest{RobotID: "ghost"}},
		{id: "SEL-05", title: "target object absent from the world: the TARGETS edge is still emitted, the node is not", world: w(), req: jRequest{RobotID: "tb1", TargetObjectID: "nowhere"}},
		{id: "SEL-06", title: "target object with no location: node and TARGETS edge only", world: w(), req: jRequest{RobotID: "tb1", TargetObjectID: "box2"}},
		{id: "SEL-EPH-01", title: "ephemeral world: linear limit only", eph: &jEphemeral{RobotID: "r1", MaxLinearSpeedMps: 0.5}, req: jRequest{RobotID: "r1"}},
		{id: "SEL-EPH-02", title: "ephemeral world: target object and all three limits", eph: &jEphemeral{RobotID: "r1", TargetObjectID: "box", MaxLinearSpeedMps: 0.25, MaxAngularSpeedRps: 1.5, MaxDurationSec: 6}, req: jRequest{RobotID: "r1", TargetObjectID: "box"}},
		{id: "SEL-EPH-03", title: "ephemeral world: no limits, no constraint node", eph: &jEphemeral{RobotID: "r1"}, req: jRequest{RobotID: "r1"}},
	}
}

func buildSelection() (*jSelection, error) {
	out := &jSelection{}
	for _, s := range selectionSpecs() {
		jc := jSelCase{ID: s.id, Title: s.title, Request: s.req}
		world := s.world
		if s.eph != nil {
			jc.Mode = "ephemeral"
			jc.Ephemeral = s.eph
			world = graph.EphemeralIssuanceGraph(s.eph.RobotID, s.eph.TargetObjectID, &graph.EphemeralConstraints{
				MaxLinearSpeedMps: s.eph.MaxLinearSpeedMps, MaxAngularSpeedRps: s.eph.MaxAngularSpeedRps, MaxDurationSec: s.eph.MaxDurationSec})
		} else {
			jc.Mode = "site"
		}
		jc.World = graphToJSON(world)
		sg, err := graph.BuildSubgraph(graph.ActionRequest{SubgraphID: s.id, RobotID: s.req.RobotID, TargetObjectID: s.req.TargetObjectID}, world)
		if err != nil {
			return nil, fmt.Errorf("%s: BuildSubgraph: %v", s.id, err)
		}
		jc.Selected = jSelected{NodeIDs: sortedNodeIDs(sg), Edges: []jEdge{}}
		for _, ed := range sg.Edges {
			jc.Selected.Edges = append(jc.Selected.Edges, edgeToJSON(ed))
		}
		sortEdges(jc.Selected.Edges)
		v, r := graph.Evaluate(sg)
		jc.Evaluate = jEvaluate{Violated: v, Reason: r}
		b, err := graph.CanonicalSubgraph(sg)
		if err != nil {
			return nil, fmt.Errorf("%s: encode: %v", s.id, err)
		}
		jc.CanonicalHex = hex.EncodeToString(b)
		jc.SHA256 = hashHex(b)
		out.Cases = append(out.Cases, jc)
	}
	return out, nil
}

// ------------------------------------------------------------- world.json

const siteYAMLW1 = `site: vector-site
schema: "3"
zones:
  - id: z7
    type: work_area
    adjacent: [z9, z8]
  - id: z8
  - id: z9
    type: corridor
objects:
  - id: box1
    at: z8
  - id: box2
robots:
  - id: tb1
    home: z7
    capabilities: [lift, drive]
    schema: "3"
    robot_class: tb3
  - id: tb2
constraints:
  - type: human_exclusion
    zone: "*"
  - type: exclusive
    object: box1
actions:
  - name: go_to
    classes: [MOVE]
policy:
  unverified_targets: refuse
`

const siteYAMLMinimal = `site: empty-site
`

const siteYAMLSpeedLimit = `site: s
zones:
  - id: z1
constraints:
  - type: speed_limit
    zone: z1
    max_linear_speed_mps: 0.5
`

const siteYAMLUnknownType = `site: s
zones:
  - id: z1
constraints:
  - type: one_way
    zone: z1
`

const siteYAMLDangling = `site: s
zones:
  - id: z1
robots:
  - id: r1
    home: z9
`

type evSpec struct {
	kind, nodeID, arg string
}

func applyEvent(g *graph.Graph, ev evSpec) (uint64, uint64, uint64, error) {
	strip := func(prefix string) (string, error) {
		if !strings.HasPrefix(ev.nodeID, prefix) {
			return "", fmt.Errorf("node_id %q lacks prefix %q", ev.nodeID, prefix)
		}
		return strings.TrimPrefix(ev.nodeID, prefix), nil
	}
	switch ev.kind {
	case "MAINTENANCE_ON":
		return g.SetNodeState(ev.nodeID, graph.StateMaintenance)
	case "MAINTENANCE_OFF", "CORDON_OFF":
		return g.SetNodeState(ev.nodeID, graph.StateActive)
	case "CORDON_ON":
		return g.SetNodeState(ev.nodeID, graph.StateCordoned)
	case "HUMAN_ENTER":
		z, err := strip("zone:")
		if err != nil {
			return 0, 0, 0, err
		}
		return g.EnterHuman(ev.arg, z)
	case "HUMAN_LEAVE":
		z, err := strip("zone:")
		if err != nil {
			return 0, 0, 0, err
		}
		return g.LeaveHuman(ev.arg, z)
	case "OBJECT_MOVE":
		o, err := strip("object:")
		if err != nil {
			return 0, 0, 0, err
		}
		return g.MoveObject(o, ev.arg)
	}
	return 0, 0, 0, fmt.Errorf("unknown event kind %q", ev.kind)
}

func yamlToJSONValue(src string) (any, error) {
	var v any
	if err := yaml.Unmarshal([]byte(src), &v); err != nil {
		return nil, err
	}
	return normalizeYAML(v), nil
}

// normalizeYAML converts yaml.v3's generic decoding into JSON-marshalable
// values (string-keyed maps). yaml.v3 already yields map[string]interface{}
// for string keys; this guards nested values.
func normalizeYAML(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range t {
			out[k] = normalizeYAML(val)
		}
		return out
	case map[any]any:
		out := map[string]any{}
		for k, val := range t {
			out[fmt.Sprint(k)] = normalizeYAML(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalizeYAML(val)
		}
		return out
	}
	return v
}

func buildWorld() (*jWorld, error) {
	out := &jWorld{}

	// WLD-01: compile + seven events + two requests.
	{
		g, _, err := graph.Compile([]byte(siteYAMLW1))
		if err != nil {
			return nil, fmt.Errorf("WLD-01 compile: %v", err)
		}
		site, err := yamlToJSONValue(siteYAMLW1)
		if err != nil {
			return nil, err
		}
		jc := jWorldCase{ID: "WLD-01", Title: "compile a full declaration, then seven context events, then two requests", Expect: "accept", SiteYAML: siteYAMLW1, Site: site, Events: []jEvent{}, Requests: []jWorldRequest{}}
		events := []evSpec{
			{"HUMAN_ENTER", "zone:z8", "h1"},
			{"HUMAN_ENTER", "zone:z8", "h1"},
			{"OBJECT_MOVE", "object:box1", "z7"},
			{"MAINTENANCE_ON", "robot:tb2", ""},
			{"HUMAN_LEAVE", "zone:z8", "h1"},
			{"CORDON_ON", "robot:tb1", ""},
			{"CORDON_OFF", "robot:tb1", ""},
		}
		for _, ev := range events {
			oldV, newV, epoch, err := applyEvent(g, ev)
			if err != nil {
				return nil, fmt.Errorf("WLD-01 %s: %v", ev.kind, err)
			}
			jc.Events = append(jc.Events, jEvent{Kind: ev.kind, NodeID: ev.nodeID, Arg: ev.arg, Epoch: epoch, OldVersion: oldV, NewVersion: newV})
		}
		jc.Graph = graphToJSON(g)
		gb, err := graph.CanonicalGraph(g)
		if err != nil {
			return nil, err
		}
		jc.GraphSHA256 = hashHex(gb)
		for _, rq := range []jRequest{{RobotID: "tb1", TargetObjectID: "box1"}, {RobotID: "tb2"}} {
			sg, err := graph.BuildSubgraph(graph.ActionRequest{SubgraphID: "w", RobotID: rq.RobotID, TargetObjectID: rq.TargetObjectID}, g)
			if err != nil {
				return nil, err
			}
			h, err := graph.SnapshotHash(sg)
			if err != nil {
				return nil, err
			}
			jc.Requests = append(jc.Requests, jWorldRequest{RobotID: rq.RobotID, TargetObjectID: rq.TargetObjectID, NodeIDs: sortedNodeIDs(sg), SHA256: hex.EncodeToString(h[:])})
		}
		out.Cases = append(out.Cases, jc)
	}

	// WLD-02: minimal declaration → empty graph at epoch 0.
	{
		g, _, err := graph.Compile([]byte(siteYAMLMinimal))
		if err != nil {
			return nil, fmt.Errorf("WLD-02 compile: %v", err)
		}
		site, _ := yamlToJSONValue(siteYAMLMinimal)
		gb, _ := graph.CanonicalGraph(g)
		out.Cases = append(out.Cases, jWorldCase{ID: "WLD-02", Title: "minimal declaration: no nodes, no edges, epoch 0", Expect: "accept",
			SiteYAML: siteYAMLMinimal, Site: site, Events: []jEvent{}, Graph: graphToJSON(g), GraphSHA256: hashHex(gb), Requests: []jWorldRequest{}})
	}

	// Rejects.
	for _, rc := range []struct{ id, title, src, reason string }{
		{"WLD-90", "reject: speed_limit is refused by the compiler (per-zone limits live in the gate policy, not the world)", siteYAMLSpeedLimit, "speed_limit"},
		{"WLD-91", "reject: unknown constraint type", siteYAMLUnknownType, "unknown_constraint_type"},
		{"WLD-92", "reject: robot home names an undeclared zone", siteYAMLDangling, "dangling_reference"},
	} {
		if _, _, err := graph.Compile([]byte(rc.src)); err == nil {
			return nil, fmt.Errorf("%s: expected compile to refuse", rc.id)
		}
		site, _ := yamlToJSONValue(rc.src)
		out.Cases = append(out.Cases, jWorldCase{ID: rc.id, Title: rc.title, Expect: "reject", Reason: rc.reason, SiteYAML: rc.src, Site: site, Events: []jEvent{}, Requests: []jWorldRequest{}})
	}
	return out, nil
}

// ------------------------------------------------------------------ output

func writeJSON(path string, v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	return b, os.WriteFile(path, b, 0o644)
}

func main() {
	dest := flag.String("dest", "", "output directory (created if missing)")
	flag.Parse()
	if *dest == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gensubgraphvec -dest DIR")
		os.Exit(2)
	}

	cases, err := buildCases()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gensubgraphvec: self-verification failed:", err)
		os.Exit(1)
	}
	sel, err := buildSelection()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gensubgraphvec: self-verification failed:", err)
		os.Exit(1)
	}
	world, err := buildWorld()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gensubgraphvec: self-verification failed:", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(*dest, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "gensubgraphvec:", err)
		os.Exit(1)
	}
	files := map[string]any{"cases.json": cases, "selection.json": sel, "world.json": world}
	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)
	var lines []string
	for _, name := range names {
		b, err := writeJSON(filepath.Join(*dest, name), files[name])
		if err != nil {
			fmt.Fprintln(os.Stderr, "gensubgraphvec:", err)
			os.Exit(1)
		}
		lines = append(lines, fmt.Sprintf("%s  %s", hashHex(b), name))
	}
	body := strings.Join(lines, "\n") + "\n"
	set := hashHex([]byte(body))
	manifest := "# spec/subgraph-vectors/MANIFEST.sha256 — subgraph snapshot hash conformance vector set\n" +
		"#\n" +
		"# Per-file hash = SHA-256(file bytes).\n" +
		"# set_sha256 = SHA-256 over the \"<hex>  <name>\" lines below, sorted by file name, each\n" +
		"#              terminated by LF. Comment lines and the set_sha256 line are not inputs.\n" +
		"#\n" +
		"# This set is a different plane from the canon serialization set (spec/vectors/canon)\n" +
		"# and from the Merkle set (spec/merkle-vectors): those fix how bytes are written and\n" +
		"# how the log is folded; this one fixes how the world slice a token was issued\n" +
		"# against is encoded, selected, and hashed. Separate manifests because they are\n" +
		"# revised for unrelated reasons.\n" +
		"#\n" +
		"# Generated by cmd/gensubgraphvec (internal). The independent checker is\n" +
		"# spec/tools/spec_subgraph_check.py.\n" +
		body + "set_sha256  " + set + "\n"
	if err := os.WriteFile(filepath.Join(*dest, "MANIFEST.sha256"), []byte(manifest), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gensubgraphvec:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d files to %s\nset_sha256  %s\nSG-01 sha256 %s (golden G1)\n", len(names)+1, *dest, set, GoldenG1SHA256)
}
