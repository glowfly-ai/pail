// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package graph is the PAIL context-graph core library (milestone CG0).
//
// Scope (CG0): pure value types + a deterministic canonical encoder + snapshot
// hash + a reverse-index structure. This package does NOT touch the live issuer,
// proto, or the gate — it is imported by nobody until CG1. It depends only on the
// standard library plus golang.org/x/text (NFC), so the running demo is unaffected.
//
// The canonical encoder is the heart of evidence integrity: the same logical
// world must serialize to the same bytes (hence the same hash) regardless of map
// or slice ordering. proto3 serialization is non-canonical and is therefore never
// used for evidence — see encode.go.
package graph

// NodeKind classifies a node. KindUnspecified must never appear in an encoded
// graph (the encoder rejects it, fail-closed).
type NodeKind uint8

const (
	KindUnspecified NodeKind = 0
	KindAgent       NodeKind = 1 // robot:*   — the acting robot
	KindExecutor    NodeKind = 2 // executor:* — the driven body (arm/base); v1 is 1:1 with agent
	KindObject      NodeKind = 3 // object:*
	KindZone        NodeKind = 4 // zone:*
	KindHuman       NodeKind = 5 // human:*
	KindConstraint  NodeKind = 6 // constraint:*
)

// NodeState is reserved for CG2/CG-E1. The v1 issuance path treats only
// StateActive as normal; MAINTENANCE/CORDONED cause new-issuance refusal (CG-E1).
type NodeState uint8

const (
	StateActive      NodeState = 0
	StateMaintenance NodeState = 1 // LOTO (gap O-3)
	StateCordoned    NodeState = 2 // isolation (gap O-11)
)

// EdgeRel is the relation type of a directed edge.
type EdgeRel uint8

const (
	RelUnspecified EdgeRel = 0
	RelLocatedIn   EdgeRel = 1 // agent|object -> zone
	RelTargets     EdgeRel = 2 // agent -> object
	RelConstrains  EdgeRel = 3 // constraint -> {zone|agent|object}
	RelOperates    EdgeRel = 4 // agent -> executor
	RelOccupies    EdgeRel = 5 // agent -> object (P4/CG4 reserve; v1 issuance does not evaluate)
)

// AttrTag is the type tag of an attribute value. Tags make attribute maps
// canonically encodable (no ambiguous string/number/bool coercion).
type AttrTag uint8

const (
	TagString AttrTag = 0x01
	TagInt64  AttrTag = 0x02
	TagDouble AttrTag = 0x03
	TagBool   AttrTag = 0x04
)

// AttrVal is a typed attribute value. Only the field selected by Tag is
// meaningful; the encoder reads exactly that field.
type AttrVal struct {
	Tag AttrTag
	S   string
	I   int64
	F   float64
	B   bool
}

// AString/AInt/ADouble/ABool are constructors keeping call sites terse.
func AString(s string) AttrVal  { return AttrVal{Tag: TagString, S: s} }
func AInt(i int64) AttrVal      { return AttrVal{Tag: TagInt64, I: i} }
func ADouble(f float64) AttrVal { return AttrVal{Tag: TagDouble, F: f} }
func ABool(b bool) AttrVal      { return AttrVal{Tag: TagBool, B: b} }

// Node is a world entity. ID follows the "kind:local" convention
// (e.g. "zone:z7", "robot:tb1"). Version is a per-node monotonic counter bumped
// on every mutation.
type Node struct {
	ID      string
	Kind    NodeKind
	State   NodeState
	Attrs   map[string]AttrVal
	Version uint64
}

// clone returns a deep copy so a subgraph snapshot is immutable against later
// graph mutation (P0 claim 6: the snapshot is issuance-time evidence).
func (n *Node) clone() *Node {
	c := &Node{ID: n.ID, Kind: n.Kind, State: n.State, Version: n.Version}
	if n.Attrs != nil {
		c.Attrs = make(map[string]AttrVal, len(n.Attrs))
		for k, v := range n.Attrs {
			c.Attrs[k] = v
		}
	}
	return c
}

// Edge is a directed relation between two node IDs.
type Edge struct {
	From string
	To   string
	Rel  EdgeRel
}

// Graph is the issuer-side world model. Epoch is a global monotonic version
// bumped on every mutation.
type Graph struct {
	Epoch uint64
	Nodes map[string]*Node
	Edges []Edge
}

// NewGraph returns an empty graph at epoch 0.
func NewGraph() *Graph {
	return &Graph{Nodes: make(map[string]*Node)}
}

// Subgraph is the execution-authorization subgraph (P0 ref 210): the world slice
// selected at issuance time. ID identifies the subgraph for the reverse index
// (CG2) and is NOT part of the canonical/snapshot bytes — the snapshot commits
// world state only; token identifiers are committed by other token fields.
type Subgraph struct {
	ID         string
	GraphEpoch uint64
	Nodes      []*Node
	Edges      []Edge
}
