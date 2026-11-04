// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

import "fmt"

// CG-E1 mutations. These operate in place and are NOT thread-safe: the issuer
// holds a single write lock around both mutation and issuance-time reads so every
// token in a plan is signed against one consistent epoch (single-writer world
// cut). Each accepted mutation bumps the target node's Version and the global
// Epoch monotonically, so RecordGraphMutation entries replay deterministically
// (CG3 snapshot recompute).
//
// All mutators are fail-closed: an unknown node/zone is an error, never a silent
// no-op — a dropped mutation is a safety incident (a human the issuer never
// learned about).

// Clone returns a deep copy of the graph. The caller holds the write lock; the
// returned graph is an independent world cut safe to read (build subgraphs, hash)
// without the lock, so signing never blocks ingest.
func (g *Graph) Clone() *Graph {
	c := &Graph{Epoch: g.Epoch, Nodes: make(map[string]*Node, len(g.Nodes))}
	for id, n := range g.Nodes {
		c.Nodes[id] = n.clone()
	}
	if len(g.Edges) > 0 {
		c.Edges = append([]Edge(nil), g.Edges...)
	}
	return c
}

func (g *Graph) hasEdge(from, to string, rel EdgeRel) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to && e.Rel == rel {
			return true
		}
	}
	return false
}

// removeEdges drops every edge matching (from, rel) and, when to != "", also the
// specific To. It returns the surviving edges.
func (g *Graph) removeEdges(from, to string, rel EdgeRel) {
	kept := g.Edges[:0:0]
	for _, e := range g.Edges {
		if e.From == from && e.Rel == rel && (to == "" || e.To == to) {
			continue
		}
		kept = append(kept, e)
	}
	g.Edges = kept
}

func (g *Graph) hasAnyEdgeFrom(from string, rel EdgeRel) bool {
	for _, e := range g.Edges {
		if e.From == from && e.Rel == rel {
			return true
		}
	}
	return false
}

// SetNodeState transitions an existing node to st. Used for MAINTENANCE_ON/OFF
// and CORDON_ON/OFF (node_id is a fully-qualified id, e.g. "robot:robot-01").
func (g *Graph) SetNodeState(nodeID string, st NodeState) (oldV, newV, epoch uint64, err error) {
	n, ok := g.Nodes[nodeID]
	if !ok {
		return 0, 0, g.Epoch, fmt.Errorf("no such node %q", nodeID)
	}
	oldV = n.Version
	n.State = st
	n.Version++
	g.Epoch++
	return oldV, n.Version, g.Epoch, nil
}

// EnterHuman records a human present in a declared zone (bare local ids). The
// human node is created on first sighting; a repeat sighting bumps its version.
func (g *Graph) EnterHuman(humanLocal, zoneLocal string) (oldV, newV, epoch uint64, err error) {
	zid := "zone:" + zoneLocal
	if _, ok := g.Nodes[zid]; !ok {
		return 0, 0, g.Epoch, fmt.Errorf("no such zone %q", zoneLocal)
	}
	hid := "human:" + humanLocal
	n, ok := g.Nodes[hid]
	if !ok {
		n = &Node{ID: hid, Kind: KindHuman, State: StateActive, Version: 0}
		g.Nodes[hid] = n
	} else {
		oldV = n.Version
		n.Version++
	}
	if !g.hasEdge(hid, zid, RelLocatedIn) {
		g.Edges = append(g.Edges, Edge{From: hid, To: zid, Rel: RelLocatedIn})
	}
	g.Epoch++
	return oldV, n.Version, g.Epoch, nil
}

// LeaveHuman removes a human's presence in a zone. When the human is no longer in
// any zone its node is dropped entirely.
func (g *Graph) LeaveHuman(humanLocal, zoneLocal string) (oldV, newV, epoch uint64, err error) {
	hid := "human:" + humanLocal
	n, ok := g.Nodes[hid]
	if !ok {
		return 0, 0, g.Epoch, fmt.Errorf("no such human %q", humanLocal)
	}
	oldV = n.Version
	g.removeEdges(hid, "zone:"+zoneLocal, RelLocatedIn)
	if g.hasAnyEdgeFrom(hid, RelLocatedIn) {
		n.Version++
		newV = n.Version
	} else {
		delete(g.Nodes, hid)
		newV = oldV + 1 // node gone; report a monotonic step for the record
	}
	g.Epoch++
	return oldV, newV, g.Epoch, nil
}

// MoveObject relocates an object's LOCATED_IN edge to a declared destination zone.
func (g *Graph) MoveObject(objectLocal, destZoneLocal string) (oldV, newV, epoch uint64, err error) {
	oid := "object:" + objectLocal
	n, ok := g.Nodes[oid]
	if !ok {
		return 0, 0, g.Epoch, fmt.Errorf("no such object %q", objectLocal)
	}
	zid := "zone:" + destZoneLocal
	if _, ok := g.Nodes[zid]; !ok {
		return 0, 0, g.Epoch, fmt.Errorf("no such zone %q", destZoneLocal)
	}
	oldV = n.Version
	g.removeEdges(oid, "", RelLocatedIn)
	g.Edges = append(g.Edges, Edge{From: oid, To: zid, Rel: RelLocatedIn})
	n.Version++
	g.Epoch++
	return oldV, n.Version, g.Epoch, nil
}
