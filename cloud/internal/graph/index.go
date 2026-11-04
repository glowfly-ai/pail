// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

import "sort"

// ReverseIndex maps node_id -> set of active subgraph IDs referencing it. It is
// the dependency inverse used by selective revocation (CG2): a context event on
// a node yields exactly the affected subgraphs in O(|affected|), instead of
// scanning all active tokens. CG0 ships the structure and proves it correct;
// CG2 wires it into the revocation path.
type ReverseIndex struct {
	byNode map[string]map[string]struct{} // node_id -> set<subgraph_id>
	bySub  map[string][]string            // subgraph_id -> node_ids (for removal)
}

// NewReverseIndex returns an empty index.
func NewReverseIndex() *ReverseIndex {
	return &ReverseIndex{
		byNode: make(map[string]map[string]struct{}),
		bySub:  make(map[string][]string),
	}
}

// Add registers a subgraph under every node it references. Re-adding the same
// subgraph ID first removes the old registration (idempotent replace).
func (ri *ReverseIndex) Add(sg *Subgraph) {
	if sg.ID == "" {
		return
	}
	ri.Remove(sg.ID)
	nodeIDs := make([]string, 0, len(sg.Nodes))
	for _, n := range sg.Nodes {
		if _, ok := ri.byNode[n.ID]; !ok {
			ri.byNode[n.ID] = make(map[string]struct{})
		}
		ri.byNode[n.ID][sg.ID] = struct{}{}
		nodeIDs = append(nodeIDs, n.ID)
	}
	ri.bySub[sg.ID] = nodeIDs
}

// Remove unregisters a subgraph from all nodes it referenced.
func (ri *ReverseIndex) Remove(subgraphID string) {
	nodeIDs, ok := ri.bySub[subgraphID]
	if !ok {
		return
	}
	for _, nid := range nodeIDs {
		if set, ok := ri.byNode[nid]; ok {
			delete(set, subgraphID)
			if len(set) == 0 {
				delete(ri.byNode, nid)
			}
		}
	}
	delete(ri.bySub, subgraphID)
}

// Affected returns the sorted set of subgraph IDs referencing any of the given
// node IDs (the minimum blast radius of a context event).
func (ri *ReverseIndex) Affected(nodeIDs ...string) []string {
	seen := make(map[string]struct{})
	for _, nid := range nodeIDs {
		for sid := range ri.byNode[nid] {
			seen[sid] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for sid := range seen {
		out = append(out, sid)
	}
	sort.Strings(out)
	return out
}
