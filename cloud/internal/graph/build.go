// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

// ActionRequest is a proto-free description of an action-token request. CG1
// adapts the proto RequestActionToken into this struct so that this package
// stays independent of proto (canonical, testable value types only).
type ActionRequest struct {
	SubgraphID     string // caller-assigned id (e.g. token_id) for the reverse index
	RobotID        string // node id without the "robot:" prefix
	TargetObjectID string // node id without the "object:" prefix; "" if none
}

// BuildSubgraph selects the execution-authorization subgraph for a request: the
// acting agent, its current zone (LOCATED_IN), constraints on that agent/zone
// (CONSTRAINS), the agent's executor (OPERATES), and the target object
// (TARGETS) if any. Referenced nodes are deep-copied so the snapshot is frozen
// at issuance-time versions/attrs.
//
// Determinism note: node/edge selection order does not affect the snapshot hash
// (the canonical encoder sorts). The returned slices may be in any order.
func BuildSubgraph(req ActionRequest, g *Graph) (*Subgraph, error) {
	agentID := "robot:" + req.RobotID
	picked := make(map[string]*Node)
	var edges []Edge

	add := func(id string) {
		if n, ok := g.Nodes[id]; ok {
			if _, done := picked[id]; !done {
				picked[id] = n.clone()
			}
		}
	}

	add(agentID)

	// Walk edges once, pulling in neighbors relevant to the request.
	for _, e := range g.Edges {
		switch {
		case e.From == agentID && e.Rel == RelLocatedIn:
			add(e.To) // agent's zone
			edges = append(edges, e)
		case e.From == agentID && e.Rel == RelOperates:
			add(e.To) // executor
			edges = append(edges, e)
		}
	}

	// Zones the agent is in — pull constraints that CONSTRAINS them.
	zoneIDs := make(map[string]struct{})
	for id, n := range picked {
		if n.Kind == KindZone {
			zoneIDs[id] = struct{}{}
		}
	}
	for _, e := range g.Edges {
		if e.Rel != RelConstrains {
			continue
		}
		_, toAgent := (map[string]struct{}{agentID: {}})[e.To]
		_, toZone := zoneIDs[e.To]
		if toAgent || toZone {
			add(e.From) // the constraint node
			edges = append(edges, e)
		}
	}

	// Humans co-located in the agent's zones (human-exclusion evidence). The
	// CG1 ephemeral issuance graph never contained humans, so this pass is inert
	// there; a loaded site graph mutated by HUMAN_ENTER events populates it.
	for _, e := range g.Edges {
		if e.Rel != RelLocatedIn {
			continue
		}
		if _, inZone := zoneIDs[e.To]; !inZone {
			continue
		}
		if n, ok := g.Nodes[e.From]; ok && n.Kind == KindHuman {
			add(e.From)
			edges = append(edges, e)
		}
	}

	// Target object.
	if req.TargetObjectID != "" {
		objID := "object:" + req.TargetObjectID
		add(objID)
		edges = append(edges, Edge{From: agentID, To: objID, Rel: RelTargets})
		// object location, if modeled
		for _, e := range g.Edges {
			if e.From == objID && e.Rel == RelLocatedIn {
				add(e.To)
				edges = append(edges, e)
			}
		}
	}

	nodes := make([]*Node, 0, len(picked))
	for _, n := range picked {
		nodes = append(nodes, n)
	}
	return &Subgraph{
		ID:         req.SubgraphID,
		GraphEpoch: g.Epoch,
		Nodes:      nodes,
		Edges:      edges,
	}, nil
}
