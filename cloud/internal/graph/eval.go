// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

// Violation reasons returned by Evaluate. These are proto-free; CG1 maps them to
// the existing burst/reason codes (reason_map.go, 0x10..0x99) — no new wire code
// is introduced in the CG0..CG1 scope.
const (
	ReasonOK          = ""
	ReasonHumanInZone = "HUMAN_IN_ZONE" // a HUMAN node shares the agent's zone
	ReasonMaintenance = "NODE_MAINTENANCE"
	ReasonCordoned    = "NODE_CORDONED"
)

// Evaluate re-expresses the fixed predicates (human-safety, maintenance,
// cordon) as a subgraph query. It returns (violated, reason). CG1 requires this
// to produce bit-identical verdicts to the legacy predicates on the v1 fleet —
// the regression gate enforces that; this function does not change WHAT is
// decided, only makes the decision expressible as a graph query.
//
// v1 scope: human-in-zone + node lifecycle state. Geo-fence and speed limits are
// carried as constraint nodes but enforced at CG1 issuance (they need the
// concrete request parameters), not here.
func Evaluate(sg *Subgraph) (bool, string) {
	// Agent lifecycle state: maintenance/cordoned agents get no new tokens.
	for _, n := range sg.Nodes {
		if n.Kind != KindAgent {
			continue
		}
		switch n.State {
		case StateMaintenance:
			return true, ReasonMaintenance
		case StateCordoned:
			return true, ReasonCordoned
		}
	}

	// Human exclusion: if a HUMAN node is LOCATED_IN a zone the agent is in.
	agentZones := make(map[string]struct{})
	for _, n := range sg.Nodes {
		if n.Kind == KindZone {
			agentZones[n.ID] = struct{}{}
		}
	}
	for _, e := range sg.Edges {
		if e.Rel != RelLocatedIn {
			continue
		}
		if _, isZone := agentZones[e.To]; !isZone {
			continue
		}
		if n, ok := nodeByID(sg.Nodes, e.From); ok && n.Kind == KindHuman {
			return true, ReasonHumanInZone
		}
	}
	return false, ReasonOK
}

func nodeByID(nodes []*Node, id string) (*Node, bool) {
	for _, n := range nodes {
		if n.ID == id {
			return n, true
		}
	}
	return nil, false
}
