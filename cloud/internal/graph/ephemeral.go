// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

// EphemeralConstraints are the per-token policy limits the issuer knows at
// issuance time when no site model is loaded. A zero value means "not set" and
// contributes nothing to the ephemeral world (the constraint node is only
// created when at least one limit is positive, and only positive limits become
// attributes).
type EphemeralConstraints struct {
	MaxLinearSpeedMps  float64
	MaxAngularSpeedRps float64
	MaxDurationSec     float64
}

// EphemeralEpoch is the fixed graph epoch of an ephemeral issuance world. There
// is no standing site graph to mutate, so the epoch never moves.
const EphemeralEpoch uint64 = 0

// EphemeralIssuanceGraph assembles the per-request world slice the issuer
// authorizes against when PAIL_SITE_MODEL is not set (the pre-site-model
// behaviour, kept bit-identical): the acting agent at version 1, one
// constraint node `constraint:speed@<robot>` carrying the positive limits, and
// the target object at version 1 if one is named. robotID/targetObjectID are
// bare local ids; the "robot:"/"object:" prefixes are added here.
//
// This is spec surface: spec/SUBGRAPH_HASH.md §6.3 states these rules and the
// frozen selection vectors pin their bytes. Changing anything here changes
// every ephemeral-mode snapshot hash and must be an intentional, reviewed
// evidence-format change.
func EphemeralIssuanceGraph(robotID, targetObjectID string, c *EphemeralConstraints) *Graph {
	g := NewGraph()
	g.Epoch = EphemeralEpoch

	agentID := "robot:" + robotID
	g.Nodes[agentID] = &Node{ID: agentID, Kind: KindAgent, State: StateActive, Version: 1}

	if c != nil && (c.MaxLinearSpeedMps > 0 || c.MaxAngularSpeedRps > 0 || c.MaxDurationSec > 0) {
		cid := "constraint:speed@" + robotID
		attrs := map[string]AttrVal{}
		if c.MaxLinearSpeedMps > 0 {
			attrs["max_linear_speed_mps"] = ADouble(c.MaxLinearSpeedMps)
		}
		if c.MaxAngularSpeedRps > 0 {
			attrs["max_angular_speed_rps"] = ADouble(c.MaxAngularSpeedRps)
		}
		if c.MaxDurationSec > 0 {
			attrs["max_duration_sec"] = ADouble(c.MaxDurationSec)
		}
		g.Nodes[cid] = &Node{ID: cid, Kind: KindConstraint, State: StateActive, Version: 1, Attrs: attrs}
		g.Edges = append(g.Edges, Edge{From: cid, To: agentID, Rel: RelConstrains})
	}

	if targetObjectID != "" {
		objID := "object:" + targetObjectID
		g.Nodes[objID] = &Node{ID: objID, Kind: KindObject, State: StateActive, Version: 1}
	}
	return g
}
