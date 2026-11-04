// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

import "crypto/sha256"

// SnapshotHash returns SHA-256 over the canonical subgraph bytes. This 32-byte
// value is what CG1 binds into ActionToken.subgraph_snapshot_hash (field 61),
// covered by the token signature. It errors if the subgraph is not encodable
// (unspecified kind, non-finite double, duplicate node_id) — fail-closed: an
// unencodable world must not be issued against.
func SnapshotHash(sg *Subgraph) ([32]byte, error) {
	b, err := CanonicalSubgraph(sg)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// GraphHash returns SHA-256 over the canonical whole-graph bytes. Used for
// genesis/mutation evidence records (CG-E1) and debugging determinism.
func GraphHash(g *Graph) ([32]byte, error) {
	b, err := CanonicalGraph(g)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}
