// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import "github.com/glowfly/pail/services/pkg/robotid"

// CollectorProbe describes the registry actually parsed for this query. The
// collector resolves names per request; it is NOT a startup-loaded cache.
type CollectorProbe struct {
	SchemaVersion      int              `json:"schema_version"`
	Component          string           `json:"component"`
	InstanceID         string           `json:"instance_id"`
	BuildID            string           `json:"build_id"`
	Nonce              string           `json:"nonce"`
	GeneratedAtMS      int64            `json:"generated_at_ms"`
	ResolutionStrategy string           `json:"resolution_strategy"`
	RegistryState      string           `json:"registry_state"`
	RegistryDigest     string           `json:"registry_digest"`
	Robots             []CollectorRobot `json:"robots"`
	EvidenceKind       string           `json:"evidence_kind"`
}
type CollectorRobot struct {
	RobotID   string `json:"robot_id"`
	RobotHash string `json:"robot_hash"`
}

// CollectorRobotHash uses the collector's canonical hash implementation.
func CollectorRobotHash(id string) string { return robotid.Hash16(id) }
