// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

// SignalProbe is RECEIVER evidence. Legacy packets do not bind a query nonce,
// producer boot epoch, or a per-robot signing-key identity. They cannot establish
// current authorization, producer freshness or a physical stop.
type SignalProbe struct {
	SchemaVersion       int              `json:"schema_version"`
	Component           string           `json:"component"`
	InstanceID          string           `json:"instance_id"`
	ClockID             string           `json:"clock_id"`
	Nonce               string           `json:"nonce"`
	GeneratedAtMS       int64            `json:"generated_at_ms"`
	RegistryState       string           `json:"registry_state"`
	RegistryDigest      string           `json:"registry_digest"`
	RegistryRobots      []CollectorRobot `json:"registry_robots"`
	Signals             []RobotSignals   `json:"signals"`
	DroppedSubjects     uint64           `json:"dropped_subjects"`
	UntrackedUnverified uint64           `json:"untracked_unverified"`
	EvidenceKind        string           `json:"evidence_kind"`
	SourceFreshness     string           `json:"source_freshness"`
	IdentityBasis       string           `json:"identity_basis"`
}
type RobotSignals struct {
	RobotHash string        `json:"robot_hash"`
	Burst     SignalReceipt `json:"burst"`
	Mirror    SignalReceipt `json:"mirror"`
}
type SignalReceipt struct {
	State           string           `json:"state"`
	Signature       string           `json:"signature"`
	KeyRole         string           `json:"key_role"`
	LatestAgeMS     int64            `json:"latest_receive_age_ms"`
	AdvancingAgeMS  int64            `json:"advancing_receive_age_ms"`
	Sequence        uint32           `json:"sequence"`
	ProgressSamples uint64           `json:"progress_samples"`
	NonAdvancing    uint64           `json:"nonadvancing_samples"`
	Event           string           `json:"event"`
	MirrorStatement *MirrorStatement `json:"mirror_statement"`
}

// MirrorStatement is absent for burst/never-observed rows. Zero-valued claims
// must not be fabricated by serializing fields of the wrong packet kind.
type MirrorStatement struct {
	PermitAgeMS uint32 `json:"permit_age_ms"`
	DeadmanMS   uint16 `json:"deadman_window_ms"`
	TickMS      uint16 `json:"tick_ms"`
	Mode        string `json:"mode"`
}
