// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ProjectionSnapshot (LLD §12.2/§13) is the sanitized, read-only view the
// executor publishes for the collector's /v1/telemetry/robotops endpoint. It
// carries states and digests only: no approval bytes, keys, secret handles or
// private paths. The collector validates it; it never trusts a row because a
// file claims to be a projection.
type ProjectionSnapshot struct {
	SchemaVersion    int             `json:"schema_version"`
	DocumentKind     string          `json:"document_kind"`
	DeploymentID     string          `json:"deployment_id"`
	SnapshotRevision uint64          `json:"snapshot_revision"`
	Source           string          `json:"source"`
	Producer         string          `json:"producer"`
	GeneratedAtMS    int64           `json:"generated_at_ms"`
	Capabilities     []string        `json:"capabilities"`
	Rows             []ProjectionRow `json:"rows"`
	Findings         []string        `json:"findings"`
}
type ProjectionRow struct {
	RobotID           string             `json:"robot_id"`
	DisplayName       string             `json:"display_name"`
	Lifecycle         string             `json:"lifecycle"`
	DesiredGeneration string             `json:"desired_generation"`
	ExecutionID       string             `json:"execution_id"`
	JobState          string             `json:"job_state"`
	Registration      map[string]string  `json:"registration"`
	LoadedConfig      []ProjectionLoaded `json:"loaded_config"`
	IdentityBinding   map[string]string  `json:"identity_binding"`
	ApplyReadiness    string             `json:"apply_readiness"`
	Findings          []string           `json:"findings"`
	Diagnostics       map[string]string  `json:"diagnostics"`
}
type ProjectionLoaded struct {
	ComponentRef string `json:"component_ref"`
	Kind         string `json:"kind"`
	Status       string `json:"status"`
	Reason       string `json:"reason"`
}

const ProjectionSchemaVersion = 1

var forbiddenProjectionKeys = []string{"private_key", "secret", "approval_document", "signature", "seed", "token"}

// DecodeProjection strictly decodes and validates a snapshot: schema version,
// deployment id, non-empty rows with valid robot ids, bounded sizes, no
// absolute paths in string values and no forbidden keys anywhere.
func DecodeProjection(raw []byte) (ProjectionSnapshot, error) {
	var p ProjectionSnapshot
	var generic map[string]interface{}
	if err := StrictDecode(raw, &generic, []string{"schema_version", "document_kind", "deployment_id", "snapshot_revision", "source", "producer", "generated_at_ms", "capabilities", "rows", "findings"}); err != nil {
		return p, err
	}
	if v, _ := generic["schema_version"].(float64); int(v) != ProjectionSchemaVersion {
		return p, fmt.Errorf("SCHEMA_UNSUPPORTED")
	}
	if err := scanProjectionValue(generic, ""); err != nil {
		return p, err
	}
	if err := StrictDecode(raw, &p, nil); err != nil {
		return p, err
	}
	if p.DocumentKind != "RobotOpsProjection" || !deploymentName.MatchString(p.DeploymentID) || p.SnapshotRevision > uint64(MaxSafeInteger) || p.GeneratedAtMS <= 0 || p.Source == "" || p.Producer == "" {
		return p, fmt.Errorf("RO_SCHEMA: projection header invalid")
	}
	if len(p.Rows) > 1000 {
		return p, fmt.Errorf("RO_SCHEMA: too many rows")
	}
	seen := map[string]bool{}
	for i, r := range p.Rows {
		if !robotName.MatchString(r.RobotID) || seen[r.RobotID] {
			return p, fmt.Errorf("RO_SCHEMA: invalid or repeated robot id at row %d", i)
		}
		seen[r.RobotID] = true
		switch r.Lifecycle {
		case "planned", "active", "disabled", "retired":
		default:
			return p, fmt.Errorf("RO_SCHEMA: invalid lifecycle at row %d", i)
		}
		if r.ApplyReadiness == "" || r.JobState == "" {
			return p, fmt.Errorf("RO_SCHEMA: readiness/job state required at row %d", i)
		}
	}
	return p, nil
}

func scanProjectionValue(v interface{}, path string) error {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			lk := strings.ToLower(k)
			for _, f := range forbiddenProjectionKeys {
				if strings.Contains(lk, f) {
					return fmt.Errorf("RO_SCHEMA: forbidden key in projection: %s", path+"/"+k)
				}
			}
			if err := scanProjectionValue(val, path+"/"+k); err != nil {
				return err
			}
		}
	case []interface{}:
		for i, val := range t {
			if err := scanProjectionValue(val, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case string:
		if strings.HasPrefix(t, "/") && len(t) > 1 && !strings.HasPrefix(t, "/v1/") {
			return fmt.Errorf("RO_SCHEMA: absolute path in projection value at %s", path)
		}
		if len(t) > 4096 {
			return fmt.Errorf("RO_SCHEMA: oversized string at %s", path)
		}
	}
	return nil
}

// MembershipETag changes only with the list itself (robot id, display name,
// lifecycle, desired generation), never with heartbeat times or diagnostics.
func MembershipETag(p ProjectionSnapshot) string {
	rows := make([]string, 0, len(p.Rows))
	for _, r := range p.Rows {
		rows = append(rows, r.RobotID+"\x00"+r.DisplayName+"\x00"+r.Lifecycle+"\x00"+r.DesiredGeneration)
	}
	sort.Strings(rows)
	sum := sha256.Sum256([]byte("pail.robotops.membership/v1\n" + p.DeploymentID + "\n" + strings.Join(rows, "\n")))
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}
