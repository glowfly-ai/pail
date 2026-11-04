// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package robotops defines the offline robot-operations inspection contract.
// It contains no issuer, network client, credential minting or deployment code.
package robotops

import (
	"encoding/json"
	"fmt"
	"golang.org/x/text/unicode/norm"
	"regexp"
	"strings"
)

const SchemaVersion = 1
const MaxDocument = 4 << 20
const MaxSafeInteger = int64(9007199254740991)

var robotName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var refName = regexp.MustCompile(`^(res|cmp|cred):[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var deploymentName = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Inventory describes intent, not an authorization grant or loaded runtime state.
type Inventory struct {
	SchemaVersion    int      `json:"schema_version"`
	DeploymentID     string   `json:"deployment_id"`
	Revision         uint64   `json:"revision"`
	BaseRevision     *uint64  `json:"base_revision"`
	ProfileID        string   `json:"profile_id"`
	Robots           []Robot  `json:"robots"`
	ResourceBindings Bindings `json:"resource_bindings"`
}
type Robot struct {
	RobotID             string `json:"robot_id"`
	DisplayName         string `json:"display_name"`
	Lifecycle           string `json:"lifecycle"`
	ClassRef            string `json:"class_ref"`
	HomeRef             string `json:"home_ref"`
	AgentRef            string `json:"agent_ref"`
	GateRef             string `json:"gate_ref"`
	BridgeRef           string `json:"bridge_ref"`
	ClientCredentialRef string `json:"client_credential_ref"`
	RequesterRef        string `json:"requester_ref"`
	TransportRef        string `json:"transport_ref"`
	CollectorRef        string `json:"collector_ref"`
}
type Bindings struct {
	Registry  string `json:"registry"`
	SiteModel string `json:"site_model"`
	Policy    string `json:"policy"`
	Skills    string `json:"skills"`
}

// ResourceMap is a caller-supplied UNPRIVILEGED inspection map in this milestone.
// Loading it does not establish installation trust or permission to apply it.
type ResourceMap struct {
	SchemaVersion int        `json:"schema_version"`
	DeploymentID  string     `json:"deployment_id"`
	Resources     []Resource `json:"resources"`
}
type Resource struct {
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Path          string   `json:"path,omitempty"`
	Value         string   `json:"value,omitempty"`
	RobotID       string   `json:"robot_id,omitempty"`
	CredentialRef string   `json:"credential_ref,omitempty"`
	CARef         string   `json:"ca_ref,omitempty"`
	RegistryRef   string   `json:"registry_ref,omitempty"`
	UpstreamRef   string   `json:"upstream_ref,omitempty"`
	Group         string   `json:"group,omitempty"`
	Port          int      `json:"port,omitempty"`
	Skills        []string `json:"skills,omitempty"`
	RequesterKind string   `json:"requester_kind,omitempty"`
}

func DecodeInventory(raw []byte) (Inventory, error) {
	var v Inventory
	if err := StrictDecode(raw, &v, []string{"schema_version", "deployment_id", "revision", "base_revision", "profile_id", "robots", "resource_bindings"}); err != nil {
		return v, err
	}
	return v, v.Validate()
}
func (v *Inventory) Validate() error {
	if v.SchemaVersion != 1 || !deploymentName.MatchString(v.DeploymentID) {
		return fmt.Errorf("RO_SCHEMA: unsupported version or deployment id")
	}
	if v.Revision == 0 || v.Revision > uint64(MaxSafeInteger) || (v.BaseRevision == nil && v.Revision != 1) || (v.BaseRevision != nil && *v.BaseRevision >= v.Revision) {
		return fmt.Errorf("RO_SCHEMA: invalid revision relationship")
	}
	if v.ProfileID != "local-compose-ros2/v1" {
		return fmt.Errorf("RO_CAPABILITY: unsupported profile")
	}
	if len(v.Robots) == 0 || len(v.Robots) > 1024 {
		return fmt.Errorf("RO_SCHEMA: robots must contain 1..1024 entries")
	}
	seen := map[string]bool{}
	for i := range v.Robots {
		r := &v.Robots[i]
		if !robotName.MatchString(r.RobotID) || seen[r.RobotID] {
			return fmt.Errorf("RO_SCHEMA: invalid or repeated robot id at row %d", i)
		}
		seen[r.RobotID] = true
		r.DisplayName = norm.NFC.String(r.DisplayName)
		if strings.TrimSpace(r.DisplayName) == "" || len(r.DisplayName) > 512 {
			return fmt.Errorf("RO_SCHEMA: invalid display name at row %d", i)
		}
		switch r.Lifecycle {
		case "planned", "active", "disabled", "retired":
		default:
			return fmt.Errorf("RO_SCHEMA: invalid lifecycle at row %d", i)
		}
		for _, x := range []string{r.ClassRef, r.HomeRef, r.AgentRef, r.GateRef, r.BridgeRef, r.ClientCredentialRef, r.RequesterRef, r.TransportRef, r.CollectorRef} {
			if !refName.MatchString(x) {
				return fmt.Errorf("RO_SCHEMA: missing or invalid reference at robot row %d", i)
			}
		}
	}
	for _, x := range []string{v.ResourceBindings.Registry, v.ResourceBindings.SiteModel, v.ResourceBindings.Policy, v.ResourceBindings.Skills} {
		if !refName.MatchString(x) {
			return fmt.Errorf("RO_SCHEMA: invalid resource binding")
		}
	}
	return nil
}
func DecodeResourceMap(raw []byte) (ResourceMap, error) {
	var m ResourceMap
	if err := StrictDecode(raw, &m, []string{"schema_version", "deployment_id", "resources"}); err != nil {
		return m, err
	}
	if m.SchemaVersion != 1 {
		return m, fmt.Errorf("RO_SCHEMA: resource map schema_version must be 1")
	}
	if !deploymentName.MatchString(m.DeploymentID) {
		return m, fmt.Errorf("RO_SCHEMA: resource map deployment_id must be a lowercase UUID")
	}
	if len(m.Resources) == 0 {
		return m, fmt.Errorf("RO_SCHEMA: resource map resources must not be empty")
	}
	if len(m.Resources) > 10000 {
		return m, fmt.Errorf("RO_SCHEMA: resource map resources exceeds 10000 entries")
	}
	seen := map[string]bool{}
	for i, r := range m.Resources {
		if !refName.MatchString(r.ID) || seen[r.ID] {
			return m, fmt.Errorf("RO_SCHEMA: invalid or repeated resource at row %d", i)
		}
		seen[r.ID] = true
		switch r.Kind {
		case "registry", "site_model", "policy", "skills_dir", "certificate", "ca_certificate", "requesters", "private_key":
			if r.Path == "" {
				return m, fmt.Errorf("RO_SCHEMA: file resource needs a relative path")
			}
		case "class", "zone":
			if r.Value == "" {
				return m, fmt.Errorf("RO_SCHEMA: class/zone needs value")
			}
		case "agent", "gate", "bridge", "collector", "requester", "transport", "issuer":
		default:
			return m, fmt.Errorf("RO_CAPABILITY: unsupported resource kind at row %d", i)
		}
		if r.Port < 0 || r.Port > 65535 {
			return m, fmt.Errorf("RO_SCHEMA: invalid port")
		}
	}
	return m, nil
}
func (m ResourceMap) Index() map[string]Resource {
	out := map[string]Resource{}
	for _, r := range m.Resources {
		out[r.ID] = r
	}
	return out
}

// ValidateMap applies the same validation to programmatically constructed maps
// as to CLI input. A caller cannot bypass duplicate/kind checks by skipping decode.
func (m ResourceMap) ValidateMap() error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("RO_SCHEMA: resource map encoding")
	}
	_, err = DecodeResourceMap(b)
	return err
}
