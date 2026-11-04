// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package observability contains read-only, bounded observation state. It is
// not an authorization registry and cannot issue tokens or drive robots.
package observability

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"

	"github.com/google/uuid"
)

const MaxRobots = 1024
const MaxUnresolved = 1000
const MaxProviders = 2048
const MaxEvent = 64 << 10
const MaxDocument = 1 << 20

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$`)

// SourceMap is installer-owned. Paths never come from an HTTP request and
// are omitted from all responses. Empty deployment means legacy/unknown.
type SourceMap struct {
	SchemaVersion int        `json:"schema_version"`
	SourceID      string     `json:"source_id"`
	DeploymentID  string     `json:"deployment_id"`
	Providers     []Provider `json:"providers"`
}
type Provider struct {
	ProviderID   string   `json:"provider_id"`
	Kind         string   `json:"kind"`
	DeploymentID string   `json:"expected_deployment_id"`
	RobotID      string   `json:"expected_robot_id"`
	Identity     string   `json:"expected_identity"`
	PathRef      string   `json:"path_ref"`
	EndpointRef  string   `json:"endpoint_ref"`
	Allowed      []string `json:"allowed_event_kinds"`
	Owner        string   `json:"expected_owner"`
	RunID        string   `json:"expected_run_id"`
	StreamID     string   `json:"expected_stream_id"`
	Trust        string   `json:"trust_basis"`
	Role         string   `json:"role"`
	ClockBinding string   `json:"clock_binding,omitempty"`
}

// StrictJSON also rejects duplicate keys at every nesting level: the standard
// decoder alone accepts last-key-wins and is not a configuration validator.
func StrictJSON(b []byte, out any) error {
	if len(b) > MaxDocument {
		return errors.New("DOCUMENT_OVERSIZE")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	var value func() error
	value = func() error {
		tok, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("DUPLICATE_KEY")
				}
				seen[s] = true
				if e = value(); e != nil {
					return e
				}
			}
		} else if delim == '[' {
			for d.More() {
				if e = value(); e != nil {
					return e
				}
			}
		} else {
			return errors.New("INVALID_JSON")
		}
		_, e = d.Token()
		return e
	}
	if e := value(); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("TRAILING_DATA")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func ParseSourceMap(b []byte) (SourceMap, error) {
	var c SourceMap
	if e := StrictJSON(b, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func validUUID(s string) bool {
	u, e := uuid.Parse(s)
	return e == nil && u.String() == s && u != uuid.Nil
}
func (c SourceMap) Validate() error {
	if c.SchemaVersion != 1 || !validUUID(c.SourceID) || (c.DeploymentID != "" && !validUUID(c.DeploymentID)) || len(c.Providers) > MaxProviders {
		return errors.New("SOURCE_MAP_SCHEMA")
	}
	seen := map[string]bool{}
	robots := map[RobotKey]bool{}
	ledgers := 0
	for _, p := range c.Providers {
		if p.Kind == LedgerKind {
			// The collector's own reading of the ledger it already verifies:
			// it names no file, no address and no robot, and there is one.
			ledgers++
			if !identifier.MatchString(p.ProviderID) || seen[p.ProviderID] || (p.Role != "primary" && p.Role != "secondary") {
				return errors.New("SOURCE_MAP_IDENTITY")
			}
			seen[p.ProviderID] = true
			if p.Trust != LedgerTrust || ledgers > 1 || p.DeploymentID != "" || p.RobotID != "" || p.Identity != "" || p.PathRef != "" || p.EndpointRef != "" || p.Owner != "" || p.RunID != "" || p.StreamID != "" || p.ClockBinding != "" {
				return errors.New("SOURCE_MAP_LEDGER_PROVIDER")
			}
			if len(p.Allowed) == 0 || len(p.Allowed) > 2 || (len(p.Allowed) == 2 && p.Allowed[0] == p.Allowed[1]) {
				return errors.New("SOURCE_MAP_KINDS")
			}
			for _, k := range p.Allowed {
				if k != "plan" && k != "ledger" {
					return errors.New("SOURCE_MAP_KINDS")
				}
			}
			continue
		}
		if !identifier.MatchString(p.ProviderID) || seen[p.ProviderID] || !identifier.MatchString(p.RobotID) || (p.DeploymentID != "" && !validUUID(p.DeploymentID)) || !identifier.MatchString(p.Identity) || (p.Role != "primary" && p.Role != "secondary") {
			return errors.New("SOURCE_MAP_IDENTITY")
		}
		seen[p.ProviderID] = true
		robots[RobotKey{p.DeploymentID, p.RobotID}] = true
		if len(p.Allowed) == 0 || len(p.Allowed) > len(ttls) {
			return errors.New("SOURCE_MAP_KINDS")
		}
		ks := map[string]bool{}
		for _, k := range p.Allowed {
			if _, ok := ttls[k]; !ok || ks[k] {
				return errors.New("SOURCE_MAP_KINDS")
			}
			ks[k] = true
		}
		// A binding request is a claim to be checked against every record, and
		// only a producer that writes its own monotonic time can be checked.
		if p.ClockBinding != "" && (p.ClockBinding != ClockBindingShared || p.Kind != "normalized_jsonl") {
			return errors.New("SOURCE_MAP_CLOCK_BINDING")
		}
		switch p.Kind {
		case "legacy_burst":
			if p.Trust != "verified_signature" || len(p.Allowed) != 1 || p.Allowed[0] != "gate" {
				return errors.New("SOURCE_MAP_LEGACY")
			}
		case "legacy_permit":
			if p.Trust != "verified_signature" || len(p.Allowed) != 1 || p.Allowed[0] != "permit" {
				return errors.New("SOURCE_MAP_LEGACY")
			}
		case "normalized_jsonl":
			for _, k := range p.Allowed {
				if k == "ledger" || k == "management" {
					return errors.New("SOURCE_MAP_VERIFIED_PROVIDER_REQUIRED")
				}
			}
			if p.Trust != "local_self_report" || !filepath.IsAbs(p.PathRef) || len(p.PathRef) > 4096 || !identifier.MatchString(p.Owner) || !validUUID(p.RunID) || !validUUID(p.StreamID) {
				return errors.New("SOURCE_MAP_FILE_BINDING")
			}
		case PushKind:
			// pushed over an authenticated connection (design 15.1): the robot is
			// named by its certificate, the records by the same binding as a file
			// source; the collector listens, so there is no path and no address
			// here (the rule below the switch refuses both for every kind but a file)
			for _, k := range p.Allowed {
				if k == "ledger" || k == "management" {
					return errors.New("SOURCE_MAP_VERIFIED_PROVIDER_REQUIRED")
				}
			}
			if p.Trust != PushTrust || !identifier.MatchString(p.Owner) || !validUUID(p.RunID) || !validUUID(p.StreamID) {
				return errors.New("SOURCE_MAP_PUSH_BINDING")
			}
		default:
			return errors.New("SOURCE_MAP_UNSUPPORTED_PROVIDER")
		}
		if p.EndpointRef != "" || (p.Kind != "normalized_jsonl" && p.PathRef != "") {
			return errors.New("SOURCE_MAP_UNSUPPORTED_ENDPOINT")
		}
	}
	if len(robots) > MaxRobots {
		return errors.New("SOURCE_MAP_ROBOT_LIMIT")
	}
	return nil
}
