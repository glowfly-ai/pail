// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package identity binds a transport-level caller (grpcauth's mTLS
// fingerprint) to a fleet identity (robot_id) through the robot registry
// . The judgment is four-valued (§2.5): bound / delegated /
// unbound / unchecked — "we could not check" and "we checked and it matched"
// must never share a value (H-B2); that collapse is exactly what let the
// fleet-wide shared certificate stay invisible (§1.1).
package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/glowfly/pail/services/internal/grpcauth"
)

// Verdict is the four-valued identity judgment (§2.5).
type Verdict int

const (
	// VerdictInvalid is the zero value: a Binding nobody judged. It exists so
	// that a forgotten assignment can never read as a pass (H-B2).
	VerdictInvalid Verdict = iota
	Bound
	Delegated
	Unbound
	Unchecked
)

// verdictNames is the journal vocabulary for the robot_id_bound key (§2.8).
var verdictNames = map[Verdict]string{
	VerdictInvalid: "invalid",
	Bound:          "bound",
	Delegated:      "delegated",
	Unbound:        "unbound",
	Unchecked:      "unchecked",
}

func (v Verdict) String() string {
	if s, ok := verdictNames[v]; ok {
		return s
	}
	// Out-of-vocabulary is labeled as unjudged, never as any passing value.
	return "invalid"
}

// Binding is the result of judging one call.
type Binding struct {
	Verdict Verdict
	// Reason is empty for Bound; otherwise it names why, in the journal's
	// vocabulary (§2.8). Never an ERR_ literal — gRPC status text is the
	// interceptor's concern, not the registry's.
	Reason string
}

// Role vocabulary (§2.3). Anything else refuses at load (RG-3's spirit: the
// registry has no "else" arm — an unknown role must not quietly become a
// robot).
type Role string

const (
	RoleRobot        Role = "robot"
	RoleOrchestrator Role = "orchestrator"
)

type entry struct {
	robotID string
	role    Role
}

// Registry is the loaded fingerprint→robot_id map. RG-2 keeps it a function;
// 1:N (one robot, several fingerprints) stays legal — that is the rotation
// window (§2.1 DC-3).
type Registry struct {
	loadedDigest  string
	byFingerprint map[string]entry
}

type registryFile struct {
	Version int             `yaml:"version"`
	Robots  []registryRobot `yaml:"robots"`
}

type registryRobot struct {
	RobotID      string   `yaml:"robot_id"`
	Role         string   `yaml:"role"`
	Fingerprints []string `yaml:"fingerprints"`
}

// RG-1: sha256(leaf DER) as 64-char lowercase hex, nothing else.
var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Load reads and validates config/robot_registry.yaml. Every violation is a
// load refusal — the caller must treat an error as "do not start" (RG-4): an
// empty or half-loaded registry turns every call into unbound, which the
// operator reads as "the interceptor is broken", not "the registry is wrong".
func Load(path string) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("robot registry: RG-4: %w", err)
	}
	return Parse(raw)
}

// Parse validates registry bytes (split from Load so units can probe rules
// without a filesystem).
func Parse(raw []byte) (*Registry, error) {
	// Version before strict fields — a strict parser in front of the version
	// check dies with "unknown field" on the very file that should have been
	// told to upgrade (OB2 commit17).
	var v struct {
		Version int `yaml:"version"`
	}
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("robot registry: RG-4: %w", err)
	}
	if v.Version != 1 {
		return nil, fmt.Errorf("robot registry: RG-4: unsupported version %d (want 1)", v.Version)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f registryFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("robot registry: RG-4: %w", err)
	}
	if len(f.Robots) == 0 {
		return nil, fmt.Errorf("robot registry: RG-4: no robots declared — an empty registry makes every call unbound")
	}
	r := &Registry{byFingerprint: map[string]entry{}}
	for _, robot := range f.Robots {
		if robot.RobotID == "" {
			return nil, fmt.Errorf("robot registry: RG-4: entry with empty robot_id")
		}
		role := Role(robot.Role)
		if role != RoleRobot && role != RoleOrchestrator {
			return nil, fmt.Errorf("robot registry: RG-3: robot_id %q has unknown role %q", robot.RobotID, robot.Role)
		}
		// RG-3, both directions: orchestrator ⇔ robot_id "*".
		if (role == RoleOrchestrator) != (robot.RobotID == "*") {
			return nil, fmt.Errorf("robot registry: RG-3: role %q with robot_id %q — orchestrator and \"*\" imply each other", robot.Role, robot.RobotID)
		}
		if len(robot.Fingerprints) == 0 {
			return nil, fmt.Errorf("robot registry: RG-4: robot_id %q declares no fingerprints", robot.RobotID)
		}
		for _, fp := range robot.Fingerprints {
			if !fingerprintRe.MatchString(fp) {
				return nil, fmt.Errorf("robot registry: RG-1: fingerprint %q of robot_id %q is not 64-char lowercase hex", fp, robot.RobotID)
			}
			if prev, dup := r.byFingerprint[fp]; dup && prev.robotID != robot.RobotID {
				return nil, fmt.Errorf("robot registry: RG-2: fingerprint %s… appears under both %q and %q — fingerprint→robot_id must stay a function (DC-3)", fp[:16], prev.robotID, robot.RobotID)
			}
			r.byFingerprint[fp] = entry{robotID: robot.RobotID, role: role}
		}
	}
	loadedSum := sha256.Sum256(raw)
	r.loadedDigest = hex.EncodeToString(loadedSum[:])
	return r, nil
}

// RobotIDs lists the declared robot identities (role robot only — the
// orchestrator's "*" is a wildcard, not a robot that emits bursts), sorted and
// unique. AL-0 (implementation contract D7) consumes this for hash→name resolution in the
// telemetry dashboard so the registry stays one file: the collector must not
// parse YAML a second time (a second parser drifts silently from RG-1..RG-4).
func (r *Registry) RobotIDs() []string {
	seen := map[string]bool{}
	for _, e := range r.byFingerprint {
		if e.role != RoleRobot || seen[e.robotID] {
			continue
		}
		seen[e.robotID] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Bind judges one call (§2.5). kind and id come from
// grpcauth.CallerFromContext; requestedRobotID from the request message's
// robot_id field, or the resource owner resolved under a handler lock via
// AuthorizeResolvedRobot for a request that has no robot_id field.
func (r *Registry) Bind(kind, id, requestedRobotID string) Binding {
	if kind == grpcauth.CallerMTLS {
		e, ok := r.byFingerprint[id]
		if !ok {
			return Binding{Verdict: Unbound, Reason: "fingerprint_unregistered"}
		}
		if e.role == RoleOrchestrator {
			// Pass, but never merged into Bound: "the orchestrator called on
			// robot-7's behalf" and "robot-7 called" are different facts in a
			// post-incident trace (§2.5).
			return Binding{Verdict: Delegated, Reason: "orchestrator_delegation"}
		}
		if e.robotID == requestedRobotID {
			return Binding{Verdict: Bound}
		}
		return Binding{Verdict: Unbound, Reason: "robot_id_mismatch"}
	}
	if kind == grpcauth.CallerUDS || kind == grpcauth.CallerUnknown {
		// §1.2: the UDS plane has different identity material by principle —
		// SO_PEERCRED names a process, not a robot. Passing is deliberate;
		// what H-B2 forbids is passing under the same value as checked.
		return Binding{Verdict: Unchecked, Reason: "caller_kind=" + kind}
	}
	// A caller kind outside the frozen vocabulary (implementation contract F6) is not
	// "unchecked" — it is evidence the transport layer changed under us.
	return Binding{Verdict: Unbound, Reason: "caller_kind_unrecognized"}
}

// LoadedDigest identifies bytes actually accepted by Parse.
func (r *Registry) LoadedDigest() string {
	if r == nil {
		return ""
	}
	return r.loadedDigest
}
