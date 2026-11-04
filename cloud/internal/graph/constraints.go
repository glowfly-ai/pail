// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// Constraint registry (CG-E1).
//
// Robot operators do not all speak the same rule vocabulary: one warehouse cares
// about payload limits, another about one-way corridors, a third about dock-only
// zones. Rather than hard-code every rule, a constraint *type* is one entry in
// this registry — a function that compiles its YAML declaration into constraint
// node(s) and CONSTRAINS edges over the generic node model (KindConstraint +
// typed attrs). Adding a rule vocabulary is therefore a localized, additive
// registration, not scattered edits, and the evidence/hash contract never moves
// (a constraint is always a node with attrs, encoded by the same canonical
// encoder).
//
// Fail-closed is the invariant: an unknown constraint type is a compile error,
// never a silent skip. You cannot sign off on a rule you cannot compile — a
// typo'd rule must stop issuance, not quietly disappear.

// rawConstraint is the front-end-neutral view of one constraint declaration.
// The YAML compiler fills Type from the `type:` key and Fields from the
// remaining keys; a future JSON/API front-end can populate the same shape.
type rawConstraint struct {
	Type   string
	Fields map[string]*yaml.Node
}

// constraintCompiler turns one constraint declaration into constraint node(s)
// and CONSTRAINS edges within g, using sc to resolve and validate references
// (zones/objects must exist; "*" expands over all zones/objects). It must be
// deterministic and fail-closed on bad references or unexpected fields.
type constraintCompiler func(rc rawConstraint, sc *siteContext, g *Graph) error

// constraintRegistry maps a constraint `type` to its compiler. Extended via
// RegisterConstraint. The CG-E1 baseline vocabulary is human_exclusion,
// speed_limit, and exclusive (the last is a CG4/P4 hook — it marks objects but
// v1 issuance does not yet evaluate occupancy).
var constraintRegistry = map[string]constraintCompiler{
	"human_exclusion": compileHumanExclusion,
	"speed_limit":     compileSpeedLimit,
	"exclusive":       compileExclusive,
}

// RegisterConstraint adds or overrides a constraint type compiler. This is the
// integrator extension point: a new rule vocabulary is one registration.
// Registering a nil compiler panics (programmer error at init time).
func RegisterConstraint(ctype string, fn constraintCompiler) {
	if fn == nil {
		panic("graph: RegisterConstraint with nil compiler for " + ctype)
	}
	constraintRegistry[ctype] = fn
}

// knownConstraintTypes returns the registered type names, sorted — for error
// messages and diagnostics.
func knownConstraintTypes() []string {
	names := make([]string, 0, len(constraintRegistry))
	for k := range constraintRegistry {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// compileConstraint dispatches one declaration to its registered compiler.
// Unknown type = fail-closed error.
func compileConstraint(rc rawConstraint, sc *siteContext, g *Graph) error {
	fn, ok := constraintRegistry[rc.Type]
	if !ok {
		return fmt.Errorf("graph: unknown constraint type %q (known: %v)", rc.Type, knownConstraintTypes())
	}
	return fn(rc, sc, g)
}

// --- baseline constraint compilers ---

// compileHumanExclusion: a HUMAN present in a listed zone forbids issuance for
// agents in that zone. Produces one constraint node per target zone plus a
// CONSTRAINS edge to each. zone:"*" expands over every declared zone.
func compileHumanExclusion(rc rawConstraint, sc *siteContext, g *Graph) error {
	if err := ensureOnlyFields(rc, "zone"); err != nil {
		return err
	}
	zone, err := reqString(rc, "zone")
	if err != nil {
		return err
	}
	zones, err := sc.resolveZones(zone)
	if err != nil {
		return fmt.Errorf("human_exclusion: %w", err)
	}
	for _, z := range zones {
		cid := "constraint:human_excl@" + z
		g.Nodes[cid] = &Node{
			ID: cid, Kind: KindConstraint, State: StateActive, Version: 0,
			Attrs: map[string]AttrVal{"ctype": AString("human_exclusion")},
		}
		g.Edges = append(g.Edges, Edge{From: cid, To: "zone:" + z, Rel: RelConstrains})
	}
	return nil
}

// compileSpeedLimit refuses the constraint (SK-1, implementation contract, G-POL-11).
//
// Until 2026-09-09 this compiled `speed_limit` into a constraint node that
// nothing enforced: the gate compares the commanded speed against the token's
// limit, and that limit came from policy.yaml `motion:` alone. A site model
// that "set" a zone limit set nothing, while its spec page said the gate would
// refuse (SITE_MODEL.md overclaimed). The one place a per-zone bound now lives
// is policy.yaml `guardrails.zones.<zone>.<name>`, which the issuer bakes into
// the token envelope. Refusing here is what stops the old file from reading as
// a limit that holds.
func compileSpeedLimit(rc rawConstraint, sc *siteContext, g *Graph) error {
	_ = sc
	_ = g
	// The field vocabulary stays declared so an old file is diagnosed by name
	// (spec §5.3 keeps the table; scripts/spec_site_model_check.py derives the
	// vocabulary from this call). The refusal follows regardless of the fields.
	if err := ensureOnlyFields(rc, "zone", "max_linear_speed_mps", "max_angular_speed_rps"); err != nil {
		return err
	}
	zone, err := reqString(rc, "zone")
	if err != nil {
		return err
	}
	if _, _, err := optFloat(rc, "max_linear_speed_mps"); err != nil {
		return err
	}
	if _, _, err := optFloat(rc, "max_angular_speed_rps"); err != nil {
		return err
	}
	return fmt.Errorf("speed_limit: no longer accepted in the site model (zone %q) — per-zone limits live in policy.yaml guardrails.zones and are carried in the token envelope; the site model never enforced this constraint", zone)
}

// compileExclusive marks objects as exclusively occupiable (P4/CG4 hook). v1
// issuance does not evaluate occupancy; the flag lives on the object node so the
// snapshot records intent and CG4 can activate OCCUPIES evaluation later.
func compileExclusive(rc rawConstraint, sc *siteContext, g *Graph) error {
	if err := ensureOnlyFields(rc, "object"); err != nil {
		return err
	}
	obj, err := reqString(rc, "object")
	if err != nil {
		return err
	}
	objs, err := sc.resolveObjects(obj)
	if err != nil {
		return fmt.Errorf("exclusive: %w", err)
	}
	for _, o := range objs {
		n, ok := g.Nodes["object:"+o]
		if !ok {
			return fmt.Errorf("exclusive: object %q not in graph", o)
		}
		if n.Attrs == nil {
			n.Attrs = map[string]AttrVal{}
		}
		n.Attrs["exclusive"] = ABool(true)
	}
	return nil
}

// --- field helpers (front-end-neutral, strict) ---

// ensureOnlyFields rejects any constraint field outside the allowed set —
// fail-closed against typos that would silently drop a rule parameter.
func ensureOnlyFields(rc rawConstraint, allowed ...string) error {
	ok := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		ok[a] = struct{}{}
	}
	var extra []string
	for k := range rc.Fields {
		if _, good := ok[k]; !good {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("constraint %q: unexpected field(s) %v (allowed: %v)", rc.Type, extra, allowed)
	}
	return nil
}

func reqString(rc rawConstraint, key string) (string, error) {
	n, ok := rc.Fields[key]
	if !ok {
		return "", fmt.Errorf("constraint %q: missing required field %q", rc.Type, key)
	}
	var s string
	if err := n.Decode(&s); err != nil {
		return "", fmt.Errorf("constraint %q: field %q must be a string: %w", rc.Type, key, err)
	}
	if s == "" {
		return "", fmt.Errorf("constraint %q: field %q must not be empty", rc.Type, key)
	}
	return s, nil
}

// optFloat decodes an optional float field. Returns (value, present, error).
func optFloat(rc rawConstraint, key string) (float64, bool, error) {
	n, ok := rc.Fields[key]
	if !ok {
		return 0, false, nil
	}
	var f float64
	if err := n.Decode(&f); err != nil {
		return 0, false, fmt.Errorf("constraint %q: field %q must be a number: %w", rc.Type, key, err)
	}
	return f, true, nil
}
