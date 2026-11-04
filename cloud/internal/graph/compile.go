// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

// Declarative site-model compiler (CG-E1).
//
// An operator adopts the context graph with a single YAML file, not code. This
// compiler turns that YAML into a CG0 Graph: the deterministic, canonically
// encodable world model the issuer holds in memory. YAML is purely a front-end —
// the evidence/determinism contract lives in the Graph model and its canonical
// encoder (encode.go), so the same logical site compiles to the same snapshot
// hashes regardless of key ordering, and a different front-end (JSON, an API)
// could produce an identical graph.
//
// strict parsing (fail-closed): unknown top-level keys, unknown struct fields,
// unknown constraint types, and dangling references all abort compilation. A
// silently-dropped constraint is a safety incident, so a typo must stop
// issuance, not be ignored.

// SiteModel is the parsed, validated site declaration. Schema is the operator's
// declared token schema_version for the site. It is recorded (boot log, issuer
// state) and nothing is bounded by it yet — no issuance path reads it, so a
// value here neither raises nor caps the schema_version of an issued token.
type SiteModel struct {
	Site   string
	Schema string
	// AL-3 (implementation contract D3/D4): registered action names and the unverified-target
	// policy. Both are declarations the issuer enforces; neither is world state
	// (they are not graph nodes and do not enter the snapshot hash).
	Actions map[string]ActionDef
	Policy  Policy
	// ObjectIDs lets the issuer ask "is this target declared?" without
	// walking the graph.
	ObjectIDs map[string]struct{}
	// ObjectZone (AL-4, implementation contract D5): declared object → its `at` zone, resolved
	// at issuance into TOKEN_ISSUED.zone_id. Objects without `at` are absent.
	ObjectZone map[string]string
	// RobotClass (SK-1, implementation contract L17): robot id → its `robot_class`, the key
	// that picks the skill registry (`config/skills.<robot_class>.yaml`).
	// Robots without the field are absent — the issuer then has no registry
	// to match against, which is a profile question (S39), not a default.
	RobotClass map[string]string
	// CustomEvents (AG-8): customer-defined context event name
	// ("<namespace>.<name>") → the built-in ContextEventKind name it maps to.
	// A declaration, not world state (not a graph node, not in the hash). An
	// event whose name is not here is refused by IngestContextEvent.
	CustomEvents map[string]string
}

// yamlSite mirrors the YAML document. Decoded with KnownFields(true) so unknown
// keys are rejected. Constraints keep their type-specific fields as raw nodes so
// each constraint compiler can validate its own vocabulary strictly.
type yamlSite struct {
	Site        string           `yaml:"site"`
	Schema      string           `yaml:"schema"`
	Zones       []yamlZone       `yaml:"zones"`
	Objects     []yamlObject     `yaml:"objects"`
	Robots      []yamlRobot      `yaml:"robots"`
	Constraints []yamlConstraint `yaml:"constraints"`
	Actions     []yamlAction     `yaml:"actions"`
	Policy      *yamlPolicy      `yaml:"policy"`
	// AG-8: customer-defined event names mapped onto the built-in kinds.
	CustomEvents []yamlCustomEvent `yaml:"custom_events"`
}

type yamlCustomEvent struct {
	ID          string `yaml:"id"`
	Effect      string `yaml:"effect"`
	Description string `yaml:"description"`
}

// customEventName is "<namespace>.<name>": both sides lowercase [a-z0-9_],
// 1..32 each. The namespace keeps two vendors' "alarm" apart; the dot keeps a
// custom name from ever colliding with a built-in kind name.
var customEventName = regexp.MustCompile(`^[a-z0-9_]{1,32}\.[a-z0-9_]{1,32}$`)

// CustomEventEffects are the built-in kinds a custom event may map to. The
// unspecified kind and CUSTOM itself are not effects: mapping to them would
// be a refusal or a loop dressed as a declaration.
var CustomEventEffects = map[string]bool{"HUMAN_ENTER": true, "HUMAN_LEAVE": true, "OBJECT_MOVE": true, "MAINTENANCE_ON": true, "MAINTENANCE_OFF": true, "CORDON_ON": true, "CORDON_OFF": true}

type yamlAction struct {
	Name        string   `yaml:"name"`
	Classes     []string `yaml:"classes"`
	Description string   `yaml:"description"`
}

type yamlPolicy struct {
	UnverifiedTargets string `yaml:"unverified_targets"`
}

type yamlZone struct {
	ID       string   `yaml:"id"`
	Type     string   `yaml:"type"`
	Adjacent []string `yaml:"adjacent"`
}

type yamlObject struct {
	ID string `yaml:"id"`
	At string `yaml:"at"`
}

type yamlRobot struct {
	ID           string   `yaml:"id"`
	Capabilities []string `yaml:"capabilities"`
	Schema       string   `yaml:"schema"`
	Home         string   `yaml:"home"`
	RobotClass   string   `yaml:"robot_class"` // SK-1: SKILL_VOCAB.tsv robot_class
}

// yamlConstraint captures `type` plus every other key as a raw node, so per-type
// strict validation happens in the constraint compiler. A custom unmarshaler is
// used because yaml.Node is only special-cased as a direct struct field, not as
// an inline-map value.
type yamlConstraint struct {
	typ    string
	fields map[string]*yaml.Node
}

func (c *yamlConstraint) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("constraint must be a mapping")
	}
	c.fields = make(map[string]*yaml.Node)
	for i := 0; i+1 < len(value.Content); i += 2 {
		var key string
		if err := value.Content[i].Decode(&key); err != nil {
			return fmt.Errorf("constraint key: %w", err)
		}
		if key == "type" {
			if err := value.Content[i+1].Decode(&c.typ); err != nil {
				return fmt.Errorf("constraint type: %w", err)
			}
			continue
		}
		c.fields[key] = value.Content[i+1]
	}
	return nil
}

// siteContext gives constraint compilers read access to the declared universe
// for reference validation and "*" expansion.
type siteContext struct {
	zoneIDs       map[string]struct{}
	objectIDs     map[string]struct{}
	sortedZones   []string
	sortedObjects []string
}

func (sc *siteContext) resolveZones(ref string) ([]string, error) {
	if ref == "*" {
		return sc.sortedZones, nil
	}
	if _, ok := sc.zoneIDs[ref]; !ok {
		return nil, fmt.Errorf("references undefined zone %q", ref)
	}
	return []string{ref}, nil
}

func (sc *siteContext) resolveObjects(ref string) ([]string, error) {
	if ref == "*" {
		return sc.sortedObjects, nil
	}
	if _, ok := sc.objectIDs[ref]; !ok {
		return nil, fmt.Errorf("references undefined object %q", ref)
	}
	return []string{ref}, nil
}

// Compile parses and validates a site-model YAML document and builds the initial
// issuer graph (epoch 0, every node version 0, state ACTIVE). It returns the
// graph and the parsed SiteModel metadata, or a compile error (fail-closed).
func Compile(src []byte) (*Graph, *SiteModel, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(true)
	var y yamlSite
	if err := dec.Decode(&y); err != nil {
		return nil, nil, fmt.Errorf("graph: site model parse error: %w", err)
	}

	if y.Site == "" {
		return nil, nil, fmt.Errorf("graph: site model missing required `site`")
	}

	g := NewGraph() // epoch 0
	sc := &siteContext{
		zoneIDs:   make(map[string]struct{}),
		objectIDs: make(map[string]struct{}),
	}

	// Zones first (constraints and object placement reference them).
	for _, z := range y.Zones {
		if z.ID == "" {
			return nil, nil, fmt.Errorf("graph: zone with empty id")
		}
		if _, dup := sc.zoneIDs[z.ID]; dup {
			return nil, nil, fmt.Errorf("graph: duplicate zone id %q", z.ID)
		}
		sc.zoneIDs[z.ID] = struct{}{}
		attrs := map[string]AttrVal{}
		if z.Type != "" {
			attrs["type"] = AString(z.Type)
		}
		if len(z.Adjacent) > 0 {
			adj := append([]string(nil), z.Adjacent...)
			sort.Strings(adj)
			attrs["adjacent"] = AString(joinCSV(adj))
		}
		g.Nodes["zone:"+z.ID] = &Node{ID: "zone:" + z.ID, Kind: KindZone, State: StateActive, Version: 0, Attrs: attrs}
	}
	// Validate adjacency references after all zones are known. Only existence is
	// checked: `a: [b]` without `b: [a]` compiles. Adjacency is carried as a node
	// attribute (evidence), not as a routing edge, so an asymmetric declaration
	// cannot mislead any issuance decision.
	for _, z := range y.Zones {
		for _, a := range z.Adjacent {
			if _, ok := sc.zoneIDs[a]; !ok {
				return nil, nil, fmt.Errorf("graph: zone %q adjacent to undefined zone %q", z.ID, a)
			}
		}
	}

	// Objects.
	for _, o := range y.Objects {
		if o.ID == "" {
			return nil, nil, fmt.Errorf("graph: object with empty id")
		}
		if _, dup := sc.objectIDs[o.ID]; dup {
			return nil, nil, fmt.Errorf("graph: duplicate object id %q", o.ID)
		}
		sc.objectIDs[o.ID] = struct{}{}
		g.Nodes["object:"+o.ID] = &Node{ID: "object:" + o.ID, Kind: KindObject, State: StateActive, Version: 0}
		if o.At != "" {
			if _, ok := sc.zoneIDs[o.At]; !ok {
				return nil, nil, fmt.Errorf("graph: object %q at undefined zone %q", o.ID, o.At)
			}
			g.Edges = append(g.Edges, Edge{From: "object:" + o.ID, To: "zone:" + o.At, Rel: RelLocatedIn})
		}
	}

	// Robots: agent node + executor node (1:1 v1) + home LOCATED_IN.
	robotIDs := make(map[string]struct{})
	robotClass := make(map[string]string)
	for _, r := range y.Robots {
		if r.ID == "" {
			return nil, nil, fmt.Errorf("graph: robot with empty id")
		}
		if _, dup := robotIDs[r.ID]; dup {
			return nil, nil, fmt.Errorf("graph: duplicate robot id %q", r.ID)
		}
		robotIDs[r.ID] = struct{}{}
		attrs := map[string]AttrVal{}
		if len(r.Capabilities) > 0 {
			caps := append([]string(nil), r.Capabilities...)
			sort.Strings(caps)
			attrs["capabilities"] = AString(joinCSV(caps))
		}
		if r.Schema != "" {
			attrs["schema"] = AString(r.Schema)
		}
		if r.RobotClass != "" {
			// Declared only: attrs are added when present, so models without the
			// field keep their snapshot hash (golden vectors unchanged).
			attrs["robot_class"] = AString(r.RobotClass)
			robotClass[r.ID] = r.RobotClass
		}
		g.Nodes["robot:"+r.ID] = &Node{ID: "robot:" + r.ID, Kind: KindAgent, State: StateActive, Version: 0, Attrs: attrs}

		exID := "executor:" + r.ID
		g.Nodes[exID] = &Node{ID: exID, Kind: KindExecutor, State: StateActive, Version: 0}
		g.Edges = append(g.Edges, Edge{From: "robot:" + r.ID, To: exID, Rel: RelOperates})

		if r.Home != "" {
			if _, ok := sc.zoneIDs[r.Home]; !ok {
				return nil, nil, fmt.Errorf("graph: robot %q home is undefined zone %q", r.ID, r.Home)
			}
			g.Edges = append(g.Edges, Edge{From: "robot:" + r.ID, To: "zone:" + r.Home, Rel: RelLocatedIn})
		}
	}

	// Deterministic snapshot of reference universe for "*" expansion.
	sc.sortedZones = sortedKeys(sc.zoneIDs)
	sc.sortedObjects = sortedKeys(sc.objectIDs)

	// Constraints (dispatch to registry; unknown type = fail-closed).
	for i, c := range y.Constraints {
		if c.typ == "" {
			return nil, nil, fmt.Errorf("graph: constraint #%d missing `type`", i)
		}
		if err := compileConstraint(rawConstraint{Type: c.typ, Fields: c.fields}, sc, g); err != nil {
			return nil, nil, fmt.Errorf("graph: %w", err)
		}
	}

	// AL-3 (D3): `actions:` — registered names must declare a non-empty,
	// known class set; duplicates refuse (two declarations of one name would
	// make the enforced meaning depend on file order).
	actions := map[string]ActionDef{}
	for i, a := range y.Actions {
		if a.Name == "" {
			return nil, nil, fmt.Errorf("graph: actions[%d]: empty name", i)
		}
		if _, dup := actions[a.Name]; dup {
			return nil, nil, fmt.Errorf("graph: actions: duplicate name %q", a.Name)
		}
		if len(a.Classes) == 0 {
			return nil, nil, fmt.Errorf("graph: actions[%q]: no classes — a registered action must say what it does", a.Name)
		}
		var mask uint32
		for _, c := range a.Classes {
			bit, ok := ClassNames[c]
			if !ok {
				return nil, nil, fmt.Errorf("graph: actions[%q]: unknown class %q (want MOVE|MANIPULATE|ACTUATE|NONE)", a.Name, c)
			}
			mask |= bit
		}
		actions[a.Name] = ActionDef{Name: a.Name, Mask: mask, Description: a.Description}
	}
	// AL-3 (D4): `policy.unverified_targets` — refuse (default) | allow.
	var pol Policy
	if y.Policy != nil {
		switch y.Policy.UnverifiedTargets {
		case "", "refuse":
			pol.UnverifiedTargets = "refuse"
		case "allow":
			pol.UnverifiedTargets = "allow"
		default:
			return nil, nil, fmt.Errorf("graph: policy.unverified_targets %q (want refuse|allow)", y.Policy.UnverifiedTargets)
		}
	} else {
		pol.UnverifiedTargets = "refuse"
	}
	objs := make(map[string]struct{}, len(sc.objectIDs))
	for id := range sc.objectIDs {
		objs[id] = struct{}{}
	}
	zones := map[string]string{}
	for _, o := range y.Objects {
		if o.At != "" {
			zones[o.ID] = o.At
		}
	}
	// AG-8: custom events — every declaration names a known effect, no
	// duplicates, and the name has the namespaced shape.
	custom := map[string]string{}
	for i, ce := range y.CustomEvents {
		if ce.ID == "" {
			return nil, nil, fmt.Errorf("graph: custom_events[%d]: customevent with empty id", i)
		}
		if ce.Effect == "" {
			return nil, nil, fmt.Errorf("graph: custom_events[%q]: customevent with empty effect", ce.ID)
		}
		if !customEventName.MatchString(ce.ID) {
			return nil, nil, fmt.Errorf("graph: custom_events[%d].id %q (want <namespace>.<name>, lowercase [a-z0-9_])", i, ce.ID)
		}
		if !CustomEventEffects[ce.Effect] {
			return nil, nil, fmt.Errorf("graph: custom_events[%q].effect %q is not a built-in context event kind", ce.ID, ce.Effect)
		}
		if _, dup := custom[ce.ID]; dup {
			return nil, nil, fmt.Errorf("graph: duplicate custom_events id %q", ce.ID)
		}
		custom[ce.ID] = ce.Effect
	}
	return g, &SiteModel{Site: y.Site, Schema: y.Schema, Actions: actions, Policy: pol, ObjectIDs: objs, ObjectZone: zones, RobotClass: robotClass, CustomEvents: custom}, nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// joinCSV joins already-sorted ids with a comma. Ids never contain commas
// (they follow the "kind:local" convention over restricted charsets).
func joinCSV(xs []string) string {
	var b bytes.Buffer
	for i, x := range xs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(x)
	}
	return b.String()
}
