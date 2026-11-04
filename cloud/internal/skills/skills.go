// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package skills loads the per-robot-class skill registries
// (`config/skills.<robot_class>.yaml`, spec/SKILLS.md) that skill-level
// authorization (implementation contract, SK-1) matches plan steps against.
//
// A registry is an allow-list: a name that is not in it is not authorized,
// and there is no "*" row. The parser is strict (unknown keys refuse the
// file), because a registry the issuer half-read is a registry the operator
// did not write. The same bytes are what the gate seals (SK-4).
package skills

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/glowfly/pail/services/internal/graph"
)

// DefaultDir is where a deployment keeps its registries (beside policy.yaml).
const DefaultDir = "/etc/pail"

// EnvDir overrides DefaultDir.
const EnvDir = "PAIL_SKILLS_DIR"

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Closed code vocabularies (LLD §1.1). The gate session gets the same sets
// in SK-3; check_skills.py carries them as constants.
var (
	CompleteSignals = map[string]struct{}{"duration": {}, "robot_report": {}, "robot_report+evidence": {}}
	EvidenceWhens   = map[string]struct{}{"none": {}, "before": {}, "at_complete": {}}
)

// Skill is one registry row.
type Skill struct {
	Name           string
	Classes        []string
	Mask           uint32
	EvidenceWhen   string
	EvidenceTrust  string
	Envelope       []string
	Feeds          []string
	CompleteSignal string
	SafeState      string
	Slot           string
}

// RequiresTarget says whether a step calling this skill must name a target.
func (s Skill) RequiresTarget() bool { return s.EvidenceWhen != "none" }

// Registry is one robot class's file.
type Registry struct {
	RobotClass string
	Path       string
	SHA256Hex  string
	Skills     map[string]Skill
}

// Lookup finds a row by its bare name (no namespace).
func (r *Registry) Lookup(name string) (Skill, bool) {
	if r == nil {
		return Skill{}, false
	}
	s, ok := r.Skills[name]
	return s, ok
}

// Names lists the rows, sorted (for banners and tests).
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.Skills))
	for n := range r.Skills {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Set is every registry a deployment loaded, by robot class.
type Set struct {
	ByClass map[string]*Registry
}

// ForClass finds the registry serving a robot class.
func (s *Set) ForClass(class string) (*Registry, bool) {
	if s == nil || class == "" {
		return nil, false
	}
	r, ok := s.ByClass[class]
	return r, ok
}

// Len is the number of registries loaded.
// UnknownFeeds (SK-5, implementation contract) lists every feed id a registry row names
// that is not one of `known` (the policy's preconditions[].id), as
// "<class>/<skill>:<feed>", sorted. A feed nobody checks live is a promise
// with no observer — refused at start, not discovered at the first permit.
func (s *Set) UnknownFeeds(known []string) []string {
	have := map[string]struct{}{}
	for _, k := range known {
		have[k] = struct{}{}
	}
	var out []string
	for class, reg := range s.ByClass {
		for name, sk := range reg.Skills {
			for _, f := range sk.Feeds {
				if _, ok := have[f]; !ok {
					out = append(out, class+"/"+name+":"+f)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.ByClass)
}

// Classes lists the robot classes with a registry, sorted.
func (s *Set) Classes() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.ByClass))
	for c := range s.ByClass {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

type fileShape struct {
	Version    int        `yaml:"version"`
	RobotClass string     `yaml:"robot_class"`
	Skills     []rowShape `yaml:"skills"`
}

type rowShape struct {
	Name     string   `yaml:"name"`
	Classes  []string `yaml:"classes"`
	Evidence struct {
		When  string `yaml:"when"`
		Trust string `yaml:"trust"`
	} `yaml:"evidence"`
	Envelope []string `yaml:"envelope"`
	Feeds    []string `yaml:"feeds"`
	Complete struct {
		Signal string `yaml:"signal"`
	} `yaml:"complete"`
	SafeState    string  `yaml:"safe_state"`
	Slot         string  `yaml:"slot"`
	ParamsSchema *string `yaml:"params_schema"`
}

// Parse validates one registry's bytes. wantClass, when non-empty, must equal
// the file's robot_class (the file name carries the class — a mismatch is a
// misplaced file, not a different robot).
func Parse(raw []byte, wantClass string) (*Registry, error) {
	var v struct {
		Version int `yaml:"version"`
	}
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("skills: %w", err)
	}
	if v.Version != 1 {
		return nil, fmt.Errorf("skills: unsupported version %d (want 1)", v.Version)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f fileShape
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("skills: %w", err)
	}
	if f.RobotClass == "" {
		return nil, fmt.Errorf("skills: robot_class is required")
	}
	if wantClass != "" && f.RobotClass != wantClass {
		return nil, fmt.Errorf("skills: file is named for robot class %q but declares %q", wantClass, f.RobotClass)
	}
	if len(f.Skills) == 0 {
		return nil, fmt.Errorf("skills[%s]: no rows — an empty registry authorizes nothing; delete the file instead if that is the intent", f.RobotClass)
	}
	sum := sha256.Sum256(raw)
	r := &Registry{RobotClass: f.RobotClass, SHA256Hex: hex.EncodeToString(sum[:]), Skills: map[string]Skill{}}
	for i, row := range f.Skills {
		at := fmt.Sprintf("skills[%s][%d]", f.RobotClass, i)
		if row.Name == "*" {
			// LLD §14.4: an allow-everything row is the deny-list-only world.
			return nil, fmt.Errorf("%s: name \"*\" is not a skill — registries are allow-lists", at)
		}
		if !nameRe.MatchString(row.Name) {
			return nil, fmt.Errorf("%s: name %q must match %s", at, row.Name, nameRe)
		}
		if _, dup := r.Skills[row.Name]; dup {
			return nil, fmt.Errorf("%s: duplicate name %q", at, row.Name)
		}
		if len(row.Classes) == 0 {
			return nil, fmt.Errorf("%s (%s): classes is empty", at, row.Name)
		}
		var mask uint32
		for _, c := range row.Classes {
			bit, ok := graph.ClassNames[c]
			if !ok {
				return nil, fmt.Errorf("%s (%s): class %q outside the vocabulary", at, row.Name, c)
			}
			mask |= bit
		}
		if _, ok := EvidenceWhens[row.Evidence.When]; !ok {
			return nil, fmt.Errorf("%s (%s): evidence.when %q outside {none, before, at_complete}", at, row.Name, row.Evidence.When)
		}
		if row.Evidence.When != "none" && row.Evidence.Trust == "" {
			return nil, fmt.Errorf("%s (%s): evidence.when=%s needs evidence.trust", at, row.Name, row.Evidence.When)
		}
		if _, ok := CompleteSignals[row.Complete.Signal]; !ok {
			return nil, fmt.Errorf("%s (%s): complete.signal %q outside {duration, robot_report, robot_report+evidence}", at, row.Name, row.Complete.Signal)
		}
		if row.SafeState == "" {
			return nil, fmt.Errorf("%s (%s): safe_state is required", at, row.Name)
		}
		if row.Envelope == nil || row.Feeds == nil {
			return nil, fmt.Errorf("%s (%s): envelope and feeds must be present (an empty list is written as [])", at, row.Name)
		}
		for _, n := range row.Envelope {
			if strings.TrimSpace(n) == "" {
				return nil, fmt.Errorf("%s (%s): empty envelope name", at, row.Name)
			}
		}
		slot := row.Slot
		if slot == "" {
			slot = "main"
		} else if !nameRe.MatchString(slot) {
			return nil, fmt.Errorf("%s (%s): slot %q must match %s", at, row.Name, slot, nameRe)
		}
		if row.ParamsSchema != nil {
			// SK-1 does not validate JSON Schema (no dependency in this module).
			// Refusing the row keeps "declared" and "enforced" the same word —
			// a schema the issuer ignores would read as a check that ran.
			return nil, fmt.Errorf("%s (%s): params_schema is not supported by this issuer yet — remove it or upgrade", at, row.Name)
		}
		r.Skills[row.Name] = Skill{
			Name: row.Name, Classes: graph.ClassMaskNames(mask), Mask: mask,
			EvidenceWhen: row.Evidence.When, EvidenceTrust: row.Evidence.Trust,
			Envelope: append([]string(nil), row.Envelope...), Feeds: append([]string(nil), row.Feeds...),
			CompleteSignal: row.Complete.Signal, SafeState: row.SafeState, Slot: slot,
		}
	}
	return r, nil
}

// LoadDir reads every `skills.<class>.yaml` in dir. A directory with no such
// file returns an empty Set and no error — whether that is acceptable is the
// caller's profile question (S39), not a parse question. Any file that does
// not parse is an error: one bad registry is not "the others still load".
func LoadDir(dir string) (*Set, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "skills.*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	set := &Set{ByClass: map[string]*Registry{}}
	for _, p := range matches {
		base := filepath.Base(p)
		class := strings.TrimSuffix(strings.TrimPrefix(base, "skills."), ".yaml")
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		r, err := Parse(raw, class)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		r.Path = p
		set.ByClass[r.RobotClass] = r
	}
	return set, nil
}

// LoadFromEnv resolves PAIL_SKILLS_DIR (default DefaultDir).
func LoadFromEnv() (*Set, string, error) {
	dir := os.Getenv("PAIL_SKILLS_DIR") // literal: the config registry scanner reads env names from source
	if dir == "" {
		dir = DefaultDir
	}
	s, err := LoadDir(dir)
	return s, dir, err
}
