// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Files captures only explicitly selected PUBLIC resources. The map is not an
// authorization source. Callers run without elevation; a trusted installation
// classifier is required before this map could ever support application.
type Files struct {
	Root      string
	Resources map[string]Resource
	Hashes    map[string]string
	cache     map[string][]byte
}

func NewFiles(root string, m ResourceMap) (*Files, error) {
	p, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("RO_RESOURCE_IO: config root")
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return nil, fmt.Errorf("RO_RESOURCE_IO: config root")
	}
	return &Files{p, m.Index(), map[string]string{}, map[string][]byte{}}, nil
}
func (f *Files) Resource(id, kind string) (Resource, error) {
	r, ok := f.Resources[id]
	if !ok || r.Kind != kind {
		return r, fmt.Errorf("RO_REF_UNKNOWN: resource missing or wrong kind")
	}
	return r, nil
}
func publicPath(p string) error {
	if p == "" || filepath.IsAbs(p) || filepath.Clean(p) != p || p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) {
		return fmt.Errorf("RO_RESOURCE_PATH: path is not contained")
	}
	low := strings.ToLower(filepath.ToSlash(p))
	for _, part := range strings.Split(low, "/") {
		if part == "private" || part == "root-keys" || strings.HasSuffix(part, ".key") {
			return fmt.Errorf("RO_SECRET_RESOURCE: private path cannot be read")
		}
	}
	return nil
}
func (f *Files) Read(id, kind string) ([]byte, error) {
	r, err := f.Resource(id, kind)
	if err != nil {
		return nil, err
	}
	switch kind {
	case "registry", "site_model", "policy", "certificate", "ca_certificate", "requesters":
	default:
		return nil, fmt.Errorf("RO_SECRET_RESOURCE: unsupported public file kind")
	}
	if err = publicPath(r.Path); err != nil {
		return nil, err
	}
	if b, ok := f.cache[id]; ok {
		return append([]byte(nil), b...), nil
	}
	b, err := readContained(f.Root, r.Path)
	if err != nil {
		return nil, fmt.Errorf("RO_RESOURCE_IO: declared public resource unreadable")
	}
	f.cache[id] = append([]byte(nil), b...)
	h := sha256.Sum256(b)
	f.Hashes[id] = hex.EncodeToString(h[:])
	return b, nil
}

// ReadSkill reads a public skills.<class>.yaml file from the declared skills dir.
func (f *Files) ReadSkill(id, class string) ([]byte, error) {
	r, err := f.Resource(id, "skills_dir")
	if err != nil {
		return nil, err
	}
	if !regexpClass(class) {
		return nil, fmt.Errorf("RO_SCHEMA: invalid robot class")
	}
	if err = publicPath(r.Path); err != nil {
		return nil, err
	}
	key := id + "/" + class
	if b, ok := f.cache[key]; ok {
		return append([]byte(nil), b...), nil
	}
	b, err := readContained(f.Root, filepath.Join(r.Path, "skills."+class+".yaml"))
	if err != nil {
		return nil, fmt.Errorf("RO_RESOURCE_IO: declared skill registry unreadable")
	}
	f.cache[key] = append([]byte(nil), b...)
	h := sha256.Sum256(b)
	f.Hashes[key] = hex.EncodeToString(h[:])
	return b, nil
}
func regexpClass(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || i > 0 && (c >= '0' && c <= '9' || c == '_')) {
			return false
		}
	}
	return true
}

// SkillClasses uses the same filename pattern as skills.LoadDir. Every matching
// file is observed, even when no currently declared robot selects its class.
func (f *Files) SkillClasses(id string) ([]string, error) {
	r, e := f.Resource(id, "skills_dir")
	if e != nil {
		return nil, e
	}
	if e = publicPath(r.Path); e != nil {
		return nil, e
	}
	names, e := listContained(f.Root, r.Path)
	if e != nil {
		return nil, fmt.Errorf("RO_RESOURCE_IO: skills directory unavailable")
	}
	classes := []string{}
	for _, name := range names {
		if strings.HasPrefix(name, "skills.") && strings.HasSuffix(name, ".yaml") {
			class := strings.TrimSuffix(strings.TrimPrefix(name, "skills."), ".yaml")
			if !regexpClass(class) {
				return nil, fmt.Errorf("RO_SCHEMA: skill filename class unsupported")
			}
			classes = append(classes, class)
		}
	}
	sort.Strings(classes)
	return classes, nil
}
