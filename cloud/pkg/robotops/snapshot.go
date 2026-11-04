// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
)

// PublicArtifact is an immutable capture, never secret-provider key material.
type PublicArtifact struct {
	ResourceID   string `json:"resource_id"`
	RelativePath string `json:"relative_path"`
	SHA256       string `json:"sha256"`
	Bytes        []byte `json:"public_bytes"`
	OwnerUID     uint32 `json:"owner_uid"`
	Mode         uint32 `json:"mode"`
}
type fileMetadata struct {
	UID  uint32
	Mode uint32
}

// CapturePublic captures every declared public file plus every declared robot
// class registry. The caller must validate semantics on THESE bytes, not reopen
// a mutable original. Aliased resource paths refuse rather than duplicate writes.
func CapturePublic(root string, m ResourceMap, inv Inventory) ([]PublicArtifact, error) {
	if m.ValidateMap() != nil || inv.Validate() != nil || m.DeploymentID != inv.DeploymentID {
		return nil, fmt.Errorf("RO_SCHEMA: capture input invalid")
	}
	f, e := NewFiles(root, m)
	if e != nil {
		return nil, e
	}
	selected := map[string]Resource{}
	for _, r := range m.Resources {
		switch r.Kind {
		case "registry", "requesters", "site_model", "policy", "certificate", "ca_certificate":
			selected[r.ID] = r
		}
	}
	for _, bot := range inv.Robots {
		c, ok := f.Resources[bot.ClassRef]
		if !ok || c.Kind != "class" || !regexpClass(c.Value) {
			return nil, fmt.Errorf("RO_REF_UNKNOWN: class")
		}
		d, e := f.Resource(inv.ResourceBindings.Skills, "skills_dir")
		if e != nil {
			return nil, e
		}
		id := d.ID + "/" + c.Value
		selected[id] = Resource{ID: id, Kind: "skill", Path: filepath.Join(d.Path, "skills."+c.Value+".yaml")}
	}
	classes, e := f.SkillClasses(inv.ResourceBindings.Skills)
	if e != nil {
		return nil, e
	}
	for _, class := range classes {
		d, _ := f.Resource(inv.ResourceBindings.Skills, "skills_dir")
		id := d.ID + "/" + class
		selected[id] = Resource{ID: id, Kind: "skill", Path: filepath.Join(d.Path, "skills."+class+".yaml")}
	}
	ids := []string{}
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	paths := map[string]string{}
	out := []PublicArtifact{}
	total := 0
	for _, id := range ids {
		r := selected[id]
		if e := publicPath(r.Path); e != nil {
			return nil, e
		}
		if _, dup := paths[r.Path]; dup {
			return nil, fmt.Errorf("RO_RESOURCE_ALIAS: duplicate physical file references")
		}
		paths[r.Path] = id
		b, meta, e := readContainedInfo(f.Root, r.Path)
		if e != nil {
			return nil, fmt.Errorf("RO_RESOURCE_IO: public capture unavailable for %s", id)
		}
		total += len(b)
		if total > 2<<20 {
			return nil, fmt.Errorf("RO_INPUT_LIMIT: public capture exceeds 2 MiB aggregate")
		}
		h := sha256.Sum256(b)
		out = append(out, PublicArtifact{id, r.Path, hex.EncodeToString(h[:]), b, meta.UID, meta.Mode})
	}
	return out, nil
}
