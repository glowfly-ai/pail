// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotopscheck

import (
	"crypto/sha256"
	"encoding/json"
	fixture "github.com/glowfly/pail/services/internal/robotopstest"
	ops "github.com/glowfly/pail/services/pkg/robotops"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func has(r ops.Report, id string, status ops.Status) bool {
	for _, f := range r.Findings {
		if f.CheckID == id && f.Status == status {
			return true
		}
	}
	return false
}
func TestTwoRobotSnapshotAndNoSourceWrites(t *testing.T) {
	f := fixture.New(t)
	before := map[string][32]byte{}
	entries, _ := os.ReadDir(f.Root)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(f.Root, e.Name()))
		before[e.Name()] = sha256.Sum256(b)
	}
	result := Check(f.Inventory, f.Map, f.Root, f.Now)
	if result.ExitCode() != 0 {
		b, _ := json.MarshalIndent(result, "", " ")
		t.Fatal(string(b))
	}
	if result.ReadyForApply || result.RuntimeObserved {
		t.Fatal("offline results claim runtime/apply authority")
	}
	if _, ok := result.InputHashes["cred:private"]; ok {
		t.Fatal("private material was hashed")
	}
	after, _ := os.ReadDir(f.Root)
	if len(after) != len(entries) {
		t.Fatal("source directory mutated")
	}
	for name, h := range before {
		b, _ := os.ReadFile(filepath.Join(f.Root, name))
		if sha256.Sum256(b) != h {
			t.Fatal("source changed: " + name)
		}
	}
	if len(result.RequiredSubjects["RO-C03.static"]) != 2 {
		t.Fatal("robot coverage denominator missing")
	}
}
func TestWrongCertificateRefRefuses(t *testing.T) {
	f := fixture.New(t)
	f.Inventory.Robots[1].ClientCredentialRef = "cred:c0"
	r := Check(f.Inventory, f.Map, f.Root, f.Now)
	if !has(r, "RO-C03.static", ops.Fail) {
		t.Fatal(r)
	}
}
func TestWrongAgentUpstreamIdentityRefuses(t *testing.T) {
	f := fixture.New(t)
	f.Change("cmp:a1", func(r *ops.Resource) { r.CredentialRef = "cred:c0" })
	r := Check(f.Inventory, f.Map, f.Root, f.Now)
	if !has(r, "RO-C07.declared", ops.Fail) {
		t.Fatal(r)
	}
}
func TestStaleCollectorRegistryRefuses(t *testing.T) {
	f := fixture.New(t)
	raw, _ := os.ReadFile(filepath.Join(f.Root, "robot_registry.yaml"))
	raw = []byte(strings.Replace(string(raw), "robot-added-02", "retired-robot", 1))
	os.WriteFile(filepath.Join(f.Root, "old-registry.yaml"), raw, 0600)
	f.Map.Resources = append(f.Map.Resources, ops.Resource{ID: "res:old", Kind: "registry", Path: "old-registry.yaml"})
	f.Change("cmp:collector", func(r *ops.Resource) { r.RegistryRef = "res:old" })
	r := Check(f.Inventory, f.Map, f.Root, f.Now)
	if !has(r, "RO-C11.declared", ops.Fail) {
		t.Fatal(r)
	}
}
func TestMissingSiteRobotRefuses(t *testing.T) {
	f := fixture.New(t)
	p := filepath.Join(f.Root, "site_model.yaml")
	raw, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(raw), "robot-added-02", "other-robot", 1)), 0600)
	r := Check(f.Inventory, f.Map, f.Root, f.Now)
	if !has(r, "RO-C04", ops.Fail) {
		t.Fatal(r)
	}
}
func TestSharedDeclaredNetworkRefuses(t *testing.T) {
	f := fixture.New(t)
	f.Change("res:n1", func(r *ops.Resource) { r.Group = "net0" })
	r := Check(f.Inventory, f.Map, f.Root, f.Now)
	if !has(r, "RO-C08.declared", ops.Fail) {
		t.Fatal(r)
	}
}
func TestExpiredCertificateAndMissingInputsDiffer(t *testing.T) {
	f := fixture.New(t)
	r := Check(f.Inventory, f.Map, f.Root, f.Now.Add(48*time.Hour))
	if !has(r, "RO-C03.static", ops.Fail) {
		t.Fatal("expired leaf accepted")
	}
	os.Remove(filepath.Join(f.Root, "client1.crt"))
	r = Check(f.Inventory, f.Map, f.Root, f.Now)
	if !has(r, "RO-C03.static", ops.CannotCheck) || r.ExitCode() != 2 {
		t.Fatal("missing leaf not unmeasured")
	}
}
func TestUnknownSkill(t *testing.T) {
	f := fixture.New(t)
	f.Change("res:q1", func(r *ops.Resource) { r.Skills = []string{"not_defined"} })
	r := Check(f.Inventory, f.Map, f.Root, f.Now)
	if !has(r, "RO-C05", ops.Fail) {
		t.Fatal(r)
	}
}

func TestComponentOnWrongNetworkRefuses(t *testing.T) {
	f := fixture.New(t)
	f.Change("cmp:g1", func(r *ops.Resource) { r.Group = "net0" })
	r := Check(f.Inventory, f.Map, f.Root, f.Now)
	if !has(r, "RO-C08.declared", ops.Fail) {
		t.Fatal(r)
	}
}
func TestDescribeImportsBothRobotsWithoutActivating(t *testing.T) {
	f := fixture.New(t)
	inv, e := Describe(f.Map, f.Root)
	if e != nil {
		t.Fatal(e)
	}
	if len(inv.Robots) != 2 {
		t.Fatal(inv)
	}
	for _, r := range inv.Robots {
		if r.Lifecycle != "planned" || r.DisplayName != r.RobotID {
			t.Fatal("import granted activation", r)
		}
	}
	if Check(inv, f.Map, f.Root, f.Now).ExitCode() != 0 {
		t.Fatal("derived inventory inconsistent")
	}
	duplicate := f.Map.Resources[len(f.Map.Resources)-1]
	duplicate.ID = "res:duplicate"
	f.Map.Resources = append(f.Map.Resources, duplicate)
	if _, e = Describe(f.Map, f.Root); e == nil {
		t.Fatal("ambiguous transport guessed")
	}
}
func TestInvalidUnusedSkillFileCannotHide(t *testing.T) {
	f := fixture.New(t)
	if e := os.WriteFile(filepath.Join(f.Root, "skills.viam_base.yaml"), []byte("invalid: shape\n"), 0600); e != nil {
		t.Fatal(e)
	}
	r := Check(f.Inventory, f.Map, f.Root, f.Now)
	if !has(r, "RO-C05", ops.Fail) {
		t.Fatal("unused broken registry hidden", r)
	}
}
