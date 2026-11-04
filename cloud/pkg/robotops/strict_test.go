// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validInventory() Inventory {
	return Inventory{1, "5e8b24a0-2319-4a53-b5cf-a03afc977301", 1, nil, "local-compose-ros2/v1", []Robot{{"robot-01", "Robot 1", "active", "res:class", "res:home", "cmp:agent", "cmp:gate", "cmp:bridge", "cred:client", "res:requester", "res:network", "cmp:collector"}}, Bindings{"res:registry", "res:site", "res:policy", "res:skills"}}
}
func TestStrictDocumentRefusals(t *testing.T) {
	good, _ := json.Marshal(validInventory())
	if _, err := DecodeInventory(good); err != nil {
		t.Fatal(err)
	}
	bad := map[string][]byte{"duplicate": []byte(`{"schema_version":1,"schema_version":1}`), "alias": []byte("a: &x [1]\nb: *x\n"), "tag": []byte("a: !Thing value"), "float": []byte("a: 1.0"), "unsafe integer": []byte("a: 9007199254740992"), "multiple": append(append([]byte{}, good...), []byte("\n---\na: 2")...), "unknown": bytes.Replace(good, []byte(`"schema_version":1`), []byte(`"schema_version":1,"secret":"DO_NOT_ECHO"`), 1), "wrong type": bytes.Replace(good, []byte(`"robot_id":"robot-01"`), []byte(`"robot_id":123`), 1), "empty robots": bytes.Replace(good, []byte(`"robots":[`), []byte(`"robots":[],"duplicate_field":[`), 1)}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			var out Inventory
			err := StrictDecode(b, &out, []string{"schema_version", "base_revision"})
			if err == nil {
				t.Fatal("accepted invalid management input")
			}
			if strings.Contains(err.Error(), "DO_NOT_ECHO") {
				t.Fatal("raw input leaked")
			}
		})
	}
	inv := validInventory()
	inv.Robots = append(inv.Robots, inv.Robots[0])
	b, _ := json.Marshal(inv)
	if _, err := DecodeInventory(b); err == nil {
		t.Fatal("duplicate robot accepted")
	}
	inv = validInventory()
	inv.Robots[0].RobotID = "../escape"
	b, _ = json.Marshal(inv)
	if _, err := DecodeInventory(b); err == nil {
		t.Fatal("path-like robot id accepted")
	}
	inv = validInventory()
	inv.Robots = nil
	b, _ = json.Marshal(inv)
	if _, err := DecodeInventory(b); err == nil {
		t.Fatal("empty denominator accepted")
	}
}
func TestReportMissingRobotAndUnknownCannotPass(t *testing.T) {
	r := NewReport("test", validInventory().DeploymentID, []string{"check"})
	r.RequiredSubjects = map[string][]string{"check": {"r1", "r2"}}
	r.Add("check", Pass, "r1", "x", "measured", "", "")
	if r.Finish() != 2 {
		t.Fatal("missing robot counted as pass")
	}
	r = NewReport("test", "d", []string{"check"})
	r.Add("check", Fail, "r1", "x", "mismatch", "", "")
	r.Add("check", CannotCheck, "r2", "x", "unavailable", "", "")
	if r.Finish() != 2 || r.Counts[Fail] != 1 {
		t.Fatal("partial failure was lost")
	}
	r = NewReport("test", "d", nil)
	if r.Finish() != 2 {
		t.Fatal("zero checks passed")
	}
}
func TestReadOnlyCLIRefusesBeforeReads(t *testing.T) {
	calls := 0
	checker := func(Inventory, ResourceMap, string, time.Time) Report { calls++; return Report{Summary: Pass} }
	for _, args := range [][]string{{"--mode", "live", "--inventory", "missing", "--resources", "missing", "--root", "/"}, {"--apply"}, {"--skip-auth"}, {"--inventory", "missing", "--resources", "missing", "--root", "/", "extra"}} {
		var out, err bytes.Buffer
		if RunCLI(args, &out, &err, checker) != 2 {
			t.Fatal("unsupported operation accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid arguments reached inspector")
	}
}
func TestPublicReaderDoesNotFollowLinksOrOpenPrivateResources(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	os.WriteFile(outside, []byte("CANARY"), 0600)
	os.Symlink(outside, filepath.Join(root, "link.yaml"))
	os.WriteFile(filepath.Join(root, "private.key"), []byte("SECRET_CANARY"), 0000)
	m := ResourceMap{1, validInventory().DeploymentID, []Resource{{ID: "res:link", Kind: "registry", Path: "link.yaml"}, {ID: "cred:private", Kind: "private_key", Path: "private.key"}, {ID: "res:escape", Kind: "policy", Path: "../outside.yaml"}}}
	f, err := NewFiles(root, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct{ id, kind string }{{"res:link", "registry"}, {"cred:private", "private_key"}, {"cred:private", "certificate"}, {"res:escape", "policy"}} {
		if _, err = f.Read(q.id, q.kind); err == nil {
			t.Fatalf("read refused resource: %s", q.id)
		}
	}
	if len(f.Hashes) != 0 {
		t.Fatal("refused/secret contents hashed")
	}
}
func TestCanonicalDomainAndMemberOrder(t *testing.T) {
	a := map[string]interface{}{"z": "<\u2028>", "a": int64(4)}
	b := map[string]interface{}{"a": int64(4), "z": "<\u2028>"}
	x, e := InspectionDigest("inventory", a)
	if e != nil {
		t.Fatal(e)
	}
	y, _ := InspectionDigest("inventory", b)
	if x != y {
		t.Fatal("object order changes digest")
	}
	z, _ := InspectionDigest("resource-map", b)
	if x == z {
		t.Fatal("domains not separated")
	}
	if _, e = InspectionDigest("approval", a); e == nil {
		t.Fatal("inspection helper accepted privileged domain")
	}
}

func TestExplicitStandardTagsAndAmbiguousIntegersRefuse(t *testing.T) {
	for _, raw := range []string{"value: !!str text", "!!str key: value", "value: 012", "value: +12", "value: -0"} {
		var v interface{}
		if StrictDecode([]byte(raw), &v, nil) == nil {
			t.Fatalf("ambiguous management document accepted: %s", raw)
		}
	}
}
