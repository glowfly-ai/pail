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

func neverCheck(t *testing.T) Checker {
	return func(Inventory, ResourceMap, string, time.Time) Report {
		t.Fatal("checker ran without complete, valid usage")
		return Report{}
	}
}

// The evaluator of rc20 reached `describe` only by reading source. Usage must
// name it, and asking for help must not run a check.
func TestUsageNamesDescribeAndRefusesWithoutRunning(t *testing.T) {
	var out, errs bytes.Buffer
	if rc := RunCLI([]string{"--help"}, &out, &errs, neverCheck(t)); rc != 2 {
		t.Fatalf("--help rc=%d, want 2", rc)
	}
	for _, want := range []string{"describe --resources FILE --root DIR", "planned inventory draft", "--inventory", "--resources", "--root"} {
		if !strings.Contains(errs.String(), want) {
			t.Fatalf("usage lacks %q:\n%s", want, errs.String())
		}
	}
	if out.Len() != 0 {
		t.Fatal("usage wrote to stdout; a report consumer would parse it")
	}
	errs.Reset()
	if rc := RunCLI([]string{"--inventory", "a", "--resources", "b", "--root", "c", "extra"}, &out, &errs, neverCheck(t)); rc != 2 || !strings.Contains(errs.String(), "RO_USAGE") {
		t.Fatalf("stray positional accepted: rc=%d %s", rc, errs.String())
	}
	errs.Reset()
	if rc := RunCLI([]string{"--mode", "live", "--inventory", "a", "--resources", "b", "--root", "c"}, &out, &errs, neverCheck(t)); rc != 2 || !strings.Contains(errs.String(), "only --mode offline") {
		t.Fatalf("non-offline mode accepted: rc=%d %s", rc, errs.String())
	}
	errs.Reset()
	if rc := RunDescribeCLI([]string{"--resources", "x"}, &out, &errs, nil); rc != 2 {
		t.Fatalf("describe without --root rc=%d, want 2", rc)
	}
}

// examples/robotops/README.md promises the describe draft is byte-for-byte the
// fixture's inventory.json; the fixture writes MarshalIndent("", "  ") + "\n".
func TestDescribeDraftUsesTheFixtureSerialization(t *testing.T) {
	const dep = "5e8b24a0-2319-4a53-b5cf-a03afc977301"
	res := filepath.Join(t.TempDir(), "resources.json")
	if err := os.WriteFile(res, []byte(`{"schema_version":1,"deployment_id":"`+dep+`","resources":[{"id":"res:class","kind":"class","value":"diff_drive_amr"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	inv := Inventory{SchemaVersion: 1, DeploymentID: dep, Revision: 1, ProfileID: "local-compose-ros2/v1", Robots: []Robot{{RobotID: "robot-01", DisplayName: "robot-01", Lifecycle: "planned"}}}
	var out, errs bytes.Buffer
	rc := RunDescribeCLI([]string{"--resources", res, "--root", t.TempDir()}, &out, &errs, func(ResourceMap, string) (Inventory, error) { return inv, nil })
	if rc != 0 {
		t.Fatalf("rc=%d %s", rc, errs.String())
	}
	want, _ := json.MarshalIndent(inv, "", "  ")
	if !bytes.Equal(out.Bytes(), append(want, '\n')) {
		t.Fatalf("draft bytes differ from the fixture serialization:\n%s", out.String())
	}
}

// One message for four causes made the evaluator guess. Each cause names itself.
func TestResourceMapSchemaErrorsAreSpecific(t *testing.T) {
	const dep = "5e8b24a0-2319-4a53-b5cf-a03afc977301"
	ok := `{"schema_version":1,"deployment_id":"` + dep + `","resources":[{"id":"res:class","kind":"class","value":"diff_drive_amr"}]}`
	if _, err := DecodeResourceMap([]byte(ok)); err != nil {
		t.Fatalf("positive control rejected: %v", err)
	}
	many := `{"schema_version":1,"deployment_id":"` + dep + `","resources":[` + strings.Repeat(`{"id":"res:class","kind":"class","value":"x"},`, 10000) + `{"id":"res:last","kind":"class","value":"x"}]}`
	cases := []struct{ name, raw, want string }{
		{"version", `{"schema_version":2,"deployment_id":"` + dep + `","resources":[{"id":"res:class","kind":"class","value":"x"}]}`, "schema_version must be 1"},
		{"deployment", `{"schema_version":1,"deployment_id":"5E8B24A0-2319-4A53-B5CF-A03AFC977301","resources":[{"id":"res:class","kind":"class","value":"x"}]}`, "deployment_id must be a lowercase UUID"},
		{"empty", `{"schema_version":1,"deployment_id":"` + dep + `","resources":[]}`, "resources must not be empty"},
		{"too many", many, "exceeds 10000 entries"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		_, err := DecodeResourceMap([]byte(c.raw))
		if err == nil {
			t.Fatalf("%s: accepted", c.name)
		}
		if !strings.HasPrefix(err.Error(), "RO_SCHEMA: ") || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v (want RO_SCHEMA … %s)", c.name, err, c.want)
		}
		if seen[err.Error()] {
			t.Fatalf("%s: message %q reused for a different cause", c.name, err.Error())
		}
		seen[err.Error()] = true
	}
}
