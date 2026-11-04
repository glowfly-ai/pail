// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package robotops

import (
	"encoding/json"
	"strings"
	"testing"
)

func projectionFixture() ProjectionSnapshot {
	return ProjectionSnapshot{SchemaVersion: 1, DocumentKind: "RobotOpsProjection", DeploymentID: testDeployment, SnapshotRevision: 7, Source: "executor-store", Producer: "test", GeneratedAtMS: 1_700_000_000_000, Capabilities: []string{"inventory.v1"}, Findings: []string{}, Rows: []ProjectionRow{
		{RobotID: "robot-01", DisplayName: "one", Lifecycle: "planned", DesiredGeneration: strings.Repeat("ab", 32), ExecutionID: "9a1f2e3d-4c5b-4a69-8877-665544332211", JobState: "VERIFYING", Registration: map[string]string{"state": "ACTIVATED"}, LoadedConfig: []ProjectionLoaded{{ComponentRef: "cmp:issuer", Kind: "issuer-loaded-status", Status: "PASS", Reason: "ok"}}, IdentityBinding: map[string]string{"state": "CANNOT_CHECK"}, ApplyReadiness: "VERIFICATION_INCOMPLETE", Findings: []string{}, Diagnostics: map[string]string{}},
		{RobotID: "robot-02", DisplayName: "two", Lifecycle: "active", DesiredGeneration: strings.Repeat("ab", 32), ExecutionID: "9a1f2e3d-4c5b-4a69-8877-665544332211", JobState: "VERIFYING", Registration: map[string]string{}, LoadedConfig: []ProjectionLoaded{}, IdentityBinding: map[string]string{}, ApplyReadiness: "CANNOT_CHECK", Findings: []string{}, Diagnostics: map[string]string{}},
	}}
}

func TestProjectionDecodeRejectsSecretsPathsAndSchema(t *testing.T) {
	good := projectionFixture()
	raw, _ := json.Marshal(good)
	p, e := DecodeProjection(raw)
	if e != nil || len(p.Rows) != 2 {
		t.Fatal(e)
	}
	cases := map[string]func(m map[string]interface{}){
		"schema 2": func(m map[string]interface{}) { m["schema_version"] = 2 },
		"secret key": func(m map[string]interface{}) {
			m["rows"].([]interface{})[0].(map[string]interface{})["diagnostics"].(map[string]interface{})["secret_handle"] = "x"
		},
		"token key": func(m map[string]interface{}) { m["approval_token"] = "x" },
		"absolute path": func(m map[string]interface{}) {
			m["rows"].([]interface{})[0].(map[string]interface{})["diagnostics"].(map[string]interface{})["evidence"] = "/var/lib/pail/x.json"
		},
		"bad lifecycle": func(m map[string]interface{}) {
			m["rows"].([]interface{})[0].(map[string]interface{})["lifecycle"] = "gone"
		},
		"dup robot": func(m map[string]interface{}) {
			m["rows"].([]interface{})[1].(map[string]interface{})["robot_id"] = "robot-01"
		},
		"wrong kind": func(m map[string]interface{}) { m["document_kind"] = "ChangePlan" },
		"empty readiness": func(m map[string]interface{}) {
			m["rows"].([]interface{})[0].(map[string]interface{})["apply_readiness"] = ""
		},
		"unknown field": func(m map[string]interface{}) { m["extra"] = 1 },
	}
	for name, mutate := range cases {
		var m map[string]interface{}
		json.Unmarshal(raw, &m)
		mutate(m)
		b, _ := json.Marshal(m)
		if _, e := DecodeProjection(b); e == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// API paths are allowed in strings (they are not filesystem paths).
	var m map[string]interface{}
	json.Unmarshal(raw, &m)
	m["findings"] = []interface{}{"see /v1/telemetry/robotops"}
	b, _ := json.Marshal(m)
	if _, e := DecodeProjection(b); e != nil {
		t.Fatal("API path refused", e)
	}
}

func TestMembershipETagIgnoresDiagnostics(t *testing.T) {
	a := projectionFixture()
	b := projectionFixture()
	b.GeneratedAtMS++
	b.SnapshotRevision++
	b.Rows[0].JobState = "APPLIED_HELD"
	b.Rows[0].Diagnostics["x"] = "y"
	if MembershipETag(a) != MembershipETag(b) {
		t.Fatal("etag changed without a membership change")
	}
	c := projectionFixture()
	c.Rows[1].DisplayName = "renamed"
	d := projectionFixture()
	d.Rows = d.Rows[:1]
	e := projectionFixture()
	e.Rows[0].Lifecycle = "disabled"
	for name, v := range map[string]ProjectionSnapshot{"display name": c, "membership": d, "lifecycle": e} {
		if MembershipETag(v) == MembershipETag(a) {
			t.Fatalf("etag unchanged on %s change", name)
		}
	}
	// Order-independent.
	f := projectionFixture()
	f.Rows[0], f.Rows[1] = f.Rows[1], f.Rows[0]
	if MembershipETag(f) != MembershipETag(a) {
		t.Fatal("etag depends on row order")
	}
}
