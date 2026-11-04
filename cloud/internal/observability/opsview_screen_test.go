// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func screenDocument(t *testing.T, a *API) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	a.Capabilities(w, httptest.NewRequest("GET", "/v2/observation/capabilities", nil))
	var m map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &m) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	return m
}

// The page draws a tab or a column only where the collector says there is a
// source behind it. Each member is judged on a source map that differs from
// the plain one in that member only.
func TestOpsviewScreenCapabilities(t *testing.T) {
	c, _ := ledgerFixture(t)
	m := screenDocument(t, NewAPI(c))
	want := map[string]any{"observation": true, "signed_events": false, "signed_permit_statements": false,
		"management_projection": false, "management_observation": false, "clock_binding": "none"}
	for k, v := range want {
		if got, ok := m[k]; !ok || got != v {
			t.Fatalf("%s = %v (present %v), want %v", k, got, ok, v)
		}
	}

	a := NewAPI(c)
	a.SetManagementProjection(true)
	if m = screenDocument(t, a); m["management_projection"] != true || m["management_observation"] != false {
		t.Fatal("projection flag", m)
	}

	burst := Provider{ProviderID: "burst", Kind: "legacy_burst", DeploymentID: dep, RobotID: "robot-1", Identity: "device-1", Allowed: []string{"gate"}, Trust: "verified_signature", Role: "primary"}
	c, _ = fixture(t, burst, ledgerSource())
	if m = screenDocument(t, NewAPI(c)); m["signed_events"] != true || m["signed_permit_statements"] != false {
		t.Fatal("signed events", m)
	}
	mirror := Provider{ProviderID: "mirror", Kind: "legacy_permit", DeploymentID: dep, RobotID: "robot-1", Identity: "device-1", Allowed: []string{"permit"}, Trust: "verified_signature", Role: "primary"}
	c, _ = fixture(t, mirror, ledgerSource())
	if m = screenDocument(t, NewAPI(c)); m["signed_events"] != false || m["signed_permit_statements"] != true {
		t.Fatal("signed permit statements", m)
	}

	// No provider kind of this release may supply management observations (the
	// source map refuses it), so the member is false on every accepted source
	// map. The rule itself is judged on a collector whose declaration is
	// widened after it was accepted.
	c, _ = ledgerFixture(t)
	c.config.Providers[0].Allowed = append(c.config.Providers[0].Allowed, "management")
	if m = screenDocument(t, NewAPI(c)); m["management_observation"] != true || m["management_projection"] != false {
		t.Fatal("management observation", m)
	}

	bound := provider("one", "robot-1", dep)
	bound.ClockBinding = ClockBindingShared
	c, _ = fixture(t, bound, ledgerSource())
	if m = screenDocument(t, NewAPI(c)); m["clock_binding"] != ClockBindingShared {
		t.Fatal("clock binding", m)
	}
}

// A source map written for RC22 gets the document RC22 gave: no new member.
func TestOpsviewScreenCapabilitiesAbsentWithoutLedgerSource(t *testing.T) {
	c, _ := fixture(t, provider("one", "robot-1", dep))
	a := NewAPI(c)
	a.SetManagementProjection(true)
	m := screenDocument(t, a)
	for _, k := range []string{"observation", "signed_events", "signed_permit_statements", "management_projection", "management_observation", "clock_binding", "feeds"} {
		if _, ok := m[k]; ok {
			t.Fatalf("%s present without the ledger source", k)
		}
	}
}
