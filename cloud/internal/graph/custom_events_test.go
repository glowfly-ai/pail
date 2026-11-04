// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package graph

import (
	"strings"
	"testing"
)

const customSite = `
site: warehouse-A
schema: v3
zones:
  - id: z7
    type: work_area
robots:
  - id: robot-01
    capabilities: [move]
    schema: v3
    home: z7
`

// AG-8: custom_events is a declaration (not world state): it compiles into
// the SiteModel map, never into the graph or its hash, and every entry must
// have the namespaced shape, a built-in effect and a unique id.
func TestCompileCustomEvents(t *testing.T) {
	g0, _, err := Compile([]byte(customSite))
	if err != nil {
		t.Fatal(err)
	}
	g, sm, err := Compile([]byte(customSite + `
custom_events:
  - id: acme.gas_alarm
    effect: CORDON_ON
    description: gas detector near the robot
  - id: acme.gas_clear
    effect: CORDON_OFF
`))
	if err != nil {
		t.Fatal(err)
	}
	if sm.CustomEvents["acme.gas_alarm"] != "CORDON_ON" || sm.CustomEvents["acme.gas_clear"] != "CORDON_OFF" || len(sm.CustomEvents) != 2 {
		t.Fatalf("custom events not compiled: %v", sm.CustomEvents)
	}
	if len(g.Nodes) != len(g0.Nodes) || len(g.Edges) != len(g0.Edges) || g.Epoch != g0.Epoch {
		t.Fatal("a declaration must not change the graph")
	}
	for id := range g.Nodes {
		if strings.HasPrefix(id, "custom") || strings.Contains(id, "acme") {
			t.Fatalf("declaration leaked into the graph as %s", id)
		}
	}
	for name, body := range map[string]string{
		"no namespace":   "  - id: gas_alarm\n    effect: CORDON_ON\n",
		"uppercase":      "  - id: Acme.gas_alarm\n    effect: CORDON_ON\n",
		"two dots":       "  - id: acme.site.gas_alarm\n    effect: CORDON_ON\n",
		"unknown effect": "  - id: acme.gas_alarm\n    effect: EVACUATE\n",
		"effect CUSTOM":  "  - id: acme.gas_alarm\n    effect: CUSTOM\n",
		"effect unspec":  "  - id: acme.gas_alarm\n    effect: CONTEXT_EVENT_KIND_UNSPECIFIED\n",
		"missing effect": "  - id: acme.gas_alarm\n",
		"duplicate id":   "  - id: acme.gas_alarm\n    effect: CORDON_ON\n  - id: acme.gas_alarm\n    effect: CORDON_OFF\n",
		"unknown key":    "  - id: acme.gas_alarm\n    effect: CORDON_ON\n    zone: z7\n",
	} {
		if _, _, err := Compile([]byte(customSite + "custom_events:\n" + body)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "custom_events") && !strings.Contains(err.Error(), "field zone not found") {
			t.Errorf("%s: error does not name the section: %v", name, err)
		}
	}
	// Absent section: no declarations, nothing refused.
	if _, sm, err := Compile([]byte(customSite)); err != nil || len(sm.CustomEvents) != 0 {
		t.Fatalf("absent section: %v %v", err, sm.CustomEvents)
	}
}
