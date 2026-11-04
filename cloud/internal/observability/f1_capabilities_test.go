// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package observability

import (
	"net/http/httptest"
	"testing"
)

// A collector without a source map answers its
// capabilities as a document that says "no observation here", not as a 503 the
// page reads as an outage. The data endpoint keeps its 503.
func TestF1CapabilitiesWithoutSourceMapIsAnAnswer(t *testing.T) {
	for _, managed := range []bool{false, true} {
		a := NewAPI(nil)
		a.SetManagementProjection(managed)
		m := screenDocument(t, a)
		if m["observation"] != false || m["management_projection"] != managed || m["reason"] != "SOURCE_MAP_UNCONFIGURED" {
			t.Fatalf("managed=%v: capabilities without a source map = %v", managed, m)
		}
		if eps, ok := m["endpoints"].([]any); !ok || len(eps) != 0 {
			t.Fatalf("endpoints = %v, want an empty list", m["endpoints"])
		}
	}
	w := httptest.NewRecorder()
	NewAPI(nil).Robots(w, httptest.NewRequest("GET", "/v2/observation/robots", nil))
	if w.Code != 503 {
		t.Fatalf("robots without a source map answered %d, want 503 (no data is not empty data)", w.Code)
	}
}
