// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMOBSFleetEmbeddedAssets(t *testing.T) {
	for _, path := range []string{"/dashboard/", "/dashboard/fleet.js"} {
		w := httptest.NewRecorder()
		serveDashboard(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("%s status %d", path, w.Code)
		}
		if path == "/dashboard/" && (!strings.Contains(w.Body.String(), `src="fleet.js"`) || !strings.Contains(w.Body.String(), `id="tab-fleet" class="tab on"`)) {
			t.Fatal("fleet module/default tab not shipped")
		}
		if path == "/dashboard/fleet.js" && (!strings.Contains(w.Header().Get("Content-Type"), "javascript") || !strings.Contains(w.Body.String(), "root.PAIL_FLEET")) {
			t.Fatal("fleet script not served")
		}
	}
}

// P22-N4: the page carries the robot-operations capability so the script never probes a 404.
func TestDashboardPageCarriesRobotopsCapability(t *testing.T) {
	for _, tc := range []struct {
		on   bool
		want string
	}{{false, `<meta name="pail-robotops" content="off">`}, {true, `<meta name="pail-robotops" content="on">`}} {
		w := httptest.NewRecorder()
		serveDashboardWith(tc.on)(w, httptest.NewRequest("GET", "/dashboard/", nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), tc.want) || strings.Contains(w.Body.String(), robotopsMetaPlaceholder) {
			t.Fatalf("robotops=%v: page lacks %s (status %d)", tc.on, tc.want, w.Code)
		}
	}
	if !strings.Contains(string(mustRead(t, "dashboard/robotops.js")), `meta[name="pail-robotops"]`) {
		t.Fatal("robotops.js does not read the page capability")
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := dashboardFS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
