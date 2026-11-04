// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"encoding/json"
	"github.com/glowfly/pail/services/internal/ledgerq"
	"net/http/httptest"
	"testing"
)

func TestMOBSFrontierPlansHTTP(t *testing.T) {
	ledgerFixture(t)
	for _, tc := range []struct {
		query      string
		count      int
		resolution string
	}{{"from_ms=1&robot=robot-1", 1, "registry"}, {"from_ms=1&robot=not-registered", 0, "unresolved"}} {
		rr := httptest.NewRecorder()
		ledgerPlansHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/v1/ledger/plans?"+tc.query, nil))
		var got ledgerq.PlansResult
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if rr.Code != 200 || len(got.Plans) != tc.count || got.Resolution != tc.resolution {
			t.Fatalf("HTTP %d %s", rr.Code, rr.Body.String())
		}
	}
	prev := ledgerIndex
	ledgerIndex = nil
	rr := httptest.NewRecorder()
	ledgerPlansHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/v1/ledger/plans", nil))
	ledgerIndex = prev
	if rr.Code != 503 {
		t.Fatal(rr.Code)
	}
	rr = httptest.NewRecorder()
	ledgerPlansHandler().ServeHTTP(rr, httptest.NewRequest("POST", "/v1/ledger/plans", nil))
	if rr.Code != 405 {
		t.Fatal(rr.Code)
	}
}

func TestMOBSFrontierPlansInvalidCursor(t *testing.T) {
	ledgerFixture(t)
	rr := httptest.NewRecorder()
	ledgerPlansHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/v1/ledger/plans?cursor=bad!", nil))
	if rr.Code != 400 {
		t.Fatalf("invalid cursor: %d %s", rr.Code, rr.Body.String())
	}
}
