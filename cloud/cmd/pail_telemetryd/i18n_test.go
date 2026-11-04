// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestDashboardLanguageAssetIsEmbeddedAndServed(t *testing.T) {
 for _,method:=range []string{http.MethodGet,http.MethodHead} {
  rr:=httptest.NewRecorder()
  serveDashboard(rr,httptest.NewRequest(method,"/dashboard/i18n.js",nil))
  if rr.Code!=http.StatusOK || !strings.Contains(rr.Header().Get("Content-Type"),"javascript") { t.Fatalf("%s: code=%d type=%s",method,rr.Code,rr.Header().Get("Content-Type")) }
  if method==http.MethodGet && !strings.Contains(rr.Body.String(),"pail.dashboard.language") { t.Fatal("served asset lacks locale persistence") }
 }
 rr:=httptest.NewRecorder();serveDashboard(rr,httptest.NewRequest(http.MethodGet,"/dashboard/",nil))
 body:=rr.Body.String()
 if !strings.Contains(body,`<html lang="en">`) || !strings.Contains(body,`id="language"`) || !strings.Contains(body,`src="i18n.js"`) { t.Fatal("dashboard does not wire English-default language picker") }
 rr=httptest.NewRecorder();serveDashboard(rr,httptest.NewRequest(http.MethodPost,"/dashboard/i18n.js",nil))
 if rr.Code!=http.StatusMethodNotAllowed { t.Fatalf("POST: %d",rr.Code) }
}
