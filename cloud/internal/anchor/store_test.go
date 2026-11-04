// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package anchor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureAuth(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	got := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestHTTPStoreBearerAttached(t *testing.T) {
	srv, got := captureAuth(t)
	s := &HTTPStore{BaseURL: srv.URL, AuthToken: "sekrit-123"}
	if err := s.Put("a.json", []byte("{}")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if *got != "Bearer sekrit-123" {
		t.Fatalf("Authorization = %q, want %q", *got, "Bearer sekrit-123")
	}
}

func TestHTTPStoreNoTokenNoHeader(t *testing.T) {
	srv, got := captureAuth(t)
	s := &HTTPStore{BaseURL: srv.URL}
	if err := s.Put("a.json", []byte("{}")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if *got != "" {
		t.Fatalf("Authorization = %q, want empty (legacy behavior)", *got)
	}
}

func TestStoreFromEnvBearerWiring(t *testing.T) {
	t.Setenv("PAIL_ANCHOR_URL", "http://example.invalid/v1/anchors/t/r")
	t.Setenv("PAIL_ANCHOR_TOKEN", "tok-1")
	t.Setenv("PAIL_ANCHOR_TOKEN_FILE", "")
	store, desc := StoreFromEnv()
	hs, ok := store.(*HTTPStore)
	if !ok {
		t.Fatalf("store type = %T, want *HTTPStore", store)
	}
	if hs.AuthToken != "tok-1" {
		t.Fatalf("AuthToken = %q, want tok-1", hs.AuthToken)
	}
	if desc != "http store http://example.invalid/v1/anchors/t/r (bearer)" {
		t.Fatalf("desc = %q, want bearer suffix", desc)
	}
	// token value must never leak into the loggable description
	if strings.Contains(desc, "tok-1") {
		t.Fatalf("desc leaks token: %q", desc)
	}
}

// LLD ROTATE-v1 D2: TokenFile is re-read on every Put — a rotation lands on
// the next upload with no restart. Trailing whitespace/newline is trimmed.
func TestHTTPStoreTokenFileReload(t *testing.T) {
	srv, got := captureAuth(t)
	tf := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tf, []byte("old-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	s := &HTTPStore{BaseURL: srv.URL, TokenFile: tf,
		Logf: func(f string, v ...any) { fmt.Fprintf(&logs, f+"\n", v...) }}

	if err := s.Put("a.json", []byte("{}")); err != nil {
		t.Fatalf("put1: %v", err)
	}
	if *got != "Bearer old-key" {
		t.Fatalf("put1 Authorization = %q, want trimmed old-key", *got)
	}

	// atomic swap
	tmp := tf + ".tmp"
	if err := os.WriteFile(tmp, []byte("new-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, tf); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("b.json", []byte("{}")); err != nil {
		t.Fatalf("put2: %v", err)
	}
	if *got != "Bearer new-key" {
		t.Fatalf("put2 Authorization = %q, want new-key (no restart)", *got)
	}

	out := logs.String()
	if n := strings.Count(out, "bearer token reloaded"); n != 2 {
		t.Fatalf("want 2 reload fingerprints (initial+swap), got %d in %q", n, out)
	}
	if strings.Contains(out, "old-key") || strings.Contains(out, "new-key") {
		t.Fatalf("token plaintext leaked into logs: %q", out)
	}
}

// Read failure falls back to the last good token (availability; the server
// remains the fail-closed authority) and warns once.
func TestHTTPStoreTokenFileReadErrorKeepsLastGood(t *testing.T) {
	srv, got := captureAuth(t)
	tf := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tf, []byte("good-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	s := &HTTPStore{BaseURL: srv.URL, TokenFile: tf,
		Logf: func(f string, v ...any) { fmt.Fprintf(&logs, f+"\n", v...) }}

	if err := s.Put("a.json", []byte("{}")); err != nil {
		t.Fatalf("put1: %v", err)
	}
	if err := os.Remove(tf); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("b.json", []byte("{}")); err != nil {
		t.Fatalf("put2: %v", err)
	}
	if *got != "Bearer good-key" {
		t.Fatalf("Authorization = %q, want last good token", *got)
	}
	if err := s.Put("c.json", []byte("{}")); err != nil {
		t.Fatalf("put3: %v", err)
	}
	if n := strings.Count(logs.String(), "token file read failed"); n != 1 {
		t.Fatalf("want exactly 1 read-failure warning, got %d", n)
	}
}

// No file ever readable and no cache => header-free PUT (server answers 401
// no_credential and the record queues — no silent failure).
func TestHTTPStoreTokenFileMissingNoCache(t *testing.T) {
	srv, got := captureAuth(t)
	s := &HTTPStore{BaseURL: srv.URL,
		TokenFile: filepath.Join(t.TempDir(), "absent"),
		Logf:      func(string, ...any) {}}
	if err := s.Put("a.json", []byte("{}")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if *got != "" {
		t.Fatalf("Authorization = %q, want empty (no cache, no header)", *got)
	}
}

// LLD ROTATE-v1 D1: PAIL_ANCHOR_TOKEN_FILE wins over PAIL_ANCHOR_TOKEN; desc
// shows the file mode without leaking anything secret.
func TestStoreFromEnvTokenFilePrecedence(t *testing.T) {
	t.Setenv("PAIL_ANCHOR_URL", "http://example.invalid/v1/anchors/t/r")
	t.Setenv("PAIL_ANCHOR_TOKEN", "static-tok")
	t.Setenv("PAIL_ANCHOR_TOKEN_FILE", "/etc/pail/token")
	store, desc := StoreFromEnv()
	hs, ok := store.(*HTTPStore)
	if !ok {
		t.Fatalf("store type = %T, want *HTTPStore", store)
	}
	if hs.TokenFile != "/etc/pail/token" {
		t.Fatalf("TokenFile = %q", hs.TokenFile)
	}
	if hs.AuthToken != "" {
		t.Fatalf("AuthToken = %q, want empty when file mode wins", hs.AuthToken)
	}
	if !strings.HasSuffix(desc, " (bearer:file)") {
		t.Fatalf("desc = %q, want bearer:file suffix", desc)
	}
	if strings.Contains(desc, "static-tok") {
		t.Fatalf("desc leaks static token: %q", desc)
	}
}

func TestStoreFromEnvNoToken(t *testing.T) {
	t.Setenv("PAIL_ANCHOR_URL", "http://example.invalid/v1/anchors/t/r")
	t.Setenv("PAIL_ANCHOR_TOKEN", "")
	t.Setenv("PAIL_ANCHOR_TOKEN_FILE", "")
	store, desc := StoreFromEnv()
	hs, ok := store.(*HTTPStore)
	if !ok {
		t.Fatalf("store type = %T, want *HTTPStore", store)
	}
	if hs.AuthToken != "" {
		t.Fatalf("AuthToken = %q, want empty", hs.AuthToken)
	}
	if desc != "http store http://example.invalid/v1/anchors/t/r" {
		t.Fatalf("desc = %q, want no bearer suffix", desc)
	}
}
