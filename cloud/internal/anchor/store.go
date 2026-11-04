// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package anchor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store abstracts the append-only anchor repository (LLD-v2 §7.1). Reference
// implementations: HTTP PUT and local filesystem. No vendor lock-in.
type Store interface {
	Put(name string, data []byte) error
}

// HTTPStore uploads via HTTP PUT to BaseURL/<name>. When AuthToken is set it
// is presented as a bearer transport credential (Anchor SaaS auth-on front
// door); empty AuthToken keeps the legacy header-free behavior.
//
// TokenFile (rotation, LLD ROTATE-v1 D2) takes precedence over AuthToken: the
// file is re-read on every Put, so a credential rotation lands on the next
// upload without a process restart. Writers must replace the file atomically
// (same-dir tmp + rename). A read failure falls back to the last good token
// (the server stays the fail-closed authority for stale tokens); token values
// are never logged — only a non-reversible fingerprint on change.
type HTTPStore struct {
	BaseURL   string
	AuthToken string
	TokenFile string
	Client    *http.Client
	Logf      func(format string, v ...any)

	mu       sync.Mutex
	cached   string
	warnOnce bool
}

func (s *HTTPStore) logf(format string, v ...any) {
	if s.Logf != nil {
		s.Logf(format, v...)
		return
	}
	log.Printf(format, v...)
}

func (s *HTTPStore) token() string {
	if s.TokenFile == "" {
		return s.AuthToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.TokenFile)
	if err != nil {
		if !s.warnOnce {
			s.warnOnce = true
			s.logf("anchor: token file read failed, using last good token: %v", err)
		}
		return s.cached
	}
	s.warnOnce = false
	t := strings.TrimSpace(string(b))
	if t != s.cached {
		s.cached = t
		fp := sha256.Sum256([]byte(t))
		s.logf("anchor: bearer token reloaded (fp=%s)", hex.EncodeToString(fp[:4]))
	}
	return t
}

func (s *HTTPStore) Put(name string, data []byte) error {
	c := s.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	url := strings.TrimRight(s.BaseURL, "/") + "/" + name
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := s.token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("anchor put %s: http %d", name, resp.StatusCode)
	}
	return nil
}

// StoreFromEnv picks the anchor store adapter (LLD-v2 §7.1 — no vendor
// lock-in): PAIL_ANCHOR_URL (HTTP PUT) takes precedence over PAIL_ANCHOR_DIR
// (mounted filesystem). Neither set => nil (anchor agent disabled).
// PAIL_ANCHOR_TOKEN_FILE (rotatable, re-read per upload) takes precedence
// over PAIL_ANCHOR_TOKEN (static); either arms a bearer transport credential
// for the HTTP store. Token values are never logged.
func StoreFromEnv() (Store, string) {
	if u := os.Getenv("PAIL_ANCHOR_URL"); u != "" {
		desc := "http store " + u
		if tf := os.Getenv("PAIL_ANCHOR_TOKEN_FILE"); tf != "" {
			return &HTTPStore{BaseURL: u, TokenFile: tf}, desc + " (bearer:file)"
		}
		tok := os.Getenv("PAIL_ANCHOR_TOKEN")
		if tok != "" {
			desc += " (bearer)"
		}
		return &HTTPStore{BaseURL: u, AuthToken: tok}, desc
	}
	if d := os.Getenv("PAIL_ANCHOR_DIR"); d != "" {
		return &FSStore{Dir: d}, "fs store " + d
	}
	return nil, ""
}

// FSStore writes anchor records into a local directory (e.g. mounted
// append-only storage).
type FSStore struct {
	Dir string
}

func (s *FSStore) Put(name string, data []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.Dir, name), data, 0o600)
}
