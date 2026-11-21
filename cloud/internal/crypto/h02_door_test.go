// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

// SEC-H02 — the one seam between the Go batteries of this package and the product
// (test LLD §1.2). Everything the SEC-H02 tests ask of the bundle trust path goes
// through the three functions below; their bodies are the only test code that differs
// before and after the fix. (These are the fixed tree's bodies. On the unfixed tree a
// function with no product counterpart returned errH02NotImplemented, so the tests
// compiled and failed in their assertions.)

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/glowfly/pail/services/internal/deploysec"
)

var errH02NotImplemented = errors.New("H02_NOT_IMPLEMENTED")

// h02Verdict is a load result in the terms the parity vectors compare.
type h02Verdict struct {
	Loaded     bool
	Class      string // "" when loaded; else one of SIG EXPIRED ROLLBACK LIFETIME STATE ENTRY POLICY
	IssuerIDs  []string
	RevokedIDs []string
	Err        error
}

// h02Class maps a load error to its cause class. An error outside the table is a class
// of its own, so an unexpected refusal shows as a mismatch instead of a neighbour.
func h02Class(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrBundleSignature) {
		return "SIG"
	}
	switch deploysec.RuleID(err) {
	case "S20":
		return "LIFETIME"
	case "S20b":
		return "POLICY"
	case "S20d":
		return "EXPIRED"
	case "S15", "S15b":
		return "ENTRY"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "rollback rejected"):
		return "ROLLBACK"
	case strings.HasPrefix(msg, "bundle state"):
		return "STATE"
	case strings.Contains(msg, "unknown field"), strings.Contains(msg, "duplicate"),
		strings.Contains(msg, "bundle: entry"), strings.Contains(msg, "bundle: key "),
		strings.Contains(msg, "parse payload"):
		return "ENTRY"
	}
	return "UNCLASSIFIED(" + msg + ")"
}

// h02LoadGo loads a bundle the way a Go consumer starts: files in a directory of its
// own, the environment pointing at them, LoadTrustedKeyringFromEnv.
// state: "absent" | "garbled" | "floor:<N>". maxLifetimeSec "" leaves the ceiling undeclared.
func h02LoadGo(t *testing.T, bundle []byte, rootPubB64, state, profile, maxLifetimeSec string) h02Verdict {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "keyring_bundle.json")
	rootPath := filepath.Join(dir, "root_pub.b64")
	statePath := filepath.Join(dir, "keyring_bundle.state.json")
	mustWrite(t, bundlePath, bundle, 0644)
	mustWrite(t, rootPath, []byte(rootPubB64+"\n"), 0644)
	switch {
	case state == "absent":
	case state == "garbled":
		mustWrite(t, statePath, []byte("this is not json"), 0600)
	case strings.HasPrefix(state, "floor:"):
		mustWrite(t, statePath, []byte(`{"last_version": `+strings.TrimPrefix(state, "floor:")+"}\n"), 0600)
	default:
		t.Fatalf("h02LoadGo: unknown state %q", state)
	}
	t.Setenv("PAIL_KEYRING_MODE", "bundle")
	t.Setenv("PAIL_KEYRING_BUNDLE", bundlePath)
	t.Setenv("PAIL_ROOT_PUBKEY_FILE", rootPath)
	t.Setenv("PAIL_KEYRING_STATE", statePath)
	t.Setenv("PAIL_PROFILE", profile)
	t.Setenv(EnvBundleMaxLifetime, maxLifetimeSec)
	if maxLifetimeSec == "" {
		os.Unsetenv(EnvBundleMaxLifetime)
	}
	kr, _, err := LoadTrustedKeyringFromEnv(filepath.Join(dir, "keyring.json"))
	v := h02Verdict{Err: err, Class: h02Class(err), IssuerIDs: []string{}, RevokedIDs: []string{}}
	if err != nil {
		return v
	}
	v.Loaded = true
	for _, e := range kr.Keys {
		if e.Role == "issuer" {
			v.IssuerIDs = append(v.IssuerIDs, e.KeyID)
		}
	}
	for _, e := range kr.RevokedKeys {
		if e.Role == "issuer" {
			v.RevokedIDs = append(v.RevokedIDs, e.KeyID)
		}
	}
	sort.Strings(v.IssuerIDs)
	sort.Strings(v.RevokedIDs)
	return v
}

// h02InitFloor is the explicit first-install step of a production consumer: verify the
// placed bundle against the root and write its version as the floor, never over an
// existing state file.
func h02InitFloor(bundlePath, rootPubFile, statePath string) error {
	rootPub, err := ReadRootPubFile(rootPubFile)
	if err != nil {
		return err
	}
	_, err = InitBundleFloor(bundlePath, rootPub, statePath)
	return err
}

func mustWrite(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
}

func h02B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
