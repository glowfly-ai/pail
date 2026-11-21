// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

// SEC-H02 — the explicit floor initialisation (test LLD §3.4, T11c–T11f).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type h02Material struct {
	dir, bundle, rootPub, state string
	rootPriv                    ed25519.PrivateKey
	rootPubKey                  ed25519.PublicKey
}

func h02NewMaterial(t *testing.T, dir string, version uint64) h02Material {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(BundlePayload{
		BundleVersion: version, IssuedAtUnix: time.Now().Unix(), ExpiresAtUnix: time.Now().Add(time.Hour).Unix(),
		Keys: []KeyringEntry{{KeyID: "h02-issuer-1", PublicKeyB64: h02B64(issuerPub), Role: "issuer"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := BuildBundle(rootPriv, "h02-root", payload)
	if err != nil {
		t.Fatal(err)
	}
	m := h02Material{dir: dir, bundle: filepath.Join(dir, "keyring_bundle.json"), rootPub: filepath.Join(dir, "root_pub.b64"),
		state: filepath.Join(dir, "keyring_bundle.state.json"), rootPriv: rootPriv, rootPubKey: rootPub}
	mustWrite(t, m.bundle, bundle, 0644)
	mustWrite(t, m.rootPub, []byte(h02B64(rootPub)+"\n"), 0644)
	return m
}

// T11c: a verified bundle's version becomes the floor, in a private file.
func TestH02InitFloorWritesTheBundleVersion(t *testing.T) {
	m := h02NewMaterial(t, t.TempDir(), 7)
	if err := h02InitFloor(m.bundle, m.rootPub, m.state); err != nil {
		t.Fatalf("init floor: %v", err)
	}
	got, err := readBundleState(m.state)
	if err != nil || got != 7 {
		t.Fatalf("floor = %d, err = %v ; want 7", got, err)
	}
	st, err := os.Stat(m.state)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Errorf("state file mode %v ; want 0600", st.Mode().Perm())
	}
}

// T11d: an existing state file is never overwritten — initialisation is a first-install
// step, not a way to lower a floor.
func TestH02InitFloorRefusesAnExistingState(t *testing.T) {
	m := h02NewMaterial(t, t.TempDir(), 7)
	before := []byte(`{"last_version": 9}` + "\n")
	mustWrite(t, m.state, before, 0600)
	if err := h02InitFloor(m.bundle, m.rootPub, m.state); err == nil {
		t.Error("init floor over an existing state file succeeded")
	}
	after, err := os.ReadFile(m.state)
	if err != nil || !bytes.Equal(after, before) {
		t.Errorf("state file changed: %q (err %v)", after, err)
	}
}

// T11e: a bundle the root did not sign initialises nothing.
func TestH02InitFloorRefusesAForgedBundle(t *testing.T) {
	m := h02NewMaterial(t, t.TempDir(), 7)
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(BundlePayload{BundleVersion: 7, IssuedAtUnix: time.Now().Unix(),
		ExpiresAtUnix: time.Now().Add(time.Hour).Unix(),
		Keys:          []KeyringEntry{{KeyID: "h02-issuer-1", PublicKeyB64: h02B64(m.rootPubKey), Role: "issuer"}}})
	forged, err := BuildBundle(otherPriv, "other-root", payload)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, m.bundle, forged, 0644)
	err = h02InitFloor(m.bundle, m.rootPub, m.state)
	if err == nil {
		t.Error("init floor accepted a bundle signed by another root")
	}
	if err == errH02NotImplemented {
		t.Error("refusal is the not-implemented marker, not a judgement of the bundle")
	}
	if _, statErr := os.Stat(m.state); statErr == nil {
		t.Error("a state file was written for a forged bundle")
	}
}

// T11f (first half): leaves a directory the C++ gate loader opens under the production
// profile — `test_trust_live --interop <dir>`. Runs only when H02_INTEROP_DIR is set.
func TestH02InitFloorInteropDir(t *testing.T) {
	dir := os.Getenv("H02_INTEROP_DIR")
	if dir == "" {
		t.Skip("H02_INTEROP_DIR not set")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	m := h02NewMaterial(t, dir, 3)
	if err := h02InitFloor(m.bundle, m.rootPub, m.state); err != nil {
		t.Fatalf("init floor: %v", err)
	}
	t.Logf("interop directory ready: %s", dir)
}
