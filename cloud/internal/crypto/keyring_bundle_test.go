// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makePayload builds a valid payload JSON with one issuer key.
func makePayload(t *testing.T, version uint64, expiresAt int64) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := BundlePayload{
		BundleVersion: version,
		IssuedAtUnix:  time.Now().Unix(),
		ExpiresAtUnix: expiresAt,
		Keys: []KeyringEntry{
			{KeyID: "prod-issuer-1", PublicKeyB64: base64.StdEncoding.EncodeToString(pub), Role: "issuer"},
		},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func futureUnix() int64 { return time.Now().Add(24 * time.Hour).Unix() }

// testBundlePolicy 는 이 파일의 24h 번들이 통과하는 상한이다. 값을 크게 잡되
// **무한이 아니게** 두는 이유는, 영값이 통과가 되면 `S20b` 를 재는 시험이 다른
// 시험들의 부수 효과로 초록이 되기 때문이다.
var testBundlePolicy = BundlePolicy{MaxLifetime: 7 * 24 * time.Hour}

// Normal bundle loads and advances the persisted version floor.
func TestBundleValidLoadsAndAdvancesVersion(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	bundle, err := BuildBundle(rootPriv, "root-1", makePayload(t, 7, futureUnix()))
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "keyring_bundle.json")
	statePath := filepath.Join(dir, "state.json")
	writeFile(t, bundlePath, bundle)

	kr, err := LoadKeyringBundle(bundlePath, rootPub, statePath, testBundlePolicy)
	if err != nil {
		t.Fatalf("valid bundle must load: %v", err)
	}
	if len(kr.Keys) != 1 || kr.Keys[0].KeyID != "prod-issuer-1" {
		t.Fatalf("unexpected keyring: %+v", kr.Keys)
	}
	last, err := readBundleState(statePath)
	if err != nil || last != 7 {
		t.Fatalf("state floor: got %d err %v, want 7", last, err)
	}
}

// DC-10 / C3-C7 : the C++ gate persists a wall-clock rewind
// floor (wall_ms0) in the SAME state file this writer bumps. A version bump
// must carry the floor through — a clobbered floor reads as first boot and
// the rewind window silently reopens.
func TestBundleStateWritePreservesWallFloor(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	// State as the gate leaves it: version floor + wall floor.
	writeFile(t, statePath, []byte("{\n  \"last_version\": 7,\n  \"wall_ms0\": 100000\n}\n"))

	bundle, err := BuildBundle(rootPriv, "root-1", makePayload(t, 9, futureUnix()))
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "keyring_bundle.json")
	writeFile(t, bundlePath, bundle)
	if _, err := LoadKeyringBundle(bundlePath, rootPub, statePath, testBundlePolicy); err != nil {
		t.Fatalf("v9 bundle must load over the v7 floor: %v", err)
	}

	b, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var st bundleState
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("state after bump must stay parseable: %v", err)
	}
	if st.LastVersion != 9 {
		t.Fatalf("version floor: got %d, want 9", st.LastVersion)
	}
	if st.WallMs0 != 100000 {
		t.Fatalf("wall floor clobbered by the version bump: got %d, want 100000", st.WallMs0)
	}

	// The writer must refuse to clobber a state file it cannot read.
	writeFile(t, statePath, []byte("not json at all"))
	if err := writeBundleState(statePath, 10); err == nil {
		t.Fatal("writing over an unreadable state file must refuse, not clobber")
	}
}

// A forged signature (wrong root key) is rejected.
func TestBundleForgedSignatureRejected(t *testing.T) {
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	realRootPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	bundle, err := BuildBundle(attackerPriv, "root-1", makePayload(t, 1, futureUnix()))
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "b.json")
	writeFile(t, bundlePath, bundle)
	if _, err := LoadKeyringBundle(bundlePath, realRootPub, filepath.Join(dir, "s.json"), testBundlePolicy); err == nil {
		t.Fatal("forged signature must be rejected")
	}
}

// Flipping a single byte of the signed payload breaks verification.
func TestBundlePayloadTamperRejected(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	bundle, err := BuildBundle(rootPriv, "root-1", makePayload(t, 1, futureUnix()))
	if err != nil {
		t.Fatal(err)
	}
	var env BundleEnvelope
	if err := json.Unmarshal(bundle, &env); err != nil {
		t.Fatal(err)
	}
	pb, _ := base64.StdEncoding.DecodeString(env.PayloadB64)
	pb[0] ^= 0x01 // flip one byte of the signed payload
	env.PayloadB64 = base64.StdEncoding.EncodeToString(pb)
	tampered, _ := json.Marshal(env)
	bundlePath := filepath.Join(dir, "b.json")
	writeFile(t, bundlePath, tampered)
	if _, err := LoadKeyringBundle(bundlePath, rootPub, filepath.Join(dir, "s.json"), testBundlePolicy); err == nil {
		t.Fatal("tampered payload must be rejected")
	}
}

// A genuine older bundle re-presented after a newer one is rejected (rollback).
func TestBundleRollbackRejected(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	newB, _ := BuildBundle(rootPriv, "root-1", makePayload(t, 8, futureUnix()))
	newPath := filepath.Join(dir, "new.json")
	writeFile(t, newPath, newB)
	if _, err := LoadKeyringBundle(newPath, rootPub, statePath, testBundlePolicy); err != nil {
		t.Fatalf("v8 must load: %v", err)
	}

	oldB, _ := BuildBundle(rootPriv, "root-1", makePayload(t, 6, futureUnix()))
	oldPath := filepath.Join(dir, "old.json")
	writeFile(t, oldPath, oldB)
	if _, err := LoadKeyringBundle(oldPath, rootPub, statePath, testBundlePolicy); err == nil {
		t.Fatal("rollback to v6 after v8 must be rejected")
	}

	// Re-presenting the SAME version must load: bundles are applied by
	// restart, so a plain restart re-reads the unchanged bundle. Only
	// strictly-smaller versions are rollbacks.
	if _, err := LoadKeyringBundle(newPath, rootPub, statePath, testBundlePolicy); err != nil {
		t.Fatalf("re-loading v8 (restart with unchanged bundle) must succeed: %v", err)
	}
	if last, err := readBundleState(statePath); err != nil || last != 8 {
		t.Fatalf("floor after equal-version reload: got %d err %v, want 8", last, err)
	}
}

// An expired bundle is rejected even with a valid signature.
func TestBundleExpiredRejected(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	past := time.Now().Add(-1 * time.Hour).Unix()
	bundle, err := BuildBundle(rootPriv, "root-1", makePayload(t, 1, past))
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "b.json")
	writeFile(t, bundlePath, bundle)
	if _, err := LoadKeyringBundle(bundlePath, rootPub, filepath.Join(dir, "s.json"), testBundlePolicy); err == nil {
		t.Fatal("expired bundle must be rejected")
	}
}

// BuildBundle refuses to sign a payload that would never load (defense in depth).
func TestBuildBundleRejectsBadPayload(t *testing.T) {
	_, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := BuildBundle(rootPriv, "root-1", []byte(`{"bundle_version":0}`)); err == nil {
		t.Fatal("bundle_version 0 must be rejected at sign time")
	}
	if _, err := BuildBundle(rootPriv, "root-1", makePayload(t, 1, 0)); err == nil {
		t.Fatal("missing expires must be rejected at sign time")
	}
}

// Selector: bundle is the default; unsigned keyring needs an explicit dev flag.
func TestSelectorUnsignedRequiresDevMode(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "keyring.json")
	writeFile(t, legacy, []byte(`{"keys":[{"key_id":"dev-key-1","ed25519_public_key_base64":"`+
		base64.StdEncoding.EncodeToString(mustPub(t))+`","role":"issuer"}]}`))

	// Default mode with no root pubkey configured => refuse (fail-closed).
	t.Setenv("PAIL_KEYRING_MODE", "")
	t.Setenv("PAIL_ROOT_PUBKEY_FILE", "")
	if _, _, err := LoadTrustedKeyringFromEnv(legacy); err == nil {
		t.Fatal("default mode without root pubkey must refuse")
	}

	// Explicit dev mode loads the unsigned keyring.
	t.Setenv("PAIL_KEYRING_MODE", "unsigned-dev")
	kr, mode, err := LoadTrustedKeyringFromEnv(legacy)
	if err != nil || mode != "unsigned-dev" || len(kr.Keys) != 1 {
		t.Fatalf("unsigned-dev load: mode=%q err=%v keys=%d", mode, err, len(kr.Keys))
	}
}

// Selector: bundle mode with a configured root pubkey loads a signed bundle e2e.
func TestSelectorBundleModeLoads(t *testing.T) {
	// SEC-H02: the selector's policy asks for an initialised floor in the production
	// profile (TestH02StateRule pins that). This test measures the selector's wiring on
	// a first load, which is the dev profile's behaviour.
	t.Setenv("PAIL_PROFILE", "dev")
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "keyring_bundle.json")
	b, _ := BuildBundle(rootPriv, "root-1", makePayload(t, 3, futureUnix()))
	writeFile(t, bundlePath, b)
	rootPubFile := filepath.Join(dir, "root_pub.b64")
	writeFile(t, rootPubFile, []byte(base64.StdEncoding.EncodeToString(rootPub)+"\n"))

	t.Setenv("PAIL_KEYRING_MODE", "bundle")
	t.Setenv("PAIL_KEYRING_BUNDLE", bundlePath)
	t.Setenv("PAIL_ROOT_PUBKEY_FILE", rootPubFile)
	t.Setenv("PAIL_KEYRING_STATE", filepath.Join(dir, "state.json"))
	t.Setenv(EnvBundleMaxLifetime, "604800")

	kr, mode, err := LoadTrustedKeyringFromEnv(filepath.Join(dir, "keyring.json"))
	if err != nil || mode != "bundle" || len(kr.Keys) != 1 {
		t.Fatalf("bundle mode load: mode=%q err=%v keys=%v", mode, err, kr)
	}
}

func mustPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
