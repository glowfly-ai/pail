// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/crypto"
)

func testPayload(t *testing.T, version uint64, expiresAt int64) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(crypto.BundlePayload{
		BundleVersion: version,
		IssuedAtUnix:  time.Now().Unix(),
		ExpiresAtUnix: expiresAt,
		Keys: []crypto.KeyringEntry{
			{KeyID: "prod-issuer-1", PublicKeyB64: base64.StdEncoding.EncodeToString(pub), Role: "issuer"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustBundle(t *testing.T, priv ed25519.PrivateKey, version uint64, expiresAt int64) []byte {
	t.Helper()
	b, err := crypto.BuildBundle(priv, "root-1", testPayload(t, version, expiresAt))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func future() int64 { return time.Now().Add(24 * time.Hour).Unix() }

// A valid pulled bundle is placed atomically when nothing is placed yet.
func TestApplyBundleFreshPlacement(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dest := filepath.Join(t.TempDir(), "keys", "keyring_bundle.json")
	placed, err := applyBundle(mustBundle(t, rootPriv, 3, future()), rootPub, dest)
	if err != nil || !placed {
		t.Fatalf("fresh placement: placed=%v err=%v", placed, err)
	}
	if p, _, err := crypto.VerifyBundle(readAll(t, dest), rootPub); err != nil || p.BundleVersion != 3 {
		t.Fatalf("placed file must verify as v3: %v", err)
	}
}

// The same version again is a no-op (no restart churn on every poll tick).
func TestApplyBundleEqualVersionNoop(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dest := filepath.Join(t.TempDir(), "b.json")
	b := mustBundle(t, rootPriv, 3, future())
	if placed, err := applyBundle(b, rootPub, dest); err != nil || !placed {
		t.Fatalf("first: %v %v", placed, err)
	}
	placed, err := applyBundle(b, rootPub, dest)
	if err != nil || placed {
		t.Fatalf("equal version must be a no-op: placed=%v err=%v", placed, err)
	}
}

// A genuine but older bundle must never clobber a newer placed one (F3).
func TestApplyBundleRollbackRefused(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dest := filepath.Join(t.TempDir(), "b.json")
	if _, err := applyBundle(mustBundle(t, rootPriv, 8, future()), rootPub, dest); err != nil {
		t.Fatal(err)
	}
	placed, err := applyBundle(mustBundle(t, rootPriv, 6, future()), rootPub, dest)
	if err == nil || placed {
		t.Fatalf("rollback must be refused: placed=%v err=%v", placed, err)
	}
	if p, _, _ := crypto.VerifyBundle(readAll(t, dest), rootPub); p == nil || p.BundleVersion != 8 {
		t.Fatal("placed v8 must survive the rollback attempt")
	}
}

// A forged bundle (wrong root) is rejected and the existing file kept (F2).
func TestApplyBundleForgedRejectedKeepsExisting(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	dest := filepath.Join(t.TempDir(), "b.json")
	if _, err := applyBundle(mustBundle(t, rootPriv, 5, future()), rootPub, dest); err != nil {
		t.Fatal(err)
	}
	placed, err := applyBundle(mustBundle(t, attackerPriv, 9, future()), rootPub, dest)
	if err == nil || placed {
		t.Fatalf("forged bundle must be rejected: placed=%v err=%v", placed, err)
	}
	if p, _, _ := crypto.VerifyBundle(readAll(t, dest), rootPub); p == nil || p.BundleVersion != 5 {
		t.Fatal("existing v5 must survive the forged push")
	}
}

// Truncated/tampered bytes are rejected (F4).
func TestApplyBundleTruncatedRejected(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dest := filepath.Join(t.TempDir(), "b.json")
	b := mustBundle(t, rootPriv, 2, future())
	placed, err := applyBundle(b[:len(b)/2], rootPub, dest)
	if err == nil || placed {
		t.Fatalf("truncated bundle must be rejected: placed=%v err=%v", placed, err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatal("nothing may be placed from a truncated bundle")
	}
}

// An expired bundle is rejected even with a valid root signature (F5).
func TestApplyBundleExpiredRejected(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dest := filepath.Join(t.TempDir(), "b.json")
	placed, err := applyBundle(mustBundle(t, rootPriv, 2, time.Now().Add(-time.Hour).Unix()), rootPub, dest)
	if err == nil || placed {
		t.Fatalf("expired bundle must be rejected: placed=%v err=%v", placed, err)
	}
}

// Garbage at the destination never blocks a valid bundle (floor 0).
func TestApplyBundleReplacesGarbage(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	dest := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(dest, []byte("not a bundle"), 0644); err != nil {
		t.Fatal(err)
	}
	placed, err := applyBundle(mustBundle(t, rootPriv, 1, future()), rootPub, dest)
	if err != nil || !placed {
		t.Fatalf("valid bundle must replace garbage: placed=%v err=%v", placed, err)
	}
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
