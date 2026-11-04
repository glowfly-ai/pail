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
	"strings"
	"testing"
)

// W7 (KM1-1): 짜깁기된 keyfile(priv=A, pub=B)은 로드 거부.
func TestKeyfilePairMismatchRejected(t *testing.T) {
	_, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen A: %v", err)
	}
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen B: %v", err)
	}
	jf := KeyFileJSON{
		KeyID:        "dev-key-1",
		PrivKeyB64:   base64.StdEncoding.EncodeToString(privA),
		PublicKeyB64: base64.StdEncoding.EncodeToString(pubB),
	}
	b, err := json.Marshal(jf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "issuer_ed25519.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err = LoadEd25519KeypairJSON(path, "dev-key-1")
	if err == nil {
		t.Fatal("spliced keyfile (priv A / pub B) must be rejected")
	}
	if !strings.Contains(err.Error(), "pair mismatch") {
		t.Fatalf("want pair mismatch error, got: %v", err)
	}
}

// W7 대조군: 정상 keyfile은 생성→재로드 통과.
func TestKeyfilePairMatchLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issuer_ed25519.json")
	created, err := GenerateEd25519KeypairJSON(path, "dev-key-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	loaded, err := LoadEd25519KeypairJSON(path, "dev-key-1")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !created.Public.Equal(loaded.Public) {
		t.Fatal("reloaded public key differs from created")
	}
}
