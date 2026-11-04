// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// `B6-6` : burst_recv reads its trust anchors through the one
// keyring path. Three rules, three tests — measured apart, because a single
// aggregate lets one of them die under the other two's green (`H-B9`).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/glowfly/pail/services/internal/deploysec"
)

func writeKeyring(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func pubB64(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// The keyring here is perfectly valid; it must still be refused, because in
// bundle mode nothing vouches for it. The deleted local parser read exactly
// this file and never asked which mode the deployment was in.
func TestBurstRecvRefusesUnsignedKeyringInBundleMode(t *testing.T) {
	path := writeKeyring(t, `{"keys":[{"key_id":"issuer-1",`+
		`"ed25519_public_key_base64":"`+pubB64(t)+`","role":"issuer"}]}`)
	t.Setenv("PAIL_KEYRING_MODE", "")
	t.Setenv("PAIL_ROOT_PUBKEY_FILE", "")
	if keys, mode, err := issuerKeys(path); err == nil {
		t.Fatalf("bundle mode must not read the unsigned keyring (mode=%s keys=%d)", mode, len(keys))
	}
}

// An operator key must not become a burst trust anchor: it would let whoever
// holds it mint alerts the fleet reports as authentic.
func TestBurstRecvLoadsIssuerKeysOnly(t *testing.T) {
	issuerPub := pubB64(t)
	path := writeKeyring(t, `{"keys":[`+
		`{"key_id":"op-key-1","ed25519_public_key_base64":"`+pubB64(t)+`","role":"operator"},`+
		`{"key_id":"issuer-1","ed25519_public_key_base64":"`+issuerPub+`","role":"issuer"}]}`)
	t.Setenv("PAIL_KEYRING_MODE", "unsigned-dev")
	keys, mode, err := issuerKeys(path)
	if err != nil {
		t.Fatalf("unsigned-dev keyring must load: %v", err)
	}
	if mode != "unsigned-dev" {
		t.Errorf("mode=%q — the caller logs this, so it must say what was trusted", mode)
	}
	if len(keys) != 1 || keys[0].id != "issuer-1" {
		t.Fatalf("want only the issuer key, got %+v", keys)
	}
	if base64.StdEncoding.EncodeToString(keys[0].pub) != issuerPub {
		t.Error("the loaded key is not the one in the keyring")
	}
}

// The deleted parser folded a missing role into "issuer" (pre-M9 grace). `S15`
// removed that fold from the canonical loader in `B6-1`, and this file kept it
// — the shape of a rule fixed in one loader and still absent in the other.
func TestBurstRecvRefusesRolelessEntry(t *testing.T) {
	path := writeKeyring(t, `{"keys":[{"key_id":"legacy-1",`+
		`"ed25519_public_key_base64":"`+pubB64(t)+`"}]}`)
	t.Setenv("PAIL_KEYRING_MODE", "unsigned-dev")
	_, _, err := issuerKeys(path)
	if err == nil {
		t.Fatal("a roleless entry must refuse the start")
	}
	if id := deploysec.RuleID(err); id != "S15" {
		t.Fatalf("want S15, got %q (%v)", id, err)
	}
}
