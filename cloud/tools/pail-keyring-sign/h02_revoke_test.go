// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package main

// SEC-H02 — preparing a revocation payload (test LLD §3.4, T20a–T20d).
//
// A revocation used to mean editing the payload that the root is about to sign by hand,
// during an incident. These rows pin a command that does that one edit: move one key
// from `keys` to `revoked_keys`, raise the version by one, change nothing else — the
// expiry in particular (a revocation must not quietly extend the bundle's life).
//
// h02PrepareRevoke is the seam; its body is the only code here that differs before and
// after the fix.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/glowfly/pail/services/internal/crypto"
)

var errH02NotImplemented = errors.New("H02_NOT_IMPLEMENTED")

// h02PrepareRevoke returns the payload of the bundle that revokes keyID: the given bundle
// (verified against rootPub) with that key moved to revoked_keys and the version raised
// by one. allowNoIssuer permits a result that leaves no active issuer key.
func h02PrepareRevoke(bundle []byte, rootPub ed25519.PublicKey, keyID string, allowNoIssuer bool) ([]byte, error) {
	return prepareRevoke(bundle, rootPub, keyID, allowNoIssuer)
}

type h02Keys struct {
	rootPub  ed25519.PublicKey
	rootPriv ed25519.PrivateKey
	k1, k2   crypto.KeyringEntry
	o1       crypto.KeyringEntry
	expires  int64
}

func h02NewKeys(t *testing.T) h02Keys {
	t.Helper()
	pub := func() string {
		p, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(p)
	}
	rp, rk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return h02Keys{rootPub: rp, rootPriv: rk,
		k1:      crypto.KeyringEntry{KeyID: "h02-issuer-1", PublicKeyB64: pub(), Role: "issuer"},
		k2:      crypto.KeyringEntry{KeyID: "h02-issuer-2", PublicKeyB64: pub(), Role: "issuer"},
		o1:      crypto.KeyringEntry{KeyID: "h02-operator-1", PublicKeyB64: pub(), Role: "operator"},
		expires: time.Now().Add(6 * time.Hour).Unix()}
}

func (k h02Keys) bundle(t *testing.T, version uint64, keys, revoked []crypto.KeyringEntry) []byte {
	t.Helper()
	payload, err := json.Marshal(crypto.BundlePayload{BundleVersion: version, IssuedAtUnix: time.Now().Unix(),
		ExpiresAtUnix: k.expires, Keys: keys, RevokedKeys: revoked})
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.BuildBundle(k.rootPriv, "h02-root", payload)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// T20a: one key moves, the version rises by one, nothing else changes.
func TestH02PrepareRevokeMovesOneKey(t *testing.T) {
	k := h02NewKeys(t)
	in := k.bundle(t, 4, []crypto.KeyringEntry{k.k1, k.k2, k.o1}, nil)
	out, err := h02PrepareRevoke(in, k.rootPub, "h02-issuer-1", false)
	if err != nil {
		t.Fatalf("prepare revoke: %v", err)
	}
	var p crypto.BundlePayload
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if p.BundleVersion != 5 {
		t.Errorf("bundle_version = %d ; want 5", p.BundleVersion)
	}
	if p.ExpiresAtUnix != k.expires {
		t.Errorf("expires_at_unix = %d ; want %d unchanged — a revocation must not extend the bundle", p.ExpiresAtUnix, k.expires)
	}
	if !reflect.DeepEqual(p.Keys, []crypto.KeyringEntry{k.k2, k.o1}) {
		t.Errorf("keys = %+v ; want the other two entries, unchanged and in order", p.Keys)
	}
	if !reflect.DeepEqual(p.RevokedKeys, []crypto.KeyringEntry{k.k1}) {
		t.Errorf("revoked_keys = %+v ; want the revoked key with its public half and role", p.RevokedKeys)
	}
}

// T20b: a key that is not there to revoke is an error, not an unchanged payload.
func TestH02PrepareRevokeRefusesWhatItCannotRevoke(t *testing.T) {
	k := h02NewKeys(t)
	in := k.bundle(t, 4, []crypto.KeyringEntry{k.k2, k.o1}, []crypto.KeyringEntry{k.k1})
	for _, id := range []string{"no-such-key", "h02-issuer-1"} {
		out, err := h02PrepareRevoke(in, k.rootPub, id, false)
		if err == nil {
			t.Errorf("%s: a payload was produced (%d bytes)", id, len(out))
		}
		if errors.Is(err, errH02NotImplemented) {
			t.Errorf("%s: refusal is the not-implemented marker, not a judgement of the request", id)
		}
	}
	// A bundle the root did not sign is not a base for a revocation either.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := json.Marshal(crypto.BundlePayload{BundleVersion: 4, IssuedAtUnix: time.Now().Unix(),
		ExpiresAtUnix: k.expires, Keys: []crypto.KeyringEntry{k.k1, k.k2, k.o1}})
	forged, err := crypto.BuildBundle(otherPriv, "other-root", payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h02PrepareRevoke(forged, k.rootPub, "h02-issuer-1", false); err == nil || errors.Is(err, errH02NotImplemented) {
		t.Errorf("forged base bundle: err = %v ; want a refusal of the bundle", err)
	}
}

// T20c: revoking the last active issuer key stops every gate that loads the result.
// That can be the intent of an emergency, so it is possible — but only when asked for.
func TestH02PrepareRevokeLastIssuerNeedsTheFlag(t *testing.T) {
	k := h02NewKeys(t)
	in := k.bundle(t, 4, []crypto.KeyringEntry{k.k1, k.o1}, nil)
	if out, err := h02PrepareRevoke(in, k.rootPub, "h02-issuer-1", false); err == nil {
		t.Errorf("without the flag a payload with no issuer key was produced (%d bytes)", len(out))
	} else if errors.Is(err, errH02NotImplemented) {
		t.Error("refusal is the not-implemented marker, not the last-issuer rule")
	}
	out, err := h02PrepareRevoke(in, k.rootPub, "h02-issuer-1", true)
	if err != nil {
		t.Fatalf("with the flag: %v", err)
	}
	var p crypto.BundlePayload
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatal(err)
	}
	for _, e := range p.Keys {
		if e.Role == "issuer" {
			t.Errorf("an issuer key is still active: %s", e.KeyID)
		}
	}
	if len(p.RevokedKeys) != 1 || p.RevokedKeys[0].KeyID != "h02-issuer-1" {
		t.Errorf("revoked_keys = %+v", p.RevokedKeys)
	}
}

// T20d: the prepared payload, signed by the real CLI, is a bundle the loader accepts with
// the key revoked. With H02_INTEROP_REVOKE_DIR set the result is also left as a
// directory for the C++ gate loader (`test_trust_live --interop <dir>`).
func TestH02PrepareRevokeThroughTheRealSigner(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "pail-keyring-sign")
	if out, err := exec.Command("go", "build", "-tags", "pail_generated", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build signer: %v\n%s", err, out)
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	rootKey := filepath.Join(dir, "root.json")
	run("gen-root", "--out", rootKey, "--key-id", "h02-root")
	var jf crypto.KeyFileJSON
	raw, err := os.ReadFile(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &jf); err != nil {
		t.Fatal(err)
	}
	rootPub, err := base64.StdEncoding.DecodeString(jf.PublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	rootPubFile := filepath.Join(dir, "root_pub.b64")
	if err := os.WriteFile(rootPubFile, []byte(jf.PublicKeyB64+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	k := h02NewKeys(t)
	k.expires = time.Now().Add(time.Hour).Unix()
	base, _ := json.Marshal(crypto.BundlePayload{BundleVersion: 1, IssuedAtUnix: time.Now().Unix(),
		ExpiresAtUnix: k.expires, Keys: []crypto.KeyringEntry{k.k1, k.k2, k.o1}})
	basePayload := filepath.Join(dir, "payload-1.json")
	baseBundle := filepath.Join(dir, "bundle-1.json")
	if err := os.WriteFile(basePayload, base, 0644); err != nil {
		t.Fatal(err)
	}
	run("sign", "--root", rootKey, "--payload", basePayload, "--out", baseBundle)

	in, err := os.ReadFile(baseBundle)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := h02PrepareRevoke(in, ed25519.PublicKey(rootPub), "h02-issuer-1", false)
	if err != nil {
		t.Fatalf("prepare revoke: %v", err)
	}
	revPayload := filepath.Join(dir, "payload-2.json")
	revBundle := filepath.Join(dir, "bundle-2.json")
	if err := os.WriteFile(revPayload, revoked, 0644); err != nil {
		t.Fatal(err)
	}
	run("sign", "--root", rootKey, "--payload", revPayload, "--out", revBundle)

	state := filepath.Join(dir, "state.json")
	if err := os.WriteFile(state, []byte(`{"last_version": 1}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	kr, err := crypto.LoadKeyringBundle(revBundle, ed25519.PublicKey(rootPub), state, crypto.BundlePolicy{MaxLifetime: 24 * time.Hour})
	if err != nil {
		t.Fatalf("the signed revocation bundle does not load: %v", err)
	}
	if len(kr.RevokedKeys) != 1 || kr.RevokedKeys[0].KeyID != "h02-issuer-1" {
		t.Errorf("revoked keys after load = %+v", kr.RevokedKeys)
	}
	for _, e := range kr.Keys {
		if e.KeyID == "h02-issuer-1" {
			t.Error("the revoked key is still active after load")
		}
	}

	if out := os.Getenv("H02_INTEROP_REVOKE_DIR"); out != "" {
		if err := os.MkdirAll(out, 0755); err != nil {
			t.Fatal(err)
		}
		signed, _ := os.ReadFile(revBundle)
		for name, b := range map[string][]byte{"keyring_bundle.json": signed, "root_pub.b64": []byte(jf.PublicKeyB64 + "\n"),
			"keyring_bundle.state.json": []byte(`{"last_version": 1}` + "\n")} {
			if err := os.WriteFile(filepath.Join(out, name), b, 0644); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("interop directory ready: %s", out)
	}
}
