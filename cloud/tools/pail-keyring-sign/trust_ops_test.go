// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/glowfly/pail/services/internal/crypto"
)

func TestInspectJSONExpiredIsNotLoadedOrUnconditionallyValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := json.Marshal(crypto.BundlePayload{BundleVersion: 7, IssuedAtUnix: 1, ExpiresAtUnix: 2, Keys: []crypto.KeyringEntry{{KeyID: "issuer", PublicKeyB64: base64.StdEncoding.EncodeToString(pub), Role: "issuer"}}})
	bundle, e := crypto.BuildBundle(priv, "root", payload)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	bpath := filepath.Join(dir, "bundle.json")
	rpath := filepath.Join(dir, "root.pub")
	if e = os.WriteFile(bpath, bundle, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(rpath, []byte(base64.StdEncoding.EncodeToString(pub)), 0600); e != nil {
		t.Fatal(e)
	}
	old := os.Stdout
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	os.Stdout = w
	e = cmdInspectJSON([]string{"--root-pub", rpath, "--bundle", bpath})
	w.Close()
	os.Stdout = old
	raw, readErr := io.ReadAll(r)
	r.Close()
	if e != nil || readErr != nil {
		t.Fatalf("%v %v", e, readErr)
	}
	var result map[string]any
	if e = json.Unmarshal(raw, &result); e != nil {
		t.Fatal(e)
	}
	if result["clock_basis"] != "UNVERIFIED" || result["remaining_s"] != nil {
		t.Fatal("unverified time became trusted")
	}
	if result["runtime"].(map[string]any)["state"] != "NOT_OBSERVED" {
		t.Fatal("file presented as loaded")
	}
	if result["file"].(map[string]any)["state"] != "SIGNATURE_VALID_TIME_UNASSESSED" {
		t.Fatal("expiry was not separated")
	}
	if _, e = os.Stat(filepath.Join(dir, "state.json")); !os.IsNotExist(e) {
		t.Fatal("created runtime state")
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(rpath, []byte(base64.StdEncoding.EncodeToString(pub2)), 0600)
	if cmdInspectJSON([]string{"--root-pub", rpath, "--bundle", bpath}) == nil {
		t.Fatal("wrong root authenticated")
	}
}
