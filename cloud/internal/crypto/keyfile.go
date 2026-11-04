// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyFileJSON is a minimal on-disk schema for persisting an ed25519 keypair.
// IMPORTANT: never log the private key.
//
// Schema:
// {
//   "key_id": "dev-key-1",
//   "ed25519_private_key_base64": "...",
//   "ed25519_public_key_base64": "..."
// }
//
// This is used to keep issuer keys stable across restarts in Phase 2.

var pairCheckMsg = []byte("pail-keyfile-pair-check")

// ErrKeyFileNotFound is returned by LoadEd25519KeypairJSON when the keyfile is
// absent. It carries the S18 (§3.7) meaning: a missing key is a config error,
// not a cue to silently mint one. Callers that legitimately own key creation
// (provisioning tools, test harnesses) detect this and call
// GenerateEd25519KeypairJSON explicitly; production paths fail closed.
var ErrKeyFileNotFound = errors.New("key not found (generate explicitly)")

type KeyFileJSON struct {
	KeyID        string `json:"key_id"`
	PrivKeyB64   string `json:"ed25519_private_key_base64"`
	PublicKeyB64 string `json:"ed25519_public_key_base64"`
}

// LoadEd25519KeypairJSON loads a keypair from disk. If the file is absent it
// returns ErrKeyFileNotFound and does NOT create anything (F-KEY-23 / S18):
// auto-generation is the caller's decision, spelled out via
// GenerateEd25519KeypairJSON — not a side effect of a load.
func LoadEd25519KeypairJSON(path string, keyID string) (*Keypair, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("keyfile %s: %w", path, ErrKeyFileNotFound)
		}
		return nil, fmt.Errorf("keyfile read: %w", err)
	}
	var jf KeyFileJSON
	if err := json.Unmarshal(b, &jf); err != nil {
		return nil, fmt.Errorf("keyfile unmarshal: %w", err)
	}
	if jf.KeyID == "" {
		return nil, errors.New("keyfile: missing key_id")
	}
	if keyID != "" && jf.KeyID != keyID {
		return nil, fmt.Errorf("keyfile: key_id mismatch (file=%q want=%q)", jf.KeyID, keyID)
	}
	priv, err := base64.StdEncoding.DecodeString(jf.PrivKeyB64)
	if err != nil {
		return nil, fmt.Errorf("keyfile: decode private key: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(jf.PublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("keyfile: decode public key: %w", err)
	}
	if l := len(priv); l != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("keyfile: invalid private key size: %d", l)
	}
	if l := len(pub); l != ed25519.PublicKeySize {
		return nil, fmt.Errorf("keyfile: invalid public key size: %d", l)
	}
	// W7 (KM1-1): a corrupted or spliced keyfile can pair a private key
	// with the wrong public key — the issuer would sign tokens no verifier
	// accepts. One probe sign/verify at load rejects that state up front.
	probe := ed25519.Sign(ed25519.PrivateKey(priv), pairCheckMsg)
	if !ed25519.Verify(ed25519.PublicKey(pub), pairCheckMsg, probe) {
		return nil, errors.New("keyfile: public/private key pair mismatch (corrupted or spliced keyfile)")
	}
	return &Keypair{Public: ed25519.PublicKey(pub), Private: ed25519.PrivateKey(priv), KeyID: jf.KeyID}, nil
}

// GenerateEd25519KeypairJSON mints a fresh keypair and writes it to path. This
// is the ONLY code path that creates a keyfile (F-KEY-23). The write is durable
// (B6-5): the temp file is fsync'd before the rename and the parent directory is
// fsync'd after, so a power loss cannot leave a service believing a key exists
// while the disk has none (the X30 checkpoint-fsync shape).
func GenerateEd25519KeypairJSON(path string, keyID string) (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	jf := KeyFileJSON{
		KeyID:        keyID,
		PrivKeyB64:   base64.StdEncoding.EncodeToString(priv),
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub),
	}
	out, err := json.MarshalIndent(jf, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("keyfile mkdir: %w", err)
	}

	// Write atomically with 0600 perms, fsync'ing the payload before the rename.
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("keyfile create tmp: %w", err)
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		return nil, fmt.Errorf("keyfile write tmp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("keyfile fsync tmp: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("keyfile close tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("keyfile rename: %w", err)
	}
	// fsync the directory so the rename itself survives a crash.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}

	return &Keypair{Public: pub, Private: priv, KeyID: keyID}, nil
}
