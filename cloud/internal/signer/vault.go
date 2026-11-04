// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package signer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Vault signs via HashiCorp Vault's (or OpenBao's) Transit engine. Only the
// standard Transit HTTP API is used — Go stdlib net/http, no vendor SDK — so
// the backend stays swappable (KM1-2①, LLD §2). The private key never leaves
// the vault; this process holds only a scoped access token.
//
// Key-version pinning: the public key and its Transit version are fetched
// once at init. If a later signature comes back under a different version
// (someone rotated the Transit key while verifiers' keyrings still hold the
// old public key), Sign refuses — rotation is only valid as "new key name +
// KM2 bundle + restart".
type Vault struct {
	addr    string
	keyName string
	keyID   string
	token   string
	client  *http.Client
	pub     ed25519.PublicKey
	version int
}

// NewVaultFromEnv builds the Transit signer from PAIL_VAULT_* env and fetches
// the public key immediately. Any failure here must abort process start —
// there is no state where a Vault signer exists without a validated pubkey.
func NewVaultFromEnv(keyID string) (*Vault, error) {
	addr := strings.TrimRight(os.Getenv("PAIL_VAULT_ADDR"), "/")
	if addr == "" {
		return nil, fmt.Errorf("vault signer: PAIL_VAULT_ADDR is required")
	}
	keyName := os.Getenv("PAIL_VAULT_KEY_NAME")
	if keyName == "" {
		return nil, fmt.Errorf("vault signer: PAIL_VAULT_KEY_NAME is required")
	}
	tokenFile := os.Getenv("PAIL_VAULT_TOKEN_FILE")
	if tokenFile == "" {
		return nil, fmt.Errorf("vault signer: PAIL_VAULT_TOKEN_FILE is required")
	}
	tb, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("vault signer: read token file: %w", err)
	}
	token := strings.TrimSpace(string(tb))
	if token == "" {
		return nil, fmt.Errorf("vault signer: token file %s is empty", tokenFile)
	}
	timeout := 2000 * time.Millisecond
	if v := os.Getenv("PAIL_VAULT_TIMEOUT_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("vault signer: invalid PAIL_VAULT_TIMEOUT_MS=%q", v)
		}
		timeout = time.Duration(n) * time.Millisecond
	}
	vt := &Vault{
		addr:    addr,
		keyName: keyName,
		keyID:   keyID,
		token:   token,
		client:  &http.Client{Timeout: timeout},
	}
	if err := vt.fetchPublicKey(); err != nil {
		return nil, err
	}
	return vt, nil
}

// do issues one Transit request with a single immediate retry on transport
// error or 5xx (Ed25519 signing is deterministic, so a duplicate is
// idempotent). No backoff loops: a slow refusal is worse than a fast one.
func (v *Vault) do(method, path string, reqBody []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(method, v.addr+path, bytes.NewReader(reqBody))
		if err != nil {
			return nil, fmt.Errorf("vault signer: build request: %w", err)
		}
		req.Header.Set("X-Vault-Token", v.token)
		if reqBody != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := v.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("vault signer: %s %s: %w", method, path, err)
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if rerr != nil {
			lastErr = fmt.Errorf("vault signer: %s %s: read body: %w", method, path, rerr)
			continue
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("vault signer: %s %s: status %d", method, path, resp.StatusCode)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			// 403 = token expired/revoked or policy change: same fail-closed
			// refusal, but the status makes the operator diagnosis obvious.
			return nil, fmt.Errorf("vault signer: %s %s: status %d (403=token expired/policy; no auto re-auth in v1)", method, path, resp.StatusCode)
		}
		return body, nil
	}
	return nil, lastErr
}

func (v *Vault) fetchPublicKey() error {
	body, err := v.do(http.MethodGet, "/v1/transit/keys/"+v.keyName, nil)
	if err != nil {
		return err
	}
	var out struct {
		Data struct {
			Type          string `json:"type"`
			LatestVersion int    `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("vault signer: parse key info: %w", err)
	}
	if out.Data.Type != "ed25519" {
		return fmt.Errorf("vault signer: transit key %q type=%q (want ed25519)", v.keyName, out.Data.Type)
	}
	if out.Data.LatestVersion <= 0 {
		return fmt.Errorf("vault signer: transit key %q has no latest_version", v.keyName)
	}
	entry, ok := out.Data.Keys[strconv.Itoa(out.Data.LatestVersion)]
	if !ok {
		return fmt.Errorf("vault signer: transit key %q: version %d not in keys map", v.keyName, out.Data.LatestVersion)
	}
	pub, err := base64.StdEncoding.DecodeString(entry.PublicKey)
	if err != nil {
		return fmt.Errorf("vault signer: decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("vault signer: public key size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	v.pub = ed25519.PublicKey(pub)
	v.version = out.Data.LatestVersion
	return nil
}

func (v *Vault) Sign(msg []byte) ([]byte, error) {
	reqBody, err := json.Marshal(map[string]string{
		"input": base64.StdEncoding.EncodeToString(msg),
	})
	if err != nil {
		return nil, fmt.Errorf("vault signer: marshal sign request: %w", err)
	}
	body, err := v.do(http.MethodPost, "/v1/transit/sign/"+v.keyName, reqBody)
	if err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("vault signer: parse sign response: %w", err)
	}
	// Format: vault:vN:<base64(sig)>
	parts := strings.SplitN(out.Data.Signature, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
		return nil, fmt.Errorf("vault signer: unexpected signature format %q", out.Data.Signature)
	}
	ver, err := strconv.Atoi(parts[1][1:])
	if err != nil {
		return nil, fmt.Errorf("vault signer: parse signature version %q: %w", parts[1], err)
	}
	if ver != v.version {
		// The Transit key was rotated after init: verifiers' keyrings do not
		// know the new key, so these signatures verify nowhere. Refuse.
		return nil, fmt.Errorf("vault signer: signature version v%d != pinned v%d — transit key rotated; rotate via new key name + KM2 bundle + restart", ver, v.version)
	}
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("vault signer: decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("vault signer: signature size %d (want %d)", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

func (v *Vault) KeyID() string             { return v.keyID }
func (v *Vault) Public() ed25519.PublicKey { return v.pub }
