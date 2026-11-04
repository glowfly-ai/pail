// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/glowfly/pail/services/internal/crypto"
)

// These commands operate only on supplied files. No runtime loading, process
// management, permission grant or state-floor writes occur here.
func readTrustInput(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 32769))
	if e != nil {
		return nil, e
	}
	if len(b) > 32768 {
		return nil, fmt.Errorf("TRUST_INPUT_TOO_LARGE")
	}
	return b, nil
}
func pubHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func cmdInspectJSON(args []string) error {
	fs := flag.NewFlagSet("inspect-json", flag.ContinueOnError)
	rootPath := fs.String("root-pub", "", "approved root public key file")
	bundlePath := fs.String("bundle", "", "bundle file (signature checked, not runtime loaded)")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *rootPath == "" || *bundlePath == "" || fs.NArg() != 0 {
		return fmt.Errorf("--root-pub and --bundle required")
	}
	root, e := readRootPub(*rootPath)
	if e != nil {
		return e
	}
	raw, e := readTrustInput(*bundlePath)
	if e != nil {
		return e
	}
	p, _, e := crypto.InspectTrustBundle(raw, root)
	if e != nil {
		state := "INVALID_METADATA"
		if errors.Is(e, crypto.ErrBundleSignature) {
			state = "INVALID_SIGNATURE"
		}
		// Inspection failure stays a nonzero CLI exit; only sanitized state
		// and observed public-byte fingerprints are emitted for the UI.
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema_version": 1, "file": map[string]any{
			"state": state, "bundle_sha256": pubHash(raw), "root_fingerprint_sha256": pubHash(root)},
			"runtime": map[string]any{"state": "NOT_OBSERVED"}, "clock_basis": "UNVERIFIED"})
		return e
	}
	if len(p.Keys)+len(p.RevokedKeys) > 128 {
		return fmt.Errorf("TRUST_KEY_LIMIT")
	}
	material, e := crypto.TrustMaterialDigest(p)
	if e != nil {
		return e
	}
	publicEntries := func(entries []crypto.KeyringEntry) []map[string]any {
		result := make([]map[string]any, 0, len(entries))
		for _, k := range entries {
			pub, _ := base64.StdEncoding.DecodeString(k.PublicKeyB64)
			result = append(result, map[string]any{"key_id": k.KeyID, "roles": []string{k.Role}, "public_key_fingerprint": pubHash(pub)})
		}
		return result
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"schema_version": 1, "clock_basis": "UNVERIFIED", "remaining_s": nil,
		"file":    map[string]any{"state": "SIGNATURE_VALID_TIME_UNASSESSED", "bundle_sha256": pubHash(raw), "root_fingerprint_sha256": pubHash(root), "bundle_version": p.BundleVersion, "issued_at_unix": p.IssuedAtUnix, "expires_at_unix": p.ExpiresAtUnix, "keys": publicEntries(p.Keys), "revoked_keys": publicEntries(p.RevokedKeys), "material_digest_sha256": material, "max_bundle_version_decimal": strconv.FormatUint(^uint64(0), 10)},
		"runtime": map[string]any{"state": "NOT_OBSERVED", "components": []any{}},
		"renewal": map[string]any{"allowed": false, "reasons": []string{"APPROVED_PLAN_AND_EXECUTION_FENCE_REQUIRED"}},
	})
}
func cmdPrepareRenewal(args []string) error  { return cmdRenewal(args, false) }
func cmdValidateRenewal(args []string) error { return cmdRenewal(args, true) }
func cmdRenewal(args []string, validate bool) error {
	fs := flag.NewFlagSet("renewal", flag.ContinueOnError)
	rootPath := fs.String("root-pub", "", "approved root public key file")
	basePath := fs.String("bundle", "", "base signed bundle")
	consumersPath := fs.String("consumers", "", "fresh verified consumer observations JSON")
	candidatePath := fs.String("candidate", "", "externally signed candidate, validation only")
	issued := fs.Int64("issued-at", 0, "issued unix seconds")
	expires := fs.Int64("expires-at", 0, "expires unix seconds")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *rootPath == "" || *basePath == "" || *consumersPath == "" || fs.NArg() != 0 {
		return fmt.Errorf("--root-pub, --bundle and --consumers required")
	}
	root, e := readRootPub(*rootPath)
	if e != nil {
		return e
	}
	base, e := readTrustInput(*basePath)
	if e != nil {
		return e
	}
	raw, e := readTrustInput(*consumersPath)
	if e != nil {
		return e
	}
	consumers, e := crypto.DecodeRenewalConsumers(raw)
	if e != nil {
		return e
	}
	if validate {
		if *candidatePath == "" {
			return fmt.Errorf("--candidate required")
		}
		candidate, e := readTrustInput(*candidatePath)
		if e != nil {
			return e
		}
		if e = crypto.ValidateTrustRenewal(base, candidate, root, consumers); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema_version": 1, "result": "CANDIDATE_VALIDATED_NOT_APPLIED", "base_sha256": pubHash(base), "candidate_sha256": pubHash(candidate), "motion_action": "NONE"})
	}
	if *candidatePath != "" {
		return fmt.Errorf("--candidate is validation-only")
	}
	proposal, e := crypto.PrepareTrustRenewal(base, root, consumers, *issued, *expires)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(proposal)
}
