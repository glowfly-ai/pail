// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package releaseverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Ed25519 SubjectPublicKeyInfo prefix (RFC 8410): SEQUENCE { AlgorithmIdentifier id-Ed25519, BIT STRING }.
var spkiEd25519Prefix, _ = hex.DecodeString("302a300506032b6570032100")

// ParsePublicKeyPEM extracts the raw 32-byte Ed25519 key from a PEM
// SubjectPublicKeyInfo; label names the source in the error text.
func ParsePublicKeyPEM(pem []byte, label string) (ed25519.PublicKey, error) {
	var body []byte
	for _, line := range bytes.Split(pem, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || bytes.HasPrefix(line, []byte("-----")) {
			continue
		}
		body = append(body, line...)
	}
	der, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil || len(der) != 44 || !bytes.Equal(der[:12], spkiEd25519Prefix) {
		return nil, errors.New("not an Ed25519 SubjectPublicKeyInfo: " + label)
	}
	return ed25519.PublicKey(der[12:]), nil
}

// KeyFingerprint is sha256 of the raw 32-byte key (the value RELEASE.md and
// SECURITY.md print); the PEM/DER wrapper is not part of it.
func KeyFingerprint(pemPath string) (string, error) {
	pem, err := os.ReadFile(pemPath)
	if err != nil {
		return "", err
	}
	pub, err := ParsePublicKeyPEM(pem, pemPath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:]), nil
}

// Signature result codes, as in verify_evaluation.verify_signature().
const (
	SigVerified    = 0 // signature verified with the given key
	SigBad         = 1 // bad signature, wrong key, or fingerprint mismatch
	SigNotVerified = 2 // no .sig or no public key
)

// Backend is the backend word printed after VERIFIED (the Python tool prints
// "python cryptography" or the OpenSSL version here).
const Backend = "pail_verify"

// VerifySignature checks <manifestPath>.sig with the PEM key at pemPath.
// rc and msg follow the Python tool exactly; err is set only for verifier
// faults (unreadable files, a key that is not an Ed25519 SPKI), which the
// Python tool raises as exceptions.
func VerifySignature(manifestPath, pemPath, expectedFingerprint string) (rc int, msg string, err error) {
	sigPath := manifestPath + ".sig"
	if !isFile(sigPath) {
		return SigNotVerified, "no signature file beside the manifest (" + filepath.Base(sigPath) + ")", nil
	}
	if pemPath == "" || !isFile(pemPath) {
		return SigNotVerified, "public key not found; expected RELEASE-SIGNING-KEY.pub beside this tool or --public-key", nil
	}
	pem, err := os.ReadFile(pemPath)
	if err != nil {
		return SigNotVerified, "", err
	}
	pub, err := ParsePublicKeyPEM(pem, pemPath)
	if err != nil {
		return SigNotVerified, "", err
	}
	sum := sha256.Sum256(pub)
	fp := hex.EncodeToString(sum[:])
	if expectedFingerprint != "" {
		want := strings.ToLower(strings.TrimSpace(expectedFingerprint))
		if fp != want {
			return SigBad, "KEY MISMATCH key=" + fp + " expected=" + want, nil
		}
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return SigNotVerified, "", err
	}
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		return SigNotVerified, "", err
	}
	// A .sig of the wrong length is InvalidSignature for python cryptography too (rc 1).
	if len(raw) == ed25519.SignatureSize && ed25519.Verify(pub, data, raw) {
		return SigVerified, "VERIFIED key=" + fp + " with " + Backend, nil
	}
	return SigBad, "BAD SIGNATURE key=" + fp, nil
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
