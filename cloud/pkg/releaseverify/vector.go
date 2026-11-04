// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package releaseverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

// Vector is the doctor capability check: a known-good signature that must
// verify and a corrupted one that must be rejected.
type Vector struct {
	Purpose               string `json:"purpose"`
	PublicKeyPEM          string `json:"public_key_pem"`
	Fingerprint           string `json:"fingerprint"`
	MessageB64            string `json:"message_b64"`
	SignatureB64          string `json:"signature_b64"`
	CorruptedSignatureB64 string `json:"corrupted_signature_b64"`
}

// VerifyVector returns the Ed25519 result (0 verified / 1 bad) for the good
// and the corrupted signature; err for an unreadable vector or a key whose
// sha256 differs from the stated fingerprint.
func VerifyVector(path string) (positiveRC, negativeRC int, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	var v Vector
	if err := json.Unmarshal(data, &v); err != nil {
		return 0, 0, err
	}
	pub, err := ParsePublicKeyPEM([]byte(v.PublicKeyPEM), path)
	if err != nil {
		return 0, 0, err
	}
	sum := sha256.Sum256(pub)
	if fp := hex.EncodeToString(sum[:]); fp != strings.ToLower(strings.TrimSpace(v.Fingerprint)) {
		return 0, 0, errors.New("vector fingerprint mismatch: key=" + fp + " stated=" + v.Fingerprint)
	}
	msg, err := base64.StdEncoding.DecodeString(v.MessageB64)
	if err != nil {
		return 0, 0, errors.New("message_b64: " + err.Error())
	}
	good, err := base64.StdEncoding.DecodeString(v.SignatureB64)
	if err != nil {
		return 0, 0, errors.New("signature_b64: " + err.Error())
	}
	bad, err := base64.StdEncoding.DecodeString(v.CorruptedSignatureB64)
	if err != nil {
		return 0, 0, errors.New("corrupted_signature_b64: " + err.Error())
	}
	return sigRC(pub, msg, good), sigRC(pub, msg, bad), nil
}

func sigRC(pub ed25519.PublicKey, msg, sig []byte) int {
	if len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, msg, sig) {
		return SigVerified
	}
	return SigBad
}
