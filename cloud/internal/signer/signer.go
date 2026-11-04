// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// Package signer abstracts issuer-authority signing (tokens, blackbox
// checkpoints, anchor records) behind an interface so key custody can move
// from a local dev keyfile to an external KMS without touching the call
// sites (D5, 배치형상 §7.3). Sign may fail (remote KMS): every caller must
// treat a signing failure as fail-closed.
package signer

import (
	"crypto/ed25519"
	"fmt"
	"os"

	devcrypto "github.com/glowfly/pail/services/internal/crypto"
)

type Signer interface {
	Sign(msg []byte) ([]byte, error)
	KeyID() string
	Public() ed25519.PublicKey
}

// Local signs with an in-process ed25519 private key. Behavior-identical to
// the pre-D5 direct devcrypto.Sign call sites.
type Local struct {
	kp *devcrypto.Keypair
}

func NewLocal(kp *devcrypto.Keypair) *Local { return &Local{kp: kp} }

func (l *Local) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(l.kp.Private, msg), nil
}

func (l *Local) KeyID() string             { return l.kp.KeyID }
func (l *Local) Public() ed25519.PublicKey { return l.kp.Public }

// KMS is the adapter seam for an external key-management service. The
// transport is deliberately not implemented: selecting it without a real
// backend refuses to start rather than silently falling back to a local key.
//
// Public() contract (KM1-1): a real transport must fetch the public key from
// the vault at init, validate it (32-byte Ed25519), and cache it in pub —
// or fail the whole process start. A constructed KMS signer therefore never
// exists with an empty pub; Public() returns the immutable cache.
type KMS struct {
	Endpoint string
	KeyName  string
	pub      ed25519.PublicKey
}

func (k *KMS) Sign(msg []byte) ([]byte, error) {
	return nil, fmt.Errorf("kms signer: transport not implemented (endpoint=%q key=%q)", k.Endpoint, k.KeyName)
}

func (k *KMS) KeyID() string             { return k.KeyName }
func (k *KMS) Public() ed25519.PublicKey { return k.pub }

// FromEnv selects the signing backend via PAIL_SIGNER:
//   - "" / "local": load the ed25519 keyfile at keyfilePath. Absent = refuse
//     (F-KEY-23 / S18): a production signer never mints its own issuer key.
//   - "vault": Vault/OpenBao Transit engine (KM1-2①) — key never on disk here.
//   - "kms": refuse to start until a generic KMS transport is wired (fail-closed).
func FromEnv(keyfilePath, keyID string) (Signer, error) {
	switch mode := os.Getenv("PAIL_SIGNER"); mode {
	case "", "local":
		kp, err := devcrypto.LoadEd25519KeypairJSON(keyfilePath, keyID)
		if err != nil {
			return nil, fmt.Errorf("local signer: %w", err)
		}
		return NewLocal(kp), nil
	case "vault":
		return NewVaultFromEnv(keyID)
	case "kms":
		return nil, fmt.Errorf("PAIL_SIGNER=kms selected but no generic KMS transport is implemented in this build — refusing to start (fail-closed; endpoint=%q key=%q; for Vault Transit use PAIL_SIGNER=vault)",
			os.Getenv("PAIL_KMS_ENDPOINT"), os.Getenv("PAIL_KMS_KEY_NAME"))
	default:
		return nil, fmt.Errorf("unknown PAIL_SIGNER=%q (want local|vault|kms)", mode)
	}
}
