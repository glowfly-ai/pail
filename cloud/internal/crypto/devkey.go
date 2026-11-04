// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
)

// DevKeypair generates an ephemeral ed25519 keypair for phase-1 development.
// In production, keys must come from secure storage / HSM.

type Keypair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
	KeyID   string
}

func NewDevKeypair(keyID string) (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Keypair{Public: pub, Private: priv, KeyID: keyID}, nil
}

func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	sig := ed25519.Sign(priv, msg)
	return sig
}

func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

func PublicKeyBase64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}
