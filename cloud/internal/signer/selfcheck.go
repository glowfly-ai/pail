// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

package signer

import (
	"bytes"
	"fmt"

	devcrypto "github.com/glowfly/pail/services/internal/crypto"
)

// VerifyAgainstKeys rejects at boot the misconfiguration where the issuer
// signs with key A while verifiers trust key B under the same key_id (KM1-1
// self-check). Any failure — missing issuer entry, byte mismatch — must abort
// startup: issuing tokens nobody can verify is worse than not starting
// (fail-closed). src names the keyring source for the error message.
//
// It takes an already-loaded keyring, never a path: the path variant read the
// unsigned file directly and so was a second trust path that no PAIL_KEYRING_MODE
// setting could reach or refuse (`B6-6`). Callers load through
// crypto.LoadTrustedKeyringFromEnv and pass the mode as src.
func VerifyAgainstKeys(s Signer, kr *devcrypto.Keyring, src string) error {
	issuers, err := kr.PublicKeysByRole("issuer")
	if err != nil {
		return fmt.Errorf("issuer self-check: %w", err)
	}
	want, ok := issuers[s.KeyID()]
	if !ok {
		return fmt.Errorf("issuer self-check: key_id %q not in keyring %s (role issuer) — add the logged ISSUER_PUBKEY_B64 to the keyring", s.KeyID(), src)
	}
	if !bytes.Equal(want, s.Public()) {
		return fmt.Errorf("issuer self-check: public key mismatch for key_id %q — keyring %s trusts a different key; verifiers would reject every token", s.KeyID(), src)
	}
	return nil
}
