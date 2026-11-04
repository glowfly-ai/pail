# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Ed25519 verification shim .

Prefers PyNaCl, falls back to `cryptography`. Both verify the SUT's raw Ed25519
signatures (crypto/ed25519 in Go). Kept dependency-agnostic so the pure-python
verifiers run under the CI image or a bare venv.
"""

from __future__ import annotations

try:  # PyNaCl path
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    def ed25519_verify(pub32: bytes, msg: bytes, sig64: bytes) -> bool:
        if len(pub32) != 32 or len(sig64) != 64:
            return False
        try:
            VerifyKey(pub32).verify(msg, sig64)
            return True
        except BadSignatureError:
            return False

except ImportError:  # cryptography fallback
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    def ed25519_verify(pub32: bytes, msg: bytes, sig64: bytes) -> bool:
        if len(pub32) != 32 or len(sig64) != 64:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(pub32).verify(sig64, msg)
            return True
        except InvalidSignature:
            return False
