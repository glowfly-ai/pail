# Revoked development signing keys

These keys appeared in tracked development source and must be treated as disclosed.
This notice preserves their public fingerprints and recorded retirement history;
it does not supply private keys or establish current trust roots.

The fingerprint namespace is SHA-256 of the derived 32-byte Ed25519 public key.
Use the same namespace when comparing fingerprints; a different encoding or hash
input is not interchangeable. See [../spec/TRUST_ROOT.md](../spec/TRUST_ROOT.md).

## Revoked fingerprints

| Role | Fingerprint (SHA-256, 64 hex characters) | fpr16 | Status |
|---|---|---|---|
| LOG (transparency-log checkpoint signing) | `425aca391f43372640e62985c3d936e3cf1f3ae13b046776b49186aa98c02208` | `425aca391f433726` | **Revoked** |
| VERDICT (verdict signing) | `da7337e3d701b01b97c60ba3cc5e4b5ae3eea8462ba6dc8834d2c195cfc8c781` | `da7337e3d701b01b` | **Revoked** |

## Recorded dates

| Role | First observed in tracked source | Removed from verification trust |
|---|---|---|
| LOG | 2026-07-25T16:39:56+09:00 (`1b65123`) | 2026-08-09T18:18:04+09:00 (`b239f65`) |
| VERDICT | 2026-07-25T16:39:56+09:00 (`1b65123`) | 2026-08-09T18:18:04+09:00 (`b239f65`) |

Epoch milliseconds: first observed `1784965196000`; retired `1786267084000`.
The first-observed dates came from source history searches, not proof that no earlier
representation existed. Commit identifiers are historical provenance, not prerequisites
for using the clean public snapshot.

## Recorded replacement fingerprints

| Role | Replacement fingerprint (64 hex characters) | fpr16 |
|---|---|---|
| LOG | `bde38b8fd1f2f7b7beb6da639972611033982734e85cbdb5d1c950ccb3131b83` | `bde38b8fd1f2f7b7` |
| VERDICT | `2b76331c119d6d5ca637a65aef3a604bdb05e6c7db8fbb6293783e0bb16f1379` | `2b76331c119d6d5c` |

Replacement fingerprints are historical metadata, not permission to trust a key supplied
by an untrusted server. Obtain current trust roots out of band. Private replacement key
material is not distributed.

## Interpreting historical signatures

Distinguish a valid signature under current trust, a signature attributable to a revoked
key, and a signature that cannot be verified. Do not silently promote a revoked key to
current trust or label every revoked-key signature as a forgery.

Because the old keys were disclosed, an attacker could also produce signatures with
them. A signature alone does not prove that only the project created a record, nor does
it independently prove a creation time before retirement. Evaluate trusted time and
retained external evidence separately. Removing the old material from a new release
cannot invalidate copies already received.

This notice describes public history and verification boundaries. It does not require
an internal verification program or a private design document.
