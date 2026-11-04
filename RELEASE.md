# Verify this preview distribution

[VERSION](VERSION) identifies the candidate. [CHANGELOG.md](CHANGELOG.md) describes changes.
<!-- release-identity:delivery:start -->
Public release: **`0.2.0`**. Four separate artifacts per architecture; the Linux ARM64 set:

- `PAIL-Core-0.2.0-src.zip` — Apache-2.0 Core source, including the complete robot gateway (one source ZIP for both architectures).
- `PAIL-Issuer-Eval-0.2.0-linux-arm64-image.tar` — private-source Issuer evaluation image (Linux ARM64).
- `PAIL-Evaluation-0.2.0.zip` — evaluation bootstrap; runtime images supplied separately.
- `PAIL-Evaluation-0.2.0-linux-arm64-offline.zip` — same evaluation with pinned runtime images included.

The Linux amd64 delivery uses the same names with `linux-amd64` in place of `linux-arm64`:
the evaluation bootstrap `…-linux-amd64.zip`, the offline bundle `…-linux-amd64-offline.zip`,
the Core runtime images `…-linux-amd64-images.tar` and the Issuer image `…-linux-amd64-image.tar`;
its `images.lock.json` says `amd64` and its VALIDATION names its own image identities.
Each ZIP and TAR travels with a `.sha256` and a `.manifest.json`. Which set to use is decided by the
Docker daemon's CPU architecture, not by preference (the launcher refuses the other one).

No Issuer source overlay is distributed. Core builds without it. Evaluation uses
the real single-node Issuer executable under separate evaluation terms.
Online bootstrap does not imply a public registry has been published.
Offline means runtime, not rebuilding all source without dependencies.

```sh
shasum -a 256 -c PAIL-Core-0.2.0-src.zip.sha256
```
<!-- release-identity:delivery:end -->

On Linux, `sha256sum -c` can be used instead. Run beside the ZIP and checksum file.
A digest detects mismatched bytes only when obtained through a trusted channel; it
is **not a publisher signature**. The signature is separate: every `*.manifest.json`
travels with a `*.manifest.json.sig`, a raw Ed25519 signature over the manifest bytes
by the release key. The public key ships as `RELEASE-SIGNING-KEY.pub` (in the Core ZIP
root and in every evaluation bundle); its fingerprint is

    sha256(raw public key) = 8917d27e9c68e0e88538177c76279db450ad615ffe00a58f338a45474f318a17

This line travels inside the archive it describes, so on its own it only shows that the
archive agrees with itself. The copy that anchors trust is published outside every
archive: the `Release signing key` section of `SECURITY.md` in the public repository
(and the release page that announces a version). Compare the fingerprint you compute
with that copy, and pass it to the verifiers as `--expected-fingerprint`, so a key that
differs is refused before any signature is checked:

```sh
python3 scripts/sign_release.py --public-key RELEASE-SIGNING-KEY.pub --fingerprint
# the standalone verifier (standard-library Go, no module download; the Core source
# carries it and every evaluation bundle ships it built as native/pail_verify-<host>):
go run ./cloud/cmd/pail_verify --sig-only \
  --manifest PAIL-Core-0.2.0-src.zip.manifest.json \
  --public-key RELEASE-SIGNING-KEY.pub \
  --expected-fingerprint 8917d27e9c68e0e88538177c76279db450ad615ffe00a58f338a45474f318a17
# or with the python `cryptography` package:
python3 scripts/sign_release.py --public-key RELEASE-SIGNING-KEY.pub \
  --expected-fingerprint 8917d27e9c68e0e88538177c76279db450ad615ffe00a58f338a45474f318a17 \
  --verify PAIL-Core-0.2.0-src.zip.manifest.json
# or with OpenSSL 3 (the macOS system `openssl` is LibreSSL and cannot verify Ed25519;
# use Homebrew's openssl@3 there):
openssl pkeyutl -verify -pubin -inkey RELEASE-SIGNING-KEY.pub -rawin \
  -in PAIL-Core-0.2.0-src.zip.manifest.json \
  -sigfile PAIL-Core-0.2.0-src.zip.manifest.json.sig
```

`verify_release.py` and `verify_evaluation.py` run the same check and accept
`--expected-fingerprint`; `verify_release.py` uses `go run ./cloud/cmd/pail_verify` when
the Go toolchain is present and `verify_evaluation.py` uses the bundled
`native/pail_verify-<host>` after checking its bytes against the lock, before either
falls back to python `cryptography` or OpenSSL 3. The signature is required by the
verifiers themselves — nothing inside an archive can waive it — so when the `.sig` is
missing they report `FAIL (signature)` instead of falling back to digests, unless
`--allow-unsigned` is given on purpose. Do not treat the test keyring, the frozen vector
keys or the `doctor` capability vector (`checks/signature_vector.json`, a test-only key)
as release-signing trust roots. A verifier that travels inside the archive cannot be the
trust root for that archive — the manifest binds its bytes, but the signature it checks is
the one it would have to lie about; the independent legs are the fingerprint published
outside every archive, the negative vector `doctor` runs on the same backend, and a
verifier you build yourself from the Core source. A signature proves that the
publisher's key signed these bytes; SBOM completeness and byte-reproducible builds are
separate properties, and this document does not claim they are complete.

The publisher uses a new clean public history, not a copy of private development Git
objects. No `.git` directory is required inside a source ZIP. Retain the candidate
ID, ZIP digest, commands, image IDs and reviewed evidence when reporting results.

The executable-specific boundary is in [ISSUER_EVALUATION.md](ISSUER_EVALUATION.md).

See [SUPPORT.md](SUPPORT.md) and [SECURITY.md](SECURITY.md) for the distinct support and
vulnerability-reporting boundaries.


## Verify the pristine extracted tree

Run from the delivery directory, immediately after extracting and **before** any
build, test or provisioning. Obtain the manifest and checksum from a trusted channel.

<!-- release-identity:verify:start -->
```sh
python3 pail-core/scripts/verify_release.py \
  --root pail-core \
  --manifest PAIL-Core-0.2.0-src.zip.manifest.json \
  --zip PAIL-Core-0.2.0-src.zip \
  --expected-release 0.2.0
```

Obtain the manifest through a trusted channel. The evaluation launcher checks
its image lock before starting services; checksums alone do not authenticate a publisher.
<!-- release-identity:verify:end -->

The checker rejects changed, missing, extra and symlink files, invalid manifest paths,
duplicate JSON fields and inconsistent counts; `--zip` also checks archive identity,
size and digest. Exit codes: 0 agreement, 1 mismatch, 2 unable to check. It never
repairs or deletes files. Empty directories and file permissions are not authenticated
by this source-byte manifest. The checker itself is supplied source, not an independent
trust root: verify the ZIP through a trusted channel before executing its code.

Runners generate keys, configuration and evidence; code generation/builds can also
change the tree. Such changes are not automatically attacks. Keep a pristine copy for
release verification and a separate working copy for execution. Never share generated
private keys while reporting differences. The evaluation bundle applies the same rule
mechanically: its verification receipt carries the digest of the extracted tree and the
launcher re-hashes the tree on every start, so a run from a modified tree is reported
`VERIFICATION: TREE_MODIFIED` (and refused under `--require-verified`) instead of
inheriting the verdict of the ZIP it came from.


## Archive modes

Public regular files are packaged with Unix mode 0644, shell scripts with 0755,
and directory entries with 0755. Packaging does not inherit the publisher's umask.
The byte manifest still does not authenticate filesystem modes; TB3 separately
stages and reads its public reference inputs as UID 10001. Private runtime keys
are generated outside the source archive and are not covered by this public-file
mode rule. Validate the final ZIP with Linux `unzip`, not only a source checkout.


Runtime permission checks cover both producer and consumer UIDs, including ancestor
directory traversal, not just archive file modes. Run the TB3 test with both umask
022 and 077 on a real Linux filesystem before treating a candidate's access checks
as complete. A clock prerequisite failure is not a successful functional test.


## Release identity contract

`release.json` is the single source for the candidate ID, archive basename and top folder.
VERSION and the marked command blocks above are generated from it. Run
`python3 scripts/release_identity.py` from the extracted root to check their agreement.
The verifier also binds manifest identity to these files; `--expected-release` specifies
the intended release independently. A checksum success for an older file is not a
verification of this candidate. This identity check is not publisher authentication.
