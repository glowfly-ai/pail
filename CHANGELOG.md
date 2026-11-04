# Changes

## 0.2.0

- First public release of **PAIL Core** under Apache-2.0: the robot gateway, the ROS 2 gate and
  motion bridge, the adapters, the SDK and protocol definitions, the journal libraries and two
  independent verifiers.
- Spec edition `PAIL-CORE-2026.1` with the canonical test-vector set
  `spec/vectors/canon/MANIFEST.sha256` (`set_sha256 bbddff16…`). A conformance claim names both
  values; neither one identifies the target on its own (`spec/CONFORMANCE.md`).
- Evaluation bundles for Linux ARM64 and Linux amd64. Each bundle travels with a `.sha256` and a
  `.manifest.json`, and the publisher signature must verify before anything runs; a standalone Go
  verifier ships beside the bundle so that no extra package has to be installed to check it.
- The Issuer is distributed as an evaluation image under separate evaluation terms. No Issuer
  source is distributed, and PAIL Core builds and runs without it.
- Licence boundaries are answerable file by file: the per-file SPDX header, the directory layout
  and the manifest's bundle field all say which of the two licences covers a given path
  (`README.md` §License, `NOTICE`).
