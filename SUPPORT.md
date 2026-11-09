# Support for this distribution

No public support SLA or guaranteed response time is established. Questions and
non-security problem reports go to this repository's GitHub Issues. Include VERSION,
ZIP SHA-256, OS/CPU, Docker/Python versions, command, exit code, expected/observed
behavior and reviewed evidence paths. Do not attach private keys, complete keystores,
authentication tokens or unreviewed customer data. A report is answered as
"reproduced" or "not yet reproduced", not with a date.

For suspected vulnerabilities follow [SECURITY.md](SECURITY.md), not a public issue;
the security reporting address is stated there and only there.

**How fixes reach you.** A release is one hash-bound set (Core source, runtime and
Issuer images, evaluation bundles). The bytes we have verified are the ones at the
release tag and in the signed archives; `main` moves ahead of the tag toward the next
release. Documentation, CI and example fixes land on `main` without a new release.
Fixes that change shipped behaviour are collected into the next point release as a
complete, re-verified set; they are not backported. Security fixes follow
[SECURITY.md](SECURITY.md) §1, including its notification times, and are shipped as a
complete release as well.

Evaluation of what Glowfly offers separately from this repository (production Issuer
licensing, Anchor SaaS, fleet operations) goes through
[www.glowfly.ai](https://www.glowfly.ai).
