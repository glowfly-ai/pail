# PAIL Issuer evaluation executable

The single-node evaluation executable performs policy judgment, signed token
issuance, delegation, revocation, journal persistence and replay. Its source is
not included in PAIL Core. The public protocols, SDK, robot gateway and independent
verifiers are included. Core source tests and executable integration tests have
different scopes; neither is silently substituted for the other.

## Configuration rules specific to the executable

These are externally observable executable requirements, not claims that the
corresponding implementation is available in the Core archive. The rest of the
shared configuration and robot-side checks are described in CONFIG.md and
TRUST_BOUNDARY.md. Profiles must be chosen deliberately; a development profile
is not a production-security assertion.

| ID | Required behavior |
|---|---|
| `S23` | Refuse service when a site-model snapshot cannot be stored under `PAIL_SNAPSHOT_DIR`; do not issue against an unretained model. |
| `S39` | In production, require skill registries in `PAIL_SKILLS_DIR` for the site's robot classes. Malformed registries are refused in every profile. |

HA synchronous replication, standby/promotion and multi-tenant orchestration are
not supplied by this evaluation image. HA configuration is rejected, not ignored.
Anchor SaaS is not required for local evaluation or local evidence verification.
A local file anchor does not constitute an independent external witness.

## Delivery and rights

Use only the image ID pinned by the matching evaluation lock, with external
state and per-run keys. No private keys or activation credentials are embedded.
See RELEASE.md and the evaluation bundle's EVALUATION-LICENSE.txt. Those terms
apply to the executable, not to the Apache-2.0 Core. They are the only Issuer terms
in a Core delivery; no source licence for the Issuer is part of it. Existing grants for previous
source distributions are not retroactively withdrawn.

The image can be inspected and its behavior independently exercised through the
public APIs; that is not source reproducibility or proof of all internal policy
branches. Checksums and image IDs do not authenticate the publisher without a
trusted delivery path. This local preview has no official release signature.
