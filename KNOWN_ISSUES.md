# Known open items

> 한국어판: [`KNOWN_ISSUES.ko.md`](KNOWN_ISSUES.ko.md). The English
> document is canonical; if the two diverge, the English text governs.

> **This document is machine-generated.** Do not edit it by hand — the
> next regeneration check will revert it. Generated from the guarantee
> registry (delegations) and the public test profile of the release
> harness (measured).

An empty document here does not mean there is no boundary — it means we
have not written it down. This document is therefore right **when it is
accurate, not when it shrinks.**

---

## 1. What this document does not cover

**Nothing here blocks release.** Release-blocking items must be closed
at release time, and that verdict is rendered not by a document but by
the harness exit code. These entries describe operating responsibilities,
manual recovery and tests outside this repository's scope. They do not
transfer investigation of unresolved defects to the operating team.

What counts as a vulnerability is defined in
[`SECURITY.md`](SECURITY.md) §2.

---

## 2. Operating responsibilities and manual recovery

These entries assign operating responsibilities and manual recovery procedures.
They do not classify every listed issue as an intentional feature exclusion.
Unresolved defects remain the maintainer's responsibility for investigation.
The DDS authentication defect in G-DEL-L16 remains open; only keeping stopped
and manual recovery are assigned to the operating team.
The full text and refutation condition of each entry are in
[`TRUST_BOUNDARY.md`](TRUST_BOUNDARY.md) §3.

| ID | What is delegated | Delegated to |
|---|---|---|
| `G-DEL-01` | The identity of a token-issuance requester is checked against the request content and enforced | Operator (caller authorization policy) |
| `G-DEL-02` | The Vault and Anchor transport legs have confidentiality and authenticity | Operator (internal network layout; TLS termination; CA trust) |
| `G-DEL-03` | The permit heartbeat and the perception-evidence topics are not forged | Operator (SROS2 deployment; keystore operations) |
| `G-DEL-04` | The keyring-bundle rollback floor state file cannot be rolled back | Operator (file permissions; OS accounts; persistent volumes) |
| `G-DEL-05` | Containers run with least privilege | Operator (container runtime policy; orchestrator) |
| `G-DEL-L01` | Whoever holds a signing key was the rightful party to hold it | Operator (key custody; PKI; HSM/TPM binding; issuer identity vetting) |
| `G-DEL-L02` | Key distribution, revocation, and rotation procedures are carried out correctly | Operator (key distribution pipeline; revocation-declaration rollout; rotation schedule) |
| `G-DEL-L03` | The trust roots are separated from one another | Operator (PKI design; root-separation policy) |
| `G-DEL-L04` | The object designated as the authorization target is actually that object | Adopter (choice, installation, and calibration of the target-identification modality) |
| `G-DEL-L05` | No control path exists that bypasses the gate | Adopter (robot integration shape; actuation access-path control) |
| `G-DEL-L06` | What the journal holds is everything that actually happened | Operator (independent observation; external-anchor cross-checks; audit procedure) |
| `G-DEL-L07` | The transport channels carrying records and commands are encrypted | Operator (TLS termination; network policy; certificate trust stores) |
| `G-DEL-L08` | Availability · redundancy · uninterrupted operation | Operator (redundancy shape; capacity planning; recovery procedure) |
| `G-DEL-L09` | Defense against denial of service, resource exhaustion, and performance degradation | Operator (rate limiting; reverse proxy; resource quotas; network isolation) |
| `G-DEL-L11` | Integrity of the build supply chain — what we built is what we wrote | Adopter (CI isolation; dependency pinning; artifact signing; SBOM) |
| `G-DEL-L12` | The recorded values are semantically accurate | Adopter (accuracy of event producers; sensor calibration; upstream-system validation) |
| `G-DEL-L13` | Retention, archival and disk monitoring of the blackbox journal segments | Adopter (operating organization: retention period, capacity rule, archive location, free-space monitoring) |
| `G-DEL-L14` | Handling of the base OS packages' security advisories | Adopter (base-image rebase and rebuild cadence, own vulnerability policy) |
| `G-DEL-L15` | Comparing the signing-key fingerprint outside the archive | Adopter (the receiving party: compare with the external fingerprint and pass --expected-fingerprint) |
| `G-DEL-L16` | TurtleBot3 DDS authentication after gate restart remains an unresolved defect. Independent evaluation reported one DDS failure in 29 valid restarts; a separate 117-restart investigation reported one DDS failure and one unrelated movement shortfall. Late Final and asymmetric authentication were observed; library internals and a repair remain unverified. On RIG_FAILED, keep stopped, cancel/stop the active plan, preserve logs and retry manually. No automatic recovery or authority release is provided. | Adopter (operating team: keep stopped and retry manually; the maintainer retains DDS root-cause investigation) |

20 delegations. These entries are registered in the guarantee registry, so they do not vanish from the totals — **a delegation is a registration, not prose.**

---

## 3. Anchor service

The anchor service is operated separately and is outside the scope of
this repository.

---

## 4. Tests that do not run in this repository

These tests **do not run** in this repository. That tests of components
outside this repository do not run here is the natural consequence —
but staying silent about it makes readers assume **everything ran.**
The table below transcribes exactly what the public test profile of
the release harness excludes.

| Block | Excluded scope | Reason |
|---|---|---|
| `TB-8` | entire block | hosted anchor service tests — outside this repository; hosted anchor acceptance tests — outside this repository |
| `TB-10` | steps 1/6 | hosted anchor service tests — outside this repository |
| `TB-12` | entire block | hosted anchor service tests — outside this repository |
| `TB-13` | steps 1/10 | hosted anchor service tests — outside this repository |
| `TB-14` | entire block | hosted anchor service tests — outside this repository; hosted anchor acceptance tests — outside this repository |

Of 20 blocks, 5 are affected. The rest run in this repository as-is.
