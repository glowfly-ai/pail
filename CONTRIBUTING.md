# Contributing to PAIL

> 한국어: [CONTRIBUTING.ko.md](CONTRIBUTING.ko.md). The English text governs.

This project follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Read [TRUST_BOUNDARY.md](TRUST_BOUNDARY.md) before proposing a change: some responsibilities
are deliberately delegated to the deploying organization. Report vulnerabilities through
[SECURITY.md](SECURITY.md) §1, **not a public issue or PR**.

## 1. Sign-off (DCO) for every contribution; a CLA only for substantial ones

Every commit carries a Developer Certificate of Origin sign-off
(`git commit -s`, which adds `Signed-off-by: Name <email>`; the text of the
certificate is at <https://developercertificate.org>). The sign-off states that
you have the right to submit the change under [LICENSE](LICENSE); contributions
are accepted under Apache-2.0 Section 5 and nothing more is asked. The `dco`
workflow (`.github/workflows/ci-dco.yml`) checks the trailer on every commit of a
pull request.

A **substantial contribution** is asked to sign the [CLA](CLA.md) (individual or
corporate — an individual cannot grant rights the employer owns) before it is
merged, and to be discussed in an issue first. A contribution is substantial when
any of these holds:

- it changes files under `cloud/`, `libpail_gate/` or `spec/` (the issuance and
  gate logic and the frozen formats), other than a comment, a test or a
  documentation fix;
- it adds or changes more than 300 lines in total;
- it adds a new public interface, message, reason code or configuration setting.

The maintainers may instead accept a substantial proposal as an issue and
implement it themselves; in that case they work from the issue text, not from
the declined pull request's code. Small fixes, typo and documentation changes,
and robot or ROS 2 interface adaptations outside those paths need only the
sign-off. The code license is [LICENSE](LICENSE); this guide grants no new rights.

## 2. Frozen canonical formats

The formats in `spec/` are versioned. Prefixes, field order, delimiters and hash-input
definitions cannot change without a spec version change.

| Proposed change | Treatment |
|---|---|
| Fix a typo in a frozen prefix | Not accepted as an ordinary fix: the bytes are the format |
| Replace a delimiter or regenerate frozen vectors | Requires a specification/profile revision |
| Remove a legacy parser | Not accepted: existing recorded bytes must remain readable |
| Fix implementation behavior without changing the format | Welcome |

Discuss format changes in an issue first (except security findings). The vector set is
pinned by `spec/vectors/canon/MANIFEST.sha256`; changing it changes the conformance claim.
See [spec/CONFORMANCE.md](spec/CONFORMANCE.md).

## 3. Generated documentation

`TRUST_BOUNDARY.md` §3 and `KNOWN_ISSUES.md` are generated from the guarantee registry
and public test profile. Do not hand-edit generated output. Report the discrepancy or
change its source and regenerate. Do not delete an unresolved limitation to shorten a
list: close it with supporting evidence instead.

## 4. Behavioral fixes need a reproducer

1. Add a test that reproduces the fault and observe its failure.
2. Fix the cause and run the same test.
3. Include the before/after results in the PR.

A passing test alone does not establish that it detects the reported fault.

## 5. Checks before submitting

Run the build and relevant tests for the layer changed and include the output:

- `cloud/`: Go build/vet and the relevant tests; generate protos before generated builds.
- `robot/`: ROS 2 Humble / colcon build and relevant tests.
- `pvs-public/`: the applicable pytest profile; not every internal rig ships here.
- `spec/tools/`: the applicable spec checkers.
- Public documentation: `python3 scripts/check_public_links.py`.

[KNOWN_ISSUES.md](KNOWN_ISSUES.md) §4 lists excluded internal tracks. A skipped test must
retain its reason; SKIP is neither a failure nor evidence of a successful test.

## 6. Scope of this repository

| Item | Boundary |
|---|---|
| Anchor SaaS server | Offered as a hosted service; the public formats and verification inputs it speaks are in `spec/` |
| Issuer replication and standby | The evaluation issuer is single-node and refuses `PAIL_HA_*` replication settings at startup |
| Design rationale and field evidence | What the public needs is in `spec/`, the README and `KNOWN_ISSUES.md` |
| Operator-owned deployment layers | See [TRUST_BOUNDARY.md](TRUST_BOUNDARY.md) §3 |

The [README](README.md) describes the public scope. The local authorization example does
not depend on an Anchor server; its absence is not a missing dependency.

## 7. PR checklist

- [ ] Every commit is signed off (DCO); the CLA is signed if §1 calls the change substantial.
- [ ] No unversioned change to frozen canon bytes.
- [ ] Generated documents changed through their source, not by hand.
- [ ] Behavioral fixes include the failing-before result.
- [ ] Relevant build/test results attached.
- [ ] This is not a privately reportable vulnerability.

Contributions are distributed under [Apache License 2.0](LICENSE). The Issuer is supplied
as a single-node evaluation executable under the separate terms of `EVALUATION-LICENSE.txt`,
so there is no Issuer source file here to contribute to.

## Public language policy

Use English for new public-facing diagnostics, CI step names and API explanations.
When changing core implementation comments, make the relevant rationale readable in
English. Keep translations in their language-specific files, and preserve multilingual
fixtures and frozen bytes. Never translate identifiers, wire values or evidence bytes.
Screen dictionaries and screen files are bilingual by requirement (the dashboard under
`cloud/cmd/pail_telemetryd/dashboard/` and the examples' `*_ui.html`); they are exempt from
the maintainers' Korean-content ratchet that applies to every other public non-document
file.
