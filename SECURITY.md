# PAIL Security Policy

> 한국어판: [`SECURITY.ko.md`](SECURITY.ko.md). The English document is
> canonical; if the two diverge, the English text governs.

> **This is the document you read *after* finding a flaw.**
> What you should read **before** deploying is [`TRUST_BOUNDARY.md`](TRUST_BOUNDARY.md).
> The answer to "what counts as a vulnerability" is mostly decided there —
> in its §2 (what we defend) and §3 (what we do **not** defend).

Spec edition: **`PAIL-CORE-2026.1`** · test-vector set: `spec/vectors/canon/MANIFEST.sha256`
(`set_sha256 bbddff16…`).

---

## 1. Reporting channel

Do **not** open a public issue for a security flaw. Send it here instead.

- Mail: `security@glowfly.ai`
- PGP key: **not provided.**

Having no PGP key means a report is **not protected beyond the transport
leg**. If the content is sensitive enough to need an encrypted channel, **do
not put the details in the body** — first send only the fact that "an
encrypted channel is needed" to the address above. The channel is agreed
then. Stating that we have no key and giving an alternative is better than
writing down a key we do not hold.

What we do on receipt:

| Step | What we do |
|---|---|
| Acknowledgement | Acknowledge receipt. **Not "under review" — one of "reproduced / not yet reproduced"** |
| Impact verdict | Which cell of §2 below it falls into |
| After the fix | Coordinate the disclosure schedule with the reporter. If the reporter wishes, their name goes into the Acknowledgements section of this file (not `NOTICE`, which is the Apache-2.0 attribution file every redistributor must carry) |

Reports are handled in the order received. The reporting deadlines of §1a are
set by law and do not depend on this table.

**Without reproduction information we cannot reproduce.** Send at least the
deployment shape (SROS2 or not, HA or not, the `PAIL_PROFILE` value) and the
observed log lines.

### 1a. CRA clock (from 2026-09-11)

The EU Cyber Resilience Act (Regulation (EU) 2024/2847, Art. 14) puts a
reporting clock on the **manufacturer** of a product with digital elements.
The reporting obligation applies from **2026-09-11**; the regulation applies in
full from 2027-12-11. It binds us for the artefacts in §1b where our role is
*manufacturer*, and it runs **next to** the §1 table, not instead of it: §1 is
what we do with a report that comes *in*; this section is what goes *out*.

The clock starts at **awareness**, not at reproduction. A report that goes out
before we have reproduced says so ("not yet reproduced") rather than waiting.

| We become aware of … | Deadline | What goes out | Where |
|---|---|---|---|
| an **actively exploited vulnerability** in an artefact we manufacture | **24 hours** — early warning | that exploitation is happening, which artefact, which versions | the single reporting platform under Art. 16 (the coordinating CSIRT / ENISA) |
| the same | **72 hours** — vulnerability notification | nature and severity, affected versions, available mitigations and corrective measures | the same |
| the same | **14 days** after a corrective or mitigating measure is available — final report | description and root cause, the mitigation, and (where known) the actor | the same |
| a **severe incident** having an impact on the security of an artefact we manufacture | 24 hours early warning · 72 hours incident notification · **1 month** after that notification — final report | as above, plus the impact and any indicators of compromise | the same |

Two rules that the regulation does not spell out but that follow from how this
software is deployed:

- **When the robot OEM is the manufacturer** of the machine our artefact is
  built into (§1b, last two rows), the OEM's clock is theirs, but it must not
  start late because ours did. We forward what we know to the OEM **within the
  same 24 hours**, in the same shape as the early warning above.
- **Users are told** when a corrective measure exists, with the mitigation they
  can apply until they update. For the public core that is a release note and
  a `CHANGELOG.md` entry; for the anchor service it is a message to every affected
  tenant.

The timestamps of awareness and of each outgoing report are kept with the fix.
No report under this clock has been sent as of this edition; the table is what
we are bound to, not a record of what has happened.

### 1b. Which artefacts are a "product", and whose obligation it is

The CRA distinguishes an **open-source software steward** (Art. 24: a
security policy, coordinated vulnerability handling, cooperation with market
surveillance on request; no conformity assessment and no CE marking of the
open-source software as such) from a **manufacturer** (Annex I obligations,
the §1a clock, security updates for the support period, an SBOM per release).
Our role differs by artefact:

| Artefact | Where it lives | Our role | What that binds us to |
|---|---|---|---|
| **Public core (PAIL-Core)** — gate, verifier, spec, SDK: the source files included in this release that carry the Apache-2.0 licence | this repository, Apache-2.0, no charge | **open-source software steward** | this policy, §1 handling, cooperation with market surveillance. **Not** the §1a clock for the core as such — the clock attaches to a product that ships it |
| **Issuer (PAIL-Issuer)** — the token issuer; its source (`cloud/issuer/` and the files a release manifest would list as bundle "issuer") is **not included** in this release | supplied beside PAIL-Core as a single-node evaluation executable under the separate terms of its `EVALUATION-LICENSE.txt` (binary-only evaluation terms): not open source and not source-available | **not determined yet** — the Art. 24 role is defined for free and open-source software, so it is not claimed for this artefact | this policy and §1 handling apply in full. Whether the §1a clock attaches to the issuer as such is not determined yet; where it ships inside the anchor service or a commercial kit, the rows below apply |
| **Anchor service** — managed anchoring, tenant console, verification as a service | operated by Glowfly Identity Systems Co.,Ltd for tenants | **manufacturer** (a remote data processing solution of the kits below) | the §1a clock · security updates · SBOM per release · tenant notification |
| **Commercial kits** — gate + issuer + verifier delivered as built images with support | delivered to a robot OEM or an operator under contract | **manufacturer of the kit**; the OEM stays manufacturer of the machine | the §1a clock for the kit · SBOM and build identification handed to the OEM · the forwarding rule of §1a for anything we learn |
| **An OEM's own integration** of the public core into its machine | the OEM's product | **none** — the OEM is the manufacturer | the OEM's; toward them we act as steward of the core they used |

If you are unsure which row a deployment falls under, ask through the §1
channel before reporting; the answer decides whose clock is running.

---

## 2. What counts as a vulnerability

There is one dividing line — **does it refute one of the four strong claims
in `TRUST_BOUNDARY.md` §2?**

That line decides *what kind of defect* counts. Which attacker you are
allowed to be is a separate question, and it is answered in
[`THREAT_MODEL.md`](THREAT_MODEL.md) §2, where each attacker is listed with
where it stands and what it is granted. Anything not on that list is outside
the model — which means unexamined, not absent. A report is easiest to act on
when it names the attacker it assumes.

If your finding needs a capability that no attacker in §2 has, say so rather
than leaving it out. That does not automatically put the finding out of
scope: it may mean the attacker model is short a row, and a model that
cannot express your attacker is itself a defect.

| Report | Treatment |
|---|---|
| It meets a **refutation condition** of §2.1–§2.4 | **Vulnerability.** Signature bypass, issuer-first inversion, single-use bypass, fail-closed inversion |
| A startup refusal gate (`TRUST_BOUNDARY.md` §6) **fails to block** a shape it must block | **Vulnerability.** A gate that passes silently is worse than no gate |
| The canon canonical text (§`spec/`) and an implementation **produce different values** | **Vulnerability.** Two implementations emitting different bytes for the same input break interoperability |
| An attack that uses a **delegated entry** of `TRUST_BOUNDARY.md` §3 | **Not a vulnerability** — but if the delegation wording **understates the actual risk**, that is a vulnerability. A defect in the document is also a defect |
| It points at an **unimplemented entry** of §5 | Not a vulnerability. It is already written down. **If you found an unimplemented part that is not written down, that is a vulnerability** |
| A flaw in the demo (`demo/`) composition | **Not a vulnerability.** The demo is built to run without authentication or authorization, and it is for isolated networks only. It is not part of the distribution |

**We single out one kind of report we welcome.** The fourth row above —
delegation wording that understates a risk. We are not confident that we
know all the consequences of the things we decided not to do.

That row is checkable rather than a matter of taste. `THREAT_MODEL.md` §7
names, for every delegation, the attacker it assumes. If you can reach the
same outcome with a **weaker** attacker than the one named there, the
wording understates the risk, and that is the report we want.

---

## 3. Supported range

- Supported are the **latest public release** and the release before it.
- Security fixes are not backported to earlier releases.
- The canon canonical text in `spec/` is **pinned by edition number**
  (`PAIL-CORE-2026.1`). When the canonical text changes, the edition number
  goes up, and old-edition parsers are not removed — making old records
  unreadable is suicide for an evidentiary layer.

---

## 4. Unimplemented items and known limitations

**A document with this section and a document without it are different
documents, even when they describe the same code.** Without it, readers take
what is in the design documents and the patent specification as implemented.

### 4.1 Not implemented — the design exists, the code does not

The full list and grounds are in [`TRUST_BOUNDARY.md` §5](TRUST_BOUNDARY.md). Summary:

| Item | State |
|---|---|
| Binding the perception-evidence snapshot hash into the token signature (P0 v4 marks 215·251) | **Not implemented.** Disclosed in the patent specification, absent from this repository's code |
| Permit application-layer signature | **Not implemented.** Delegated to transport-layer authentication (SROS2) — delegation `G-DEL-03` |
| Startup refusal gates S12·S13 | **Not implemented.** Designed, no code |
| Context signature verification | **Not implemented.** Context changes are **recorded** (record 51), but the signature is not verified. The authorization record's `context_verification` (3-valued) is **always `not_attempted`** in the current deployment — "there is no verification path", not "verified and failed" |

**"It is in the design document" and "it is in the code" are different
statements.** This table is the list of the points where the two part.

### 4.2 Durability model — what is on disk, when

> **Durability model.** The PAIL issuer appends the authorization record to
> the journal before the issuance response (issuer-first). What "append"
> means depends on the deployment shape.
> **(a) In a replicated deployment** (the evaluation issuer is single-node and
> refuses `PAIL_HA_*` settings at startup), the response
> returns only after the standby node has fsynced those bytes and passed chain
> verification.
> **(b) In a single-node deployment** — the only shape this distribution
> builds — the bytes are handed to the operating
> system and are **fsynced at checkpoint time (default: every 1000 records
> or every 60 seconds).**
> Therefore, on sudden power loss in a single-node deployment, **records
> after the last checkpoint can be lost** — at the defaults above, up to
> 1000 records or 60 seconds' worth. For the lost span, issuer-first does
> not hold at the disk level.
> A deployment that cannot accept this bound must use a replicated issuer or lower
> `CheckpointEveryRecords`.

**We state the verification range of this paragraph.** What we measured is
**where the fsync calls happen** (syscall level). What actually survives a
power loss depends on the disk cache, the file system, and the manner of the
power loss, and **we have not tested that.**

In particular — **killing the process (SIGKILL) is no evidence for this
paragraph.** The page cache does not die with the process, so the data
survives whether the fsync is there or not. A "pass" from that test is not
a pass.

### 4.3 What we do not check

- **Sender authentication on the evidence plane (ROS 2 topics).** That is
  carried by SROS2 Enforce. PAIL does not enforce it — whether it is active
  is recorded in the seal instead. Booting with it off is refused in
  production (deploy guard `S1`); in dev it remains a degraded seal. And a
  verdict rendered while it was off is left on the issuing-side
  authorization record as `evidence_provenance: "unenforced"` — so that the
  verdict cannot later be read as "rendered on verified evidence."
- **Transport protection outside the control plane.** In the production
  profile PAIL refuses plaintext TCP on the control-plane gRPC (`S4`; a unix
  socket protected by file permissions is the exception). It does **not**
  inspect the Vault or Anchor URLs — `S12` exists in the design only. Nor
  does it enforce certificate-verification policy, internal-CA trust stores,
  or certificate lifetimes on any leg. All of that is the deploying
  organization's configuration.
- **Physical protection of key material.** In the local-keyfile shape,
  private keys are protected by file-system permissions alone. No HSM/TPM
  binding is done.
- **The robot hardware's safety functions.** PAIL is the authorization and
  evidencing layer; the final physical stop is owned by the robot's safety
  system.

**The four above are a summary, not the list.** The canonical full list is
[`TRUST_BOUNDARY.md` §3](TRUST_BOUNDARY.md), and that section is not prose —
it is **generated** from the `status: delegated` entries of the guarantee
registry. If an entry leaves the registry, it
disappears from that section too, and an empty receiver (`delegated_to`)
fails CI. Editing this document's prose can neither add nor remove a
delegation.

**No counts are written here.** A number in a hand-written document does not
update itself, and a number that does not update emits no signal that it is
wrong. The counting is done by the generated line at the end of that
section.

Each entry says three things — what is delegated / **what happens if the
delegation fails** / who receives it. A delegation missing the middle is not
a delegation but silence.

### 4.4 What is observed when a delegation breaks (O-2)

**O-2** is the condition that a delegated limit, when it actually breaks,
does not pass silently. The table below is the result of measuring that,
one row per delegation. Each row's verdict is exactly one of four:

- **observed** — breaking it produces a named refusal or a record.
- **quiet** — breaking it produces no line at all.
- **unmeasured** — not yet measured. **The reason why is written with it.**
- **as declared** — the absence itself is the declared behavior.

| # | Delegation | O-2 method | Measured | Verdict |
|---|---|---|---|---|
| L1 | Legitimacy of whoever holds a signing key | Present a token signed with a key not in the trust list | The gate refuses. `test_gate_failclosed` 5 cases / 0 failed, `internal/token` ok. In addition, the startup banner names committed dev keys **by name and sha256** (`S8`) | **observed** |
| L2 | Key distribution, revocation, and rotation | Present a token signed with a revoked `key_id` | `keyring.json` and the keyring bundle have **no** revocation or expiry fields. Gate verification looks only at the existence of the `key_id`. The operations-side `RevokeIssuerV1` puts the issuer into LOCKDOWN but is **not an input that reaches the gate** | **quiet** |
| L3 | Trust-root separation (identity / permissions / mTLS CA) | Cross-use the three roots in the same deployment | In the live keystore, `identity_ca.cert.pem` and `permissions_ca.cert.pem` are not two files with the same content — they are **symbolic links** to `ca.cert.pem` (one inode, three names). And the `scripts/sros2_provision.sh` we ship signs the gRPC mTLS certificates **with that SROS2 CA** — the collapse is not a deployment accident but **our tool's default**. The seal carries only **one** gRPC CA fingerprint (`control_trust_anchors`) and `SealInput` has **no** place for the other two roots — we measured that the seal canonical texts of a collapsed tree and a separated tree are **byte-identical** | **quiet** |
| L4 | Identity of the target object | Request an action with no target identity | No target-identity axis **exists** in the issuance/gate path. Optical identity is a separate perception driver, default off — the pass is as declared, and an absent axis has nothing to propagate (O-3) | **as declared** |
| L5 | Absence of paths that bypass the gate | Skip the gate and publish `/safe_cmd_vel` directly | In the Enforce shape, a rogue enclave's publish attempt was **refused with a named reason** — `rt/safe_cmd_vel topic not found in allow rule`, process rc=1. The shape with SROS2 off remains as the seal's `S1` axis (`test_config_seal`: `S1 must change the canonical text`) | **observed** |
| L6 | Is this record everything that happened | Delete one record from the journal | Chain breakage is detected (`internal/blackbox` ok, including the exhaustive tamper-position test). **That something existed and was deleted** still cannot be proven — as declared | **observed** (completeness not claimed, as declared) |
| L7 | Encryption of the transport channels | Cross the control plane in plaintext | The startup banner names the shape: `PAIL PREFLIGHT: profile=dev INSECURE(S4,S5,S8)` + `S4 … the control plane accepts unauthenticated ReportDecision/Unlock from any local process`. The seal carries the transport **the channel factory actually chose** (not the declared env) | **observed** (non-enforcement is as declared) |
| L8 | Availability · redundancy · uninterrupted operation | Issue while the anchor is down / exhaust the buffer | Journal-append failure refuses issuance (issuer-first) — observed. But **anchor-down is not a stop**: upload failures pile into the queue and issuance continues. And queueing sets `emitted=true` **before** the write, and a failed write leaves only a log line → when the disk fills, that record **vanishes while marked as recorded**, and the next unchanged tick is skipped | **quiet** (anchor layer) |
| L9 | DoS · resource exhaustion · performance | Request flood | The control plane has **no** rate limit, concurrency cap, or backlog metric. Degradation is quiet. This is outside the two sentences (no unauthorized action · every action recorded), but the fact that it is quiet is itself written down | **quiet** (outside the two sentences) |
| L10 | Process isolation · uid separation | Run as root | The containers run unprivileged (`User=10001:10001`, `id` → `uid=10001(pail)`). But **nowhere in the production path reads or records the executing uid** — across the whole tree, `Getuid`/`Geteuid` is called in exactly one test. A deployment brought up as root emits no line | **quiet** |
| L11 | Build supply chain (protoc integrity, CI pinning) | Replace generated artifacts with a tampered protoc | **Could not measure.** Without a reproducible-build baseline, "the artifact changed" and "the build environment changed" arrive as the same bytes. Non-observability is as declared, but this is **not confirming that it is as declared — it is failing to confirm** | **unmeasured** — reason: no reproducible-build baseline |
| L12 | Semantic accuracy of context events | Submit semantically wrong attestation values | The claimant's measurements and build info are **written to the journal as-is** and the verdict comes from the table. There is no semantic verification — as declared. But **provenance is recorded**, so what was claimed remains readable afterwards | **as declared** (no verification / the record exists) |

**Promotion candidates — L2 · L3 · L8 · L9 · L10.** The five above have
delegation wording only — when the delegation breaks, no readable line comes
out. **This list is not a verdict; it is the entirety of the rows that were
quiet** — being quiet and needing promotion are different things, but
splitting them apart here in advance would shorten the list while the
splitting criterion is written nowhere. The disposition (promote from
delegation to guarantee, keep the delegation but build an observation point,
or write down that quiet is acceptable) must be decided row by row.

---

## 5. Known open items

What this repository does not do — the items delegated to the operator
and the tests that do not run here — is listed in
[`KNOWN_ISSUES.md`](KNOWN_ISSUES.md), and that file is
**machine-generated** — it cannot be edited by hand.

> An empty list is not the absence of a boundary — it is a boundary we
> have not written down yet.

## 6. Release signing key

Every release manifest (`*.manifest.json` beside each ZIP and image archive) is
signed with the publisher's Ed25519 release key; the public key ships as
`RELEASE-SIGNING-KEY.pub` inside every archive. The copy of the fingerprint that
anchors trust is this one, published outside the archives:

    sha256(raw public key) = 8917d27e9c68e0e88538177c76279db450ad615ffe00a58f338a45474f318a17

Pass it to `verify_release.py` / `verify_evaluation.py` / `scripts/sign_release.py`
as `--expected-fingerprint`; a key that differs is refused. A new key is announced
here and in the release that introduces it, with the manifests of that release
signed by the old key as well.

## 7. Acknowledgements

Reporters who asked to be named after a fix are listed here. None yet.
