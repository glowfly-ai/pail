<!-- Canonical English edition. The Korean edition is `TRUST_BOUNDARY.ko.md`;
     if the two diverge, this English text governs. §3 and §6 of both editions
     are machine-generated from the same guarantee registry and the same
     source scan; do not edit them by hand. -->

# PAIL Trust Boundary

> 한국어판: [`TRUST_BOUNDARY.ko.md`](TRUST_BOUNDARY.ko.md). The English
> document is canonical; if the two diverge, the English text governs.

> **This is the document you read *before* deploying.**
> The document you read after finding a flaw is [`SECURITY.md`](SECURITY.md). The two are
> not merged because their readers differ — if "deploying without SROS2 lets permits be
> forged" is buried under a vulnerability-report inbox, the person who needs to read it
> never will.

Spec edition: **`PAIL-CORE-2026.1`** · test vector set: `spec/vectors/canon/MANIFEST.sha256`
(`set_sha256 bbddff16…`). A conformance claim must cite both together.

---

## 1. What this document answers

> **"I turned PAIL on. What am I now allowed to trust?"**

PAIL is an **authorization layer and an evidence layer** over the actions of a physical
robot. "Evidence layer" means two things — we make **what happened undeniable**, and
**what gets blocked is mostly decided by the deploying organization**.

That is why this document has three parts. What we uphold (§2), what we do **not**
uphold (§3), and a short list of things the shipped code **does not do** that a reader
might otherwise assume it does (§5). Everything here is about the code you received,
not about plans.

---

## 2. What PAIL upholds

Four strong claims. Each carries a **refutation condition** — a claim that cannot be
refuted is not a claim.

### 2.1 Raw-byte signature verification

An action token's signature is verified against **the raw bytes of
`SignedToken.action_token_bytes`**. The verifier **does not re-serialize** those bytes.
The serializer may change, the field order may change — the signed subject remains the
exact bytes the issuer signed.

*Refutation* — false if changing any field still passes signature verification. Also
false if a point is found on the verification path that re-serializes the message and
compares the signature against the result.

### 2.2 Issuer-first write order

The authorization record is appended to the journal **before the issuance response.**
If the journal append fails, **issuance is refused.** The state "issued but not
recorded" does not exist by design.

The context-provenance record (record 51) is written even before the authorization
record (record 50). Therefore **a refused request leaves only a 51 and no 50**, which
proves "attempted but not effected".

*Refutation* — false if a token is issued while journal writes are made to fail.
For disk-level limits see §4.2. **Issuer-first is a process-level ordering guarantee,
not a guarantee against power loss.**

### 2.3 Single use

An action token is **used exactly once**. The consumption key is derived not from the
envelope but from **the verified token bytes**:

```
consumption_key = SHA-256( "pail-tokenkey:v1:" ‖ action_token_bytes )
```

Changing fields of the envelope (the transport layer) cannot bypass the consumption
record. The path of flipping one envelope `chain_id` to flush the entire consumption
cache is also closed as of the verified build.

*Refutation* — false if an already-consumed token is accepted again.

### 2.4 Fail-closed propagation

The default of an authorization verdict is **denial**. The verdict input struct is
initialized to "not verified (`verify_ok=false`)" and "already consumed
(`token_consumed=true`)", so **a call that does not fill in its inputs falls to denial,
not permission.** Partial initialization does not read as a pass.

The gate re-verifies the active token on every `cmd_vel` frame. When verification
breaks, a stop propagates on the spot.

*Refutation* — false if an unverified input is judged as permitted.

---

## 3. What PAIL does not uphold — delegations

<!-- BEGIN GENERATED: delegations -->

These are the things PAIL **does not do**. What follows is not prose; it
is machine-generated from the `status: delegated` entries of the
guarantee registry — when an entry leaves the registry it
disappears from this section too, and CI fails when `delegated_to` is
empty. **A delegation is a registration, not prose.**

> Each entry says three things — what is delegated / **what happens when
> the delegation fails** / what to do about it. A delegation missing the
> middle part is not a delegation but silence.

### G-DEL-01 — The identity of a token-issuance requester is checked against the request content and enforced

**Delegated to**  Operator (caller authorization policy)  ·  **Layer** `issuance` / `cloud`

PAIL records the caller fingerprint (caller_kind/caller_id). The policy decision of which certificate may claim which robot, and the refusal, belong to the deploying organization. An optional enforcement hook is provided.

> **If the delegation fails** any authenticated caller can obtain action tokens for another robot. The journal shows who obtained them, but recording and blocking are different things.

*Refutation condition* — False if issuance succeeds when a token for robot A is requested with a caller certificate that has no entitlement to robot A — though that verdict is rendered by the deploying organization's authorization policy

### G-DEL-02 — The Vault and Anchor transport legs have confidentiality and authenticity

**Delegated to**  Operator (internal network layout; TLS termination; CA trust)  ·  **Layer** `issuance` / `cloud`

PAIL does not inspect the scheme of the Vault/Anchor URLs — it starts with a non-https URL even in production. Transport protection is therefore entirely the deploying organization's: https termination, certificate-verification policy, internal CA trust stores, internal network segregation. Configure on the assumption that PAIL filters nothing.

> **If the delegation fails** what leaks over a plaintext Vault path is not a private key but the authority to request signatures.

*Refutation condition* — If a man-in-the-middle succeeds even though the endpoint is https, the operator's share is falsified. PAIL's share does not exist — today PAIL does not inspect the scheme, so a successful startup with a plaintext URL is not a refutation but the current scope of this delegation

### G-DEL-03 — The permit heartbeat and the perception-evidence topics are not forged

**Delegated to**  Operator (SROS2 deployment; keystore operations)  ·  **Layer** `enforcement` / `robot`

There is no application-layer signature. The authenticity of the 20 Hz permit heartbeat and of the perception-evidence topics depends entirely on SROS2 (DDS security). PAIL refuses to start in the production profile when ROS_SECURITY_ENABLE is off or ROS_SECURITY_STRATEGY is not Enforce (S1/S2, exit 78). But refusing startup only prevents configuration mistakes; it does not prevent a keystore compromise.

> **If the delegation fails** permit forgery becomes possible, and a forged permit means unauthorized motion. This is the highest-risk delegation of the six in gate C — it sits at PAIL's final enforcement point, and if it is breached, every cryptographic layer above it is meaningless. The action token does not bind a snapshot hash of the perception evidence — from the token alone, a gate cannot prove which perception the issuer decided on.

*Refutation condition* — False if, in a deployment with SROS2 off, the gate cannot tell a forged permit published at 20 Hz from a genuine one — the current code actually cannot. There is no application-layer signature, so this refutation holds today, and that is why this entry is a delegation

### G-DEL-04 — The keyring-bundle rollback floor state file cannot be rolled back

**Delegated to**  Operator (file permissions; OS accounts; persistent volumes)  ·  **Layer** `keymgmt` / `robot`

The state file has no integrity protection. Corrupted contents refuse startup (fail-closed), but absence is indistinguishable from a normal first start — the process has no way to tell, and the only layer that can tell is filesystem permissions. Requirements: (1) place it on a persistent volume independent of container lifetime; (2) writable only by the gate process account (recommended 0600, directory 0700); (3) never roll this file backwards in backup/restore procedures.

> **If the delegation fails** deletion alone — no tampering — makes a revoked older keyring bundle acceptable again. Even without an attacker, one container restart does the same thing.

*Refutation condition* — False if, after deletion of the PAIL_KEYRING_STATE file, a revoked older bundle is loaded and accepted — the current code actually does (absence = floor 0)

### G-DEL-05 — Containers run with least privilege

**Delegated to**  Operator (container runtime policy; orchestrator)  ·  **Layer** `deployment` / `cross`

PAIL provides an image that runs as an unprivileged user (USER pail) and an opt-in COPY Dockerfile. The actual runtime user, capabilities, mount policy, and read-only root filesystem are decided by the orchestrator operator. The limitation notice for process isolation, uid separation, and container de-privileging is this entry — G-DEL-L10 was deliberately not created so that the same thing would not carry two names, and that gap in the numbering is intentional.

> **If the delegation fails** when the gate process is compromised, the compromise spreads to the host. What we provide is a default, not an enforcement.

*Refutation condition* — False if a deployed container runs as root or carries unnecessary capabilities — what is judged is not our image but the operator's runtime shape

### G-DEL-L01 — Whoever holds a signing key was the rightful party to hold it

**Delegated to**  Operator (key custody; PKI; HSM/TPM binding; issuer identity vetting)  ·  **Layer** `keymgmt` / `cross`

What PAIL checks stops at "were these bytes signed by the private key corresponding to this public key". Who holds that private key, and why, lies outside the plane PAIL can see. Adjacent to the existing entry G-DEL-01 (caller authorization) but not the same — 01 is "is this caller entitled to make this request" (authorization); this is "is this signer the rightful holder of this key" (authenticity). A stolen key passes authorization. Folding the two into one entry would erase that fact from the document. Requirements: (1) keep private keys in an HSM/TPM or, at minimum, access-controlled storage; (2) the organization vets the identity of the people and services holding issuance authority; (3) tie changes of key custody to the rotation procedure (G-DEL-L02).

> **If the delegation fails** a forged authorization with a valid signature comes into being. The evidence layer cannot distinguish it from a normal issuance, and in a post-incident audit it reads as "a legitimate issuance".

*Refutation condition* — If a signature made with a stolen or copied private key passes verification — it passes. PAIL reads possession of a key as authenticity and does not examine the legitimacy of that possession. To show this entry false one would have to claim that PAIL examines it, and it does not

### G-DEL-L02 — Key distribution, revocation, and rotation procedures are carried out correctly

**Delegated to**  Operator (key distribution pipeline; revocation-declaration rollout; rotation schedule)  ·  **Layer** `keymgmt` / `cross`

PAIL can read a revocation-declaration file (key namespace + public half) and return a three-valued verdict (valid/revoked/no) (U-B1). But when and by whom that declaration is produced, and how it is pushed to which deployment, is the operator's procedure. The existing entry G-DEL-04 (keyring rollback floor state file) is a subset of this one — 04 covers only that one product of the rotation procedure (the rollback floor) is never rolled back; the procedure itself is carried here. We register the broad entry without deleting the narrow one: 04 has a concrete refutation condition and a reproduction log, and absorbing those into this entry's prose would erase their checkability.

> **If the delegation fails** a compromised key stays valid with no revocation declared, or a rotation lands halfway and some nodes remain ignorant of the new key. The latter looks like an availability incident but is in fact a split of the trust root.

*Refutation condition* — False if signatures made with a revoked key keep being accepted — but that verdict is only possible once the revocation declaration has reached the deployment. In a deployment it never reached, this is indistinguishable from no revocation having happened at all

### G-DEL-L03 — The trust roots are separated from one another

**Delegated to**  Operator (PKI design; root-separation policy)  ·  **Layer** `keymgmt` / `cross`

PAIL treats the issuer key, the operator key, the LOG key, and the VERDICT key as distinct keys in distinct namespaces, and records their fingerprints in the seal. But whether those four actually came from different roots, or one offline root signed all four, is something PAIL cannot see — what reaches us is a public key, not its lineage.

> **If the delegation fails** the separation exists in name only. One compromised root makes all four planes forgeable at once, and each plane's independent verification can no longer vouch for the others — because the same hand could have made all four.

*Refutation condition* — False if the issuance key, the verdict key, and the transport certificates derive from the same root and a single compromise of that root collapses all three planes at once — what is judged is not our code but the key hierarchy the operator actually built

### G-DEL-L04 — The object designated as the authorization target is actually that object

**Delegated to**  Adopter (choice, installation, and calibration of the target-identification modality)  ·  **Layer** `perception` / `robot`

Optical-RFID coupling is an optional axis of PAIL and is off in the default deployment — an axis not switched on is an option, not a defense. Even in a deployment that switches it on, what is guaranteed stops at "responses come only from inside the visible-light beam"; the binding of tag to object (that the tag is on that object) is carried by the installation procedure.

> **If the delegation fails** the authorization is recorded as granted to the right target but physically applies to a different one. The evidence cannot see this mismatch — the same identifier flows normally at both layers.

*Refutation condition* — False if authorization succeeds against an identifier attached to a different object — it does. The PAIL core takes the target identifier as a string and has no code that checks what that string points at in the physical world

### G-DEL-L05 — No control path exists that bypasses the gate

**Delegated to**  Adopter (robot integration shape; actuation access-path control)  ·  **Layer** `enforcement` / `robot`

The PAIL gate operates fail-closed on the topic path it is placed on. Whether other paths exist beside that path is a question of the robot integration shape, and the gate has no means to observe the existence of paths it cannot see. Adjacent to the existing entry G-DEL-03 (permit/perception-evidence forgery) but not the same — 03 is "the gate's inputs are forged"; this is "the gate is never traversed at all". 03's mitigation (SROS2 Enforce) does nothing here: the bypass path may lie outside the ROS plane.

> **If the delegation fails** every cryptographic guarantee of PAIL is bypassed. In that case nothing is written to the evidence — and in an incident investigation the absence of a record is easily read not as "motion PAIL was not involved in" but as "nothing happened".

*Refutation condition* — False if any command path reaches the robot's actuation without passing the gate — a local console, a manufacturer diagnostic port, a manual operation panel, and direct publication by another ROS node are all such paths. They vary with the deployment shape, and PAIL does not hold that list

### G-DEL-L06 — What the journal holds is everything that actually happened

**Delegated to**  Operator (independent observation; external-anchor cross-checks; audit procedure)  ·  **Layer** `evidence` / `cross`

What PAIL guarantees is integrity (what was written does not change) and order (chain and anchors), not completeness (nothing went unwritten). A chain is continuous if it is continuous within itself, so an event that never entered the chain is revealed by no verification. Requirements: observe the record flow independently at the external-anchor receiving side, and cross-check the intervals where the journal fell silent between anchors against a separate signal.

> **If the delegation fails** the evidence acquires a hole made not by deletion but by never-recording, and that hole passes integrity verification — because what does not exist is silent.

*Refutation condition* — False if an authorization or verdict exists that was never journaled — PAIL writes everything it processed without omission, but it cannot write what never passed through it. Completeness is the kind of claim PAIL cannot prove from within itself

### G-DEL-L07 — The transport channels carrying records and commands are encrypted

**Delegated to**  Operator (TLS termination; network policy; certificate trust stores)  ·  **Layer** `interface` / `cross`

This entry is the broad one that contains the existing entry G-DEL-02 (Vault/Anchor transport). Writing only the broad entry and deleting the narrow one would erase from the document the disposition that is specific to the Vault and Anchor legs. The boundary is visible only when the two entries are read together. The subset we enforce is **one leg, the control-plane gRPC**: in the production profile, plaintext TCP is refused (`S4`; a unix socket protected by file permissions is accepted as the exception). Even on that leg we do not enforce verification policy, CA trust stores, or certificate lifetimes. The Vault and Anchor legs we do not enforce — a fact written down in 02.

> **If the delegation fails** records are read or tampered with in transit. Tampering is caught by signature verification; reading is not — signatures give no confidentiality.

*Refutation condition* — False if plaintext PAIL traffic exists — it can. What PAIL enforces is one leg only: the control-plane gRPC in the production profile (`S4`: plaintext TCP is refused). Every other leg, the Vault and Anchor legs included, is decided by deployment configuration

### G-DEL-L08 — Availability · redundancy · uninterrupted operation

**Delegated to**  Operator (redundancy shape; capacity planning; recovery procedure)  ·  **Layer** `deployment` / `cross`

PAIL promises no availability target. The peculiarity of this delegation is that **its failure mode looks like normal operation** — if the issuer dies, no tokens are issued, and the gate blocks when there is no token. That halt is not the symptom of a defect but the execution of fail-closed.

> **If the delegation fails** work stops. What is dangerous here is not the stoppage itself but the improvised measure of bypassing the gate to avoid it — that measure realizes G-DEL-L05 by one's own hand.

*Refutation condition* — This entry cannot be falsified inside PAIL — when PAIL stops, the robot stopping is the designed behavior (fail-closed). To read a halt as a defect we would have to claim availability, and we do not

### G-DEL-L09 — Defense against denial of service, resource exhaustion, and performance degradation

**Delegated to**  Operator (rate limiting; reverse proxy; resource quotas; network isolation)  ·  **Layer** `deployment` / `cross`

PAIL is a layer of authorization and evidence, not of traffic management. Placing rate limiting and connection control in front of it is the deployment shape's share.

> **If the delegation fails** availability collapses (the same consequence as G-DEL-L08) and journal writes back up, stretching the checkpoint interval. The latter, in a single-node deployment, widens the loss window on power failure — the path by which DoS spreads into the durability of the evidence.

*Refutation condition* — If a request flood renders the issuer unresponsive — it does. Rate limiting, connection caps, and resource isolation are not in the PAIL core. This entry is not a refutation target but a notice of absence

### G-DEL-L11 — Integrity of the build supply chain — what we built is what we wrote

**Delegated to**  Adopter (CI isolation; dependency pinning; artifact signing; SBOM)  ·  **Layer** `deployment` / `cross`

PAIL catches drift of the canon representation with golden vectors and a manifest, but if the checker itself came out of a tampered build, the check moves together with the tampering. A tool that checks itself cannot see its own tampering.

> **If the delegation fails** every check stays green while the artifact does something else. This delegation's failure is quieter than any other's — the whole evidence plane sits under the same hand.

*Refutation condition* — False if an artifact produced by a tampered toolchain or dependency passes the checks — it passes. When the checker and the checked come from the same toolchain, their agreement is no evidence. PAIL does not claim reproducible builds

### G-DEL-L12 — The recorded values are semantically accurate

**Delegated to**  Adopter (accuracy of event producers; sensor calibration; upstream-system validation)  ·  **Layer** `evidence` / `cross`

What the evidence layer gives is "this value came from this signer at this time and has not changed since", not "this value is true". The two sentences are routinely confused in incident investigations, and the confusion always leans toward believing the latter.

> **If the delegation fails** a false fact remains in the record under cryptographic warranty. The signature only makes that falsehood harder to erase; it does not make it true — integrity is no substitute for accuracy.

*Refutation condition* — False if, when a sensor or an upstream system sends a value contrary to fact, PAIL signs and records it as-is — it does. PAIL writes what it received with integrity; it does not judge whether the value matches the world

### G-DEL-L13 — Retention, archival and disk monitoring of the blackbox journal segments

**Delegated to**  Adopter (operating organization: retention period, capacity rule, archive location, free-space monitoring)  ·  **Layer** `evidence` / `cloud`

Segments are hash-chained with signed checkpoints; moving whole older segments to an archive leaves the verifier reporting a missing older segment as a NOTE while verifying the rest. Measured growth: about 1.5 MB per TurtleBot3 judge run, about 45 MB per hour of continuous judging.

> **If the delegation fails** a full disk stops issuance — the ledger's integrity does not break.

*Refutation condition* — False if the operator does not watch and archive: when the disk is full the Issuer issues no token whose record cannot be appended (fail-closed) — issuance stops. The Issuer only starts a new segment every 64 MiB or 24 h; it deletes none

### G-DEL-L14 — Handling of the base OS packages' security advisories

**Delegated to**  Adopter (base-image rebase and rebuild cadence, own vulnerability policy)  ·  **Layer** `runtime` / `cross`

The bundled scan_vulnerabilities.py lets a recipient rescan against a newer database. The publisher refreshes the base digest per release to remove fixable advisories (for example perl-base 5.36.0-7+deb12u4).

> **If the delegation fails** advisories of libraries the PAIL processes do not use remain in the image scan counts — PAIL's behaviour and evidence are unaffected.

*Refutation condition* — Advisories the distribution leaves wont-fix stay in the image — on Debian 12 glibc CVE-2026-5450 (scanf `%mc` one-byte heap overflow) and sqlite CVE-2025-7458 (integer overflow for an attacker who can run arbitrary SQL). PAIL's executables are statically linked Go and sqlite is the pure-Go modernc.org/sqlite; neither library is linked

### G-DEL-L15 — Comparing the signing-key fingerprint outside the archive

**Delegated to**  Adopter (the receiving party: compare with the external fingerprint and pass --expected-fingerprint)  ·  **Layer** `deploy` / `shared`

With --expected-fingerprint the verifiers refuse a different key before any signature arithmetic; the receipt and doctor record expected_fingerprint_given so a pass without the comparison stays visible. The bundled verifier's circularity (a binary inside the archive verifying its own archive) is broken by the external fingerprint, the negative vector doctor runs, and a verifier built from the Core source.

> **If the delegation fails** an archive and key replaced together read as VERIFIED — the recipient's one line, not a default, is the boundary.

*Refutation condition* — Without comparing the fingerprint with the copy published outside the archive (the release signing key section of SECURITY.md, or the publisher's separate channel), a supply-chain attacker who replaces the archive and the key together verifies as VERIFIED — the key, fingerprint and verifier inside the archive only show that the archive agrees with itself

### G-DEL-L16 — TurtleBot3 DDS authentication after gate restart remains an unresolved defect. Independent evaluation reported one DDS failure in 29 valid restarts; a separate 117-restart investigation reported one DDS failure and one unrelated movement shortfall. Late Final and asymmetric authentication were observed; library internals and a repair remain unverified. On RIG_FAILED, keep stopped, cancel/stop the active plan, preserve logs and retry manually. No automatic recovery or authority release is provided.

**Delegated to**  Adopter (operating team: keep stopped and retry manually; the maintainer retains DDS root-cause investigation)  ·  **Layer** `deploy` / `robot`

The maintainer retains root-cause investigation. The 29- and 117-restart cohorts and induced-delay experiments remain separate, not a guaranteed failure rate. Five successful manual recovery attempts do not validate automatic recovery. The operating team keeps stopped, cancels the plan, preserves logs and retries manually. Failure archives under restart-logs/failed require operator disk-space management.

*Refutation condition* — If required DDS authentication/matching or fresh input is unavailable, startup ends with RIG_FAILED: gate IO readiness timeout; command forwarding is not ready.

20 entries registered. Delegated entries carry no `owner` — the schema does not allow the self-contradiction of "delegated, and yet we are also the owner".

<!-- END GENERATED: delegations -->

---

## 4. Differences by deployment shape

Even with the same code, **which sentences are true depends on the shape.** The four
below are where that difference matters for security.

### 4.1 With or without SROS2

In a deployment where SROS2 is not enabled, the permit heartbeat and the perception
evidence topics carry **no signature at all** (§3 G-DEL-03). Under
`PAIL_PROFILE=production` the gate refuses to start (S1/S2), but the `dev` profile does
not refuse. **Do not move a real vehicle on the dev profile.**

### 4.2 Single node — durability

In issuer-first (§2.2), "append" means the following on the single-node issuer of this
distribution.

| Deployment | The level at which issuer-first is true | On power loss |
|---|---|---|
| **Single node** | Handed to the OS + **fsync at checkpoint time** (default: 1000 records or 60 s) | **The window since the last checkpoint can be lost** |

On a single node, if power is lost abruptly, issuer-first does not hold at the disk
level for that lost window. A deployment that cannot accept this limit lowers
the checkpoint interval. The full wording is in the durability-model
section of [`SECURITY.md`](SECURITY.md).

> **Honesty notice** — the evidence we can present today is **syscall-level** (fsync is
> called exactly once per checkpoint). "The loss bound on power failure" requires a
> machine-level crash test and **has not been measured yet.** Killing the process
> (SIGKILL) does not prove it — the page cache does not die with the process, so that
> test **cannot distinguish** the presence of fsync from its absence.

### 4.3 Vault / local key file

The issuer private key can live in Vault Transit or in a local key file. In a Vault
deployment, what is at risk of leaking is not the private key but **the authority to
demand signatures** (the Transit token) — which is why the transport leg is the subject
of §3 G-DEL-02.

### 4.4 Split binaries / combined binary

**The combined binary is not recommended.** The combined shape requires the raw private
key inside the process for in-process burst emission, and even in a deployment with a
Vault signer configured it **creates a local private key file if none exists**. Use the
split shape.

### 4.5 Action token lifetime — this value is canonical

**The deployed lifetime of an action token is 1 hour** (`horizon.token_ttl_ms` in
`policy.yaml`, deployed value `3600000`).
This value is **identical to the action lease expiry**. The token's `not_after` is the
lease expiry — **a deliberate design that avoids creating a second expiry clock to
fight with the gate.**

This value has **exactly one source: the policy file**. The old
environment variables `PAIL_LEASE_TTL_MS` and `PAIL_LEASE_MAX_STEPS` are **not merely
unread — if set, startup is refused** (`S16j`, exit 78). The reason they are not
silently ignored is not the direction of the misconfiguration but that **the
misconfiguration would be invisible** — if an operator who believes the env tightened
the window gets tokens that live as long as the policy file says, the believed value
and the running value differ and no line turns red. The policy file is covered by the
configuration seal (`policy_file_sha256`); env is not.

When the value is missing or unparseable, **startup refuses first**: no file → `S16`,
no `horizon:` section → `S16e`, `token_ttl_ms <= 0` → `S16i`. The issuance path's
`LeaseTTLFloor` (30 s) is the last floor remaining after that — **a misconfiguration
of authorization lifetime always fails in the shortening direction only.**

Within this lifetime the token does not grant unlimited authority. The token is
**single-use** (§2.3), bound to `world_hash`, and the gate re-verifies the active token
on every `cmd_vel` frame. But **the fact that a stolen token's exposure window is
1 hour stands.**

If a deployment requires a shorter window, lower `horizon.token_ttl_ms` — **in the
policy file**, and that change appears in the configuration seal. The cost is that the
autonomous-progress time during a cloud outage shrinks with it — **these two are two
faces of the same knob and cannot be adjusted separately.**

> **Why we do not use the phrase "short-lived tokens."** <!-- x19-disavowal --> That phrase usually
> evokes the 30-second class, and the default here is 1 hour. PAIL's honest
> differentiator is not that the token is **short** but that it is **used once and
> bound to world state**.

---

## 5. What the shipped code does not do

Three things a reader of a token-based system tends to assume. **None of them is in
the code of this repository.**

### 5.1 The action token does not bind perception evidence

The token carries no snapshot hash of the perception evidence the issuer saw. From the
token alone, a gate cannot prove which perception the issuer decided on.

### 5.2 The permit heartbeat carries no application-layer signature

See §3 G-DEL-03. The 20 Hz heartbeat is authenticated by SROS2 only.

### 5.3 The Vault and Anchor URL scheme is not inspected

PAIL does not refuse a non-https Vault or Anchor URL, in any profile. See §3 G-DEL-02.

---

## 6. Startup refusal gates

<!-- BEGIN GENERATED: startup-gates -->

When a gate trips, the process terminates with `exit 78` (`sysexits.h`
`EX_CONFIG`) — **meaning the configuration is wrong, not the code** — and
retrying changes nothing. The table below is generated by scanning the
source. **A gate that is not in this table is not in the code you
received.**

| ID | What it blocks | Status |
|---|---|---|
| `S0` | `PAIL_PROFILE` is not `production\|dev` | implemented |
| `S1` | production, but `ROS_SECURITY_ENABLE` is off | implemented |
| `S2` | production, but `ROS_SECURITY_STRATEGY` is not `Enforce` | implemented |
| `S3` | `ROS_SECURITY_KEYSTORE` is missing or points at another component's enclave | implemented |
| `S4` | production, but gRPC is plaintext (`PAIL_GRPC_TLS=off`) | implemented |
| `S5` | production, but the keyring is unsigned (`PAIL_KEYRING_MODE=unsigned-dev`) | implemented |
| `S6` | no profile was specified, so production was assumed | warning only (startup continues) |
| `S7` | build shape and runtime configuration disagree (static / grpc mode mismatch) | implemented |
| `S8` | a known dev key or an unsigned trust anchor is in use | implemented |
| `S9` | the evidence path / external reference-point configuration does not hold | implemented |
| `S10` | a threshold is out of range or thresholds contradict one another | implemented |
| `S15` | a keyring entry has no `role` specified | implemented |
| `S15b` | the same `key_id` appears in both the active and the revoked list | implemented |
| `S16` | the authorization policy file is missing or empty | implemented |
| `S16b` | the policy YAML has an unknown field or a type mismatch (strict parse) | implemented |
| `S16c` | the policy declares no callers at all | implemented |
| `S16d` | a caller entry's value is outside the vocabulary (`caller_kind` / `caller_id` form) or duplicates another | implemented |
| `S16e` | a required section is missing — absence is not filled in with a zero value | implemented |
| `S16f` | a value outside the closed set, or a quantity that is neither an integer nor `unbounded` | implemented |
| `S16g` | a name inside the file does not resolve, or the same name is declared twice | implemented |
| `S16h` | the set the policy declares and the set the code knows disagree | implemented |
| `S16i` | a quantity violates its lower bound even after the vocabulary and name checks pass | implemented |
| `S16j` | the process environment tries to override the horizon — the policy file is its only source | implemented |
| `S17` | the issuer key id is not configured (`PAIL_ISSUER_KEY_ID`) | implemented |
| `S19` | private key material this process opens is readable by an account other than its owner (not `0600`) | implemented |
| `S19b` | a private key's mode could not be read — unexamined is not clean | implemented |
| `S19c` | a component does not declare the private key material it holds — silence is not a declaration | implemented |
| `S19d` | the private-key mode predicate (_keymode.sh) is missing or unreadable — startup refuses rather than skipping the check | implemented |
| `S20` | the trust-anchor bundle's validity window exceeds the configured ceiling — revocation would take that long to land | implemented |
| `S20b` | the bundle lifetime ceiling is unset or is not a positive integer number of seconds (`PAIL_KEYRING_MAX_LIFETIME_SEC`) — an unbounded window is a decision, and an unmade decision is not it | implemented |
| `S20c` | the keyring poll interval is unset or is not a non-negative integer (`PAIL_KEYRING_POLL_SEC`) — revocation reach is bundle lifetime plus this, and one term of that sum is unchosen | implemented |
| `S20d` | the trust-anchor bundle has expired (`now >= expires_at`) — it refuses to keep verifying on it | implemented |
| `S20e` | pulling is on but there is no way to apply a new bundle (`PAIL_GATE_RESTART_CMD`) — placing a bundle nobody loads is not a revocation path | implemented |
| `S20f` | no expiry source was declared, or no freshness gate was installed — unexamined is not unexpiring | implemented |
| `S21` | the configuration seal could not measure an axis — the seal banner does not record the unobserved as fact | does not refuse — recorded as an axis in the seal |
| `S24` | production, but the policy has no `retention:` section — the retention period must be declared and sealed (dev gets a banner) | implemented |
| `S25` | the `retention:` declaration contradicts itself — a leaf is missing, the floor is below 5 years, blackbox is below the floor, or anchor is below blackbox | implemented |
| `S26` | production, but the gate's `attest_build_info` is empty or not the seven-token `pail-build:v1:…` form — the chain would record a gate nobody can identify (dev gets a banner) | implemented |
| `S33` | gate: a skill registry (`skills.<robot_class>.yaml`) envelope name this adapter does not measure (`adapter_measures`) — a token carrying it would block every command as unmeasured; `robot_class` unset = not checked, WARN (SKL SK-2). Microduck: the skill table names a skill the robot does not answer to — refused only when the answer lists its built-ins, else unverifiable | implemented |
| `S34` | policy `guardrails.zones.<zone>.<name>` exceeds the `guardrails.common` ceiling — zone values only tighten (SKL SK-1) | implemented |
| `S34b` | policy `guardrails.common` `sls.linear_mps`/`sls.angular_rps` disagree with their `motion.*` alias — one value, two names (SKL SK-1) | implemented |
| `S36` | the physical safety controller is undeclared — this edition warns and records S36 in the seal; it does not refuse startup or provide a safety controller | warning only (startup continues) |
| `S40` | production, but no change-authorization bundle for the policy file (`PAIL_POLICY_AUTH`) — the issuer's standing inputs are loaded only under a change approval from distinct trusted principals; dev is the declaration to run without it and shows in the INSECURE banner (AS-4 / O-4) | implemented |
| `S40b` | production, but a site model (`PAIL_SITE_MODEL`) is configured without its change-authorization bundle (`PAIL_SITE_MODEL_AUTH`) — the same discipline as the policy; the bundle is judged on the exact bytes `LoadSiteModel` read (AS-4b) | implemented |
| `S41` | production, but the development switch that skips the journal replay is set (`PAIL_REPLAY=off`) — an issuer started without the replay restores no lockdown, consumed token or issuance history and verifies no checkpoint signature | implemented |

Declared in 259 Core source files; declaration is not proof that a rule trips in every deployment. This table covers Core source only. The separate Issuer evaluation executable does not include its source. Its integration tests are distinct from Core source tests.

<!-- END GENERATED: startup-gates -->

---

## 7. Known open items

The list of what this repository **knows about and has not yet closed** is in
[`KNOWN_ISSUES.md`](KNOWN_ISSUES.md), generated from the guarantee registry. It is
regenerated per release, so an item disappears from the list when closed and appears
when newly opened.

**A release with an empty list is not a release without flaws — it is a release we
have not counted yet.** We do not ship in that state.

---

## Appendix — how this document is maintained

§3 and §6 are **not written by hand.**

| Section | Source | Check |
|---|---|---|
| §3 delegations | the `status: delegated` entries of the guarantee registry | byte comparison against a regeneration; a registration gate requires `delegated_to` to be non-empty |
| §6 gates | source scan | byte comparison against a regeneration |

If a document can be edited by hand, it is not a document but a claim.
