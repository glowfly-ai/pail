# PAIL Threat Model

> **This document is generated.** It is rendered from the project's
> threat registry and guarantee registry, and CI compares the committed
> bytes against a fresh rendering. Editing it by hand does not change
> what PAIL does; it only makes the next build fail. A threat model that
> can be edited by hand is not a model but a claim.

## 1. How to read this

Each row below says one thing: **who** stands **where**, reaching for **what**, and what PAIL does — or does not do — about it. Each mitigation paragraph summarizes guarantees carried by tests in this repository, and the build checks every one of them against the guarantee registry. A guarantee that is downgraded or deleted fails the build rather than staying here as a defence.

Three things about the columns:

- **Upheld by PAIL** summarizes guarantees the project owns and tests. A threat with nothing under it is not an oversight — it is a threat nothing in PAIL stands against.
- **Startup gates** lists refusal gates that exist in the source today. A gate that is only designed is never listed here; the startup-gate table in `TRUST_BOUNDARY.md` is where design-only gates are written down as design-only.
- **Delegated** names the boundary where the work becomes the deploying organization's. Section 7 shows, for every delegation, which attacker it assumes — a delegation without an attacker is an excuse rather than a boundary.

**Residual** is the part that survives the mitigations. It is the most useful paragraph on the page and the one most likely to be unwelcome.

## 2. Attackers

10 attackers are declared. Anything not on this list is outside the model — which means it is unexamined, not absent.

| ID | Attacker | Where it stands | What it is granted |
|---|---|---|---|
| `A1` | On-path observer / tamperer | On the network legs between PAIL components — able to see at least one of the control-plane gRPC, the Vault leg, or the Anchor leg. | Can read, alter, delay, and replay bytes. Holds no private key. |
| `A2` | Authenticated caller exceeding its entitlement | A client legitimately connected to the control plane, genuinely holding a certificate or unix-socket credential. | Can compose arbitrary requests under the credential issued to it. Does not hold another party's key. |
| `A3` | Participant on the ROS 2 / DDS plane | Inside the same DDS domain, able to subscribe to and publish on topics. | Can publish arbitrary messages on arbitrary topics — where SROS2 Enforce is off, or where it holds the relevant enclave. |
| `A4` | Unprivileged account on the same host | Logged in on the same host as the PAIL processes, but is neither root nor the PAIL runtime UID. | Reads whatever the file permissions allow. Decides the environment of its own processes. |
| `A5` | Privileged host account / container escape | Host root, or a process that has crossed the container boundary. | Reads and writes any file, starts any process, and can reach the drive train directly. Reading signing keys is included. |
| `A6` | Holder of signing key material | Actually holds the private half of one or more of the issuer, operator, LOG, or VERDICT keys — whether by leak or by legitimate custody. | Can sign anything that key can sign. What it produces is not a forgery but a **valid signature**. |
| `A7` | Physical access to the robot or the site | Within reach of the robot, the tags, the sensors, and the wiring. | Can move or clone tags, occlude sensors, and rewire. |
| `A8` | Build and distribution supply chain | Anywhere on the path from source to deployed artifact — CI, dependencies, image registries, bundle distribution. | Can change the bytes that get deployed, making what runs differ from what was reviewed. |
| `A9` | Trusted upstream sending false values | A system PAIL takes as input — the perception pipeline, the safety layer, the higher-level planning system. These are already trusted. | Sends values that are formally valid but factually wrong. This may be not an intrusion but an **error or a miscalibration**. |
| `A10` | Internal operator under production pressure | A person legitimately empowered to change the deployment, with a line stopped and pressure to restart it. | Can change the profile, drop the gate to observe mode, and start components without others. Malice is not assumed — this attacker's motive is **uptime**. |

## 3. Assets

6 assets are declared.

| ID | Asset | Why it matters |
|---|---|---|
| `AS1` | The robot's authority to move | Every other asset exists to protect this one. When it falls, the damage is not data but people. |
| `AS2` | Integrity of the action token | A token is the statement "this robot may perform this action." Forged, the gate operates correctly and lets the wrong thing through. |
| `AS3` | The single-use consumption record | A permission reused is not a permission but a key. This record is what keeps the boundary in time. |
| `AS4` | The blackbox journal and the external reference point | The only ground on which what happened can later be stated. When it falls, an incident becomes an argument. |
| `AS5` | Signing key material | The issuer, operator, LOG, and VERDICT keys. Whoever holds these need not forge; they sign legitimately. |
| `AS6` | The sealed state of configuration and policy | What the gate treats as its thresholds and which mode it runs in live here. Changed quietly, enforcement appears to continue while enforcing something else. |

## 4. Attack surfaces

7 surfaces are declared.

| ID | Surface | Where |
|---|---|---|
| `X1` | Control-plane gRPC | The gRPC endpoint carrying issuance, reporting, and unlock (`:50051` by default), or a unix socket protected by file permissions. |
| `X2` | The ROS 2 / DDS topic plane | `/cmd_vel`, `/safe_cmd_vel`, `/pail/safety_state`, the perception evidence topics, and the permit heartbeat. |
| `X3` | The Vault leg and the Anchor leg | The leg on which signing requests leave, and the leg on which checkpoints go up to the external reference point. |
| `X4` | The file system | The journal segment directory, the private key files, the keyring bundle and its rollback floor state, and the SROS2 keystore. |
| `X5` | Process environment and the policy file | The `PAIL_*` environment variables and `/etc/pail/policy.yaml`. |
| `X6` | Build and deployment artifacts | Container images, release tarballs, the signed keyring bundle, and the systemd units. |
| `X7` | The physical layer | The robot itself, the optical RFID tags, the sensors' field of view, and the drive-train wiring. |

## 5. Threat matrix

16 threats. The detail — mitigations and residual — follows in the next section.

| ID | Attacker | Asset | Surface | Threat |
|---|---|---|---|---|
| `T-01` | `A2` | `AS1` | `X1` | Requests an action token for a robot its own credential gives it no entitlement to. |
| `T-02` | `A1` | `AS2` | `X1` | Eavesdrops on the control-plane gRPC, or alters the requests and responses on it. |
| `T-03` | `A1` | `AS4` | `X3` | Downgrades the Vault or Anchor leg to plaintext, or alters the bytes on it. |
| `T-04` | `A3` | `AS1` | `X2` | Publishes commands directly on the drive topic without passing through the gate. |
| `T-05` | `A3` | `AS1` | `X2` | Publishes forged safety state or perception evidence to obtain a permit. |
| `T-06` | `A4` | `AS5` | `X4` | Reads a private key file left world- or group-readable, thereby acquiring the ability to sign. |
| `T-07` | `A5` | `AS1` | `X4` | Bypasses the gate process and drives the actuators directly. |
| `T-08` | `A6` | `AS2` | `X4` | Uses the signing key it holds to legitimately sign and issue arbitrary action tokens. |
| `T-09` | `A7` | `AS1` | `X7` | Moves or clones tags and occludes the sensors' field of view to deceive target identification. |
| `T-10` | `A8` | `AS6` | `X6` | Pushes an artifact into the deployment whose bytes differ from what was reviewed. |
| `T-11` | `A9` | `AS3` | `X2` | Sends formally valid but factually wrong evidence, flipping the verdict. |
| `T-12` | `A10` | `AS1` | `X5` | To restart the line, lowers the profile, drops the gate to observe mode, or starts components without the gate. |
| `T-13` | `A2` | `AS3` | `X1` | Resubmits an already-consumed token, or re-requests a step of a revoked chain. |
| `T-14` | `A5` | `AS4` | `X4` | Rewrites or deletes journal segments out of band to change the evidence. |
| `T-15` | `A1` | `AS1` | `X1` | Cuts or exhausts the issuance path so that work stops. |
| `T-16` | `A4` | `AS6` | `X5` | Quietly swaps the gate's thresholds or horizon through the process environment or the policy file. |

## 6. Threats in detail

### T-01 — Requests an action token for a robot its own credential gives it no entitlement to.

**A2** Authenticated caller exceeding its entitlement  ×  **AS1** The robot's authority to move  ×  **X1** Control-plane gRPC

**Upheld by PAIL** — nothing. This threat is met by delegation alone.

**Startup gates** — none.

**Delegated**

- `G-DEL-01` — Operator (caller authorization policy)

*Residual* — Wholly delegated. PAIL records the caller fingerprint but does not judge which certificate may claim which robot — appearing in the journal and being blocked are different things.

### T-02 — Eavesdrops on the control-plane gRPC, or alters the requests and responses on it.

**A1** On-path observer / tamperer  ×  **AS2** Integrity of the action token  ×  **X1** Control-plane gRPC

**Upheld by PAIL**

Requests are accepted only at an endpoint that demands mTLS — a connection presenting no client certificate is refused. Tokens crossing it are verified against the signed bytes as received, with no re-serialization on the verifier's side. A signature binds to bytes, not to meaning, so bytes altered in transit do not pass merely because they can be reassembled.

*The paragraph above summarizes 2 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates**

- `S4` — production, but gRPC is plaintext (`PAIL_GRPC_TLS=off`)

**Delegated**

- `G-DEL-L07` — Operator (TLS termination; network policy; certificate trust stores)
- `G-DEL-L09` — Operator (rate limiting; reverse proxy; resource quotas; network isolation)

*Residual* — Tampering is caught by signature verification; reading is not — signatures give no confidentiality. Certificate-verification policy, CA trust stores, and certificate lifetimes are enforced on no leg.

### T-03 — Downgrades the Vault or Anchor leg to plaintext, or alters the bytes on it.

**A1** On-path observer / tamperer  ×  **AS4** The blackbox journal and the external reference point  ×  **X3** The Vault leg and the Anchor leg

**Upheld by PAIL**

The anchor ingest endpoint seals only a valid anchor, refusing forged signatures, unregistered keys, post-revocation receipt, scope mismatch, and malformed input each with its own reason. Revocation is decided by the time the server received the record, not by the time the record claims for itself. The transparency log is independently auditable by a third party: a verifier sharing none of our code checks inclusion and consistency proofs from the root parsed out of a signed checkpoint, using published mathematics alone.

*The paragraph above summarizes 2 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates** — none.

**Delegated**

- `G-DEL-02` — Operator (internal network layout; TLS termination; CA trust)

*Residual* — `S12` (refusing non-https in production) exists in the design only, so startup succeeds with a plaintext URL. Configure on the assumption that PAIL filters nothing on this leg.

### T-04 — Publishes commands directly on the drive topic without passing through the gate.

**A3** Participant on the ROS 2 / DDS plane  ×  **AS1** The robot's authority to move  ×  **X2** The ROS 2 / DDS topic plane

**Upheld by PAIL**

The gate is subtractive — what it publishes is a bit-identical copy of what it received, and in a window where it received nothing it publishes nothing. Production components do not publish the external input topics they themselves consume, and when the upstream permit heartbeat falls silent, motion is not sustained.

*The paragraph above summarizes 3 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates**

- `S1` — production, but `ROS_SECURITY_ENABLE` is off
- `S2` — production, but `ROS_SECURITY_STRATEGY` is not `Enforce`
- `S3` — `ROS_SECURITY_KEYSTORE` is missing or points at another component's enclave

**Delegated**

- `G-DEL-03` — Operator (SROS2 deployment; keystore operations)
- `G-DEL-L06` — Operator (independent observation; external-anchor cross-checks; audit procedure)

*Residual* — Publisher authentication is carried by SROS2 Enforce. Where it is off, that fact is recorded in the seal and nothing more, and a command that bypassed the gate never entered the journal at all.

### T-05 — Publishes forged safety state or perception evidence to obtain a permit.

**A3** Participant on the ROS 2 / DDS plane  ×  **AS1** The robot's authority to move  ×  **X2** The ROS 2 / DDS topic plane

**Upheld by PAIL**

The gate measures the evidence's target, freshness, and trust class. It blocks when the target differs from the token's or the confidence falls below the threshold, does not pass evidence past its freshness window, and issues no new permit while the safety feed is warning, stale, or has never arrived. The policy's trust-class floor is a closed interval, and a source outside the vocabulary clears no floor at all. Evidence is three-valued, so "never received" and "stale" do not collapse into one.

*The paragraph above summarizes 5 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates**

- `S1` — production, but `ROS_SECURITY_ENABLE` is off
- `S2` — production, but `ROS_SECURITY_STRATEGY` is not `Enforce`

**Delegated**

- `G-DEL-03` — Operator (SROS2 deployment; keystore operations)
- `G-DEL-L12` — Adopter (accuracy of event producers; sensor calibration; upstream-system validation)

*Residual* — The gate measures the evidence's target, freshness, and trust class, but not who published it. That judgement belongs to SROS2, and the accuracy of the values belongs to the integrator.

### T-06 — Reads a private key file left world- or group-readable, thereby acquiring the ability to sign.

**A4** Unprivileged account on the same host  ×  **AS5** Signing key material  ×  **X4** The file system

**Upheld by PAIL**

The split deployment shape is pinned at the unit-file level so that the robot side holds no write access to the issuer key path — the robot neither writes nor creates keys — and both units run unprivileged and hardened. Accessibility is decided by actually opening the files under the fixed roots as the unprivileged runtime UID the image declares, not by reading modes statically.

*The paragraph above summarizes 2 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates**

- `S19` — private key material this process opens is readable by an account other than its owner (not `0600`)
- `S19b` — a private key's mode could not be read — unexamined is not clean
- `S19c` — a component does not declare the private key material it holds — silence is not a declaration

**Delegated**

- `G-DEL-04` — Operator (file permissions; OS accounts; persistent volumes)
- `G-DEL-L01` — Operator (key custody; PKI; HSM/TPM binding; issuer identity vetting)

*Residual* — In the local-keyfile shape, file permissions are the only thing protecting a private key. There is no HSM/TPM binding, and the gate measures the mode only at startup.

### T-07 — Bypasses the gate process and drives the actuators directly.

**A5** Privileged host account / container escape  ×  **AS1** The robot's authority to move  ×  **X4** The file system

**Upheld by PAIL**

The emergency-stop cold path issues a stop immediately, independent of authorization state, and motion is not sustained when the upstream permit heartbeat falls silent. Neither waits on the gate's verdict.

*The paragraph above summarizes 2 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates** — none.

**Delegated**

- `G-DEL-05` — Operator (container runtime policy; orchestrator)
- `G-DEL-L05` — Adopter (robot integration shape; actuation access-path control)
- `G-DEL-L06` — Operator (independent observation; external-anchor cross-checks; audit procedure)

*Residual* — To an adversary holding host privilege a software gate is not an obstacle. What remains is how narrowly the robot integration constrains the path to the actuators — and commands taking that path leave no journal entry.

### T-08 — Uses the signing key it holds to legitimately sign and issue arbitrary action tokens.

**A6** Holder of signing key material  ×  **AS2** Integrity of the action token  ×  **X4** The file system

**Upheld by PAIL**

A keyring bundle signed under a different root is not loaded, known development key fingerprints are refused in the production profile, and that fingerprint list grows monotonically — a fingerprint is added or marked withdrawn, never dropped. Operator unlock requires both an operator-key signature and single use of a nonce.

*The paragraph above summarizes 4 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates**

- `S5` — production, but the keyring is unsigned (`PAIL_KEYRING_MODE=unsigned-dev`)
- `S8` — a known dev key or an unsigned trust anchor is in use

**Delegated**

- `G-DEL-L01` — Operator (key custody; PKI; HSM/TPM binding; issuer identity vetting)
- `G-DEL-L02` — Operator (key distribution pipeline; revocation-declaration rollout; rotation schedule)
- `G-DEL-L03` — Operator (PKI design; root-separation policy)

*Residual* — What the gate catches is known dev keys and unsigned trust anchors. A token signed with a legitimate production key stays valid **until the revocation declaration arrives**, and that arrival time is set by the distribution pipeline.

### T-09 — Moves or clones tags and occludes the sensors' field of view to deceive target identification.

**A7** Physical access to the robot or the site  ×  **AS1** The robot's authority to move  ×  **X7** The physical layer

**Upheld by PAIL**

The protocol parser does not read a damaged or malformed frame as a valid packet, the driver reflects the reader's state transitions faithfully, and debouncing does not turn a momentary dropout into presence. When the world hash signed into the token differs from the gate's current world the command is refused, and evidence whose target differs from the token's is blocked.

*The paragraph above summarizes 5 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates** — none.

**Delegated**

- `G-DEL-L04` — Adopter (choice, installation, and calibration of the target-identification modality)
- `G-DEL-L05` — Adopter (robot integration shape; actuation access-path control)

*Residual* — The parser does not read a damaged frame as a valid packet and the gate blocks a target mismatch, but **which modality is used and how it is installed and calibrated** is the integrator's decision. A miscalibrated sensor emits formally valid evidence.

### T-10 — Pushes an artifact into the deployment whose bytes differ from what was reviewed.

**A8** Build and distribution supply chain  ×  **AS6** The sealed state of configuration and policy  ×  **X6** Build and deployment artifacts

**Upheld by PAIL**

The effective configuration is canonicalized, hashed, and written to the signed journal — the same configuration canonicalizes reproducibly — and that digest is exposed identically as gate state. Remote attestation gives no healthy verdict to a tampered measurement, and expiry is fail-closed. A release build produces byte-identical tarballs across two runs on the same tree; when it does not, it fails with a per-member list of what differed rather than a single line saying they differ. A recipient verifies the delivery signature on a supported host with nothing installed (bundled static verifier; doctor measures the capability by performing a verification), and load and every run action expose whether this host recorded that verification (VERIFICATION: line and the platform record).

*The paragraph above summarizes 7 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates**

- `S7` — build shape and runtime configuration disagree (static / grpc mode mismatch)
- `S8` — a known dev key or an unsigned trust anchor is in use

**Delegated**

- `G-DEL-L02` — Operator (key distribution pipeline; revocation-declaration rollout; rotation schedule)
- `G-DEL-L11` — Adopter (CI isolation; dependency pinning; artifact signing; SBOM)
- `G-DEL-L14` — Adopter (base-image rebase and rebuild cadence, own vulnerability policy)
- `G-DEL-L15` — Adopter (the receiving party: compare with the external fingerprint and pass --expected-fingerprint)

*Residual* — The configuration seal records the running shape and the release build reproduces, but comparing that record against an expected value is the deploying organization's procedure. CI isolation, dependency pinning, artifact signing, and the SBOM belong to the integrator.

### T-11 — Sends formally valid but factually wrong evidence, flipping the verdict.

**A9** Trusted upstream sending false values  ×  **AS3** The single-use consumption record  ×  **X2** The ROS 2 / DDS topic plane

**Upheld by PAIL**

The policy's trust-class floor is a closed interval, and a source outside the vocabulary resolves to the lowest rank and clears no floor. Trust class and confidence are two separable defences, so clearing one leaves the other standing. Evidence is three-valued, and a decision report carries through to the blackbox record, where the evidence's provenance is readable.

*The paragraph above summarizes 4 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates** — none.

**Delegated**

- `G-DEL-L12` — Adopter (accuracy of event producers; sensor calibration; upstream-system validation)

*Residual* — PAIL records the evidence's provenance and enforces the trust-class floor, but does not judge whether a value inside that class is true — the kind of claim PAIL cannot measure from within itself.

### T-12 — To restart the line, lowers the profile, drops the gate to observe mode, or starts components without the gate.

**A10** Internal operator under production pressure  ×  **AS1** The robot's authority to move  ×  **X5** Process environment and the policy file

**Upheld by PAIL**

The profile truth table refuses a production profile combined with a weakening, and weakening is monotone — any combination production accepts, dev accepts too. A gate started in observe mode announces in its startup log that it does not enforce, and an enforcing gate does not emit that announcement. A mode value outside the vocabulary makes the gate refuse to start rather than guess, and a policy with no such key arrives as the same enforce as an explicit one. Every decision record from an enforcing gate carries that mode, and the effective mode enters the configuration seal.

*The paragraph above summarizes 6 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates**

- `S0` — `PAIL_PROFILE` is not `production|dev`
- `S6` — no profile was specified, so production was assumed  *(warning only, startup continues)*
- `S7` — build shape and runtime configuration disagree (static / grpc mode mismatch)

**Delegated**

- `G-DEL-L05` — Adopter (robot integration shape; actuation access-path control)
- `G-DEL-L08` — Operator (redundancy shape; capacity planning; recovery procedure)
- `G-DEL-L13` — Adopter (operating organization: retention period, capacity rule, archive location, free-space monitoring)
- `G-DEL-L16` — Adopter (operating team: keep stopped and retry manually; the maintainer retains DDS root-cause investigation)

*Residual* — A DDS rediscovery failure calls for stop/cancel and a manual retry, not disabling enforcement or SROS2. This does not attribute the observed matching failure to an attack; it records the risk of weakening the boundary under recovery pressure. The weakening is not silent — the effective mode enters the seal, an observe deployment announces the fact in its startup log, and every decision record carries the mode. But **reading those records is an operational procedure**, and a record nobody reads blocks nothing.

### T-13 — Resubmits an already-consumed token, or re-requests a step of a revoked chain.

**A2** Authenticated caller exceeding its entitlement  ×  **AS3** The single-use consumption record  ×  **X1** Control-plane gRPC

**Upheld by PAIL**

Reuse of a consumed token is blocked, and a token whose consumption verdict is true is blocked even when the consumption cache has reached its bound. Re-requesting a token consumed past its step deadline is blocked regardless of the grace setting, and the serving index only advances — a duplicate report does not wind it back. When a chain is revoked, every token of that chain is void. Forks and rewinds leave as distinct alert types, and each alert is signed.

*The paragraph above summarizes 6 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates** — none.

**Delegated**

- `G-DEL-L09` — Operator (rate limiting; reverse proxy; resource quotas; network isolation)

*Residual* — The reuse itself is blocked; the **volume** of retries is not. Rate limiting, resource quotas, and network segregation are decided by deployment configuration.

### T-14 — Rewrites or deletes journal segments out of band to change the evidence.

**A5** Privileged host account / container escape  ×  **AS4** The blackbox journal and the external reference point  ×  **X4** The file system

**Upheld by PAIL**

Blackbox records are chained in order into a segment hash chain and read back across process restarts. A one-byte flip at any structural position in the journal does not survive the verification walk. Out-of-band tampering — a changed hash, a changed size, a disappearance — is reported as an alert by a periodic sweep and re-fires on the next sweep, with no false positives on an untampered store. The four-state verdict agrees honestly across the whole stack, and corruption in the middle of the history is not a recovery case but a refusal to start. The collector's verification completes while the robot keeps writing — only identical closed segments, an active segment whose verified prefix is preserved and a contiguous continuation count as stable; a changed prefix, a shrink or a same-size replacement is refused even while the journal grows.

*The paragraph above summarizes 6 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates**

- `S9` — the evidence path / external reference-point configuration does not hold

**Delegated**

- `G-DEL-L06` — Operator (independent observation; external-anchor cross-checks; audit procedure)

*Residual* — **Changing what was written** is caught. What is not caught is **what was never written** — an event that never entered the chain passes integrity verification silently. That hole is visible only to independent observation from outside.

### T-15 — Cuts or exhausts the issuance path so that work stops.

**A1** On-path observer / tamperer  ×  **AS1** The robot's authority to move  ×  **X1** Control-plane gRPC

**Upheld by PAIL**

With no active token the gate does not pass a command. When it judges the issuer unreachable it does not pass one either; grace applies only to steps of a permit already held and does not extend an expiry. If the journal append fails no token is issued, and when the journal recovers issuance resumes — fail-closed is not a permanent lock-out.

*The paragraph above summarizes 4 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates** — none.

**Delegated**

- `G-DEL-L08` — Operator (redundancy shape; capacity planning; recovery procedure)
- `G-DEL-L09` — Operator (rate limiting; reverse proxy; resource quotas; network isolation)

*Residual* — A halt is not a defect but the execution of fail-closed, so it cannot be refuted inside PAIL. What is dangerous is not the halt but the bypass taken to avoid it — and that is T-12.

### T-16 — Quietly swaps the gate's thresholds or horizon through the process environment or the policy file.

**A4** Unprivileged account on the same host  ×  **AS6** The sealed state of configuration and policy  ×  **X5** Process environment and the policy file

**Upheld by PAIL**

The policy file is the only source of the gate's decision thresholds; no ROS-parameter copy exists. Without a policy file the gate does not start — tolerance for absence lives in keys inside the policy, never in the file itself. The issuer horizon likewise comes from the policy, and a dead horizon environment variable is refused rather than silently ignored. The seal knows the policy's content, not its path — different bytes at the same path produce a different seal digest.

*The paragraph above summarizes 4 guarantees carried by tests in this repository — not a statement of intent.*

**Startup gates**

- `S16` — the authorization policy file is missing or empty
- `S16b` — the policy YAML has an unknown field or a type mismatch (strict parse)
- `S16c` — the policy declares no callers at all
- `S16d` — a caller entry's value is outside the vocabulary (`caller_kind` / `caller_id` form) or duplicates another
- `S16e` — a required section is missing — absence is not filled in with a zero value
- `S16f` — a value outside the closed set, or a quantity that is neither an integer nor `unbounded`
- `S16g` — a name inside the file does not resolve, or the same name is declared twice
- `S16h` — the set the policy declares and the set the code knows disagree
- `S16i` — a quantity violates its lower bound even after the vocabulary and name checks pass
- `S16j` — the process environment tries to override the horizon — the policy file is its only source
- `S17` — the issuer key id is not configured (`PAIL_ISSUER_KEY_ID`)
- `S21` — the configuration seal could not measure an axis — the seal banner does not record the unobserved as fact  *(does not refuse — recorded as an axis in the seal)*

**Delegated**

- `G-DEL-04` — Operator (file permissions; OS accounts; persistent volumes)
- `G-DEL-05` — Operator (container runtime policy; orchestrator)

*Residual* — The gate refuses rather than guessing, and a dead horizon env is not silently ignored. But an account that **can write the policy file** already decides what the process reads — the remaining defence is file permissions, and that is delegated.

## 7. Delegation and the attacker it assumes

Every delegation in `TRUST_BOUNDARY.md` assumes an attacker. Without that, "not our part" is all that is written down and "against whom" is not — and a delegation in that state is an excuse rather than a boundary. All 20 delegations appear below, and each is cited by at least one row of the matrix.

| Delegation | Delegated to | Assumed attacker | Cited by |
|---|---|---|---|
| `G-DEL-01` | Operator (caller authorization policy) | `A2` | `T-01` |
| `G-DEL-02` | Operator (internal network layout; TLS termination; CA trust) | `A1` | `T-03` |
| `G-DEL-03` | Operator (SROS2 deployment; keystore operations) | `A3` | `T-04` `T-05` |
| `G-DEL-04` | Operator (file permissions; OS accounts; persistent volumes) | `A4` | `T-06` `T-16` |
| `G-DEL-05` | Operator (container runtime policy; orchestrator) | `A4` `A5` | `T-07` `T-16` |
| `G-DEL-L01` | Operator (key custody; PKI; HSM/TPM binding; issuer identity vetting) | `A4` `A6` | `T-06` `T-08` |
| `G-DEL-L02` | Operator (key distribution pipeline; revocation-declaration rollout; rotation schedule) | `A6` `A8` | `T-08` `T-10` |
| `G-DEL-L03` | Operator (PKI design; root-separation policy) | `A6` | `T-08` |
| `G-DEL-L04` | Adopter (choice, installation, and calibration of the target-identification modality) | `A7` `A9` | `T-09` |
| `G-DEL-L05` | Adopter (robot integration shape; actuation access-path control) | `A5` `A7` `A10` | `T-07` `T-09` `T-12` |
| `G-DEL-L06` | Operator (independent observation; external-anchor cross-checks; audit procedure) | `A3` `A5` `A7` | `T-04` `T-07` `T-14` |
| `G-DEL-L07` | Operator (TLS termination; network policy; certificate trust stores) | `A1` | `T-02` |
| `G-DEL-L08` | Operator (redundancy shape; capacity planning; recovery procedure) | `A1` `A10` | `T-12` `T-15` |
| `G-DEL-L09` | Operator (rate limiting; reverse proxy; resource quotas; network isolation) | `A1` `A2` | `T-02` `T-13` `T-15` |
| `G-DEL-L11` | Adopter (CI isolation; dependency pinning; artifact signing; SBOM) | `A8` | `T-10` |
| `G-DEL-L12` | Adopter (accuracy of event producers; sensor calibration; upstream-system validation) | `A3` `A9` | `T-05` `T-11` |
| `G-DEL-L13` | Adopter (operating organization: retention period, capacity rule, archive location, free-space monitoring) | `A10` | `T-12` |
| `G-DEL-L14` | Adopter (base-image rebase and rebuild cadence, own vulnerability policy) | `A8` | `T-10` |
| `G-DEL-L15` | Adopter (the receiving party: compare with the external fingerprint and pass --expected-fingerprint) | `A8` | `T-10` |
| `G-DEL-L16` | Adopter (operating team: keep stopped and retry manually; the maintainer retains DDS root-cause investigation) | `A10` | `T-12` |

## 8. What this model does not claim

**Completeness.** What is written here is what the declared vocabulary can express, not the whole of the threats. A threat absent from the table is not an absent threat but an **unwritten** one.

**That the mitigations hold in your deployment.** A guarantee listed as upheld is upheld by tests in this repository. A startup gate listed as present trips when your profile is `production`. Neither statement is about your site.

**That delegation is protection.** Sections 6 and 7 name what the deploying organization must do. Naming it does not do it.

For the vulnerability-reporting channel and what counts as a vulnerability, see `SECURITY.md`. For what PAIL upholds and where the boundary lies, see `TRUST_BOUNDARY.md`.
