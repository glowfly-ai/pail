# Trust operations: bundle expiry, bundle application, key registration

This document is for the party that operates a PAIL deployment. It answers three questions
the software does not answer by itself: what each component does when the trust bundle
expires, how a renewed bundle is applied (and how you know it was), and who decides about
keys. It describes the software as shipped in this release; every statement it makes about
code is pinned by a contract test of the release, so when the code changes this document
fails the release checks until it is updated.

What it does not do: it does not ship a management tool that applies bundles or rotates keys.
Applying is a gate restart you perform; registering and rotating keys are approval decisions
you make. The software enforces the result and refuses the rest.

## 1. Where trust lives

- **Root key.** Held only in your offline signer (`pail-keyring-sign`). No PAIL process reads
  it; nothing here generates a replacement root.
- **Signed bundle.** A payload (`bundle_version`, `issued_at_unix`, `expires_at_unix`, keys
  with roles, revocations) signed by the root. Its path is `PAIL_KEYRING_BUNDLE` (default
  `/etc/pail/keys/keyring_bundle.json`); the root public key is `PAIL_ROOT_PUBKEY_FILE`.
- **Issuer keyring.** `pail_cloud` / `pail_services` load the bundle at start and keep a
  *freshness gate* from its `expires_at`.
- **Gate (adapter) keyring.** `libpail_gate` loads the bundle at start and verifies tokens
  with the keys it loaded.
- **Robot agent puller.** Optionally fetches a newer bundle from the Issuer, places it, and
  runs the restart command you configured.
- `PAIL_KEYRING_MODE=unsigned-dev` is development trust without a bundle: no signature, no
  expiry, no version floor. It is not "a bundle that never expires"; production startup
  refuses it (`S5`).

## 2. What expiry does, per component

| Component | Checks when | On expiry | Evidence line |
|---|---|---|---|
| Issuer (`pail_cloud`, `pail_services`) | At startup (`InstallTrustFreshness`; no gate → `S20f` refusal) and on **every request**: the first statement of the plan decision is `s.Trust.Check()`. A watcher re-checks every 5 minutes only to log it. | A plan submitted after `expires_at` is refused with `ERR_BUNDLE_EXPIRED` (`S20d`). Nothing already issued is withdrawn; nothing new is issued. Startup on an expired bundle is refused. | `trust freshness: expires_at=<RFC3339> (in <duration>)` at startup; `WARNING: … expired … issuance is refused from here on` once from the watcher. |
| Gate (`libpail_gate`, the ROS 2 adapter) | **At load only.** Loading checks the root signature, the version floor (a smaller version is refused; the same version reloads), `now < expires_at` and `expires_at − now ≤ PAIL_KEYRING_MAX_LIFETIME_SEC`. There is no re-check while the process runs: a new bundle is applied by a gate **restart**. | A bundle that is already expired does not load (`ERR_BUNDLE_EXPIRED`, no keys). A gate that loaded a bundle before it expired keeps verifying tokens with those keys until it is restarted; tokens themselves carry their own short expiry, and the Issuer has stopped issuing, so the exposure ends with the last token's validity. | The loaded-trust record the gate keeps from the load and serves in its status snapshot (robot-ops status socket, field `trust_snapshot_json`; the console's readiness view reads it): `{"schema_version":1,"loaded_mode":"bundle","load_verdict":"LOADED", … "bundle_version":N,"expires_at_unix":T,"loaded_at_unix":t,"max_remaining_seconds":M,"role_fingerprints":[…]}`. It is not a log line. |
| Robot agent (`pail_robot_agent`) | Pulls only when `PAIL_ROOT_PUBKEY_FILE` is set. `PAIL_KEYRING_POLL_SEC` unset → startup refusal `S20c`; `0` → pulling off on purpose; `>0` with no `PAIL_GATE_RESTART_CMD` → `S20e` ("placing a bundle nobody loads is not a revocation path"). | The agent does not judge expiry; it verifies a fetched bundle against the root and the floor, places it, and triggers the restart command. | `keyring pull: enabled (interval=… dest=…)`, `keyring pull: placed bundle v<N> at <path> (was v<M>)`, `keyring pull: gate restart triggered ("…")`. |
| Operator tooling (`examples/common/trust_admin.py`) | `inspect`, `plan-renewal`, `stage-renewal` run offline against your profile and consumer observations. | `apply-renewal` is **refused** (`MANAGEMENT_EXECUTION_WINDOW_NOT_INSTALLED; candidate remains staged`): the managed restart framework was withdrawn from the public tree on 2026-10-29. Application is Stage 5 below, performed by you. | The staged candidate file beside the operation state; `operation-status`. |

Read the table per row. "Expiry stops issuance" is true of the Issuer; "expiry stops the
gate" is not — the gate stops when you restart it, and that is the application step.

## 3. What the demos ship

- The TB3 demo (`examples/tb3/demo.py`) runs in `bundle` mode and generates an initial bundle
  valid for 8 hours; the TB3 test tool (`examples/tb3/run.py`) one valid for 1 hour. These are
  the lifetimes of the *initial* bundle of those two entry points, not a renewal period that
  all runs must follow. The TB3 compose file sets `PAIL_KEYRING_MAX_LIFETIME_SEC: "86400"`
  (a bundle offering more than 24 h of remaining life is refused at load) and
  `PAIL_KEYRING_POLL_SEC: "0"` (no automatic pulling).
- The Microduck examples run in `unsigned-dev` mode: no bundle, no expiry, not signature
  trust.

## 4. Applying a renewed bundle

The procedure has six stages. Each stage has an input, an output and a piece of evidence;
none of them is implied by another. Generating a bundle does not require stopping anything;
applying it does.

### Stage 1 — plan

`trust_admin.py plan-renewal` fixes the baseline (`base_sha256` of the current bundle, the
root fingerprint, the keys/roles/revocations that must not change), the consumers' observed
`max_bundle_version` and lifetime ceilings, and the exact new payload (`bundle_version`,
`issued_at_unix`, `expires_at_unix`). Only the version and the validity times may change in a
renewal; a change of key material is a key-change process (§5), not a renewal. Output: the
plan and its digest; record the operation id.

### Stage 2 — sign

Sign the planned payload with the **existing** root in your offline signer. A new root is a
trust replacement, not a renewal, and every consumer must be re-pointed at it by the §5
process. Output: the candidate bundle file.

### Stage 3 — stage

`trust_admin.py stage-renewal --candidate … --approved-plan-digest …` validates the exact
candidate bytes against the plan (same root fingerprint, same material, version above the
consumers' floors, lifetime within their ceilings). Staging installs nothing and moves no
floor. Output: `STAGED_NOT_APPLIED` with the candidate's SHA-256.

### Stage 4 — place

Copy the staged candidate to `PAIL_KEYRING_BUNDLE` of **each** consumer (Issuer host, every
gate host) — the file the processes read at start. With pulling on, the robot agent does this
for its gate and logs `keyring pull: placed bundle v<N> at <path> (was v<M>)`; verify the line.
Placing changes nothing in a running process.

### Stage 5 — apply

Restart the processes that must load the new bundle: the gate (the hardware rig's
`start_demo_rig.sh restart-gate`, or `docker compose … restart robot` in the demo; with pulling
on, the agent runs your `PAIL_GATE_RESTART_CMD` right after placing) and, when the Issuer's
own bundle changed, the Issuer. While the gate restarts it accepts no command; the Issuer
refuses issuance while it is down. Plan the window accordingly; the restart is the only
application path — there is no live reload, and the lifetime ceiling is not raised to avoid one.

### Stage 6 — confirm

Read the evidence lines and compare them with the plan before calling the application
done: the gate's status snapshot (`trust_snapshot_json`) must say `"load_verdict":"LOADED"`
with the planned `bundle_version` and `expires_at_unix` and the expected `role_fingerprints`;
the Issuer's startup line `trust freshness: expires_at=…` must show the planned expiry. A
placed file without these records is Stage 4, not Stage 6.

**Resuming operation is a separate decision.** A confirmed application says the trust is
loaded; it says nothing about whether the robot, its safety feed and its operator are ready
to move again. Make and record that decision on its own evidence.

**When pulling is off** (the TB3 compose file: `PAIL_KEYRING_POLL_SEC: "0"`), nobody pulls:
the operator applies Stages 4–6 by hand, before the running bundle's `expires_at`, on every
consumer. **When pulling is on**, the agent performs Stage 4 and triggers Stage 5 for its
gate at the poll interval; Stage 6 is still yours, and the Issuer is never restarted by the
agent.

## 5. Key registration, rotation and preservation

PAIL checks the signature of the Issuer it trusts and the scope of the tokens it is handed.
Which keys deserve that trust is decided outside the software (`TRUST_BOUNDARY`: G-DEL-L01
custody and identity review, G-DEL-L02 distribution, revocation and rotation). These are the
rules that decision has to follow for the software's checks to mean anything.

- **Initial trust is an approval decision.** Before the first bundle exists, the administering
  party fixes the Issuer's identity, each key's role, the trust root and the deployment the
  bundle applies to. The software **only enforces** that decision: that a key can be generated
  (`gen_dev_keys.py`, the evaluation examples) is not a reason to grant it issuance.
- **Keep key storage separate from the disposable runtime.** The root stays in the offline
  signer; the deployed private keys and the bundle live at a location that outlives containers,
  state directories and VMs. A restart or a re-installation of the **same** operational
  identity **reuses the existing keys**; a fresh key means a fresh identity that must go
  through the approval above.
- **Show status by fingerprint, never the key value.** A status display or a report names the
  role, the identifier, the public-key **fingerprint** (`root_fingerprint_sha256`,
  `role_fingerprints` in the gate's LOADED line), the approval reference and the deployment
  state. It never contains private material, and a loaded keyring or a matching file hash is
  not evidence of approval.
- **Rotate under the existing root.** A rotation is its own operation, separate from a
  service change: the new key's role, validity, the revocation of the old key, the bundle
  version and the approval reference are checked before the bundle is distributed (Stages 1–3
  with changed material, which `stage-renewal` refuses as a renewal — use the key-change
  path). A new root is a trust replacement for every consumer, not a rotation.
- **Do not** generate a new keyring or a new trust root to make a mismatch disappear, and do
  not **overwrite** a consumer's bundle to silence `ERR_BUNDLE_EXPIRED`; renew it (§4).
  Deleting a runtime environment (a state directory, a container, a VM)
  **is not a trust decision**: it removes a copy, it revokes nothing, and the keys it held
  are still trusted until the bundle says otherwise.

## 6. Evidence to keep

For each operation: the plan JSON and its digest, the signed candidate and its SHA-256, the
staging result, the placement log line (or the copy you made, with its hash), the restart
log, the gate's LOADED record and the Issuer's freshness line, and the separate record of the
decision to resume. Keep them with the operation id; the journal records the tokens, not the
bundle procedure.
