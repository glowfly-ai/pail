# Trust operations: bundle expiry, bundle application, key registration

This document is for the party that operates a PAIL deployment. It answers three questions
the software does not answer by itself: what each component does when the trust bundle
expires, how a renewed bundle is applied (and how you know it was), and who decides about
keys. It describes the software as shipped in this release; every statement it makes about
code is pinned by a contract test of the release, so when the code changes this document
fails the release checks until it is updated.

What it does not do: it does not ship a management tool that rotates keys or decides for you. A gate takes up a
bundle that is placed beside it by itself; placing it, and registering and rotating keys, are decisions you make. The
software enforces the result and refuses the rest.

## 1. Where trust lives

- **Root key.** Held only in your offline signer (`pail-keyring-sign`). No PAIL process reads
  it; nothing here generates a replacement root.
- **Signed bundle.** A payload (`bundle_version`, `issued_at_unix`, `expires_at_unix`, keys
  with roles, revocations) signed by the root. Its path is `PAIL_KEYRING_BUNDLE` (default
  `/etc/pail/keys/keyring_bundle.json`); the root public key is `PAIL_ROOT_PUBKEY_FILE`.
- **Issuer keyring.** `pail_cloud` / `pail_services` load the bundle at start and keep a
  *freshness gate* from its `expires_at`.
- **Gate (adapter) keyring.** `libpail_gate` loads the bundle at start, takes up a newer bundle that is placed at the
  same path while it runs, and stops verifying with a bundle whose `expires_at` has passed.
- **Robot agent puller.** Optionally fetches a newer bundle from the Issuer, places it, and confirms from the gate's
  state file that the gate judges with it. A restart command you configured is the fallback when that confirmation
  does not come.
- `PAIL_KEYRING_MODE=unsigned-dev` is development trust without a bundle: no signature, no
  expiry, no version floor. It is not "a bundle that never expires"; production startup
  refuses it (`S5`).

## 2. What expiry does, per component

| Component | Checks when | On expiry | Evidence line |
|---|---|---|---|
| Issuer (`pail_cloud`, `pail_services`) | At startup (`InstallTrustFreshness`; no gate → `S20f` refusal) and on **every request**: the first statement of the plan decision is `s.Trust.Check()`. A watcher re-checks every 5 minutes only to log it. | A plan submitted after `expires_at` is refused with `ERR_BUNDLE_EXPIRED` (`S20d`). Nothing already issued is withdrawn; nothing new is issued. Startup on an expired bundle is refused. | `trust freshness: expires_at=<RFC3339> (in <duration>)` at startup; `WARNING: … expired … issuance is refused from here on` once from the watcher. |
| Gate (`libpail_gate`, the ROS 2 adapter) | At load, and **on every decision while it runs**. Loading checks the root signature, the format (an undefined member, an entry without a role or a `key_id` given twice refuses the bundle), the version floor (a smaller version is refused; the same version reloads), `now < expires_at` and `expires_at − now ≤ PAIL_KEYRING_MAX_LIFETIME_SEC`. While it runs the gate compares its own wall clock with the `expires_at` of the bundle it loaded, and it looks at the bundle file: a higher version that passes the same checks is applied without a restart (the ROS 2 gate looks four times a second; an adapter on the C ABI looks on every `pail_gate_tick`). | A bundle that is already expired does not load (`ERR_BUNDLE_EXPIRED`, no keys). A running gate refuses every command from the `expires_at` of its bundle on (`BLOCK ERR_BUNDLE_EXPIRED`), also for a token that is itself still valid, and a permit it holds ends there. It verifies again once a valid higher-version bundle is applied. A candidate that fails a check changes nothing and does not extend the expiry. | The loaded-trust record the gate keeps from the load and serves in its status snapshot (robot-ops status socket, field `trust_snapshot_json`; the console's readiness view reads it): `{"schema_version":1,"loaded_mode":"bundle","load_verdict":"LOADED", … "bundle_version":N,"expires_at_unix":T,"loaded_at_unix":t,"max_remaining_seconds":M,"role_fingerprints":[…]}`; it follows an application. The ROS 2 gate also logs one line per change: `PAIL_GATE_TRUST loaded|applied|refused|expired … bundle_version=N expires_at_unix=T`. |
| Robot agent (`pail_robot_agent`) | Pulls only when `PAIL_ROOT_PUBKEY_FILE` is set. `PAIL_KEYRING_POLL_SEC` unset → startup refusal `S20c`; `0` → pulling off on purpose. `PAIL_GATE_RESTART_CMD` is optional. | The agent does not judge expiry; it verifies a fetched bundle against the root and the placed version, places it, and then reads the gate's state file (`PAIL_KEYRING_STATE`) for up to 5 s: a floor at the placed version is the gate's own statement that it applied it. Without that statement the agent says so by name and runs the restart command when one is configured. | `keyring pull: enabled (interval=… dest=… apply=gate-self[, fallback=restart-cmd])`, `keyring pull: placed bundle v<N> at <path> (was v<M>)`, `keyring pull: gate applied v<N>`, or `keyring pull: KEYRING_APPLY_NOT_CONFIRMED placed=v<N> gate=…` followed by `keyring pull: gate restart triggered ("…")` when a command is set. |
| Operator tooling (`examples/common/trust_admin.py`) | `inspect`, `plan-renewal`, `stage-renewal` run offline against your profile and consumer observations. | `apply-renewal` is **refused** (`MANAGEMENT_EXECUTION_WINDOW_NOT_INSTALLED; candidate remains staged`): the managed restart framework was withdrawn from the public tree on 2026-10-29. Application is Stage 5 below, performed by you. | The staged candidate file beside the operation state; `operation-status`. |

Read the table per row. The Issuer and each gate judge the expiry of the bundle they themselves loaded, on their own
clocks: "expiry stops issuance" is the Issuer's row, "expiry stops the gate" is the gate's. A robot that cannot
be reached — and so can receive neither a renewal nor a revocation — stops at the `expires_at` of its bundle at the
latest; `PAIL_KEYRING_MAX_LIFETIME_SEC` is therefore the longest a revocation can take to land on it.

## 3. What the demos ship

- The TB3 demo (`examples/tb3/demo.py`) runs in `bundle` mode and generates an initial bundle
  valid for 8 hours; the TB3 test tool (`examples/tb3/run.py`) one valid for 1 hour. These are
  the lifetimes of the *initial* bundle of those two entry points, not a renewal period that
  all runs must follow. The TB3 compose file sets `PAIL_KEYRING_MAX_LIFETIME_SEC: "86400"`
  (a bundle offering more than 24 h of remaining life is refused at load) and `PAIL_KEYRING_POLL_SEC: "0"` (no automatic pulling).
  A demo that is left running past the lifetime of its initial bundle stops permitting (`ERR_BUNDLE_EXPIRED`); start a
  fresh state.
- The Microduck examples run in `unsigned-dev` mode: no bundle, no expiry, not signature
  trust.

## 4. Applying a renewed bundle

The procedure has six stages. Each stage has an input, an output and a piece of evidence;
none of them is implied by another. Neither generating a bundle nor applying it to a gate requires stopping anything;
applying one to the Issuer does.

Stages 1 to 3 are run from the Core root, and the command lines below can be followed as they stand. They use
three values:

```sh
OPS=/absolute/operator
ISSUED=1795000000
EXPIRES=1795086400
```

`OPS` is a directory you own with no symlink anywhere in its path (on macOS `/private/tmp/…`, not `/tmp/…`); it holds
your profile, your consumer observations and what the stages write. `ISSUED` and `EXPIRES` are the validity you are
asking for: `ISSUED` not later than the earliest `now_min_unix` of your observations, `EXPIRES` later than every
`now_max_unix` and within every consumer's `max_remaining_seconds`. The values shown fit the example observation file.

**Before stage 1, build the signer.** It ships as source in the Core (`cloud/tools/pail-keyring-sign`); build it once
on the operator host with the Go version `cloud/go.mod` names. The last line prints its SHA-256:

```sh
mkdir -p "$OPS/bin"
(cd cloud && go build -o "$OPS/bin/pail-keyring-sign" ./tools/pail-keyring-sign)
python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$OPS/bin/pail-keyring-sign"
```

The path of that executable is your profile's `helper_path` and the printed digest its `helper_sha256`. A changed or
moved executable is refused (`HELPER_CHANGED`), so rebuild and re-pin on purpose, not in passing.

The profile also names the root it trusts by fingerprint:

```sh
python3 -c 'import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(open(sys.argv[1]).read().strip())).hexdigest())' "$OPS/root_pub.b64"
```

The output is your profile's `root_fingerprint_sha256`; `$OPS/root_pub.b64` stands for the file its `root_public_path`
names.

### Stage 1 — plan

`trust_admin.py plan-renewal` fixes the baseline (`base_sha256` of the current bundle, the
root fingerprint, the keys/roles/revocations that must not change), the consumers' observed
`max_bundle_version` and lifetime ceilings, and the exact new payload (`bundle_version`,
`issued_at_unix`, `expires_at_unix`). Only the version and the validity times may change in a
renewal; a change of key material is a key-change process (§5), not a renewal. Output: the
plan and its digest; record the operation id.

What `plan-renewal` reads:

- **The profile** (`--profile`). Start from `examples/common/trust_observation.manifest.example.json`. It declares the
  bundle, the root public key and the signer (`helper_path`, pinned by `helper_sha256`; Stage 2 says how to build it).
- **The consumer observations** (`--consumers`). A JSON array with one object per consumer of the bundle — the Issuer
  and every gate. `examples/common/trust_renewal_consumers.example.json` shows the shape; every field is required.

| Field | What it says | Where the value comes from |
|---|---|---|
| `id` | Your name for the consumer: unique in the file, at most 128 characters. | You choose it. |
| `observed` | This row is an observation you made; `false` refuses the plan. | `true` only for a row you observed. |
| `loaded_generation` | The generation the consumer reports for what it has loaded. It is compared again when a renewal is applied. | The consumer's status answer. |
| `root_fingerprint_sha256` | The root the consumer **loaded**. A value other than the base bundle's root refuses the plan. | `trust_snapshot_json` in the consumer's status answer. |
| `material_digest_sha256` | The key material the consumer loaded: active and revoked keys, ids, roles and order. | `trust_snapshot_json`. |
| `max_bundle_version` | The largest version the consumer can accept; `0` refuses the plan. | `max_bundle_version_decimal` of `trust_snapshot_json`, written as a JSON number. |
| `rollback_floor` | The consumer's version floor. The planned version is above every consumer's floor. | `last_version` in the consumer's state file (`PAIL_KEYRING_STATE`). |
| `now_min_unix`, `now_max_unix` | The bounds of the consumer's clock while you observed it. The plan needs `issued_at_unix` ≤ `now_min_unix` and `expires_at_unix` > `now_max_unix`. | The consumer's clock at the start and at the end of your observation. |
| `max_remaining_seconds` | The consumer's lifetime ceiling: `expires_at_unix` − `now_min_unix` may not exceed it. | `max_remaining_seconds` of `trust_snapshot_json`. |

  The loaded values come from the **running consumer**. `pail-keyring-sign inspect-json` computes values of the same
  names from the bundle *file*; copying those into this file passes the decoder, but it is not runtime verification —
  it says what the file holds, not what the consumer loaded. Reading a consumer's status answer is the work of your
  management integration: the evaluation bundle carries no tool that writes this file.
- **Paths.** The profile, the three paths inside it, and `--state`, `--consumers` and `--candidate` must each be a
  resolved absolute path. A relative path or a path with a symlink in it is refused, and the refusal names the item
  (`field`), never the path. On macOS `/tmp` is a symlink to `/private/tmp`: write `/private/tmp/…`.

```sh
python3 examples/common/trust_admin.py plan-renewal \
  --profile "$OPS/profile.json" --state "$OPS/operations" --operation-id renewal-1 \
  --consumers "$OPS/observations.json" --issued-at "$ISSUED" --expires-at "$EXPIRES" \
  --payload-out "$OPS/payload.json" > "$OPS/plan.json"
PLAN_DIGEST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan_digest"])' "$OPS/plan.json")
```

`--payload-out` writes the planned payload — exactly what the root signs in stage 2 — to a new file; an existing file
is never replaced. `plan.json` holds the plan and its digest. Read the plan before you approve it: `PLAN_DIGEST` is
what stage 3 takes as your approval. When the signer refuses the request, the answer names the signer's reason as
`cause` (for example `CONSUMER_LIFETIME_REJECTED`: the validity does not fit a consumer's clock window or ceiling).

### Stage 2 — sign

Sign the planned payload with the **existing** root in your offline signer. A new root is a
trust replacement, not a renewal, and every consumer must be re-pointed at it by the §5
process. Output: the candidate bundle file.

```sh
"$OPS/bin/pail-keyring-sign" sign --root "$OPS/root_ed25519.json" --payload "$OPS/payload.json" --out "$OPS/candidate.json"
```

The root private key stays in your offline signer; `$OPS/root_ed25519.json` stands for wherever it is kept.

### Stage 3 — stage

`trust_admin.py stage-renewal --candidate … --approved-plan-digest …` validates the exact
candidate bytes against the plan (same root fingerprint, same material, version above the
consumers' floors, lifetime within their ceilings). Staging installs nothing and moves no
floor. Output: `STAGED_NOT_APPLIED` with the candidate's SHA-256.

```sh
python3 examples/common/trust_admin.py stage-renewal \
  --profile "$OPS/profile.json" --state "$OPS/operations" --operation-id renewal-1 \
  --consumers "$OPS/observations.json" --candidate "$OPS/candidate.json" \
  --approved-plan-digest "$PLAN_DIGEST"
```

A candidate that differs from the plan is refused, with the signer's reason as `cause`
(`RENEWAL_IMMUTABLE_OR_VERSION_CHANGED` when keys, roles, revocations or the version differ), and the operation stays
`PLANNED`.

### Stage 4 — place

Copy the staged candidate to `PAIL_KEYRING_BUNDLE` of **each** consumer (Issuer host, every
gate host) — the file the processes read at start. With pulling on, the robot agent does this
for its gate and logs `keyring pull: placed bundle v<N> at <path> (was v<M>)`; verify the line. Placing is what a running gate acts on: it applies a higher version that passes the load checks
within a second. Placing changes nothing in a running Issuer.

### Stage 5 — apply

A gate applies the placed bundle by itself and keeps running: a renewal does not interrupt a drive, and a revocation
ends a permit held on the revoked key at the gate's next check. The Issuer loads its own bundle at start only: when
the Issuer's bundle changed, restart the Issuer, and plan that window — it refuses issuance while it is down. A gate
restart (the hardware rig's `start_demo_rig.sh restart-gate`, `docker compose … restart robot` in the demo, or your
`PAIL_GATE_RESTART_CMD`) loads whatever is placed, as before; it is the fallback for a gate that did not apply, not
the way a bundle is applied. The lifetime ceiling is not raised to avoid renewals.

### Stage 6 — confirm

Read the evidence lines and compare them with the plan before calling the application
done: the gate's log line `PAIL_GATE_TRUST applied bundle_version=<N> …` (or its status snapshot,
`trust_snapshot_json`, saying `"load_verdict":"LOADED"`) must show the planned `bundle_version` and
`expires_at_unix` and the expected `role_fingerprints`; with pulling on, the agent's `keyring pull: gate applied v<N>`
says the same from the gate's state file;
the Issuer's startup line `trust freshness: expires_at=…` must show the planned expiry. A
placed file without these records is Stage 4, not Stage 6.

**Resuming operation is a separate decision.** A confirmed application says the trust is
loaded; it says nothing about whether the robot, its safety feed and its operator are ready
to move again. Make and record that decision on its own evidence.

**When pulling is off** (the TB3 compose file: `PAIL_KEYRING_POLL_SEC: "0"`), nobody pulls:
the operator applies Stages 4–6 by hand, before the running bundle's `expires_at`, on every
consumer. **When pulling is on**, the agent performs Stage 4 for its gate at the poll interval, the gate performs Stage 5, and
the agent reports what it could confirm; Stage 6 is still yours, and the Issuer is never restarted by the agent.

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
- **Keep the old issuer key's public half when rotating.** At start-up the issuer verifies
  every checkpoint of its journal against the issuer keys of its keyring. Keep the previous
  key under `keys` or `revoked_keys` for as long as the journal holds checkpoints it signed:
  a checkpoint signed by a key absent from both cannot be told from a forgery, and the issuer
  refuses to start.
- **Revoking an issuer key takes two steps, and the second one reaches the gates.** The operator command
  `RevokeIssuerKey` puts the issuer into permanent LOCKDOWN and changes nothing a gate reads; it answers "accepted"
  only when its record is in the journal (`JOURNAL_APPEND_FAILED` otherwise — the lock then does not survive a
  restart). Then the root signs the bundle that revokes the key:
  `pail-keyring-sign prepare-revoke --bundle <current> --root-pub <root_pub.b64> --key-id <id> --out payload.json`
  writes its payload (that one key moved to `revoked_keys`, version + 1, expiry unchanged; it refuses to leave no
  active issuer key unless `--allow-no-issuer` says so), `sign` signs it, and you place the result where the Issuer
  serves it. A reachable gate refuses the key's tokens (`ERR_REVOKED_KEY_ID`) within the agent's poll interval plus
  the seconds the gate takes to apply; an unreachable one stops at the expiry of the bundle it holds. **Until the
  root has signed, every gate still trusts the key** — keep the root ceremony short enough for that window. Moving the
  key also keeps the issuer from starting with it again from a journal cut back to before the lock: the issuer
  refuses to start with a signing key that is not an active issuer key.
- **A first install writes the version floor.** In the production profile a consumer whose state file
  (`PAIL_KEYRING_STATE`) does not exist refuses to load the bundle (`ERR_BUNDLE_STATE:missing` at the gate,
  `bundle state: missing …` in Go): a missing floor is not read as a first load, or a lost state directory would
  bring back a bundle from before a revocation. Write it once:
  `pail-keyring-sign init-floor --bundle <placed bundle> --root-pub <root_pub.b64> --state <state file>`. It never
  overwrites a state file, and the `dev` profile keeps the first-load behaviour.
- **Do not** generate a new keyring or a new trust root to make a mismatch disappear, and do
  not **overwrite** a consumer's bundle to silence `ERR_BUNDLE_EXPIRED`; renew it (§4).
  Deleting a runtime environment (a state directory, a container, a VM)
  **is not a trust decision**: it removes a copy, it revokes nothing, and the keys it held
  are still trusted until the bundle says otherwise.

## 6. Evidence to keep

For each operation: the plan JSON and its digest, the signed candidate and its SHA-256, the
staging result, the placement log line (or the copy you made, with its hash), the gate's `PAIL_GATE_TRUST applied`
line (or its LOADED record after a restart), the agent's confirmation line, the Issuer's freshness line, and the separate record of the
decision to resume. Keep them with the operation id; the journal records the tokens, not the
bundle procedure.
