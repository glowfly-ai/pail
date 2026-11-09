# Offline robot-operations check — runnable example

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Glowfly Identity Systems Co.,Ltd -->

English canonical; [한국어](README.ko.md). Contract and configuration reference:
[`spec/ROBOT_OPERATIONS.md`](../../spec/ROBOT_OPERATIONS.md).

This example runs the public offline checker and the evaluation-image Issuer checker against a
complete declaration set that a small Go program writes for you. Nothing here
talks to a robot, an issuer or a network. Everything is written **outside the
source tree** so that `scripts/verify_release.py` still reports the extracted
archive as pristine afterwards.

What a run proves, and what it does not:

- **Proves:** the declared robot identities, credential routes, site placement,
  skills and isolation groups are consistent with each other and with the
  registry, site model, policy and skill registry they point at.
- **Does not prove:** that any robot holds the private key of its certificate,
  that DDS isolation is real, that a process is running, or that anything may
  be applied. Every report says so itself: `ready_for_apply` is always `false`
  offline, `runtime_observed` is `false`, and each PASS names what it did
  **not** observe (`private-key possession NOT observed`, `actual DDS isolation
  NOT observed`).

Requirements: Go 1.27.2 or the documented supported toolchain and the module cache
or network for the first dependency download. Run from `cloud/` of the extracted
archive.

## 1. Build the three programs

```sh
cd cloud
go build -o /tmp/pail-ro/fixture ./cmd/pail_robotops_fixture
go build -o /tmp/pail-ro/check   ./cmd/pail_robotops_check
# Select the pinned Issuer evaluation executable:
ISSUER_IMAGE="$(python3 ../examples/common/evaluation_runtime.py --root .. --role issuer)"
```

`pail_robotops_check` and `pail_robotops_fixture` are PAIL-Core (Apache-2.0).
`pail_issuer_robotops_check` is PAIL Issuer (separate evaluation binary license) and is absent from a
Core-only archive; the Core checks below still run without it.

## 2. Write a declaration set outside the tree

```sh
/tmp/pail-ro/fixture --out /tmp/pail-ro/two --config ../config --robots 2
```

The directory now holds a fresh CA, two robot client certificates
(`client0.crt`, `client1.crt`), `robot_registry.yaml`, `requesters.yaml`,
`site_model.yaml`, copies of the public reference `policy.yaml` and
`skills.diff_drive_amr.yaml`, and the two documents the checkers read:
`resources.json` (what exists and where) and `inventory.json` (which robot is
bound to which of those resources). The certificates are valid for 12 hours.
**Their private keys are never written**: the set is development data for the
checkers, not an enrolment, and cannot be turned into robot credentials.

Use `--robots 1` for a single robot. The program refuses an existing `--out`
directory, an unknown robot count, and stray arguments.

## 3. Run the checks

```sh
/tmp/pail-ro/check --inventory /tmp/pail-ro/two/inventory.json \
  --resources /tmp/pail-ro/two/resources.json --root /tmp/pail-ro/two \
  > /tmp/pail-ro/two-core.json; echo rc=$?
```

Expected: `rc=0`, and the report's `summary` is `PASS` across eight check ids
(`RO-C01`, `RO-C02`, `RO-C03.static`, `RO-C04`, `RO-C05`, `RO-C07.declared`,
`RO-C08.declared`, `RO-C11.declared`; per-robot checks list both robots as
required subjects). `ready_for_apply` and
`runtime_observed` are `false`. The issuer-side requester check reads the same
inputs:

```sh
docker run --rm --network none -v /tmp/pail-ro:/tmp/pail-ro:ro \
  --entrypoint pail_issuer_robotops_check "$ISSUER_IMAGE" --inventory /tmp/pail-ro/two/inventory.json \
  --resources /tmp/pail-ro/two/resources.json --root /tmp/pail-ro/two \
  > /tmp/pail-ro/two-issuer.json; echo rc=$?
```

Expected: `rc=0`, scope `b_requester_offline/v1`, `RO-C06` PASS for both robots.

Exit codes are the contract, not the prose: `0` every scoped check passed, `1`
at least one observed mismatch, `2` usage error, unreadable or invalid input, or
a check that could not be measured (`CANNOT_CHECK`). A report that mixes FAIL and
CANNOT_CHECK keeps both and exits `2`. No flag turns a failed or unmeasured check
into a pass.

## 4. `describe`: a planned inventory draft, not an approval

```sh
/tmp/pail-ro/check describe --resources /tmp/pail-ro/two/resources.json \
  --root /tmp/pail-ro/two > /tmp/pail-ro/two-described.json; echo rc=$?
```

`describe` derives an inventory from the resource map and the official registry
and site parsers. Every robot it emits has `lifecycle: "planned"`; observing a
robot is not authority to activate it. For the fixture set the draft is
byte-for-byte the same as the generated `inventory.json`. Ambiguity refuses
rather than guesses: a resource map with two registries, or two agents claiming
the same robot, exits `2` with `RO_IMPORT_AMBIGUOUS`. Refusal codes you will see
if you edit the inputs: `RO_SCHEMA: resource map schema_version must be 1`,
`… deployment_id must be a lowercase UUID`, `… resources must not be empty`,
`… resources exceeds 10000 entries`, `… file resource needs a relative path`
(paths are relative to `--root`), `RO_CAPABILITY: unsupported resource kind`.

## 5. Make it fail on purpose

A checker that has never been seen red proves nothing. Each of the three edits
below changes exactly one thing; each trips a different check.

**Same isolation group on both robots** (edit `resources.json`: give robot 2's
agent, gate, bridge and transport the group of robot 1):

```sh
cp -R /tmp/pail-ro/two /tmp/pail-ro/samegroup
python3 - <<'EOF'
import json
p='/tmp/pail-ro/samegroup/resources.json'; d=json.load(open(p))
for r in d['resources']:
    if r['id'] in ('cmp:a1','cmp:g1','cmp:b1','res:n1'): r['group']='net0'
json.dump(d,open(p,'w'),indent=2)
EOF
/tmp/pail-ro/check --inventory /tmp/pail-ro/samegroup/inventory.json \
  --resources /tmp/pail-ro/samegroup/resources.json --root /tmp/pail-ro/samegroup \
  > /tmp/pail-ro/samegroup.json; echo rc=$?
```

Expected: `rc=1`; one finding `FAIL RO-C08.declared` for `robot-added-02`,
reason `two robots share a declared isolation group`; everything else PASS.

**Robot 2 bound to robot 1's certificate** (edit `inventory.json`):

```sh
cp -R /tmp/pail-ro/two /tmp/pail-ro/wrongcert
python3 - <<'EOF'
import json
p='/tmp/pail-ro/wrongcert/inventory.json'; d=json.load(open(p))
d['robots'][1]['client_credential_ref']='cred:c0'
json.dump(d,open(p,'w'),indent=2)
EOF
/tmp/pail-ro/check --inventory /tmp/pail-ro/wrongcert/inventory.json \
  --resources /tmp/pail-ro/wrongcert/resources.json --root /tmp/pail-ro/wrongcert \
  > /tmp/pail-ro/wrongcert.json; echo rc=$?
```

Expected: `rc=1`; `FAIL RO-C03.static` for `robot-added-02`, reason
`leaf not bound to this robot`.

**A referenced file is missing** (remove the CA):

```sh
cp -R /tmp/pail-ro/two /tmp/pail-ro/missing && rm /tmp/pail-ro/missing/ca.crt
/tmp/pail-ro/check --inventory /tmp/pail-ro/missing/inventory.json \
  --resources /tmp/pail-ro/missing/resources.json --root /tmp/pail-ro/missing \
  > /tmp/pail-ro/missing.json; echo rc=$?
```

Expected: `rc=2`; `CANNOT_CHECK RO-C03.static` for both robots (`CA ref
unavailable`) and, because the credential route can no longer be resolved,
`FAIL RO-C07.declared` for both. The summary is `CANNOT_CHECK`: an unmeasured
check is reported as unmeasured, never folded into a pass.

## 6. Clean up

```sh
rm -rf /tmp/pail-ro
```

The extracted archive was not written to. If you built inside the tree or wrote
results there, `scripts/verify_release.py` reports the extra files; that is the
integrity check working, not a robot or authorization failure.
