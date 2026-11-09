# First-release compatibility and retained evidence

한국어: [COMPATIBILITY.ko.md](COMPATIBILITY.ko.md).
The supported default is one release's issuer, robot agent, gate, SDK, tools and
example configuration together. This is a deployment boundary, not a claim of
universal wire negotiation or compatibility with every previous build.

## Check the delivered bundle before running it

Use the release's documented `scripts/verify_release.py` command in
[RELEASE.md](../RELEASE.md), with the intended `--expected-release` and the trusted
manifest. The existing checker compares identity, archive/file hashes and bundle
boundaries. A missing manifest or mismatched file is not a successful check.
It checks the delivered bytes, **not** the provenance of arbitrary already-running
processes. Pin image digests/build evidence as described by the example runner;
do not substitute another executable with the same filename and call it tested.
The verifiers need no installed cryptography on a supported host: the Core source
carries `cloud/cmd/pail_verify` (standard library only, used by `verify_release.py`
through `go run`) and every evaluation bundle ships it built as
`native/pail_verify-<host>`, checked against the lock before use. A verification PASS
leaves a receipt outside the delivery; the evaluation launcher's `load` and run actions
print a `VERIFICATION:` line from it and record it in `platform.json` — reported by
default, refused only with `--require-verified`.

| Contract | Policy |
|---|---|
| Gate ABI / signed token schema | Existing declared ABI/schema checks remain. This change does not add new token fields or weaken unknown required-authority checks |
| TOKEN_ISSUED / GATE_DECISION journal v10 | Requires the v10 completion reader/restorer; see [COMPLETION_JOURNAL.md](COMPLETION_JOURNAL.md) |
| Future issuance/completion semantic version | New operational reader refuses; it cannot safely guess |
| Legacy skill-based issuance without completion rule | Operational replay refuses with `LEGACY_COMPLETION_AMBIGUOUS`; stored bytes remain readable for integrity verification |
| Pre-skill legacy operational records | Existing fixed legacy interpretation is retained where identifiable; this is not acceptance of all historical skill configurations |
| Legacy completion in observation reports | Acceptance is unknown. Do not label the report as confirmed completion |
| New journal with old runtime/tool | Unsupported. Old binaries may ignore new fields; documentation cannot retrofit their checks |
| Mixed arbitrary component versions | Not the supported first-release path. Use an explicitly tested combination or report unverified compatibility |

## Preserve evidence; do not silently resume ambiguous state

Keep original tokens, segments, trust roots and required verification inputs.
Integrity verification and operational replay answer different questions.
A readable, intact legacy journal can still lack enough information to resume a
robot's active authority safely. Do not rewrite signed segments, manufacture
acceptance fields or bypass replay guards to make it start.

The default migration is a planned transition: account for/retire existing robot
permissions, preserve the original evidence, then initialize a fresh evaluation
state and submit new plans. Never delete active state while robots are running.
A generic in-place migration or rolling downgrade is not supplied by this change.
Where replay cannot establish the needed state, resolve the migration explicitly.

## Subsequent versions

Version external meaning, not just JSON shape. Distinguish optional application
metadata from mandatory authority conditions. Publish supported combinations,
changed fields/behavior and migration instructions. Internal implementation can
change without forcing OEM rewrites when those external contracts remain stable.

Changed external contracts in this line (additive, declared in `spec/vectors/contract/ros_msgs.vec`):

- `pail_msgs/GateState` carries four fields after `effective_mode`: `detail` (the refusal's
  detail string), `step_deadline_elapsed_ms` (the active step's deadline on the gate's elapsed
  clock), `step_clock_id` (that clock's identity) and `completed_token_id` (the token a
  completing PERMIT consumed). Subscribers that read the first seven fields by name are
  unaffected; a subscriber that froze the message by field count must take eleven.
- Reason registry: `ERR_BUNDLE_CLOCK`, `ERR_BUNDLE_LIFETIME` and `ERR_BUNDLE_POLICY` (start-up
  refusals of the keyring-bundle loader, local plane, never on the wire) are registered with
  values 0x8B–0x8D; before this release the gate issued them without an entry.

## Stateful issuer entry point

The operational replay checks described here are wired into `pail_cloud` with
replay enabled. The legacy combined `pail_services` entry point does not invoke
that restoration path and is not a supported substitute for continuing an
existing authority store. Fresh-state legacy demonstrations are a different
scope. Do not disable replay to bypass an ambiguous-journal refusal.
