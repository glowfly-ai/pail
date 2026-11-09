# PAIL architecture and implementation guide

PAIL authorizes physical actions and enforces the resulting authority at the robot.
This document is self-contained; no private design document is required.

## Components

| Component | Public source | Responsibility |
|---|---|---|
| Decision library | `libpail_gate/` | Verify the original signed token bytes, validity, identity and action constraints |
| Robot gateway | `cloud/cmd/pail_robot_agent/` | Public token relay, delegated windows, report delivery and recovery |
| Issuer | **Binary only**, separate evaluation image | Policy/skill judgment, signed issuance, journal-backed authority and replay |
| ROS 2 gate | `robot/pail_pep_gate/` | Check commands against current authority and observation prerequisites |
| Motion bridge | `robot/pail_motion_bridge/` | Forward authorized commands; emit zero after permit loss/deadman expiry |
| Journal and verifier | `cloud/internal/blackbox/`, `cmd/pail-verify/` | Record and independently check the relevant evidence formats |
| Observation UI | `cloud/cmd/pail_telemetryd/` | Display data and uncertainty; never feed an authorization decision |
| Permit mirror | `examples/permit_mirror/` | Reference signed liveness-message producer; separate from the command path |

Use [SKILLS.md](SKILLS.md) for skill fields, [SITE_MODEL.md](SITE_MODEL.md) for site
configuration, [ADAPTER_CONTRACT.md](ADAPTER_CONTRACT.md) for porting, and
[API_SURFACES.md](API_SURFACES.md) for public interfaces.

See [supported behavior and OEM extension points](SUPPORTED_BEHAVIOR.md),
[completion journal semantics](COMPLETION_JOURNAL.md), and
[first-release compatibility](COMPATIBILITY.md) before integrating or upgrading.

## Data flow and a first adapter

```text
FMS / planner -- SubmitActionPlan --> Issuer evaluation executable
                                     | signed token + journal
Your adapter -- GetActiveToken --> Robot gateway <----> Issuer
     |
     +-- original bytes / feeds / each command --> libpail_gate
     +-- forward only when authorized; otherwise stop --> controller
     +-- decision reports --> gateway --> journal --> public verifier
```

The gateway pulls and reconciles authority; the gate library makes the per-command
judgment. Neither replaces trajectory planning or hardware safety.
[Run an evaluation Issuer for your adapter](../examples/adapter/README.md) describes
ports, mounts, fresh keys, custom robot classes and the executable conformance rig.

## Authorization and evidence are distinct

The issuer records before returning issued authority. The gate validates the original
signed bytes and refuses absent, expired, revoked or mismatching authority. The bridge
has its own loss-of-permit behavior. Physical braking, sensor truth, trusted transport,
key custody and bypass prevention still require deployment integration; see
[../TRUST_BOUNDARY.md](../TRUST_BOUNDARY.md).

The local test's file anchor is not an independently operated external witness.
The anchor server is a separately offered service. Read [VERIFICATION_INPUTS.md](VERIFICATION_INPUTS.md)
and [TRUST_ROOT.md](TRUST_ROOT.md) for independent verification, not internal server paths.

## Correlation hashes are not authorization identities

The burst `token_hash16` is a truncated correlation hint, **not an identity claim**.
It MUST NOT be used as an input to an authorization decision. Use the authenticated
token bytes and `consumption_key` rules for the actual security decision. A timeline's
approximate match is not proof that a physical action occurred.

The correlation-hash invariant is checked by the distributed cross-language tests.
Other retained markers such as `G-*`, `S*`, `CA-*` and test names identify checks;
their public meaning must be explained by the adjacent code or public specification.

## Development and tests

Generate protobuf sources inside `cloud/` with `make proto PROTO_DIR=../sdk/proto`.
Run Go tests from a complete snapshot, not from a builder layer containing only cloud
sources: tests also read the distributed `spec/vectors`, ROS message definitions and
reference producer. Tests resolve both source-development and public-release layouts.
A missing required input is a failure, not an implicit skip.

The optional `red_lldb` build-tag tests include historical adversarial probes. Their
names do not imply that all such probes are supported release acceptance tests. The
correlation-warning test can run using this document and the shipped source surfaces.
For supported end-to-end entry points, see [../TRY_IT.md](../TRY_IT.md).

## Reading the source

Go directories named `internal/` are ordinary distributed implementation packages
with Go import visibility rules; the name does not mean their source is undisclosed.
Korean translations, multilingual test cases and frozen vector comments are legitimate
distributed content. Do not modify signed/hash-pinned bytes to change their language.
Older regression-test comments may retain traceability IDs; they are not required
reading of a private document. Run `python3 scripts/check_public_content.py` for the
public-reader content checks, and `scripts/check_public_links.py` for file links.

The deployment-guard truth table `robot/pail_deploy_guard/test/guard_matrix.tsv`
is also retained byte-for-byte, including original comment metadata. Such metadata
is not a runtime dependency on an unpublished design document.
