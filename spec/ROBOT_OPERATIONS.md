# Robot operations — public integration guide

English canonical; [한국어](ROBOT_OPERATIONS.ko.md).
This is an **experimental pre-1.0 contract**, not a complete fleet manager.
Check the release identity and proto/schema versions when integrating; future
incompatible changes require migration rather than silent acceptance.

## 1. Included and excluded

| Component | Delivered scope | License |
|---|---|---|
| `cloud/cmd/pail_robotops_check` | Offline declared identity, routing, skills and isolation checks; `describe` emits a planned inventory | Apache-2.0 |
| `pail_issuer_robotops_check` (evaluation image) | Offline issuer requester/grant checks | Separate evaluation binary license |
| `cloud/cmd/pail_robotops_fixture` | Writes a throwaway, complete declaration set for the two checkers; no private key is written | Apache-2.0 |
| `cloud/pkg/robotops`, [proto](../sdk/proto/robot_ops_service.proto) | Typed documents, canonicalization, approvals, probes and management RPC contracts | Apache-2.0 |
| Issuer evaluation executable | Opt-in admission holds, maintenance lock register and enforcement | Separate evaluation binary license |
| Commercial orchestrator | Planning, credential preparation, approval workflows, apply, recovery and resume orchestration | **Not included** |

The shipped dashboard can display robot operations projections. Display is not
an authority to issue or resume motion, and the projection producer/orchestrator
is not included. No physical stopping, independent safety attestation, fleet-scale
rolling update or remote apply capability is established by this guide.

Start with the [runnable offline example](../examples/robotops/README.md).
A PASS means only the stated checks passed. `ready_for_apply` remains false;
`runtime_observed` is false for offline checks. Codes: 0 all scoped checks pass,
1 observed mismatch, 2 incomplete/invalid evidence or usage. Mixed FAIL and
CANNOT_CHECK retains both and returns 2. Do not change validators to obtain PASS.

## 2. Public interfaces and listeners

| Interface | Listener / access | Meaning |
|---|---|---|
| `RobotBindingProbe.ProbeBinding` | Issuer mTLS; loaded client identity and registry binding | Nonce-bound read-only binding and loaded generation |
| `RobotAgentSelfProbe.ProbeSelf` | Agent Unix socket; owner/root UID checked by the method | Loaded agent TLS identity and queried upstream binding, no token fetch |
| `IssuerOpsAdmin.GetCapabilities/GetLoadedStatus/GetHoldStatus` | Dedicated local Unix socket, allowed kernel peer UID | Management capability/loaded/hold observations |
| `IssuerOpsAdmin.BeginHold/ConfirmQuiesced/ReleaseHold/AdoptHold` | Same local socket plus signed approval and canonical plan/evidence bindings | Durable management transitions; not a general remote administration API |
| Gate/bridge status | Private Unix socket, same UID/root; **not gRPC ProbeSelf** | 64 lowercase-hex nonce plus newline; bounded JSON string-map reply |
| `/v1/telemetry/robotops` | Existing telemetry HTTP listener/authentication | Sanitized projection; ETag/304, revision/member mismatch 409, unavailable schema/data 503, stale flag |
| `/v1/telemetry/robotops/probe` and `/signals` | Same telemetry authentication; nonce parameter | Query-time registry or verified live receipt observations, not historical substitutes |

Management mutations are not registered on the issuer TCP listener. A valid
signature alone is insufficient: deployment, plan digest, action, execution,
target scope, trust epoch and validity must match. Roles separate apply, resume,
recover and observation. Durable hold ownership and approval consumption are
additional checks; the pure `VerifyApproval` function does not itself persist them.
Do not release a hold by editing its database, deleting its volume or spoofing a
projection. BeginHold prevents new grants; it is not proof that motors have stopped.
ConfirmQuiesced concerns software observations; it is not a certified physical stop.

### Unix socket permissions are not the entire authorization policy

The TB3 kit uses UID/GID 10001: gate/bridge status sockets are 0600; `agent.sock`
is 0660. The agent socket also registers Northbound, Token and Operator services,
not only its self-probe. File mode/parent traversal, transport peer identity and
method/robot/operator authorization are separate layers. ProbeSelf rejects callers
other than the agent owner or root. The supplied Go observer client also verifies
the server's UID; a root process using that client may reject a non-root server.
Prefer running the observer as the component owner; do not widen permissions.

Gate/bridge responses are local process self-reports with boot/start/instance,
monotonic sample, nonce and loaded settings hash. The observer must pin the peer
executable/UID and compare independently prepared settings. A ZERO observation
means ROS publish returned, not driver delivery or physical stopping. Startup
NONE is not ZERO. These replies alone do not authorize apply or resume.

## 3. Configuration reference for these interfaces

These are **conditional** settings, not a list to enable indiscriminately. Existing
[security startup requirements](../TRUST_BOUNDARY.md) and component configuration
still apply. The broader configuration registry/scanner are maintainer tools,
not delivered commands. No secret values are included below.

| Setting | Consumer; default/unset | Contract |
|---|---|---|
| `PAIL_OPS_DEPLOYMENT_ID` | Issuer, agent, gate/bridge; unset disables binding probes | Lowercase UUID for the same deployment. Required by holds and node status; not an authority grant. |
| `PAIL_OPS_HOLD_DIR` | Issuer; unset means hold capability absent | Persistent issuer-owned 0700 directory. Requires deployment ID, trust file and admin socket. Store loaded before serving; unusable store refuses startup. Preserve across container replacement. |
| `PAIL_OPS_TRUST` | Issuer; no default | Path to operations trust JSON: public keys, roles, target scopes, trust epoch. Required for management and configured policy/site authorization. No private signing key belongs here. Malformed/unreadable required input refuses startup. |
| `PAIL_OPS_ADMIN_SOCKET` | Issuer; no default | Required with hold directory; local Unix path, socket 0600. Parent must be traversable by the service and protected from unintended writers. Not a TCP endpoint. |
| `PAIL_OPS_ADMIN_UIDS` | Issuer; unset adds no extra UID | Comma-separated uint32 UIDs; issuer UID is allowed by default. Invalid numeric entry refuses startup. Kernel UID permission does not replace signed mutation approval. |
| `PAIL_LOTO_DIR` | Issuer; unset means lock capability absent | Persistent issuer-owned 0700 directory; mTLS required. Active locks restore MAINTENANCE before serving. Preserve state; never delete it to unlock. |
| `PAIL_LOTO_SUPERVISORS` | Issuer; unset means no additional supervisors | Path to JSON `{"supervisors":[{"cert_sha256":"<64 hex>","id":"name"}]}`. Registered certificate fingerprints may release another applier's lock with a reason. Malformed/unreadable input refuses startup when configured. |
| `PAIL_POLICY_AUTH` | Issuer; no default | Path to authorization bundle for the exact policy bytes, using distinct trusted principals with policy_change authority. Missing authorization refuses production (S40); dev exception is explicitly marked insecure. |
| `PAIL_SITE_MODEL_AUTH` | Issuer; no default | Corresponding authorization for exact site-model bytes and scope `res:site_model`. With a configured site model, missing authorization refuses production (S40b); dev exception is explicit. |
| `PAIL_ROBOTOPS_STATUS_SOCKET` | Gate/bridge; unset disables status | Absolute Unix path in a component-owned 0700 parent; socket 0600. Requires deployment UUID and robot identity. Gate uses its resolved robot_id; bridge uses `PAIL_ROBOT_ID`. Stale same-owner refused-connection endpoints may be reclaimed; live/foreign endpoints refuse startup. |
| `PAIL_GRPC_UDS_PATH` | Agent; unset means no Unix listener | Enables the existing 0660 agent listener; deployment ID enables its additional self-probe. Existing agent mTLS configuration remains required for binding observation. |
| `PAIL_ROBOTOPS_PROJECTION` | Collector; unset gives feature-unconfigured 404 | Path to the sanitized projection JSON, produced externally. Missing/unreadable/invalid configured data is not healthy. Does not enable apply. |
| `PAIL_ROBOTOPS_PROJECTION_MAX_AGE_S` | Collector; default 300 seconds | Positive age threshold for stale display. Invalid override logs a warning and uses 300; no authorization decision is made from this value. |
| `PAIL_HW_DEPLOYMENT_ID` | TB3 kit; unset means no new probes | Wrapper that passes deployment identity and enables the robot-side probe/status endpoints; see [hardware guide](../examples/tb3/HARDWARE.md). |

Treat loaded trust, policy, site and declaration changes as controlled deployment
changes; these variables do not promise hot reload. Verify the loaded generation
after restart. Trust/public configuration may be readable to the service, but
must not be writable by untrusted users. Keep private signing keys outside public
fixtures and scopes. Back up persistent stores before maintenance, not in lieu of
an authorized hold/recovery procedure.

## 4. Tests and limits

Offline examples exercise declared snapshots, not credentials in a running robot,
DDS isolation or driver behavior. The archive also includes unit/integration tests
for `pkg/robotops`, `internal/robotopscheck`,
`issuer/internal/robotopscheck`, `issuer/internal/grpcserver` (hold transitions,
reopen durability, admission, UID and concurrent grants) and telemetry projection.
From `cloud/`, run `go test -tags pail_generated ./...` with Go 1.27.2 or the documented
supported toolchain. First dependency download requires network/cache availability.
There is no claim of an offline cold build or of live-hardware coverage from unit tests.
The management-hold and agent-guard tests read Linux kernel identity sources (boot id,
monotonic clock); on macOS or another non-Linux host they report `SKIP` with that reason
and the command still exits 0. A skip is not a pass: run the same command on Linux to
measure those paths. The whole extracted tree must be present — `cloud/` alone lacks
the `spec/vectors/` the canon tests read.

Verify the untouched archive before development. `go mod tidy` and source edits
can change checksummed files; a later release-integrity mismatch then means that
copy differs from the delivered source, not that robot authorization failed.
