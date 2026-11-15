# API surfaces

PAIL has four places where something outside it has to speak or listen: the
refusal a caller gets back, the evidence a sensor asserts, the safety state the
machine's own safety layer publishes, and the operator control plane. This
document is the contract for those four.

It is deliberately narrow. It does not describe how to issue a token, how the
gate decides, or how to deploy anything — it describes the **shapes on the
boundary**, so that a third party integrating a fleet manager, a reader, or a
safety adapter can write against them without reading our internals.

> 한국어판: [`API_SURFACES.ko.md`](API_SURFACES.ko.md). The English document is
> canonical; if the two diverge, the English text governs.

## 1. The four surfaces

| surface | transport | who speaks | who listens | reference |
| --- | --- | --- | --- | --- |
| Refusal | gRPC response field | issuer | fleet manager / caller | §2 |
| Evidence | ROS 2 topic `/pail/evidence` | reader, camera, operator UI | gate | §3 |
| Safety state | ROS 2 topic `/pail/safety_state` | machine safety layer | gate | §4 |
| Stop assertion | ROS 2 topic `/pail/stop_request` | gate | machine safety adapter | §4.4 |
| Operator plane | gRPC `OperatorService` | operator tooling | issuer | §5 |

Read the sections in this order of questions — what the surface is for, who sends it to
whom, what goes in, what comes back, what the caller has to do with it, and where a
shipped example shows it:

| surface | purpose | sender → receiver | input | response | what the caller does | example |
| --- | --- | --- | --- | --- | --- | --- |
| Refusal | tell a caller why a plan or token request was not granted, and whether to retry | issuer → fleet manager / caller | the `Denial` field of a gRPC response | `reason_code`, `disposition`, `severity`, `retry_after_ms`, two booleans | branch on `disposition`; alarm on `severity`; never retry before `retry_after_ms` | §2.6 |
| Evidence | assert what a sensor or an operator observed about a target | reader, camera, operator UI → gate | `/pail/evidence` messages | none (the gate consumes them; the decision shows in the permit) | publish at the policy's freshness rate; grade the `source` honestly | §3.4 |
| Safety state | publish the machine's own safety level | machine safety layer → gate | `/pail/safety_state` | none | publish continuously; a stale state is a stop | §4.2 |
| Stop assertion | ask the machine to stop | gate → machine safety adapter | `/pail/stop_request` | the adapter's own acknowledgement path | stop, then stay latched until the safety layer releases | §4.4 |
| Operator plane | unlock, revoke, read context events | operator tooling → issuer | `OperatorService` RPCs carrying a nonce | per-RPC responses | keep the nonce floor; treat events as read-only context | §5 |

Each section below names a shipped, runnable example. Those examples are the
third leg of the check described in §8: a surface documented but never exercised
by anything that ships is a surface nobody has tried.

## 2. Refusal — `Denial`

<!-- source: sdk/proto/pail.proto -->

Every response that can reject carries a structured `Denial`. It is present on
`SubmitActionPlanResponse`, `SubmitTextCommandResponse` and
`GetPlanStatusResponse`, and it is populated whenever the status is a rejection.

These responses also carry a free-text `rejected_reason`. **Do not branch on
it.** It is a human-readable string with no stability guarantee; the machine
contract is `Denial` and nothing else.

Transport identity failures are gRPC `PermissionDenied` with
`ERR_IDENTITY_UNBOUND`, not a successful application response. For plan-only
`CancelPlan` and `GetPlanStatus`, the server resolves the current plan owner and
checks the calling leaf against the robot registry under the chain lock before
cancelling or returning plan state. A registered orchestrator retains delegated
access. Missing registry context on an mTLS call is denied. Dev/UDS identity
remains explicitly unchecked; it is not evidence of per-robot mTLS isolation.

### 2.1 Fields

<!-- vocab: denial -->

| field | type | meaning |
| --- | --- | --- |
| `reason_code` | `string` | Stable identifier for the refusal. Drawn from the same dictionary as the on-wire burst vocabulary, so a refusal seen in a log and a refusal seen on the safety bus can be matched. |
| `reason_value` | `uint32` | The numeric form of the same reason, for byte-level correlation with burst evidence. |
| `disposition` | `Disposition` | What the caller should *do* (§2.2). This is the field to branch on. |
| `retry_after_ms` | `uint64` | Lower bound on how long to wait before retrying. It is a floor, not a schedule (§2.4). |
| `severity` | `Severity` | Whether this refusal is worth waking a human for (§2.3). Orthogonal to `disposition`. |
| `observed_epoch` | `uint64` | The world-state version the refusal was decided against. |
| `detail` | `string` | Human-readable. Not machine-parseable, not stable. |
| `origin_reason_code` | `string` | When the refusal is itself a rate limit, the reason that originally caused it. |
| `retry_forbidden` | `bool` | `true` asserts as a **fact** that retry is forbidden (§2.5). |
| `epoch_ephemeral` | `bool` | `true` asserts as a **fact** that there was no world version (§2.5). |

### 2.2 `disposition` — what to do

<!-- vocab: disposition -->

| value | number | meaning |
| --- | --- | --- |
| `DISPOSITION_UNSPECIFIED` | 0 | The sender did not say. Treat as "do not know", never as "retry is fine". |
| `PERMANENT` | 1 | This plan will never pass. Change the plan or escalate; retrying is pure load. |
| `CONDITIONAL` | 2 | Something about the world or the plan has to change first. Time alone will not fix it. |
| `TRANSIENT` | 3 | Time alone may fix it. Retry after the floor. |

### 2.3 `severity` — whether to alarm

<!-- vocab: severity -->

| value | number | meaning |
| --- | --- | --- |
| `SEVERITY_UNSPECIFIED` | 0 | The sender did not say. |
| `NORMAL_DEFENSE` | 1 | The system refusing as designed. Not an alert. |
| `ANOMALY` | 2 | Should not happen in a healthy system. Worth investigating. |
| `SUSPECTED_TAMPER` | 3 | Possible integrity violation. Investigate immediately. |

`severity` and `disposition` are independent axes and must stay that way in the
caller too. A `PERMANENT` refusal is usually `NORMAL_DEFENSE` — the system
working. Routing alerts off `disposition` instead of `severity` produces a page
for every ordinary refusal, and a channel that pages constantly is a channel
nobody reads.

### 2.4 `retry_after_ms` is a floor

The field says *not before*, not *at*. The correct wait is
`max(your own backoff, retry_after_ms)`. Treating it as a schedule turns every
client into a synchronised herd that all retries at the same instant.

### 2.5 Why two booleans exist

<!-- pin: sdk/proto/pail.proto -->
```proto
  bool        retry_forbidden = 9;   // true = 재시도 금지가 **사실**이다
  bool        epoch_ephemeral = 10;  // true = 세계 버전이 없다는 것이 **사실**이다
```

proto3 does not serialise scalar zero values. To a receiver, `retry_after_ms = 0`
and "that field never arrived" are the same bytes. That single zero was carrying
three different meanings: retry is forbidden, the floor is unknown, and the floor
had not been computed yet.

So the two assertions were moved out of the zero and into fields of their own.
The reason they are separate booleans rather than tri-state enums is
compatibility: a message from an older sender decodes with both booleans
`false`, which reads as "did not say" — silence never hardens into "forbidden"
or "ephemeral".

The rule for a caller is therefore: **read the boolean, not the zero.**
`retry_after_ms == 0` on its own means nothing.

### 2.6 Worked example

<!-- example: cloud/cmd/fms_denial_example/main.go -->

`cloud/cmd/fms_denial_example` is a fleet-manager-side handler that branches on
`disposition`, applies the floor as a floor, and routes alerts off `severity`.

<!-- example: sdk/grpc_client_go/cmd/submit_plan/main.go -->

`sdk/grpc_client_go/cmd/submit_plan` is the smaller one: a single call that reads
the structured refusal rather than the free-text string, and reads
`retry_forbidden` rather than inferring it from a zero.

## 3. Evidence — `/pail/evidence`

<!-- source: robot/pail_msgs/msg/Evidence.msg -->

An evidence message is a claim that some identifiable thing is present. It is
what an RFID reader, a barcode scanner or a vision pipeline publishes, and it is
what the gate consults before permitting motion against a target.

### 3.1 Fields

<!-- vocab: evidence -->

| field | type | meaning |
| --- | --- | --- |
| `stamp` | `builtin_interfaces/Time` | When the claim was made. Judged for freshness (§3.3) — **not** the time you published, the time you observed. |
| `source` | `string` | Which modality made the claim (§3.2). Graded; an ungraded spelling is not a weaker claim, it is an unusable one. |
| `object_id` | `string` | The thing being claimed. |
| `confidence` | `float32` | 0.0–1.0. Compared against the policy threshold. |
| `frame_id` | `string` | Optional frame for `pose`. |
| `pose` | `geometry_msgs/PoseStamped` | Optional. Where the thing is. |

<!-- pin: robot/pail_msgs/msg/Evidence.msg -->
```
builtin_interfaces/Time stamp
string source  # BARCODE|NFC|RFID|VISION|MANUAL
string object_id
float32 confidence
string frame_id
geometry_msgs/PoseStamped pose
```

### 3.2 `source` and its grade

<!-- source: config/policy.yaml -->

A source is not free text. Every accepted spelling is graded exactly once in the
site's policy file, into one of three trust classes.

<!-- vocab: evidence_source -->

| source | trust class | what it is |
| --- | --- | --- |
| `BARCODE` | `identity_bearing` | The tag itself carries the identity. |
| `NFC` | `identity_bearing` | The tag itself carries the identity. |
| `RFID` | `identity_bearing` | The tag itself carries the identity. |
| `VISION` | `inferential` | The identity is inferred from appearance, not carried. |
| `MANUAL` | `asserted` | A human said so. |

<!-- vocab: trust_class -->

| class | rank | meaning |
| --- | --- | --- |
| `identity_bearing` | 3 | The claim's identity came from the object. |
| `inferential` | 2 | The claim's identity was derived by a model. |
| `asserted` | 1 | The claim's identity was typed in. |

<!-- pin: config/policy.yaml -->
```yaml
trust_classes:
  - id: identity_bearing
    rank: 3
    sources: [RFID, NFC, BARCODE]
  - id: inferential
    rank: 2
    sources: [VISION]
  - id: asserted
    rank: 1
    sources: [MANUAL]
```

The default policy also sets `min_trust_class: identity_bearing`, and this is
the single most common surprise for an integrator: **at the default setting a
`VISION` claim is refused at any confidence.** Raising `confidence` to 1.0 does
not help, because the grade is a property of the modality, not of the reading.

Note where that refusal happens. The issuer does not enforce the minimum — it
only refuses to start if the configured name does not resolve against
`trust_classes`. The refusal on a low-grade claim is the gate's.

### 3.3 Freshness

<!-- pin: config/policy.yaml -->
```yaml
preconditions:
  - id: safety_feed
    class: must_check_live
    freshness_ms: 1000
```

Evidence and safety state are both *must-check-live* facts: they are only usable
while recent. The evidence window is longer than the safety window because a
target identification stays true for longer than a safety condition does.

This has a consequence that costs people an afternoon. A publisher that leaves
`stamp` at zero is claiming to have observed the world in 1970, so the gate
correctly judges the claim stale and blocks. The symptom — the gate refusing the
target — looks like a policy rejection rather than a message that was never
dated. Command-line publishing helpers commonly default the stamp to zero. Stamp
the message with the observation time.

### 3.4 Worked example

<!-- example: e2e/feeders.py -->

`e2e/feeders.py` publishes both live feeds at a fixed rate with current stamps.
It exists because the naive command-line publisher hits exactly the zero-stamp
trap above.

## 4. Safety state — `/pail/safety_state`

<!-- source: robot/pail_msgs/msg/SafetyState.msg -->

This is the machine's own safety layer talking to PAIL. PAIL does not evaluate
safety; it consumes a verdict and refuses to permit motion when that verdict is
anything other than good.

### 4.1 Fields

<!-- vocab: safety_state -->

| field | type | meaning |
| --- | --- | --- |
| `stamp` | `builtin_interfaces/Time` | Observation time. Judged for freshness on the shorter window (§3.3). |
| `level` | `string` | The verdict (§4.2). Exactly three spellings are recognised. |
| `source` | `string` | Which safety layer is speaking, e.g. a PLC or a zone scanner. |
| `detail` | `string` | Human-readable. Not parsed. |

### 4.2 `level` and what each one does

<!-- source: libpail_gate/include/pail_gate/safety_level.hpp -->

<!-- vocab: safety_level -->

| `level` | parses to | E-STOP action |
| --- | --- | --- |
| `OK` | `kOk` | `kRelease` |
| `WARN` | `kWarn` | `kHold` |
| `UNSAFE` | `kUnsafe` | `kTrigger` |
| `*` | `kUnknown` | `kHold` |

`*` is every other string: the empty string, a typo, a level from a future
version of your safety layer. All of them land on `kUnknown`.

<!-- pin: libpail_gate/include/pail_gate/safety_level.hpp -->
```cpp
inline SafetyLevel ParseSafetyLevel(const std::string &s) {
  if (s == "OK") return SafetyLevel::kOk;
  if (s == "WARN") return SafetyLevel::kWarn;
  if (s == "UNSAFE") return SafetyLevel::kUnsafe;
  return SafetyLevel::kUnknown;  // 빈 문자열·오타·미래 레벨 전부 여기 (§4.1)
}
```

`kUnknown` blocks new permits exactly like `kUnsafe` does, but it is a separate
value rather than an alias, because the journal has to be able to distinguish
*the feed went silent* from *the feed started speaking a level we do not know*.
Those two call for different repairs, and collapsing them into one value would
make the second one invisible.

The single most important thing on this surface: **the good level is spelled
`OK`.** Publishing `SAFE` does not mean safe — it is an unrecognised string, so
it holds the E-STOP latch and blocks new permits.

### 4.3 The E-STOP latch

<!-- vocab: estop_action -->

| action | meaning |
| --- | --- |
| `kTrigger` | Assert the stop. |
| `kRelease` | Release the latch. |
| `kHold` | Leave the latch as it is — neither assert nor release. |

<!-- pin: libpail_gate/include/pail_gate/safety_level.hpp -->
```cpp
inline EstopAction EstopActionFor(SafetyLevel l) {
  switch (l) {
    case SafetyLevel::kUnsafe:  return EstopAction::kTrigger;
    case SafetyLevel::kOk:      return EstopAction::kRelease;
    case SafetyLevel::kWarn:    return EstopAction::kHold;
    case SafetyLevel::kUnknown: return EstopAction::kHold;
  }
```

`kOk` is the only release path, and the mapping is a total switch with no
`default` label. Both properties are deliberate. An earlier shape released the
latch on every value that was not `UNSAFE`, which meant a publisher changing one
string could disarm an emergency stop. And a `default` label would let a
future safety level be absorbed silently into an existing branch — the absence of
one means a new value fails the build instead.

### 4.4 Stop assertion — `/pail/stop_request`

<!-- source: robot/pail_msgs/msg/StopRequest.msg -->

<!-- vocab: stop_request -->

| field | type | meaning |
| --- | --- | --- |
| `stamp` | `builtin_interfaces/Time` | When the stop was asserted. |
| `reason` | `string` | Why. Human-readable. |

<!-- pin: robot/pail_msgs/msg/StopRequest.msg -->
```
builtin_interfaces/Time stamp
string reason
```

Read the direction of this topic carefully. PAIL publishes it; it does not
consume it. PAIL's responsibility ends at this message. Converting it into an
actual certified safety input — a GPIO line, a safety PLC input — is the
integrator's, and a ROS topic is not by itself a safety function.

## 5. Operator plane — `OperatorService`

<!-- source: sdk/proto/operator_service.proto -->

Three RPCs, all issuer-side. Robots and the gate never see any of them.

### 5.1 Context events

The issuer authorizes against a world model. `IngestContextEvent` is how the
world changes: a person walks into a zone, an object is moved, a robot goes into
maintenance. Mutations are serialised with issuance, so every token is signed
against a consistent cut of the world.

Who may send one is decided by the requester registry, the same file that names
the identities allowed to submit plans. An entry carries a `context_events`
grant: event kind names, `CUSTOM:<namespace>.<name>` for a declared custom
event, or `"*"`. With a registry loaded the default is refusal — a transport
identity that is not in the registry, or whose entry has no grant for the kind
it sends, is refused, and the arrival is still journaled. A custom event is
granted by its declared name, not through the built-in kind it maps to. The
lock register (`ApplyLock`, `ReleaseLock`) is authorized by its own ownership rules and does not ask
for this grant. What a granted sender reports is not verified: the grant says
who may speak, not that what is said is true.

<!-- vocab: context_event_kind -->

| kind | number | `node_id` / `arg` |
| --- | --- | --- |
| `CONTEXT_EVENT_KIND_UNSPECIFIED` | 0 | Rejected. An unnamed mutation is not applied. |
| `HUMAN_ENTER` | 1 | zone id / human id |
| `HUMAN_LEAVE` | 2 | zone id / human id |
| `OBJECT_MOVE` | 3 | object id / destination zone id |
| `MAINTENANCE_ON` | 4 | robot id |
| `MAINTENANCE_OFF` | 5 | robot id |
| `CORDON_ON` | 6 | robot id |
| `CORDON_OFF` | 7 | robot id |
| `CUSTOM` | 8 | as the mapped kind; `custom_kind` = `<namespace>.<name>` declared in the site model's `custom_events` |

<!-- pin: sdk/proto/operator_service.proto -->
```proto
enum ContextEventKind {
  CONTEXT_EVENT_KIND_UNSPECIFIED = 0; // rejected (fail-closed)
  HUMAN_ENTER = 1;   // node_id = zone id; arg = human local id
  HUMAN_LEAVE = 2;   // node_id = zone id; arg = human local id
  OBJECT_MOVE = 3;   // node_id = object id; arg = destination zone id
  MAINTENANCE_ON = 4;  // node_id = robot id (LOTO)
  MAINTENANCE_OFF = 5; // node_id = robot id
  CORDON_ON = 6;       // node_id = robot id (isolation)
  CORDON_OFF = 7;      // node_id = robot id
  // AG-8: a customer-defined world event. custom_kind names it
  // ("<namespace>.<name>", lowercase [a-z0-9_] on both sides) and the site
  // model's `custom_events` maps that name to one of the built-in kinds
  // above, whose node_id/arg conventions then apply. An undeclared name, an
  // empty custom_kind, or custom_kind on a non-CUSTOM kind is rejected
  // (fail-closed); nothing is mapped implicitly.
  CUSTOM = 8;
}
```

Customer-defined events (AG-8) do not extend the vocabulary of mutations, they
name it: a site model declares

```yaml
custom_events:
  - id: acme.gas_alarm      # <namespace>.<name>
    effect: CORDON_ON       # a built-in kind; node_id/arg follow its convention
```

and a `ContextEvent{kind: CUSTOM, custom_kind: "acme.gas_alarm", node_id:
"robot:robot-01"}` is applied exactly as `CORDON_ON` would be. The journal keeps
both: `GRAPH_MUTATION.mutation_kind` is the effect (so replay is unchanged) and
`custom_kind` names the declared event; the provenance record's kind is
`CUSTOM:acme.gas_alarm`. A name the site model does not declare is refused,
never mapped by guess.

The ack returns the graph epoch after the mutation. That number is the same one
that appears in `Denial.observed_epoch`, so a refusal can be tied to the exact
world version it was decided against.

<!-- example: cloud/cmd/cge1_evidence/main.go -->

`cloud/cmd/cge1_evidence` drives these events and prints the acks.

### 5.2 Unlock and revoke

Both are signed operator commands. `Unlock` returns a robot from a safe-stop
state; `RevokeIssuerKey` puts the issuer into a lockdown that lasts for the
lifetime of the process.

<!-- vocab: unlock -->

| field | type | meaning |
| --- | --- | --- |
| `robot_id` | `string` | The robot to return to normal. |
| `unix_ms` | `int64` | Command time. Must fall inside the server's window. |
| `nonce` | `bytes` | Unpredictable, at least 16 bytes (§5.3). |
| `operator_sig` | `bytes` | Ed25519 signature over the canonical string. |
| `operator_key_id` | `string` | Which operator key signed. |

<!-- vocab: revoke -->

| field | type | meaning |
| --- | --- | --- |
| `issuer_key_id` | `string` | The issuer key to revoke. |
| `unix_ms` | `int64` | Command time. Must fall inside the server's window. |
| `nonce` | `bytes` | Unpredictable, at least 16 bytes (§5.3). |
| `operator_sig` | `bytes` | Ed25519 signature over the canonical string. |
| `operator_key_id` | `string` | Which operator key signed. |

The signature is taken over a canonical string built by concatenation, not over
a re-serialised protobuf, because two encoders can produce different bytes for
the same message and a signature that depends on the encoder is not a signature.
The exact canon for both commands is written in the service comment of the
shipped `.proto`.

### 5.3 The nonce floor

<!-- source: cloud/internal/operator/operator.go -->

<!-- pin: cloud/internal/operator/operator.go -->
```go
const MinNonceBytes = 16
```

Shorter nonces are rejected before the signature is even checked. The floor is
part of the contract rather than advice, because a caller cannot see the
server's replay window or its acceptance rate and therefore cannot work out for
itself what is safe.

It is worth being precise about what 16 does and does not buy, because the
number looks like a cryptographic derivation and is not one. Replay protection
here is a set of recently-seen nonces that expires on a short timer, so a nonce
only has to be unique within that window — and operator commands are issued by
people, not at thousands per second. What the floor actually blocks is a
*predictable* nonce such as a single byte, which lets an attacker pre-fill the
replay window regardless of length. Sixteen bytes is convention, and it is an
honest safety margin rather than a computed necessity.

<!-- example: cloud/cmd/operator_cli/main.go -->

`cloud/cmd/operator_cli` builds the canonical strings, signs them, and generates
conforming nonces.

## 6. Optional operations and management interfaces (experimental)

<!-- source: sdk/proto/robot_ops_service.proto -->

The tree also ships `sdk/proto/robot_ops_service.proto` (package
`pail.robotops.v1`, Apache-2.0) with three more gRPC services. They are not a
fifth surface in the sense of §1: none of them is needed to integrate a fleet
manager, a reader or a safety adapter, and all of them are disabled unless the
settings in [`ROBOT_OPERATIONS.md`](ROBOT_OPERATIONS.md) §3 are set. They exist
for operating several robots under one issuer, and the tool that drives them —
the planning, approval, apply and recovery orchestrator — is offered
separately by Glowfly. What ships here is the contract, the verification
library and the endpoints.

**Stability.** This is an experimental, pre-1.0 contract. Publishing the
`.proto` under Apache-2.0 is a license, not a compatibility promise: an
incompatible change is recorded in `CHANGELOG.md` under the release identity
that made it and requires a migration on your side, and nothing here is
versioned for external consumers the way §2–§5 are. Pin the release identity
you integrated against.

| service | listener | who may call | what it does |
| --- | --- | --- | --- |
| `RobotBindingProbe.ProbeBinding` | the issuer's existing mTLS listener; query only | a holder of a robot client certificate | reports whether the caller's TLS leaf is bound to the requested robot, and the registry/site/requester/policy digests the issuer actually loaded. No lease, no rotation |
| `RobotAgentSelfProbe.ProbeSelf` | the agent's Unix socket (`PAIL_GRPC_UDS_PATH`); the method accepts only the agent's owner UID or root | a local observer on the robot | the agent's actually loaded TLS identity, its upstream binding, and a runtime guard summary |
| `IssuerOpsAdmin` | a dedicated local Unix socket (`PAIL_OPS_ADMIN_SOCKET`, mode 0600); never TCP; the kernel peer UID is checked on every call | the operations executor or a local operator tool running as an allowed UID | reads `GetCapabilities`, `GetLoadedStatus`, `GetHoldStatus`; mutations `BeginHold`, `ConfirmQuiesced`, `ReleaseHold`, `AdoptHold` additionally require a signed approval bound to deployment, action, canonical plan digest, target set and execution id |

The service declarations are pinned to the shipped file:

<!-- pin: sdk/proto/robot_ops_service.proto -->
```proto
service RobotBindingProbe { rpc ProbeBinding(ProbeBindingRequest) returns (ProbeBindingResponse); }
service RobotAgentSelfProbe { rpc ProbeSelf(ProbeSelfRequest) returns (ProbeSelfResponse); }
```

<!-- pin: sdk/proto/robot_ops_service.proto -->
```proto
service IssuerOpsAdmin {
 rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse);
 rpc GetLoadedStatus(GetLoadedStatusRequest) returns (GetLoadedStatusResponse);
 rpc GetHoldStatus(GetHoldStatusRequest) returns (GetHoldStatusResponse);
 rpc BeginHold(BeginHoldRequest) returns (ManagementResponse);
 rpc ConfirmQuiesced(ConfirmQuiescedRequest) returns (ManagementResponse);
 rpc ReleaseHold(ReleaseHoldRequest) returns (ManagementResponse);
 rpc AdoptHold(AdoptHoldRequest) returns (ManagementResponse);
}
```

A valid signature alone is not authority for a mutation, a hold is not proof
that motors stopped, and `ConfirmQuiesced` records a software observation, not
a certified physical stop. Read [`ROBOT_OPERATIONS.md`](ROBOT_OPERATIONS.md)
§2 for the layers behind each listener — file mode, peer identity, per-method
checks — before pointing anything at these sockets.

<!-- example: cloud/cmd/pail_robotops_fixture/main.go -->

The shipped, runnable example for this section is offline:
[`examples/robotops/`](../examples/robotops/README.md) builds the two declaration
checkers and `cloud/cmd/pail_robotops_fixture`, runs them against a generated
declaration set, and makes each check fail on purpose. It does not exercise the
three services above against a running issuer or agent; that requires the
configuration in the guide.

## 7. What is not a surface

Four things look like part of the contract and are not.

`rejected_reason` on the submit responses is human-readable text with no
stability guarantee. It predates the structured refusal and remains only so that
old logs stay readable. Branching on it will break.

`Denial.detail` is the same: a sentence for a person, not a field for a parser.
If you need to distinguish two refusals, use `reason_code`.

Internal gRPC services and topics other than the four above are not a public
boundary. They are not versioned for external consumers and may change without
notice. The other two `.proto` files under `sdk/proto/` are of this kind:
`token_service.proto` is the wire between the gate and the agent, and
`agent_relay.proto` is the beacon relay between the agent and the issuer. They
ship because the gate and the agent are built from this tree, not because a
third party is expected to speak them.

The three services of §6 are a fourth case: they are published and documented,
but as an experimental pre-1.0 contract rather than as one of the four
surfaces above.

## 8. Keeping this document honest

Everything above is measured rather than asserted.
`spec/tools/spec_api_surfaces_check.py` reads the shipped `.proto`, `.msg`,
`.hpp` and `policy.yaml`, derives each vocabulary, and compares three things:

```
this document  ==  shipped source  ==  shipped example
```

Two would not be enough. Document and example alone could agree on a spelling
the source has never declared; document and source alone could agree while the
examples quietly rot and the first thing a reader runs fails. Every quoted block
is checked as a byte substring of the file it names, every file this document
points at is checked to actually ship, and the Korean edition is checked to
teach the same names — a translation that is never measured does not become
stale, it becomes stale while still passing.

One limitation is worth stating rather than hiding. The shipped `.proto`, `.msg`
and `.hpp` files carry their inline comments in Korean. The quoted blocks above
therefore contain Korean text, and this document is the English rendering of the
contract those files declare. The check compares names and structure, which are
language-independent; it does not translate comments.

**Basic communication receipts**

[CORE_COMM.md](CORE_COMM.md) describes additive report/operation receipts and the separate read-only readiness/local management contract. Existing authorization and driver interfaces remain in place.
