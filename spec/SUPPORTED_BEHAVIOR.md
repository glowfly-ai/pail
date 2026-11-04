# Supported behavior and OEM extension points

This is a support boundary, not a list of promised future features. Use the
versions shipped in one release together; see [COMPATIBILITY.md](COMPATIBILITY.md).
한국어: [SUPPORTED_BEHAVIOR.ko.md](SUPPORTED_BEHAVIOR.ko.md).

## What a field actually does

| Input / condition | Entry point | Current meaning | OEM extension / limit |
|---|---|---|---|
| Requester | Authenticated mTLS / UDS caller and requester registry | Maps the immediate caller to an identity and skill grants; a body field cannot impersonate it | Configure known principals. A verified multi-agent delegation chain is not supplied |
| Robot | `robot_id`, robot registry | Binds the call / token to the configured robot | Configure identities; names alone are not authentication |
| Action | `ActionSpec`, robot-class skill registry | Registered skill, class and requester grant are checked; v5 binds skill and slot | Add supported skills using [SKILLS.md](SKILLS.md); a name is not a robot driver |
| Target | `target_object_id`, site model, adapter evidence | Model membership and required target evidence are checked according to the configured profile | Connect evidence through the public adapter ABI; a declared object is not proof of its physical existence |
| Time | Signed `not_before` / `not_after`, duration envelope | Gate verifies time limits; a refresh does not extend signed expiry | Configure documented bounds; do not change host clocks to make a test pass |
| Command speed | Twist / named envelope | Supported adapters provide linear/angular command norms; named upper bounds are checked | This is not a measurement or certification of physical braking |
| Context / plan constraints JSON | `context_json`, `constraints_json` | JSON shape/size and hash/record handling; arbitrary contents are not policy predicates | Carry application context. `approved:true` is not a verified human approval |
| Skill parameters | `params_json` | JSON checks; recognized numeric guardrail names can narrow bounds or cause refusal when exceeded | Arbitrary purpose/destination/approval keys do not gain authority by being present |
| `params_schema` | Skill registry | Unsupported; declaring it refuses configuration | No JSON Schema evaluation in this release |
| Zones / destinations | Site model, graph events, task parameters | Static zone/model rules exist. Generic runtime robot-zone transition and destination/geofence enforcement are not supplied | Do not claim a live geofence merely because a zone or goal is recorded |
| Force / joint bounds | Guardrail vocabulary | Vocabulary is not proof an adapter measures/enforces a value | Declare only supported measures. Adding a name does not implement force control |
| Human approval | Application before `SubmitActionPlan`; separate robot-operations approval API | Management approval is not per-physical-action approval | OEM can gate submission upstream, with authenticated non-bypassable routing. Issuer-side approval verification needs an explicit contract |
| Gate decision | Adapter ABI and `ReportDecision` | Permit/block decision, reported completion and issuer acceptance are separate facts | Use original signed bytes and preserve report identity |
| Completion | Skill `complete.signal`, completion report | Supported signal governs consumption. Journal v10 records issuer acceptance explicitly | See [COMPLETION_JOURNAL.md](COMPLETION_JOURNAL.md). Reported/accepted completion does not prove physical success |
| Evidence | Blackbox and public verifiers | Checks supported signatures, hash chains and evidence claims against supplied trust roots | Missing inputs are not success. Offline integrity verification is not full issuer-policy or sensor-truth proof |

## Robot and adapter scope

[ADAPTERS.tsv](ADAPTERS.tsv) declares each adapter's actual measures, safe-state
handling and test status. [ADAPTER_CONTRACT.md](ADAPTER_CONTRACT.md) defines the
public ABI and deployment responsibility, including bypass prevention.
A robot class in a vocabulary is not certification or tested support for every
robot of that class. Report simulated and real-robot results separately, including
skips and the tested OS/architecture. Existing safety controllers remain separate.

## Where OEM code connects

1. Configure supported requesters, skills, policy and site-model fields.
2. Implement an adapter using token, command, safety and evidence ABI inputs.
   Forward the original command only on the gate's permitted outcome.
3. Keep application approvals/delegation upstream if the application owns those
   checks. Prevent direct unauthorized submission and handle cancellation.
4. A new issuer policy predicate or a new signed authority meaning is not a
   generic callback in `context_json`. It needs an explicit versioned contract
   and implementation. Source-level compiler registration is not a runtime plugin.

Unknown required constraints must not be silently discarded or translated into
wider authority. Unsupported optional application metadata may be recorded, but
must remain labelled as a claim rather than an enforced condition.
