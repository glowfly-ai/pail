# Adapter contract v1

PAIL puts one decision between a requester and a robot: *is this command,
right now, authorized by a token the issuer signed, under the safety and
evidence the policy demands?* The decision itself is one function
(`gate_core::decide()`, shipped as `libpail_gate`). Everything that carries a
command **to** that function and carries its verdict **back** to a robot's own
control path is transport-specific — a ROS 2 topic, a Unix socket, a gRPC
stream — and that transport-specific half is called an **adapter**.

This document is the contract an adapter has to meet. It is written so that a
robot maker or an integrator whose robot is not ROS can implement one in their
own language without reading PAIL's internals, and so that "supports PAIL" can
be checked rather than claimed.

> 한국어판: [`ADAPTER_CONTRACT.ko.md`](ADAPTER_CONTRACT.ko.md). The English
> document is canonical; if the two diverge, the English text governs.

### What PAIL's refusal is, and is not

PAIL withholds *authorization*. It does not implement, replace, or certify the
robot's safety function. The emergency stop, the protective stops, the speed and
separation monitoring, the force limits — those stay with the robot vendor and
the integrator, under the standards that already govern them (IEC 61800-5-2,
ISO 10218-1/-2, ISO 3691-4, ISO 13482). A gate that blocks a command has removed
an authorization, not applied a brake.

Two consequences the integrator has to hold on to. A deployment whose only
protection is PAIL is a deployment with no safety function: the guardrail names
in a token (`spec/GUARDRAILS.tsv`) are *bounds the issuer authorized*, and a
bound is not a measurement of what the machine did. And a gate that cannot name
the vendor safety controller it runs beside says so — the configuration seal
carries `degraded=S36` rather than silence, so "there is a safety function here"
is a recorded claim and not an assumption (SK-5).

## 1. The two halves

| Half | Who provides it | What it does |
|---|---|---|
| **SDK** (common) | PAIL | `libpail_gate` (the decision, strict token verification, the permit/step/single-use state machine, policy loading — one C ABI, `include/pail_gate/pail_gate.h`); the **robot agent** (gRPC `TokenService`: `GetActiveToken`, `ReportDecision`, `Attest`, `SealConfig`); config sealing and build identification. |
| **Adapter** (transport-specific) | the integrator | ① intent ingress ② verdict egress ③ safety and evidence ingress ④ permit deadman enforcement, plus requester identity and the bypass-free deployment. |

An adapter **never judges**. It maps an incoming command to a `CommandInput`
(action class, linear and angular norms), asks the library, and obeys the
`Outcome`: forward the *original bytes* or drop them. It has no cache of its
own, no default values for absent feeds, no mode switch of its own, and no
opinion about time beyond reading a clock.

## 2. The library ABI

`libpail_gate` is one handle per robot. All buffers are protobuf **binary** of
the messages in `abi/pail_gate_abi.proto` (shipped beside the header); any
language that has protobuf can generate its bindings from that one file.

| Function | In → out | When the adapter calls it |
|---|---|---|
| `pail_gate_abi_version()` | → `uint32` | at start; refuse to run against a different major |
| `pail_gate_new(Config)` | → handle or NULL + reason | at start; a refusal names a policy or config defect in the gate's preflight vocabulary (`POLICY_ABSENT`, `POLICY_INCOMPLETE`, …) |
| `pail_gate_set_token(TokenInput)` | | every `permit_recheck_ms` with the newest `GetActiveTokenResponse` — `reachable=false` when the agent did not answer |
| `pail_gate_observe_safety(SafetyInput)` | → `Outcome` | whenever the safety feed delivers; an `ESTOP` outcome is a stop |
| `pail_gate_observe_evidence(EvidenceInput)` | | whenever an evidence source delivers |
| `pail_gate_command(CommandInput)` | → `Outcome` | per command; `Outcome.forward` is the whole answer |
| `pail_gate_tick(TickInput)` | → `TickOutcome` | every `permit_recheck_ms` after `set_token`; carries the recheck path and the step timer |
| `pail_gate_info()` | → `Info` | at start and for status |
| `pail_gate_free()` / `pail_gate_free_buf()` | | |

A handle is not thread-safe; the adapter serialises calls on it.

`Outcome.detail` says what the reason code does not: which name, which value, which
bound. It is logged and carried on this ABI, never compared for equality (the reason
string is). Its forms today: an envelope refusal `sls.linear_mps=0.3 outside [-,0.2]`;
an unmeasured name `unmeasured:<name>` (`ERR_BAD_TOKEN`); a step overrun
`step.max_duration_s: clock=<elapsed|wall> now=<ms> deadline=<ms> overrun_ms=<ms>` (`ERR_CONSTRAINT`, on the
step clock the deadline was stamped with); a slot or skill mismatch in words.

## 3. Invariants

| # | Invariant | How it is checked |
|---|---|---|
| I-1 | A requester principal cannot reach the robot's raw control ingress behind the adapter. | CB-1 probe (transport-specific) and the adapter's own start-up check (`S27`, three values: verified / unverified / failed; `failed` refuses to start in production) |
| I-2 | The adapter does not judge — whether bytes are forwarded follows `Outcome.forward` only. | CA-01, CA-04, CA-05, CA-06 |
| I-3 | A permitted command is forwarded **byte for byte**. | CA-07 |
| I-4 | After the permit ends, forwarding stops within `permit_deadline_ms`. | CA-08, CA-09 |
| I-5 | Every decision is reported (`ReportDecision`, PERMIT included); a failed report closes the gate (issuer-first). | CA-09 |
| I-6 | An absent safety or evidence feed enters as absent — the adapter never synthesises "OK". | CA-10 |
| I-7 | The gate mode comes from the sealed policy only; under `observe` the adapter forwards and records the would-BLOCK. | CA-11 |
| I-8 | The adapter attests its own build (`Attest`, component `pep_gate`, `build_info` in the `pail-build:v1:` form). | CA-12 |

And the deployment rule behind I-1: **no fallback path.** If the adapter is
down, nothing reaches the robot; a robot with its own deadman stands still.
An adapter that "fails open to the raw socket" is not conformant.

## 4. Conformance cases

Each case is one scenario in the PVS vocabulary (`version: 2.0`, steps such as
`north_cmd`, `inject_evidence`, `inject_cmd_vel`, `expect_gate`,
`expect_bridge`, `expect_drive_never`, `fault`), executed through the same
orchestrator that judges the ROS 2 gate node. A backend per transport maps the
steps to that transport's actions and reads the outcome from the **far side**
of the adapter — what actually reached the robot — never from the adapter's own
claims. The machine-readable table is `pvs-public/scenarios/adapter/CA_MAP.yaml`.

| Case | Expectation | Scenario |
|---|---|---|
| CA-01 | no token → BLOCK `ERR_NO_TOKEN`, nothing forwarded | `functional/fn03_no_token` |
| CA-02 | forged signature → BLOCK `ERR_TAMPERED` | `adapter/ca02_forged_signature` (= PVS `token/ti03`) |
| CA-03 | expired token → BLOCK `ERR_EXPIRED` | `adapter/ca03_expired_token` (= PVS `token/ti05` without the nightly gate) |
| CA-04 | action class not carried by the token → BLOCK `ERR_ACTION_MISMATCH` | `adapter/ca04_action_class_mismatch` (= PVS `token/ti02`) |
| CA-05 | evidence names another target → BLOCK `ERR_TARGET_MISMATCH` | `adapter/ca05_target_mismatch` |
| CA-06 | command faster than the token's limit → BLOCK `ERR_CONSTRAINT` (never clamped) | `adapter/ca06_speed_over_limit` |
| CA-07 | permitted line reaches the far side byte-identical | transport tool (`tools/ca07_bytes.sh` for sockets; ROS 2: `functional/fn01` — message-field equality on `/safe_cmd_vel`, the DDS bytes are the middleware's) |
| CA-08 | the adapter dies → forwarding stops; the robot's own deadman holds | `deadman/dm01_pep_kill_bridge_hold` |
| CA-09 | the agent becomes unreachable with a permit held → BLOCK `ERR_ISSUER_UNREACHABLE` within the grace ladder, nothing forwarded on the stale token | `adapter/ca09_issuer_unreachable` (ROS 2: `…_ros`, kills the issuer container the gate dials) |
| CA-10 | safety feed stale or absent → no new permit | `safety/sf02_safety_stale_no_permit` |
| CA-11 | `gate_mode: observe` → forwarded, would-BLOCK recorded with `effective_mode=observe` | `adapter/ca11_observe_passthrough` |
| CA-12 | an `ATTESTATION` record for component `pep_gate` with the adapter's `build_info` exists in the issuer's chain | `adapter/ca12_attestation_in_chain` (`expect_audit … contains`; ROS 2: `…_ros`, the `pail-build:v1:pep_gate:` prefix) |
| CA-13 | a named skill whose declared envelope (the robot's own numbers for it) exceeds the token limit → BLOCK `ERR_CONSTRAINT`, never clamped (SK-2: the gate compares by `GUARDRAILS.tsv` name) | `adapter/ca13_skill_envelope_over_limit` (sockets: `robot.do` of a skill the rig set to 1.5 m/s); ROS 2: `NO_SKILL_INGRESS` |
| CA-14 | **unassigned.** No case carries this id and none ever did; the gap is kept so that ids in recorded conformance reports stay stable | — |
| CA-15 | the adapter's skill table names a skill the robot does not answer to → refused at start (S33) when the robot's answer lists its built-ins; an answer with `built_in: []` is `unverifiable` (banner, no refusal — unlisted is not absent) | `tools/ca15_s33_table_not_on_robot.sh` (sockets, on a daemon that lists built-ins; the fake does not → `NEEDS_UPSTREAM_BUILTIN_LIST`); ROS 2: `NO_SKILL_INGRESS` (its S33 is registry-vs-measures, in the node battery) |
| CA-16 | API44 queries preserve bytes; note is recorded; commands without a token are refused | `tools/ca16_new_methods.py`; Microduck only; ROS 2: `MICRODUCK_SOCKET_ONLY` |
| CA-17 | pickup blocks; clearing the input cannot revive old authority; a new authorized plan restores operation | `tools/ca17_pickup.py`; Microduck only; ROS 2: `MICRODUCK_SOCKET_ONLY` |
| CA-18 | actual upstream and explicit adapter support boundary agree, including the excluded head IMU stream | `tools/ca18_upstream_boundary.py`; Microduck only; ROS 2: `MICRODUCK_SOCKET_ONLY` |
| CB-1 | a requester principal is refused at the raw ingress | `enforcement/enf01_rogue_safe_cmd_vel` (ROS 2) · `tools/cb1_raw_socket_probe.py` (sockets) |

**Cases that need a separable hold.** Two cases are only observable on a transport
where the robot's authority to move is a *thing the adapter holds* — a lease, a
session, an E-stop registration — rather than the permit heartbeat itself. They are
not rows in `CA_MAP.yaml`, which is the execution map of the socket and ROS 2
backends; a gRPC adapter reports them by these ids and the definitions here govern:

- **CA-16** — the permit ends by the step deadline: the adapter's hold is released and
  the safe state executed. (gRPC interposer: the upstream session is dropped and `Stop`
  sent. Sockets and ROS 2: `NO_HOLD_INGRESS` — their hold *is* the permit heartbeat, so
  there is nothing separate to release.)
- **CB-2** — a requester cannot take the robot's own hold: the adapter holds it, and the
  requester's attempt is answered locally and never forwarded (G-ADP-17). (gRPC
  interposer: `StartSession` / `SendSessionHeartbeat`. Sockets and ROS 2:
  `NO_HOLD_INGRESS`.)

Each case violates exactly one rule. A backend that cannot perform a case on
its transport reports **SKIP with a stable reason token** (`NEEDS_ROGUE_SEAM`,
`NEEDS_FAULT_INJECTION`, `NEEDS_POLICY_VARIANT`, `NEEDS_EXPECT_AUDIT`,
`NEEDS_SROS2_KEYSTORE`, `NO_SKILL_INGRESS`, `NEEDS_UPSTREAM_BUILTIN_LIST`,
`NO_HOLD_INGRESS`, `NEEDS_TARGET_EVIDENCE`, `NEEDS_ROBOT_SIDE_PROBE`,
`NEEDS_ISSUER_SEAM`); a SKIP is never a PASS, and a run in which nothing
executed is not a run. A case id means one thing across every adapter: a report that
reuses an id for a different expectation does not describe a weaker adapter, it makes
the reports incomparable — which is the one thing a conformance id is for. A backend may execute a transport-specific scenario file
in place of the row's default (`run: <scenario>` in the map) when the case is
the same and only the rig differs — which container "the agent" is, or what
the attested build string of that adapter looks like; the ROS 2 gate node, the
reference adapter, runs through the same map and runner as every other adapter
and cites nothing. The negative
token cases are served by a **token seam** between the adapter and its agent
(`pvs-public/runner/adapters/token_seam_server.py`): the adapter keeps talking
to "its issuer", and only what it is *told* changes — every report still
reaches the real issuer. Two consequences the rig has to respect: a security
refusal the adapter reports puts the issuer into SAFE_STOP until an **operator
unlock** (the reset performs one, as an operator would), and "agent
unreachable" (CA-09) kills the endpoint the adapter actually dials. The harness
proves itself the other way round too: a non-enforcing adapter put in front of
the same rig must turn CA-01 and CA-05 red (measured 2026-09-06).

## 5. Deployment requirements

| Transport | Raw ingress | How the requester is kept away from it | `S27` reads |
|---|---|---|---|
| ROS 2 | the `/cmd_vel` subscription of the motion bridge | SROS2 permissions: the requester enclave may not publish `/cmd_vel`; only the bridge consumes `/safe_cmd_vel` | its own enclave's permissions (unverified without a keystore) |
| Unix socket (Microduck) | `/run/robotd/raw.sock` | the raw socket and its directory belong to the adapter's group (`0660` / `0750`); clients are members of the public socket's group only | mode and gid of the raw socket and its directory |
| generic TCP / gRPC | the robot's control port | network namespace or firewall rule reaching only the adapter | bind address and rule |

`S27` values: `verified` (checked and closed), `unverified` (could not check —
reported, not passed), `failed` (open to others — production refuses to start).
The probe CB-1 is the harness's, not the adapter's: an adapter never opens its
own bypass to test it.

### 5a. Microduck-compatible UDS/CLI profile

This is the concrete shape the public conformance rig (`evaluation.py test-adapter
--adapter-binary FILE`, `pvs-public/conformance/rig_microduck.sh`) drives. A replacement
adapter that keeps this shape can be tested without changing the rig; the reference
implementation is `adapters/microduck/` (`pail-duckd`). Everything below is read from
that implementation and from the compose files the rig generates, not promised beyond them.

**Executable and runtime.** A Linux ARM64 ELF executable. The rig copies the supplied file
and mounts it read-only at `/usr/local/bin/pail-duckd` in three containers of the Core
runtime image: the enforcing adapter and the observe adapter run as uid 10001 with all
capabilities dropped; the harness container (which starts the binary itself for the tool
cases below) runs as root with capabilities kept, because it drives Docker and the fault
seams. The image is Debian bookworm; the gate library is `/opt/pail/lib/libpail_gate.so`
(C ABI of §2, loaded at start — refuse on a different major). Dependencies the binary
needs must already be in that image or linked statically. A refused start exits 78 and
names its gate in the gate's preflight vocabulary. Two cases start the binary directly
from the harness: CA-07 runs it as `pail-duckd --gate none --public … --raw …` under
`PAIL_PROFILE=dev` (the non-enforcing plumbing path, so bytes can be compared tap to tap),
and CA-15 starts it with a skill table naming a skill the robot lacks and expects **exit 78
with an `S33` line in its log**; a binary without `--gate none` or without that refusal
fails those rows.

**Command line.** Long options; every one also has an environment variable where noted.
The rig invokes the enforcing adapter as

```
pail-duckd --public /run/duck/pail.sock --public-gid 10002 --raw /run/duck/raw/state-seam.sock \
  --agent http://token-seam:50052 --robot-id robot-1 --policy /etc/pail/policy.yaml \
  --keyring /etc/pail/keys/keyring.json --skills /etc/pail/duck_skills.yaml \
  --evidence /run/duck/evidence.sock --gate-log /run/duck/gate.ndjson
```

and the observe adapter as a second instance against the observe fake: `--public
/run/duck/pail_observe.sock --raw /run/duck/raw/observe-robotd.sock --agent
http://observe-agent:50051 --policy /etc/pail/policy.observe.yaml --gate-log
/run/duck/gate_observe.ndjson`, no `--evidence`, with `PAIL_PROFILE=production`,
`PAIL_KEYRING_MODE=unsigned-dev` and `PAIL_BUILD_INFO` in the environment. Both
instances read `PAIL_KEYRING_MODE` from the environment: unset means a signed keyring
bundle is required, and the rig's unsigned development keyring then loads zero keys
(every token `ERR_UNKNOWN_KEY_ID`).

| Option | Env | Meaning |
|---|---|---|
| `--public PATH` | | Unix stream socket the adapter **serves** (where robotd used to listen). Created at start with mode `--public-mode` (default `0660`) and group `--public-gid N` / `--public-group NAME` (`PAIL_DUCK_PUBLIC_GROUP`; exactly one of the two). Clients are members of that group only. |
| `--raw PATH` | | robotd's own socket the adapter **connects to** as a client and forwards permitted bytes to. Its mode/gid and its directory's are the `S27` self-check (`0660`/`0750`, closed to others). |
| `--agent URL` | `PAIL_AGENT_ADDR` | robot agent `TokenService`: `unix:/run/pail/agent.sock` or `http://host:port` (dev). Absent = no agent (dev only: no token view, no reports, no attestation). |
| `--robot-id ID` | `PAIL_ROBOT_ID` | identity in every `GetActiveToken` / `ReportDecision` / `Attest`. |
| `--policy FILE`, `--keyring FILE`, `--skills FILE` | `PAIL_POLICY`, `PAIL_KEYRING`, `PAIL_DUCK_SKILLS` | the sealed inputs of `pail_gate_new`: policy (refused when absent or incomplete), keyring (trust mode from `PAIL_KEYRING_MODE`), the skill name table `name → MOVE\|MANIPULATE\|NONE` (production refuses to start without it; a named skill not in the table is refused at judgment). |
| `--evidence PATH` | `PAIL_EVIDENCE_SOCK` | NDJSON evidence ingress the adapter serves; absent = no evidence ingress. One object per line: `{"source": "NFC", "object_id": "box-12", "confidence": 0.99, "t": <ms>}`, handed to `pail_gate_observe_evidence`. |
| `--gate-log FILE` | `PAIL_GATE_LOG` | NDJSON decision log, append-only (below). Absent = no log; the rig requires it. |
| `--profile NAME` | `PAIL_PROFILE` | `production` (default; refuses a non-enforcing gate or a failed `S27`) or `dev`. |
| `--gate libpail\|none` | `PAIL_GATE` | which gate to link; `none` is the developer plumbing path and never conformant. Default `libpail` when built with `--features libgate`. |
| `--safe-state NAME` | `PAIL_SAFE_STATE` | the safe state executed on permit revocation (`stop_zero_twist` default; must be executable, see §6). |
| `--permit-recheck-ms N` (100), `--attest-interval-s N` (300), `--attest-component NAME` (`pep_gate`), `--build-info STR` (`PAIL_BUILD_INFO`, `pail-build:v1:…`), `--safety-hz N` (20), `--battery-floor PCT` (15), `--health-poll-s N` (5), `--permit-grace-n N` (3), `--clock-skew-ms N` (500) | | timing and attestation knobs; the defaults are what the rig measured. |

**Wire on both sockets.** Newline-delimited JSON-RPC 2.0, the Microduck robotd protocol
pinned by `adapters/microduck/Cargo.toml` (`duck-ipc-proto`, rev `bc41fb5c`). The first
request of a client is `hello` and its `params` carry `"api_version": 44`; the answer is
robotd's (`{"api_version": 44, "daemon_version": …}`), forwarded. Methods fall into five
kinds (`adapters/microduck/src/classify.rs`): **pass** — handshake, queries and
subscriptions served by robotd without changing robot state (`hello`, `robot.health`,
`robot.modelApi`, `robot.mode`, `robot.policies`, `robot.safeToRestart`,
`robot.remoteSessionActive`, `robot.subscribe`, `robot.skills`, `pad.bindings`,
`chorale.subscribe`), forwarded unjudged; **stop** — `robot.stop`, the safe direction,
still a decision on the record; **judged MOVE** — `robot.move {vx, vy, vyaw}` with linear
norm `hypot(vx, vy)` and angular norm `|vyaw|`; **judged, class NONE** — posture and
expression (`robot.head`, `robot.look`, `robot.pose`, `robot.mouth`, `robot.sound`,
`robot.theremin`, `robot.chorale`), judged against the token like any command but
carrying no motion class; **judged ACTUATE** — power, posture state, policy, skill and
pad binding changes (`robot.enable`, `robot.init`, `robot.relax`, `robot.setMode`,
`robot.loadPolicy`, `robot.reloadPolicies`, `robot.shutdown`, `robot.setSkill`,
`robot.removeSkill`, `pad.bind`); **judged by skill table** — `robot.do {skill}`.
Everything else robotd's wire knows but the robot socket does not serve (updater,
policy store, account, network, system and pad-pairing calls) is answered locally with
JSON-RPC `METHOD_NOT_FOUND` and never forwarded. `robot.state` notifications from the raw
side are relayed to subscribers of the public socket — the harness reads *that* far
side, never the adapter's own word. A command the gate blocks is **not forwarded and gets
no reply**; a permitted command is forwarded byte for byte (I-3). The safety feed is the
adapter's own `robot.subscribe` on the raw socket at `--safety-hz` (`safety.fallen` /
`safety.limp` → level), the battery its `robot.health` poll. When one half of a client↔raw
pair ends, the other half is closed at once (a client is never judged against an upstream
that is already gone).

**Gate log lines.** Every outcome and every stop request, one JSON object per line:

```
{"t_ms": <ms>, "kind": "outcome", "path": "command|recheck|step|safety", "state": "PERMIT|BLOCK|ESTOP|",
 "reason": "OK|ERR_…|NOGATE", "detail": "…", "forward": bool, "report": bool,
 "permit_active": bool, "step_active": bool, "estop_active": bool, "step_complete": bool, "fatal": bool,
 "mode": "enforce|observe|none", "enforcing": bool, "conn": <n>, "uid": <peer uid or null>,
 "chain_id": "…", "token_id": "…"}
{"t_ms": <ms>, "kind": "stop", "path": "…", "state": "…", "reason": "…"}
```

(`adapters/microduck/src/state.rs`; `path` is `command` for a client request, `recheck`
for the periodic token recheck, `step` for the step timer, `safety` for the safety feed.)
The conformance backend tails this file (`permit_active`, `state`, `reason`, `path`) and
reads the far side together with it (`pvs-public/runner/adapters/microduck_backend.py`);
the reason vocabulary is the frozen dictionary vector `spec/vectors/contract/reason_dict.vec`
(source: `cloud/internal/reason/reason.go`).

**Time.** The gate compares the wall clock with the monotonic clock and, once their
difference has moved more than `--clock-skew-ms` (500 ms) since the adapter started,
refuses every command with `ERR_CLOCK_DRIFT` until the adapter restarts — by design. An
adapter therefore needs a host whose time is **slewed**, not stepped: a VM guest agent
or NTP configuration that steps the clock (Lima's guest agent steps ~100 ms every ~20 s)
reaches the bound within minutes. The deployment procedure must say how time is kept and
that a step is followed by an adapter restart. What a clock jump requires is a restart of
**the adapter (gate) process, not the robot**: the gate anchors its clocks only at start.
The official examples' "restart robot side" is a broader action — it starts the whole
robot-side container set again — and the demo text says so. A host that sleeps steps its
clock when it wakes (Docker Desktop for macOS: one +1.96 s step observed on wake), so after
a laptop wakes from sleep `ERR_CLOCK_DRIFT` is the expected state, the gate restart is the
recovery, and the threshold is not relaxed for it; a deployment procedure either prevents
sleep where the gate runs or lists "restart the gate after wake". Keep one time source where the gate runs:
a VM that runs both a guest agent that steps its clock to the host's and an NTP client
steps back and forth whenever the host clock is off NTP (measured ±2 s every ~10 s); check
the host clock against NTP first. The gateway (`pail_robot_agent`) also keeps time: it
serves a token from its edge lease only while the token's `not_after` (read from the
signed bytes) is not behind its own clock, then releases the window, declares it, and the
next read asks the Issuer. It does **not** add the gate's `clock_skew_ms` to that boundary:
a gateway clock ahead of the Issuer's releases early and re-asks (one round trip, no
refusal), a gateway clock behind it is caught by the gate's `ERR_EXPIRED`, on which the
gateway releases as well. Validity is judged once, by the gate, on the signed bytes; the
gateway's clock can shorten an offline window by at most the skew, never extend a token.

**A new plan.** Accepting a plan for a robot ends that robot's previous ACTIVE plan, and the
gateway gives up the previous plan's window even if it never spent it: the Issuer sends the
same `CHAIN_REVOKED` beacon a cancel sends, the gateway drops the window, the next read
fetches the new plan, and a gate still inside the old step ends its permit at the next
recheck (the token it is served is no longer the one it holds: `BLOCK ERR_NO_TOKEN`). A gateway cut
from the Issuer when that beacon went out keeps its window while it is offline (an outage
costs progress, not a stop); when it reconnects it declares its chain, the census answers
`CHAIN_ENDED`, and it drops the window before asking again. The offline window ends when the
gateway is connected again, not when the network is: the gateway pings its Issuer connection
(every 10 s, 5 s to answer), so a connection that died during the outage — the Issuer restarted
while the gateway was cut off, and its reset never arrived — is replaced within about 15 s of the
network's return; the Issuer's memory of which plan replaced which survives its own restart (it
is rebuilt from the journal), so the census still answers `CHAIN_ENDED` (in an earlier pre-release
it took one to three minutes and longer, during which the superseded plan's window was still
served). A command judged before the beacon
arrives is judged under the previous plan, as it would have been an instant before the new
plan was accepted. `evaluation.py test-supersede` checks this on the software rig (it is the
one thing the conformance rig's case isolation cannot show), including a gateway cut off while the
Issuer restarts and a new plan accepted in the middle of a running step. In an earlier pre-release the window
outlived the new plan until its own `not_after` and commands were judged under the old plan.

**A different transport.** None of the above is required of a non-Microduck robot. Such an
adapter is conformance-tested through its own backend: a class implementing the public
`Backend` interface (`pvs-public/runner/core/backend.py`: `setup/teardown/reset_state`, the
step methods `north_cmd`, `inject_evidence`, `inject_cmd_vel`, `inject_skill`, `inject_safety`,
`fault`, the observation methods `gate`, `bridge`, `drive`, `permits`, `stop_request_asserted`,
and `enforcement_supported()`, whose default `False` reports the Enforcement axis as SKIP —
never PASS — until a backend overrides it) placed as a module beside `microduck_backend.py`,
with unsupported axes returned as `unsupported` rather than faked
(`example_backend.py` shows the shape). The rig image carries the backends it was built
with, so this is an **online build from a working copy**, not a mount into the delivered
images: copy `pail-core`, add the module, then
`python3 examples/microduck/run.py conformance --build --issuer-image <delivered Issuer image ID>
--backend MODULE:CLASS --state DIR` builds the image from that copy, records its source
identity, runs your class and — until `CA_MAP.yaml` has a column for your transport —
executes the Microduck column of the map under your backend's name
(`examples/adapter/README.md` §4a). Two rules of that run are the verdict's, not the
backend's: **a SKIP never becomes a PASS**, and **a SKIP the rig did not review makes the
run `BLOCKED`** (`Unreviewed skip: CA-NN`). A case your backend reports as `unsupported`
is therefore accepted only by its maintainer, in writing: `--reviewed-skip "CA-NN:<why>"`
(on `run.py conformance`, `test-conformance` and `test-adapter`) keeps the row SKIP, records
the reason in the report and the result's `limitations`, and the result is
`PASS_WITH_LIMITATIONS`. A FAIL and a skip declared by the map cannot be reviewed away.
The two tool rows of the Microduck column (CA-07 `--gate none`, CA-15 built-in inventory)
run the Microduck tools whatever the backend's name; a transport that cannot be driven by
them reports them `unsupported` and reviews them like any other row. A case has a third
possible word, **`INCONCLUSIVE`**: nothing failed, but a check could not be decided from
what was observed — the gate log grew but no record reached the harness while the far side
showed the commands flowing, the tail was not running, or a permit rate was measured while
the observer itself was starved (`observation_health()` of the backend tells these apart).
The runner reruns such a case once from a fresh reset and keeps both attempts; if the word
stays, the run's result is `INCONCLUSIVE` (exit 4), never PASS and never FAIL. A refusal that
was observed is a FAIL. A gate log that did **not** grow while the adapter was being driven
is also a FAIL (`ADAPTER_GATE_LOG_MISSING` / `ADAPTER_GATE_LOG_STOPPED`): §5a's gate log is
the record of the judgement, and an unrecorded judgement cannot be verified — the harness
does not take an absent log as the host's fault.

## 6. Registry

`spec/ADAPTERS.tsv` lists every adapter with its transport, ingress and egress,
language, **status** and the result the status rests on. The raw conformance
report is the maintainer's record and is not shipped in this tree: the registry
states the reported result — the date, the executed and skipped counts, the skip
tokens — so the claim is traceable, and the verdict is the re-run of the
conformance rig, not the file. Three columns added for skill-level authorization
(SK-0, 2026-09-09): `robot_class` (the `SKILL_VOCAB.tsv` class this adapter serves),
`measures` (the `GUARDRAILS.tsv` names the adapter actually measures and hands to
`decide()`, `;`-separated) and `safe_state` (the safe states it can execute on
revocation). A skill registry may only put in `envelope[]` what its adapter declares
in `measures` — a maintainer-side registry check (not distributed) refuses the rest. SK-5: `safe_state`
is a declaration the adapter checks against itself at start (Microduck
`--safe-state`, refused when not executable; the ROS gate refuses a registry row
naming a state outside its `adapter_safe_state`), and a row's `feeds` must be
feeds the gate observes (`safety_feed`, `evidence_claim`) — a feed nobody checks
is refused at start on both the gate and the issuer. Status vocabulary:

| Status | Meaning |
|---|---|
| `designed` | design exists; no conformance run, or a run with cases still skipped |
| `conformant_fake` | every executable case passed on a stand-in robot; skips listed with reasons |
| `conformant` | every case passed on the real robot |
| `withdrawn` | no longer maintained |

An adapter not in the registry is not a PAIL adapter, whatever its README
says.

## 7. What this contract does not cover

Issuing tokens, the decision rules, the chain format, and how a fleet manager
submits plans — those are the issuer's and the canon's contracts. Updating or
configuring the adapter on the robot is the robot maker's mechanism. Timing
numbers (decision latency, stop latency) are measured on real hardware and
published per deployment, not promised here.

### Local step-duration clock (GC-TIME-1)

The shared gate measures positive `max_duration_sec` against a local, non-wall elapsed
clock that includes suspend. Wall-clock corrections and repeat commands must not reset,
shorten or extend this duration. Commands (including unreachable-issuer grace) and permit
rechecks refuse at the elapsed deadline even if the completion timer is delayed. The timer
consumes the step once; do not treat a clock fault as successful completion.

Token absolute validity, safety/evidence checks and the existing drift allowance remain
independent requirements. Zero duration retains the absolute token-expiry fallback. The
C ABI `now_ms` remains a wall timestamp; it cannot set the gate's duration clock. Refusal
detail identifies `clock=elapsed` or `clock=wall`; never compare those clock domains.
Rebuild the shared gate and its consumers together; no issuer or token-wire change is required.

### Supersession is not a mandatory physical stop (TB3 hardware clarification)

A new accepted plan invalidates the previous permit. Subsequent commands are
judged against the new plan: if it permits them, motion may continue without a
physical gap. `BLOCK ERR_NO_TOKEN` describes the Microduck test observation, not
a mandatory ROS log spelling or a stop-before-every-plan contract. The ROS gate
may log `permit recheck failed ... heartbeat stopped` and then grant the next
command under the new token. Application planners must explicitly cancel/stop
when a physical pause is required. Raised-wheel encoder results are not braking
performance.
