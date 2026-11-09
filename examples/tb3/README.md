# TurtleBot3 base reference — authorization before drive commands

> **0.2 evaluation delivery:** first run `python3 evaluation.py load` in the evaluation directory.
> The Issuer runs from the evaluation image. The lower-level commands below run from `pail-core/` after that setup.
> Prefer the `evaluation.py` launcher for a first run.


This example contains the real PAIL gate and motion bridge, synthetic identity/safety
inputs, and a **base-command sink**. The sink reads `/drive_cmd_vel`; it does not model
wheel motion. No motors, serial devices, host network or external service account are used.
The software path is:

`planner /cmd_vel → PAIL gate /safe_cmd_vel → motion bridge /drive_cmd_vel → base sink`

## Run without a robot

Prerequisites: Docker Engine/Desktop with the compose plugin v2 or newer, Python 3 and OpenSSL. Use a
Linux-container engine with at least 4 GB of memory. ARM64 and x86-64 source builds
are supported by the Dockerfiles; a successful run only establishes the platform
recorded in that run's evidence. A cold build including downloads may take 10–20 minutes or longer; cached layers may reduce this to a few minutes. See [installation and results](../../TRY_IT.md) for OS-specific limitations and interpretation.

From the root of this repository:

```sh
python3 examples/tb3/run.py
```

The runner builds **this source tree**, creates fresh local keys, provisions mTLS and
SROS2 identities, signs the keyring with a separate root, and starts a private Docker
network. The root signing key is never mounted into the running services. Generated
keys/state live in the printed `STATE=...` directory **outside the source tree**.
The source tree is not modified. Do not share that entire state directory: it contains
private keys. Share a reviewed copy of its `evidence/` directory instead.

The example selects v5 tokens and `robot_class=diff_drive_amr`. It tests:

- the gate loads the skill registry;
- no authorization means no nonzero command at the base sink;
- a real v5 token names `twist`, its slot, and its signed constraints;
- the same base observer receives motion under the matching token;
- duration completion stops forwarding;
- a 0.2 m/s request is refused under a 0.1 m/s limit;
- killing the gate makes the bridge emit zero while the planner continues;
- the generated journal verifies against the issuer's public key.

The software runs in the explicitly declared **development profile**, with mTLS,
SROS2 Enforce and a root-signed keyring. Synthetic RFID evidence is not a real sensor,
and the synthetic safety feed is not a safety controller. The undeclared physical
safety controller and other limitations remain visible; this is not a safety certification.

## Live demo console (no hardware)

Step-by-step guide with a screenshot and every scene: [`DEMO.md`](DEMO.md)
(한국어: [`DEMO.ko.md`](DEMO.ko.md)). This section is the reference summary.

`run.py` checks the path and stops. `demo.py` keeps the same stack running — real issuer,
real gate, real motion bridge, freshly generated keys — adds a **simulated** base, and
serves a console on `http://127.0.0.1:8765/` (this machine only):

```sh
python3 examples/tb3/demo.py build --build-window-confirmed
python3 examples/tb3/demo.py start
python3 examples/tb3/demo_scenes.py        # optional: runs every scene below and judges it
```

Type a command such as `forward 1 m`, `back 0.5 m`, `left 90 deg`, `left 1 m` or
`forward 1 m at 0.3 m/s` (Korean works too: `앞으로 1m`). The console turns it into a
twist plan and asks the issuer. The demo policy allows 0.1 m/s, 0.5 rad/s and 15 s per
call, so one call moves at most 1.5 m.

| Scene | Expected |
|---|---|
| forward 1 m | issued → the simulated base moves about 1 m → stops |
| forward 3 m / forward 1 m at 0.3 m/s | **refused by the issuer** (`ERR_ENVELOPE_EXCEEDED`); nothing moves; the console names the limit that was exceeded |
| left 90 deg / back 0.5 m / left 1 m | turn in place / reverse / turn 90° then 1 m (two tokens) |
| planner speeds up to 0.3 m/s after its permit | the gate refuses every command (`ERR_CONSTRAINT`); motion resumes within the permit |
| drive without a plan | the gate refuses (`ERR_NO_TOKEN`) |
| wrong tag read | the gate refuses (`ERR_TARGET_MISMATCH`) until the right tag is read |
| safety UNSAFE while moving | stop; the interrupted plan never resumes (`CHAIN_REVOKED`); a new plan is issued once safety is OK — the operator lock (`SAFE_STOP`) is for forged-token reports, not safety events |
| stop while moving | the planner idles and the console cancels the plan at the issuer (`CancelPlan`, `CHAIN_CANCELLED` in the ledger); the next plan runs on its own token, never on the cancelled plan's remaining window |
| verify ledger | the signed journal verifies |

After a plan completes the console records the displacement it observed once the base is
at rest (`moved` event); the page shows that record, live or after a reload.

The issuer never issues a shorter or slower version of a request that is above a limit;
it refuses and returns each exceeded bound (`Denial.exceeded`). `demo_scenes.py` never
judges "nothing moved" from silence: every refusal is followed by a permitted move that
the same observer must see. Ctrl-C (or SIGTERM) stops the stack.

What this is not: positions come from a simulation of the command that passed the gate,
not from wheel encoders; the tag and safety inputs are synthetic feeds. The console is a
local demonstration requester, not an operations dashboard.

If the robot-side clock jumps (observed on Docker Desktop for macOS: a single +1.96 s
step), the gate refuses every command with `ERR_CLOCK_DRIFT` until it restarts — by design,
it does not re-anchor a clock that jumped. The console reports the jump and offers
"restart robot side"; `demo_scenes.py` reports `CLOCK_PREREQUISITE_FAILED` instead of
blaming a scene. The drift limit is not relaxed.

## Evidence, not just a green line

The printed evidence path contains `FINAL_RESULT.json`, per-check expected/actual
values and timestamps, `runtime/*.jsonl`, service logs, journal files, the source
manifest and `MANIFEST.json`. A missing observer cannot establish a successful block:
the same observer must subsequently receive the authorized traffic. Failed runs remain
on disk. The runner shuts down only its own Compose project, including on failure.

`--state /absolute/new/directory` selects a new empty destination. Existing runs are
never erased. `--skip-build` requires explicit `PAIL_TB3_CLOUD_IMAGE` and
`PAIL_TB3_GATE_IMAGE` values; do not describe such a run as a fresh source build.

## Launch and configuration

`tb3_reference.launch.py` starts the guarded image entrypoints for the gate and bridge.
It does **not** start a planner or a hardware driver. It explicitly selects
`PAIL_ROBOT_CLASS=diff_drive_amr`; upgrading a binary alone does not select a registry.
`site_model.yaml` is synthetic, with robot `robot-01` and target `sample-box`.
The runner stages a private configuration, limits linear speed to 0.1 m/s and token
life to 30 seconds, and grants the generated requester the `twist` skill.

## Connecting an actual TurtleBot3 base — a separate integration step

The executable procedure — robot-side rig, operator-side issuer and console, the
configuration split, the placement statement, the scenes and the maintainers' measured
results — is [`HARDWARE.md`](HARDWARE.md) with the files in [`hardware/`](hardware/).
This section states the integration rules that procedure follows.

Use the vendor's ROS 2 Humble TurtleBot3 base driver and firmware; they are not vendored
or modified here. See <https://emanual.robotis.com/docs/en/platform/turtlebot3/bringup/>.
An OpenMANIPULATOR arm and proprietary perception drivers are outside this reference.

For a hardware deployment, create a **separate, reviewed** robot-side configuration.
Do not copy this all-in-one development configuration to a robot: keep issuer/operator
private keys on the issuer/operator hosts. Give the robot only its required identity
and trusted verification material. Use the `/driver` SROS2 enclave for the base driver,
and ensure its command subscription is remapped from `/cmd_vel` to `/drive_cmd_vel`.
Remove or prohibit other command paths; a remap without access control is not a bypass
barrier. Start the PAIL gate/bridge with the policy, signed keyring, mTLS endpoint and
skill registry appropriate to that deployment.

The sample `fastdds_loopback.xml` is **only** for the shared private namespace in this
example. A physical multi-host deployment needs its own reviewed DDS networking.
Verify the actual subscription with `ros2 topic info /drive_cmd_vel --verbose` from an
authorized diagnostic participant, then separately test wheel/encoder motion and stop
behavior in a controlled setup. A passing base-sink test is not physical-wheel evidence.
The robot's hardware safety and emergency stop remain independent responsibilities.

### Optional base-only driver launch

`tb3_base_driver.launch.py` starts no hardware by default. It uses the vendor's
`turtlebot3_ros` executable only when `enable_hardware:=true` is explicit, SROS2
Enforce is enabled, and a model parameter file and robot keystore are present.
It remaps the command input to `/drive_cmd_vel`, selects `/driver`, and requests
unstamped `Twist` input to match the PAIL bridge. Confirm the message type and
subscription on the installed driver version; this code is not physical validation.

On the prepared robot (not inside the no-device development Compose stack):

```sh
# Default is a harmless configuration check: no driver is started.
ros2 launch examples/tb3/tb3_base_driver.launch.py
# Only after hardware, firmware, security, command routing and safety review:
ros2 launch examples/tb3/tb3_base_driver.launch.py enable_hardware:=true \
  params_file:=/absolute/path/to/vendor/model.yaml usb_port:=/dev/ttyACM0
```

Do not launch a second vendor bringup that also consumes unguarded `/cmd_vel`.
This optional launch does not start a lidar, arm, perception system or safety controller.

### Hardware observation and remaining limits

Separate maintainer fixtures on 2026-09-14 and 2026-09-15 exercised the official Humble
TurtleBot3 waffle_pi driver, real OpenCR and both wheel encoders: every demo scene above
with the wheels raised, and straight moves, turns in place, stop while moving and UNSAFE
while moving on 1.5 m of floor. Identity/safety inputs were synthetic. Three software
defects were found and fixed on the way: a gateway whose first token reply arrived after
the gate's deadline stayed at NO_TOKEN; a reply that overtook a completion report
re-armed a consumed step; and a plan cancelled at the issuer kept being driven by a
gateway holding a delegated window until the step window expired (a cancel now reaches
the edge as a `CHAIN_REVOKED` beacon). This was not an unchanged source-ZIP installation
test and does not turn this default sink example into a hardware test or certify ground
braking performance.

One runtime ERR_CLOCK_DRIFT was observed on 2026-09-14 during RPi clock adjustment and
has not reproduced since. Do not disable clock checks, extend authorization bounds or
reset an issuer journal to turn such a refusal into a pass. Record the exact error and
clocks; evaluation feedback should distinguish prerequisites from functional verdicts.

## Image retention

Per-run image tags are retained by default and their exact removal commands are printed.
Use `--remove-images` to remove only tags built by this invocation after retaining
image IDs and evidence. With `--skip-build`, supplied images are always preserved.
See `evidence/image-cleanup.json`; cleanup failures do not alter authorization verdicts.


## Public reference file permissions

The runner copies the launch file, mock actor, Fast DDS XML and access checker into this run's
`runtime/reference/` (directory 0755, files 0644). It verifies the exact bytes are
readable as container UID 10001 before starting the stack. The checkout is not
chmod'ed or chowned. `evidence/reference-files.json` and `reference-access.log`
record the copy hashes and runtime read probe. This permission rule applies only
to these public inputs, never to generated private keys (0600).


## Cross-UID access contract

`permissions.py` is the executable authority for state directory modes and ownership
roles. `python3 examples/tb3/permissions.py describe` prints the declared contract.
The runner applies it at creation and after ownership transfer, then checks access
as both the service (UID 10001) and the actual host runner before starting actors.
`evidence/access-contract.json` records the result. A chmod call alone is not proof. Later read failures, lost logs or truncated logs
are prerequisite failures, never empty successful observation windows.

- Shared synthetic observations: `evidence/runtime` is 0755; JSONL and process logs
  are explicitly 0644 even when the producer's umask is 077.
- Private config root, keyring state and root-key directories remain restricted.
  Private key files must remain 0600; they are never widened to make host reads work.
- References/control are public test inputs; their readable modes do not apply to keys.
- Generated SROS2 links may point only within the generated config tree during preparation.

Run fresh states under both `umask 022` and `umask 077`. Source mode normalization
must not substitute for testing the actual ZIP extracted by Linux unzip.

## Completion and clock prerequisites

The completion check requires the issued token's `step complete: token ... consumed`
marker and an appropriate consumed/no-token BLOCK, not any transient BLOCK.
Observation rows carry wall and monotonic time. A wall/monotonic discontinuity over
0.25 seconds during observation, or an observed `ERR_CLOCK_DRIFT`, records
`clock-prerequisite.json` and fails the run as a prerequisite (exit 2).
This is a harness stability check, not a change to PAIL security thresholds or proof
of the sole cause of a clock error. Inspect VM/host clock sources before rerunning;
the runner does not alter clocks or synchronization services. Failures and their
raw logs remain evidence, not physical braking measurements.

### Command transport freshness

The gate-to-bridge and bridge-to-driver velocity publishers use RELIABLE,
volatile, depth-one DDS histories and a sample lifespan equal to the configured
permit deadline (100 ms by default). Permit samples expire on that timescale too.
This bounds stale DDS sample delivery; it is not a measurement of motor-loop
latency or physical stopping distance. Integrators must retain a driver-side
command watchdog and validate their RMW/driver combination. A command already
accepted by a driver is outside DDS lifespan enforcement.
