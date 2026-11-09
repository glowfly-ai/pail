# Testing PAIL on a real TurtleBot3

## Current split evaluation bundle (read first)

This bundle's gate, bridge and ROS messages are built together; do not mix its ROS
nodes with `pail_msgs` from another release. No floor braking/safety certification
is claimed.

1. In the evaluation directory: `python3 evaluation.py load`, then
   `python3 evaluation.py tb3 --state /tmp/hw-state` in one terminal. Once ready,
   use another terminal: `python3 evaluation.py stop-tb3 --state /tmp/hw-state`.
   This creates the local configuration; no private Issuer source build is needed.
2. Work on a writable copy of `pail-core/`; commands below run from that copy.
   Set `PAIL_HW_STATE=/tmp/hw-state`. Use the matching image IDs from
   `images.lock.json`; the tags below name this release (the Linux amd64 bundle's tags carry an `-amd64` suffix).
3. Operator Issuer: `pail/issuer-eval:0.2.0`. Robot services:
   `pail/core-microduck:0.2.0` (contains the public agent, no Issuer).
   Gate base: `pail/core-tb3-gate:0.2.0`. Add the vendor driver using hardware/Dockerfile and this matching gate image.
4. Build host-native console tools **on macOS or Linux** (Go 1.27.2+ and cached or
   online Go dependencies required):

```sh
bash examples/tb3/hardware/build_native_tools.sh /tmp/pail-hw-tools
```

The script builds only public sources in a temporary package and removes that
package afterward. It does not need Issuer source. Native host tools avoid the
Docker Desktop container-to-host-LAN route failure (TB3-H2). macOS refuses the
container-tool path before touching the robot. The console probes the actual
mTLS endpoint before writing the first idle instruction; no plan is issued by
this readiness check. Linux container tools remain optional, not universally
network-reachable.

`PAIL_HW_DEPLOYMENT_ID` is optional: unset means no gate/bridge status socket;
if set it must be a UUID. `RIG_UP` now waits for constructor-complete gate and
bridge readiness before giving OpenCR to the base driver. `S33 OK` alone is not
readiness. A failure preserves logs and does not claim success. This is software
startup readiness, not proof of physical motion or a live permit.

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Glowfly Identity Systems Co.,Ltd -->

한국어: [`HARDWARE.ko.md`](HARDWARE.ko.md)

This is the procedure the maintainers use to run the [live demo](DEMO.md) on a physical
TurtleBot3: the same console, the same scenes and the same judge, with the simulated base
replaced by the vendor's base driver on the robot's OpenCR and the position taken from the
wheel encoders. Everything it needs is in [`hardware/`](hardware/). It comes in two levels:

| Level | Placement statement | What it shows | Who may do it |
|---|---|---|---|
| **Raised wheels** | `raised` | Every demo scene; distances are how far the wheels turned | Anyone with a TurtleBot3 and the parts below |
| **Floor** | `clear-floor` | Straight moves, turns, stop while moving and UNSAFE while moving on 1.5 m of floor | An operator standing beside the robot with an immediate way to stop it |

Identity (the tag) and safety (the level) inputs stay synthetic: they come from the console,
not from a reader or a safety PLC. No result here is a braking-performance figure, a functional
safety certification or a statement about the robot's own emergency stop, which stays a separate
responsibility. Section 8 lists what the maintainers measured.

## 1. What you need

- A TurtleBot3 (`burger`, `waffle` or `waffle_pi`) with the vendor firmware on its OpenCR and a
  Raspberry Pi or other onboard computer running Ubuntu 22.04 (arm64 or amd64) with Docker
  Engine. The robot user must be able to run `docker` and, once, `sudo -n install` (the gate's
  private state directory). A Raspberry Pi 3 is enough; SROS2 discovery is slow on it, see §9.
- An operator PC (Linux or macOS) with Docker, Python 3.9+, OpenSSL and `ssh` access to the
  robot without a password prompt (`BatchMode`). It runs the issuer, the console and the judge.
- Both on one network. Only mTLS gRPC crosses it (robot agent → issuer). The ROS 2 traffic
  stays inside the robot's isolated Docker network namespace, as in the software demo.
- A completed `evaluation.py tb3` setup and stop as described above.
  Its state directory holds the keys, certificates, SROS2 keystore, policy and requester
  registration; the matching evaluation images are reused (`evidence/console.json` names them).
- The vendor driver image: built on the operator PC from that gate image and loaded on the robot:

```sh
docker build --build-arg PAIL_TB3_GATE_IMAGE=pail/core-tb3-gate:0.2.0 \
  -t pail/tb3-hardware:<tag> -f examples/tb3/hardware/Dockerfile examples/tb3/hardware
docker save pail/tb3-hardware:<tag> pail/core-microduck:0.2.0 | gzip -1 | ssh <user>@<robot> 'gunzip | docker load'
```

The Dockerfile adds only `ros-humble-turtlebot3-node` and `ros-humble-turtlebot3-bringup` to
the public gate image and records their versions in `/opt/tb3-package-versions.txt`. Build on an
arm64 machine (or with `--platform`) for a Raspberry Pi. No firmware, lidar or arm package.

## 2. Who runs where

| Operator PC | Robot |
|---|---|
| `pail_cloud` — the issuer, from the separate Issuer evaluation image, mTLS on `<pc-ip>:50064` (`hardware/issuer_host.sh`) | `pail_robot_agent` — fetches tokens from the issuer, serves them to the gate on `127.0.0.1:50051` |
| `hardware/console_hw.py` — the demo console (same page, same HTTP API) | `pep_gate` — the gate, SROS2 Enforce, `/pep_gate` enclave, skill registry `diff_drive_amr` |
| `tb3-probe`, `blackbox_verify` — run from the cloud image (`--tool-image`) or as native binaries | `motion_bridge` — forwards a permitted `/cmd_vel` to `/drive_cmd_vel` |
| `examples/tb3/demo_scenes.py` — the judge, unchanged | five participants of `hardware/demo_hw_io.py`: planner (`/oem_planner`), encoder observer (`/robot_state_publisher`), drive observer (`/driver`), safety feed (`/safety_adapter`), identity feed (`/perception`) |
| `hardware/floor_run.py` — floor scenes (§7) | `turtlebot3_ros` — the vendor base driver, `/driver` enclave, `/cmd_vel` remapped to `/drive_cmd_vel`, the only container that gets the OpenCR device |

The console writes the planner's instruction over ssh into `control/demo.json` on the robot and
mirrors the participants' `docker logs -f` into its state directory, so the page and the judge
see exactly the events the software demo produces, plus `pose` rows with `source: encoders`.

## 3. The robot's configuration

The demo generates an all-in-one development configuration. **Do not copy it to the robot.**
`issuer_host.sh robot-config` writes the subset the robot needs to a new directory:

```sh
export PAIL_HW_STATE=/path/to/demo/state PAIL_HW_ROBOT_ID=robot-01
examples/tb3/hardware/issuer_host.sh robot-config /tmp/robot-config
```

| Kept for the robot | Left on the operator PC |
|---|---|
| `policy.yaml`, `skills.diff_drive_amr.yaml`, `sros2_policy.xml` (reference), `robot_registry.yaml` | `requesters.yaml`, `site_model.yaml` |
| `keys/keyring_bundle.json`, `keys/root_pub.b64` (trust material), `keys/agent_ed25519.json` (the agent's own key) | `keys/issuer_*.json`, `keys/operator_ed25519.json`, `keys/mirror_ed25519.json`, `keys/payload.json` |
| `grpc_certs/ca.crt`, `grpc_certs/<robot>/client.crt`, `client.key`, and a freshly minted `grpc_certs/<robot>/server.crt`, `server.key` | `grpc_certs/ca.key`, the issuer's own `server.crt`, `server.key` |
| `sros2_keystore/enclaves/*`, `sros2_keystore/public/*` | `sros2_keystore/private/*` (the identity and permissions CA keys) |

Copy it to the robot and give it to the container user (the gate, bridge, agent and driver all
run as uid 10001 inside their containers):

```sh
scp -r /tmp/robot-config <user>@<robot>:/home/<user>/pail-robot-config
ssh <user>@<robot> 'sudo chown -R 10001:10001 pail-robot-config && sudo chmod 700 pail-robot-config'
```

The shipped `sros2_policy.xml` already grants `/driver` the vendor driver's topics
(`/joint_states`, `/odom`, `/tf`, …) and `/robot_state_publisher` the subscription the encoder
observer needs, so the demo keystore works unchanged. If you change the policy, re-provision the
keystore with `scripts/sros2_provision.sh` as the demo does and copy the enclaves again. The
keyring bundle the demo signs is valid for eight hours; a robot session that outlives it must
re-run `evaluation.py tb3` (or sign a new bundle) and copy `keys/keyring_bundle.json` again.

Until 2026-09-19 the maintainers' own runs used a separately provisioned robot-side
configuration, and this subset was checked on the operator side only. Run against a real
TurtleBot3 it did not start: the agent refused for a missing `robot_registry.yaml` (RG-4) and
then for a missing server certificate. Both files are in the subset now, and the run above was
repeated on the robot from this subset alone, with no file added by hand.

## 4. Robot side

Put the four files and the placement statement in one directory on the robot, for example
`/home/<user>/pail-hw`:

```sh
scp examples/tb3/hardware/start_demo_rig.sh examples/tb3/hardware/demo_hw_io.py \
    examples/tb3/tb3_base_driver.launch.py examples/tb3/fastdds_loopback.xml <user>@<robot>:pail-hw/
ssh <user>@<robot> 'mkdir -p pail-hw/control && echo "{\"seq\": 0, \"instruction\": 0, \"mode\": \"idle\", \"steps\": [], \"tag\": \"sample-box\", \"safety\": \"OK\"}" > pail-hw/control/demo.json'
```

Then, **on the robot**, with the wheels raised (or the floor cleared, §7):

```sh
echo raised > pail-hw/control/hardware_confirmed          # the operator's statement, written by the operator
export PAIL_HW_CONFIG=/home/<user>/pail-robot-config \
       PAIL_HW_CLOUD_ADDR=<pc-ip>:50064 \
       PAIL_HW_SERVICES_IMAGE=pail/core-microduck:0.2.0 \
       PAIL_HW_GATE_IMAGE=pail/tb3-hardware:<tag>
pail-hw/start_demo_rig.sh up        # RIG_UP after 1–3 minutes on a Raspberry Pi 3
pail-hw/start_demo_rig.sh status
```

`up` refuses without the placement statement (exit 78), without the OpenCR device, or when a
container of this rig already exists. It starts the agent, the five participants, the bridge,
the gate and finally the base driver, all sharing one isolated network namespace with
`--cap-drop ALL`. Optional variables: `PAIL_HW_ROBOT_ID` (`robot-01`), `PAIL_HW_MODEL`
(`waffle_pi`; selects the vendor parameter file), `PAIL_HW_USB_PORT` (`/dev/ttyACM0`),
`PAIL_HW_TARGET` (`sample-box`), `PAIL_HW_MAX_STEP_S` (`30`, the policy's per-step limit the
planner will never exceed), `PAIL_HW_PROFILE` (`production`), `PAIL_HW_KEYRING_MAX_LIFETIME_SEC`
(`86400`). `PAIL_HW_DEPLOYMENT_ID` (unset) turns on the robotops status endpoints: the gate
and bridge answer a local status query on `state/gate_status.sock` / `state/bridge_status.sock`
(mode 0600) and the agent serves its gRPC self-probe on `state/agent.sock` (mode 0660), all owned
by uid/gid 10001. The file mode is only the first layer: the agent listener also carries the
Northbound, Token and Operator services, and `ProbeSelf` itself answers only a caller whose
kernel peer UID is the agent's owner or root — so a probe runs on the robot as that user or
root. Which listener carries which service, and what each method checks, is in
[`spec/ROBOT_OPERATIONS.md`](../../spec/ROBOT_OPERATIONS.md) §2.
A node that is killed without its destructor (`docker rm -f`, SIGKILL) leaves its socket file
behind; the next start reclaims it only when it is a socket owned by the same uid with nobody
listening (log line `RO_STATUS: stale endpoint reclaimed`), a live or foreign endpoint is refused
with exit 78, and `start_demo_rig.sh down` deletes the rig's socket files.

Before the first command, read three logs:

```sh
docker logs pailhw-gate 2>&1 | grep 'S33 OK'           # the gate loaded the skill registry
docker logs pailhw-base 2>&1 | grep 'Run!'             # the vendor driver runs on the OpenCR
docker logs pailhw-agent 2>&1 | tail -3                # burst CHECKPOINT lines: the issuer link is up
```

`down` removes this rig's containers and nothing else; `restart-gate` is what the console's
`restart robot side` button calls; `restart-agent` is for a changed issuer address.

## 5. Operator side

```sh
export PAIL_HW_STATE=/path/to/demo/state \
       PAIL_HW_CLOUD_IMAGE=pail/issuer-eval:0.2.0 \
       PAIL_HW_ISSUER_IP=<pc-ip>
examples/tb3/hardware/issuer_host.sh up            # ISSUER_UP <pc-ip>:50064 …
```

The demo issued its server certificate for `localhost`; `up` re-signs it with the demo CA
adding `<pc-ip>` (the previous file is kept beside it) and starts `pail_cloud` from the cloud
image with the same settings the demo's Compose file uses, the journal in the state's
`blackbox/`. Then the console, in a **new empty** state directory:

```sh
C=$PAIL_HW_STATE/runtime/config
python3 examples/tb3/hardware/console_hw.py --state /tmp/pail-hw-console --port 8765 --placement raised \
  --robot <user>@<robot> --rig-dir /home/<user>/pail-hw --issuer <pc-ip>:50064 \
  --config $C --certs $C/grpc_certs --operator-key $C/keys/operator_ed25519.json \
  --journal $PAIL_HW_STATE/blackbox --issuer-key $C/keys/issuer_ed25519.json \
  --probe-bin /tmp/pail-hw-tools/tb3-probe --verify-bin /tmp/pail-hw-tools/blackbox_verify
```

It binds the port first, writes one idle instruction to the robot, starts mirroring the five
participants and prints `CONSOLE=http://127.0.0.1:8765/`. The page is the demo page; the
header badge reads `Position: encoders (raised wheels)`, the map's blue line is wheel odometry.
The console reads `--config` (default: the parent of `--certs`) using `tb3-probe -mode limits`:
its policy, site-model and skill parsers are the same libraries the issuer uses. The selected
robot class, `twist` skill and target zone determine the envelope (including zone tightening).
Use the **same configuration directory passed to `issuer_host.sh up`**. Missing/invalid inputs
refuse startup before any robot instruction. Rebuilt public native tools are required; older probes
without `limits` support are refused, not replaced with hard-coded defaults.

`evidence/console.json`, the ready event and `/api/state` record the source paths, selection and
SHA-256 fingerprints. This is a local configuration snapshot, **not attestation of the live
issuer**; restart the console after changing issuer configuration. Optional `--limits` JSON is
only an assertion: a mismatch is refused, never used as an override. The issuer still decides. `--target` and `--other-tag` are the site model's object ids
(`sample-box`, `other-box` for the demo site model). `--probe-bin` and `--verify-bin` replace
`--tool-image` with native binaries.

Read [the timing and recovery profile](TIMING.md) before porting the planner.

## 6. Raised wheels: the scenes and the judge

Every scene of the [walkthrough](DEMO.md#4-walkthrough-scene-by-scene) applies, driven by hand
or by the unchanged judge:

```sh
PAIL_RESULTS_DIR=$(mktemp -d /tmp/pail-tb3-raised.XXXXXX)
python3 examples/tb3/demo_scenes.py --url http://127.0.0.1:8765 --out "$PAIL_RESULTS_DIR/hw-raised-scenes.json"   # the port is the console's --port; the console prints this JUDGE line
```

Each invocation creates a new results directory outside the source tree. Keep the result JSON
and its adjacent `.events.jsonl` together: the JSON records the event count and SHA-256.
Reusing an existing `--out` is refused. Writing results inside the source tree makes
`verify_release.py` report extra files; it is not a failure of the robot or its authorization.

The judge reads `position_source` from the console and writes `scope: real robot side,
positions from encoders (raised wheels)` into its result. What differs from the simulation:

- **Distances and angles are wheel odometry.** `forward 1 m` reads about 1.00 m because the
  encoders measure what the wheels did; on a floor the same command would include slip. `left 90
  deg` reads 88–92°: the vendor driver's ramp and the planner's 0.1 s early stop.
- **Scene R restarts only the gate.** The base driver stays up; the judge does not wait for a
  base `ready`. A gate restart takes 15–45 s on a Raspberry Pi 3 (SROS2 discovery); the console
  waits for the gate's `S33 OK` and then 30 s more before it reports `robot_restarted`.
- **Stops are commands, not silence.** The planner sends zero velocity for 0.5 s after a stop
  or a completion; a planner that merely goes quiet leaves the OpenCR at its last velocity.
  The stop scene (S) records how many drive commands the driver saw after the robot side
  acknowledged the stop, and asserts zero.
- **A first `ERR_ISSUER_UNREACHABLE` or `NO_TOKEN` line** can appear on the very first plan
  after a start while the agent's first token call completes; the next permit follows within
  a second. It is not a refusal of the plan and the judge does not count it.

## 7. Floor: `floor_run.py`

Only with `clear-floor` in `control/hardware_confirmed`, written after the operator confirmed
1.5 m ahead of the robot and 0.5 m behind it are clear, is standing beside it and can stop it
at once (power switch or lifting it). Start the console with `--placement floor`, then:

```sh
PAIL_RESULTS_DIR=$(mktemp -d /tmp/pail-tb3-floor.XXXXXX)
python3 examples/tb3/hardware/floor_run.py --out "$PAIL_RESULTS_DIR/hw-floor.json"      # --only F2,F6 selects steps
```

It only ever sends straight moves along the start heading and turns in place, and before every
command projects the position along that heading; a command that would leave
`[-0.45 m, +1.45 m]` is not sent and the run aborts. Steps: F0 at rest · F1 drive without
permission · F2 forward 1 m then back 1 m · F3 forward 5 m refused, 0.3 m control · F4 1 m at
0.3 m/s refused, control · F5 planner exceeds its permit · F6 left 90°, right 90° · F7 wrong tag ·
F8 UNSAFE while moving (stop distance, no automatic resume, operator unlock) · F8b stop while
moving (cancelled at the issuer, next plan on its own token) · F9 ledger verifies. After each
step it returns to the start line. Distances are still wheel odometry, now including any slip.

## 8. What has been measured on this hardware

All runs: TurtleBot3 `waffle_pi`, Raspberry Pi 3 (arm64, Ubuntu 22.04, Docker 29), official
ROS 2 Humble driver on the OpenCR, both encoders live, issuer on a laptop on the same Wi-Fi,
synthetic identity and safety inputs, SROS2 Enforce, mTLS on, the vendor image built with
`hardware/Dockerfile` on this bundle's gate image. Gate thresholds, signatures and clocks were
never weakened for any run.

### Split-distribution hardware measurements

Each measurement names its actual source build:

<!-- hw-measurements:begin defs -->
- **publisher** — the publisher's own run with the console, judge and hardware/fault_inject.py of that bundle, before the agent's reason registry and the images were rebuilt; build 0.2.0-preview.19, 2026-10-18.
- **independent** — a recipient who did not share the publisher's tree, on that bundle's images; build 0.2.0-preview.22, 2026-10-20. Where the two differ, the later build is the current value.
- **independent (0.2.0-preview.40 bundle)** — the evaluator's run of the preview.40 ARM64 bundle on the same raised-wheel TurtleBot3 (PAIL-EVALUATION-0.2.0-preview.40-single-contract-20261029); durations were not recorded, so only counts and the fault-injection pauses are carried; build 0.2.0-preview.40, 2026-10-29.
- **independent (0.2.0-preview.44 bundle)** — final ARM64 bundle on raised-wheel TB3; full judge three times, ten restart attempts, permit outage and clock-step checks; one restart timed out; build 0.2.0-preview.44, 2026-10-31.
- **independent (0.2.0-preview.45 bundle)** — final ARM64 bundle on raised-wheel TB3; full judge three times, ten restarts, 12 s permit pause and remote agent-crash. Clock steps excluded in this evaluation.; build 0.2.0-preview.45, 2026-10-31.
- **independent (0.2.0-preview.45 bundle)** — preview.46 evaluation on source-equivalent preview.45 ARM64 hardware runtime: 29 valid restarts, then separate 117-restart investigation; not preview.47 hardware acceptance; build 0.2.0-preview.45, 2026-11-01.
<!-- hw-measurements:end defs -->

Neither is a certification. Encoder distances are not floor travel or braking distances, and
a raised-wheel judge is not floor driving.

| Check | Established | Source |
|---|---|---|
|<!-- hw-measurements:begin table --> Full judge (13 scenes, §6) | 13/13 in three independent runs; durations not reported | independent (0.2.0-preview.45 bundle): 13/13 x3 |
| Scene 8 alone (safety `UNSAFE` → `ESTOP` → `OK`; the interrupted plan never resumes) | 5/5 | independent (0.2.0-preview.22 bundle): 5/5; publisher (0.2.0-preview.19 build): 5/5 |
| Issuer outage across an E-STOP while moving under a live permit — `fault_inject.py --mode permit`, Issuer paused 12 s and 30 s, `UNSAFE` → `OK` during the pause | 12 s Issuer pause across E-STOP: PASS, no drive after OK. The 30 s case was not rerun in this evaluation. | independent (0.2.0-preview.45 bundle): 12 s PASS; no drive after OK |
| E-STOP with no live permit — `fault_inject.py --mode outage`: the Issuer is paused until the gate is already `BLOCK ERR_ISSUER_UNREACHABLE`, then `UNSAFE`, Issuer resumed 0.5 s after `OK` | 0 drive commands after `OK` in 2 runs; the chain whose step was interrupted is refused and the next plan runs on its own token | software demo (0.2.0-preview.23 build): 2/2 with `--wait-block 4`; independent (0.2.0-preview.22 bundle): Hardware no-permit outage precondition has not been established. A multi-step instruction and a longer wait do not guarantee it: an already delegated window can authorize the next step while the Issuer is paused. PRECONDITION_NOT_MET is not a safety PASS. |
| System-clock steps of ±0.6 s on the robot during a step (`date -s`), stepped back 4 s later | Clock abort in all four +/-0.6 s steps; no forwarding after the clock returned, and a new plan ran | independent (0.2.0-preview.44 bundle): 4/4; both directions |
| Step-deadline refusals during normal motion | 0 in every judge and fault run above | independent (0.2.0-preview.22 bundle): 0; publisher (0.2.0-preview.19 build): 0 |
| 1 m instruction, encoder distance | 0.998–1.005 m over three runs (encoders, wheels raised) | independent (0.2.0-preview.44 bundle): 0.998–1.005 m x3 |
| Gate restart to ready (scene R, SROS2 discovery) | Unresolved DDS authentication stall: 1/29; separately 1/117 plus one unrelated movement shortfall. No guaranteed rate or repaired-library claim. | independent (0.2.0-preview.45 bundle): Late Final / asymmetric authentication observed; manual recovery 5/5 in the reported attempts, not automatic recovery |
| Floor, 1.5 m (§7 scenes F0–F9) | F2 0.952 m / −0.996 m; F6 +88.4° / −89.2°; F5 the gate held the driver at ≤ 0.1 m/s while the planner asked 0.3 m/s; F8 `UNSAFE` → gate `ESTOP` in 0.164 s, 0.045 m travelled after the input, no driver command after it, no motion after `OK` until the operator acted | publisher (0.2.0-preview.19 build): an earlier build of the same gate line; the floor scenes were not re-run since <!-- hw-measurements:end table -->|

The judge, `hardware/fault_inject.py` and the console are the ones shipped in this bundle;
nothing above is permission to widen a gate window or threshold. `fault_inject.py` takes the
Issuer container's name on the operator PC: `pailhw-issuer` for this rig, and for the software
demo the per-run name that `docker ps --format '{{.Names}}' | grep issuer` prints. Record every run you make,
including failures, with your own evidence.

### Clock-fault interruption

The hardware reference planner ends the whole instruction on `ERR_CLOCK_DRIFT`.
Clock recovery, feed changes, or changing speed do not resume that instruction;
submit a fresh plan after checking the fault. A new instruction number with the
old tokens is not a fresh plan. The gate must actually grant a fresh token;
changing token IDs alone does not clear the interruption. Console counters may
restart and are not plan identities. The small clock-abort marker in the existing
robot runtime state directory survives planner restart; do not delete it to
bypass an interruption. Read/write failures refuse reference motion and need
state-storage repair. The marker is example execution state, not issuer revocation.
Use the ordinary stop/cancel operation to reconcile old authority before resuming;
never rely on deleting state or restarting a failed writer to prove recovery.
See [TIMING.md](TIMING.md) for the unchanged gate rules and log-count semantics.

## 9. If something looks wrong

| Symptom | Meaning | Do |
|---|---|---|
| `up` prints `REFUSED` and exits 78 | no placement statement | write `raised` or `clear-floor` yourself, after confirming it |
| `RIG_UP` but no `pose` rows on the console | the driver or the encoder observer is not up yet, or `/joint_states` is not published | `docker logs pailhw-base`, `docker logs pailhw-robot`; the observer prints `encoders_stale` after 1 s without data |
| first command refused `ERR_NO_TOKEN` then permitted | the local agent RPC (50 ms here), its cache or upstream state was not ready | nothing; recorded, not a defect of the plan |
| every command refused `ERR_CLOCK_DRIFT` | the robot's wall clock stepped (NTP) after the gate anchored | `restart robot side` (gate restart); never widen the threshold |
| gate log `attest UNKNOWN_MEASUREMENT` | the issuer runs with attestation off (demo setting); informational | nothing |
| `keyring bundle` refused at start | the demo's eight-hour bundle expired or its remaining validity exceeds `PAIL_HW_KEYRING_MAX_LIFETIME_SEC` | re-run `evaluation.py tb3` for a fresh bundle, copy `keys/keyring_bundle.json` |
| console `gate did not report preflight within 120 s` | SROS2 discovery on a slow robot | `docker logs pailhw-gate`; try `restart robot side` again |
| `restart robot side` fails with `control write failed` | ssh to the robot broke | check `ssh <user>@<robot>`; the console keeps the last instruction |
| the robot keeps moving after `stop` | the planner is not sending zeros (old `demo_hw_io.py`) or the driver lost its subscription | stop it physically first; then compare `demo_hw_io.py` on the robot with this tree |

## 10. Boundaries

- Raised-wheel numbers are wheel rotations converted to distance; floor numbers include slip.
  Neither is a stopping-distance, braking or functional-safety figure.
- The tag and the safety level are synthetic console inputs, not a reader or a safety PLC.
- The gate enforces the issuer's policy; the console's `--limits` only phrases the refusal.
- The vendor firmware, driver and parameter files are used as installed; nothing here modifies
  them, starts a lidar or an arm, or replaces the robot's own emergency stop.
- The maintainers' recorded runs used their own provisioned robot configuration and network; a
  run from this kit on your robot is your measurement, not theirs.

## Hardware feedback follow-up: observation clocks and diagnostics

The hardware console queries the robot's monotonic clock **after receiving each
batch** and charges the entire SSH round trip plus processing delay to the age
upper bound. The existing two-second freshness limit is unchanged. Unknown,
replayed, pre-start, future-monotonic and different-boot samples are not current.
`evidence/remote-clock-brackets.jsonl` records the measurement; source wall times
are preserved, not rewritten. A small PC/robot wall-clock offset no longer drops
all completion events. If SSH is too slow, the sample remains unmeasured/stale;
we do not label receipt time alone as current robot state.

The ROS `GateState` now includes diagnostic `detail`; rebuild all participating
`pail_msgs` consumers together. The gate's clock refusal identifies the measured
drift and limit. The bridge deadman and age log use suspend-inclusive elapsed
time, and the forwarding callback also checks permit age before publishing.
Only startup TLS connection preparation gets a bounded five-second wait; the
normal command/recheck RPC deadline is unchanged. This is not a first-command
latency guarantee under arbitrary CPU/network load.

## Hardware acceptance status

Gate restart DDS authentication remains a **known unresolved defect**. Independent preview.46 evaluation on preview.45/preview.46-equivalent ARM64 runtime reported one DDS failure in 29 valid restarts; a separate 117-restart investigation reported one DDS failure and one unrelated movement shortfall. Late Final / asymmetric authentication was observed; Fast DDS source-level cause and repair remain unverified. The cohorts are not a guaranteed failure rate. Five manual recovery attempts succeeded, not a promise of automatic recovery. On `RIG_FAILED: gate IO readiness timeout`, keep stopped, cancel/stop the active plan through normal controls, preserve logs and retry manually, then verify a new plan. Root-cause investigation remains with the maintainer. `PAIL_GATE_READY` means construction complete, not DDS readiness. Restart waits for current `PAIL_GATE_IO serving=1`: matching command publishers, fresh evidence/safety samples and matched safe-command/permit subscribers. No command sample is required before a plan (an idle planner may publish none). This is topology/input readiness, **not proof of actuator motion**. `PAIL_BRIDGE_IO` provides matching and input/output counters; a publisher counter does not prove driver reception. Persistent SROS2 discovery failure must be diagnosed, not bypassed by a longer sleep or automatic authority release.

Gate/bridge/planner/drive/agent logs and inspect metadata are preserved under the robot rig's `restart-logs/` (beside this script, operator-owned) before restart or down; `state/` belongs to the gate (uid 10001, mode 700) and the operator does not read it. Each archive holds the lines logged since the previous archive (`--since` the stamp in `restart-logs/.last`; the first archive is complete) and only the ten most recent ordinary archives are kept. Readiness-failure archives (including partial captures) are stored separately under `restart-logs/failed/` and are never automatically rotated. Copy them before manual cleanup and monitor disk space; failed archives have no automatic size limit. Gate, bridge, planner, drive, base, agent, safety and robot-state helper diagnostics are collected when their containers exist. This preserves evidence; it does not repair DDS authentication or retry automatically.

**C1 cohort on the hardware.** There is one communication contract and no setting that selects it: `issuer_host.sh up` and `start_demo_rig.sh up` refuse a `PAIL_CORE_COMM_CONTRACT` value of any kind by name (`CORE_COMM_CONTRACT_SETTING_REMOVED`, code 78); leave it unset. Start the Issuer first. The robot agent reads the Issuer's contract on its first census and, on a mismatch, exits with `PAIL STARTUP REFUSED: CORE_COMM_COHORT_MISMATCH …` (code 78); `up` then ends with `RIG_FAILED: agent exited`. If the Issuer is replaced or rolled back while the robot runs, the agent holds new authority (the robot stops receiving permits; `GetActiveToken` answers `CORE_COMM_COHORT_MISMATCH`), its readiness probe reports `report_storage_state=COHORT_MISMATCH`, it logs the mismatch every 30 s with the number of reports it is holding and re-declares the census with a 5 s to 60 s backoff. When the Issuer answers `v1` again the hold clears on that census — `CORE_COMM_COHORT_RESTORED` in the agent log, within one backoff interval, **without restarting the agent** — and the held reports are delivered (completed chains are then recorded as refused, `TERMINAL_REJECTED`). Only the cohort hold clears: a storage fault (`CORE_REPORT_STORAGE_UNHEALTHY`) stands until restart and the restore line names any hold still in force. Measured on the Microduck pre-seal run of this release; the in-service Issuer swap on the TurtleBot3 is not yet measured. C1 reports are never downgraded to the C0 wire, so a mixed interval leaves no decision evidence in the journal — the agent's state says that the interval happened. A restart whose logs could not be archived prints `RIG_LOGS_NOT_SAVED` and still restarts (`GATE_RESTARTED logs=unsaved`). A `down` whose logs could not be archived prints `RIG_DOWN_INCOMPLETE`, exits 3 and keeps the stopped containers; `start_demo_rig.sh down --discard-logs` removes them without archiving, after which `up` is accepted again. Planner `step_done`/`plan_done` mean the command budget ended, with `physical_execution=NOT_VERIFIED`; only the independent drive/encoder observations establish execution.

For a remote agent fault injection, supply `--robot-ssh ubuntu@tb3.local --agent pailhw-agent` (and `--robot pailhw-gate` only if gate kill is intended). Issuer pause/resume and ledger reads remain on the operator PC. The outage mode has no validated hardware recipe for reaching its no-permit precondition; pre-issued delegated steps can remain authorized. Do not label a precondition miss as PASS.
