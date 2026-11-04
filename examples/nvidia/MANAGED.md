# Managed synthetic reference v2

This optional module implements CPU-only preparation, an actual ROS synthetic endpoint, owned rig supervision/recovery, and a **MOCK-only** simulation lifecycle barrier. It does not implement actual Isaac Sim APIs, Jetson hardware qualification, GPU workload integration, or physical robot control.

## Prerequisites and separation

Use an extracted PAIL evaluation bundle with its matching local images already loaded. Python3.9+, OpenSSL, Docker/Compose v2 are required. No implicit pull/build, new CUDA dependency, host networking, device access, or privileged runtime is used. Development keys are created per rig using existing guarded PAIL provisioning. The supervisor's local user/Docker administrator remains trusted.

The v1 `run.py start` remains a bounded suite. It rejects v2 profiles. Use `session.py` for v2. No systemd, cron or boot-time autostart is installed. `serve` maintains an isolated **synthetic** rig and does not issue a plan until the explicit `exercise` request.

## Commands

Run from this directory. Use a short, new state path with an existing parent, outside the source tree. Keep the evaluation `images.lock.json` next to its `pail-core`.

```sh
python3 session.py doctor --state /tmp/nv-run --profile profiles/mock-humble-v2.json
python3 session.py prepare --state /tmp/nv-run --profile profiles/mock-humble-v2.json --core /path/to/pail-evaluation/pail-core
python3 session.py serve --state /tmp/nv-run
```

Keep `serve` in that terminal. In another terminal:

```sh
python3 session.py status --state /tmp/nv-run
python3 session.py exercise --state /tmp/nv-run
python3 session.py idle --state /tmp/nv-run
python3 session.py stop --state /tmp/nv-run
```

`exercise` submits an actual authenticated development plan to the local evaluation Issuer and enables synthetic input for at most8 seconds. The actual gate still decides each request and may stop earlier. The ROS endpoint has no actuator publisher or hardware access. `idle` disables the input and requests cancellation; it does not clear a fault latch. A fresh prepared state is required after stop/fault/recovery. Prepared source, helper, image, compose and policy hashes are bound; changes refuse reuse.

`stop` acknowledges the request, not completed cleanup. Read final `status.json`/`public/summary.json`. `stop_confirmed` describes a newly observed synthetic zero, not physical stopping. Cleanup success and observation success are separate fields.

## Abrupt supervisor death and recovery

A stored ACTIVE/RUNNING state is not proof of life. Status challenges the private Unix socket; no response is ORPHANED. Recovery takes the exclusive controller lock, checks journal integrity and matches exact container IDs, images, project, run ID and generation. It refuses ambiguous resources and live controllers.

```sh
python3 session.py recover --state /tmp/nv-run
python3 session.py recover --state /tmp/nv-run --cleanup
```

The first command only inspects. Cleanup removes only positively owned resources and never resumes a plan. Unknown ownership or unreachable Docker remains an error, not inferred cleanup success. State/logs are retained. The synthetic planner's500ms local heartbeat-age lock and endpoint's250ms timeout are development settings, not certified real-time or physical safety guarantees.

## Endpoint and diagnostics

`ros_endpoint.py` provides separate endpoint, monitor and planner roles. Linux CLOCK_BOOTTIME is required; ROS simulated time does not determine command age. The endpoint accepts only finite planar Twist values, zeros on expiry and latches invalid-input/clock faults. The monitor independently observes snapshots and explicitly reports loss; a dead node is not a confirmed stop.

Read-only doctor distinguishes host and Docker information. Mac host free memory is not Docker VM free memory. The running rig records actual ROS/RMW/security/UID, cgroup memory limit/current, runtime overlay disk free and paired clocks. Resource thresholds are estimated admission settings, not a measured Jetson capacity guarantee. NTP synchronization and absent platform observations remain unverified.

The mock profile is for Linux/macOS with matching local images. `jetson-orin-humble-v2.json` is a **candidate**, gated on native Orin Nano/L4T36; it still does not claim tested hardware support or latest JetPack compatibility.

## Explicit fault suite

The development suite creates separate isolated rigs and deliberately stops actors/supervisors. It is not a robot or production test. Run only with the supplied synthetic profile:

```sh
python3 check_managed.py --core /path/to/pail-evaluation/pail-core --root /tmp/nv-suite --case all --repeat 3
```

Cases: normal + unauthorized publishers + lifecycle mock; frozen bridge/endpoint timeout; endpoint death; monitor death; supervisor orphan/recovery; trusted test-only repeated permit. The last fixture uses the generated gate identity inside the isolated rig; it is not an attacker entitlement or production launch role. Normal `session.py` never launches it.

Expected denial requires the matching security failure and a live observation/positive control; generic process failure is not PASS. The lifecycle model preserves a retained fake actuator command across pause to test the output barrier. Its authority source is always MOCK. No actual NVIDIA callback, bridge security or first physics tick is verified.

## Evidence and export

The full state includes private keys, certificates and journals: do not zip it. Public summaries are separated under `public/`. Export only the explicit summary allowlist:

```sh
python3 session.py export --state /tmp/nv-run --dest /tmp/nv-public-export
```

Destination must be new and disjoint from private state. Symlinks/secret markers are refused. Completion is indicated only by MANIFEST.json after all files are written. This allowlist exports tool-authored summaries, not arbitrary input logs. Validate intended recipient/content before externally publishing anything.

Result fields distinguish execution_status, test_verdict, support_status, coverage, stop_confirmed and cleanup. A live service/doctor rc0 is not a passed test. Hardware/GPU/actual Sim/physical flags remain false. Return codes:0 successful requested operation;2 invalid/failed request;3 observation unavailable/orphan;4 faulted managed execution. Failures and interruptions retain evidence.

[Original v1 bounded reference](README.md) remains available. Product release ZIPs are not rebuilt merely by running these tools.

## Development trust boundary

The synthetic actors share a development container and service UID with access to the generated test keystore. The negative tests prove DDS permissions for the selected identities; they do not prove resistance to key theft by compromised code inside that trusted container. Production role/key isolation and real driver safety remain separate deployment work. Readiness requires a delivered zero snapshot at the independent observer, not merely successful node construction. A partial suite report is INCONCLUSIVE until all expected cases complete.

## Role-isolated v3

[Role-isolated v3](ISOLATION.md). Legacy v2 remains a shared-key development reference.
