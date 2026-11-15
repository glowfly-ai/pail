# NVIDIA platform preparation (experimental)

This is **not a general claim of NVIDIA/Jetson/Isaac Sim compatibility** and no official NVIDIA certification or endorsement is implied. Measured scope: the v3 role-isolated CPU reference on a Jetson Orin Nano Super (native, 7/7 scenarios and an 8-hour segmented soak, no GPU) and the v4 actual Isaac Sim endpoint on **one Brev L40S VM** (Ubuntu 24.04, driver 580.173, Isaac Sim 6.0.1 derivative image, TurtleBot3 Waffle Pi USD). See [the Isaac Sim guide](ISAAC.md) (Korean: [ISAAC.ko.md](ISAAC.ko.md)) for the support matrix and open findings.

## Support matrix

| Profile | Architecture | What was measured | Not claimed |
|---|---|---|---|
| mock v1/v2/v3 | arm64, amd64 | synthetic reference with the real gate/bridge; fault suite (normal, bridge stall, endpoint/monitor loss, orphan, permit replay, log corruption) | physical robots, GPU |
| jetson v3 | arm64 (Orin Nano Super, L4T 36) | native CPU reference 7/7; 8 h segmented soak | GPU, Isaac ROS, motors |
| isaac v4 | amd64 (Brev L40S) | BS-01..12 / BP-01..12 matrix: 14/14 cases with the expected result in two fresh-state repeats of the release run (13 PASS, the BP-11 positive control DETECTED), where a PASS means authorized motion starts (≥1 mm) and the cancel brings the body to rest — not distance or trajectory accuracy; one run of an earlier pre-release recorded one INCONCLUSIVE ([ISAAC.md](ISAAC.md)) | other GPUs/OS/SDK versions, OmniGraph ROS bridge, streaming, 50 Hz worst-case latency, SDK image redistribution |

The Isaac Sim image is derived locally from the pinned upstream digest with the two Dockerfiles under [`sim/sdk/`](sim/sdk/SDK_IMAGE.md) and the asset tree with [`sim/assets/`](sim/assets/ASSETS.md); PAIL ships the recipes, the test-only drive overlay and notices, never the image or converted assets.

### Container CPU and memory on the Jetson soak

During the 8-hour segmented soak on the Orin Nano Super (752 exercise/cancel cycles,
22 injected faults) the driver sampled `docker stats` once per cycle for all eleven role
containers: 786 samples over 8.4 h, median gap 35 s. `CPUPerc` is what `docker stats`
prints — percent of **one** CPU core — so the figures below are not a share of the
whole SoC.

| Role containers | median | p95 | max |
|---|---|---|---|
| all eleven roles, summed | 32.4 % | 35.1 % | 45.2 % |
| gate + motion bridge + robot agent (the PAIL robot side) | 4.4 % | 5.0 % | 17.2 % |
| monitor (synthetic observer) | 9.7 % | 10.7 % | 11.3 % |
| endpoint (synthetic base) | 8.9 % | 9.6 % | 10.3 % |
| planner (synthetic requester) | 6.0 % | 6.8 % | 7.3 % |
| gate | 2.2 % | 2.6 % | 15.0 % |
| issuer | 0.8 % | 1.0 % | 1.8 % |

Container memory stayed within 248–303 MiB summed and host `MemAvailable` within
4.9–5.2 GiB. Not recorded: host-level CPU (`tegrastats`), the `nvpmodel` power mode,
and anything between samples — so these are sampled operating points of a
**synthetic CPU reference**, not a robot workload, a peak, or a latency figure.
Per-decision latency on Jetson has not been measured.

## What is implemented

- Strict JSON profiles (stdlib-only; JSON is a YAML subset, but arbitrary YAML is not accepted).
- Read-only host diagnostics and a fail-closed candidate Jetson Orin Nano / L4T 36 / Humble CPU profile.
- A synchronous wrapper around the existing **real PAIL ROS gate and motion bridge** synthetic reference. This is not a second implementation of authorization.
- An independently tested endpoint timeout **model**; it is not installed as a physical driver watchdog or attached to the existing ROS reference sink.
- Exact source hashes, locked evaluation images, per-run evidence, and owned interruption/cleanup checks.

No new token format, gate policy, GPU dependency, hardware driver, Isaac Sim lifecycle controller, or new Issuer is introduced. Existing TB3 paths are unchanged. The Jetson candidate requires later exact BSP/OS/package locking and real board validation. Isaac ROS GPU workloads and latest JetPack are outside this initial CPU profile.

## Prerequisites

Python 3.9+, Docker Engine/Desktop with Compose v2, OpenSSL, and an extracted PAIL evaluation bundle with its images already loaded. Use `pail-core` from that bundle and keep `images.lock.json` beside it. The wrapper uses the existing image/protocol/release checks; it never builds or pulls images.

The mock profile runs on Linux or macOS ARM64/x86_64 with matching evaluation images. Image availability is separate: an ARM64 image is not an amd64 support claim. Never weaken SROS2 Enforce to make a check pass.

## Usage

Run from this directory. Replace the two paths below with your extracted evaluation tree and a **new, nonexistent** sibling state directory. The state parent must exist. State must be outside and not contain the source tree.

```sh
python3 run.py doctor --profile profiles/mock-humble-v1.json
python3 run.py prepare --profile profiles/mock-humble-v1.json --core /path/to/pail-evaluation/pail-core --state /path/to/new-nvidia-run
python3 run.py start --profile profiles/mock-humble-v1.json --state /path/to/new-nvidia-run
python3 run.py status --profile profiles/mock-humble-v1.json --state /path/to/new-nvidia-run
```

`start` is a bounded, synchronous synthetic suite, **not a persistent robot service**. It runs the real existing gate/bridge checks and tears down its own containers. Watch `reference.log` in the state directory. Allow up to 20 minutes (no image build); normal cached runs should finish earlier. Never reuse a started state, including failed runs.

From another terminal, `stop` requests that the live wrapper interrupt its own child. It does not signal arbitrary PIDs, delete state, or stop unrelated containers:

```sh
python3 run.py stop --profile profiles/mock-humble-v1.json --state /path/to/new-nvidia-run
```

A stop request is not a stopped receipt. Read the final result and cleanup status. If the wrapper itself was killed, it cannot consume requests: preserve logs and inspect the exact recorded project manually. A stale RUNNING result is not proof of a live worker. If child cleanup exceeds 90 seconds, an orphan PID is recorded and success is withheld; no broad kill is attempted.

For Jetson diagnostics, use `profiles/jetson-orin-humble-v1.json`. Preparation/start on that profile is limited to the same **CPU-only synthetic reference**, only after native Linux/Orin Nano/L4T checks pass. It never drives a robot or enables GPU access. Passing a CPU smoke never changes `hardware_verified:false` to true. `--require-verified` exits 3 because no verified NVIDIA support profile ships here.

## Evidence and results

- `prepared.json`: profile/source hashes, existing evaluation image lock, host preflight.
- `result.json`: PASS/FAIL/INCONCLUSIVE/NOT_RUN/RUNNING, explicit coverage and cleanup result.
- `reference.log`, `reference/evidence/`: raw existing gate/bridge synthetic evidence.
- `reference/` also contains generated **private test keys/state**. Do not publish or bundle the full run directory; the evidence boundary remains the existing runner's contract.

Read-only doctor checks do not prove Docker daemon availability or matching images; prepare validates the runtime lock. A report must contain all eight expected reference checks, successful process exit, unchanged source, and no remaining owned containers to pass. Missing/partial/duplicate checks cannot become PASS.

The observed endpoint is a ROS command sink, not physics or a real actuator. `coverage.endpoint_model` remains false for this wrapper run; the separate contract tests exercise the timeout model. GPU/Sim/physical coverage remains false. Millisecond model thresholds do not guarantee physical stopping time.

Exit codes: 0 successful operation (including explicitly NOT_RUN preparation/status), 2 invalid configuration/prerequisite, 3 missing evidence or verified support unavailable, 4 completed reference failure. Read the JSON status rather than interpreting every zero exit as a test PASS.

## Remaining work

Distributed TB3 endpoint watchdog/security; actual Isaac ROS package integration; the official OmniGraph ROS 2 bridge path; a second amd64 host and GPU model; the cause of the post-stop wheel-reading jitter seen after container-kill faults (body displacement stayed 0.0 m); log volume of the 60 Hz endpoint record. Upstream sources are research inputs, not bundled dependencies.

## Isaac Sim v4 matrix driver

[`check_isaac_matrix.py`](check_isaac_matrix.py) runs the BS/BP matrix on fresh v4 states (one case per state, four evidence levels, an authenticated ROS graph inventory, a sustained unauthorized-motion judge). `--with-fixture` adds the Sim-only controls prepared with `session.py prepare --fixture`; those runs carry `fixture_run: true` and never count toward a support claim. Read `suite.json` and the per-case `isaac-matrix-case.json` exports, not exit codes alone.

## Managed synthetic reference v2

[Optional ROS endpoint, supervision/recovery and MOCK lifecycle](MANAGED.md). Separate from the bounded v1 runner; NVIDIA hardware remains unverified.

## Role-isolated v3 (recommended for new work)

[Role-isolated v3 (recommended for new work)](ISOLATION.md). Legacy v2 remains a shared-key development reference.
