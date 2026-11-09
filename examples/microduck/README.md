# Microduck software-only preview

> **0.2 evaluation delivery:** first run `python3 evaluation.py load` in the evaluation directory.
> The Issuer runs from the evaluation image. The lower-level commands below run from `pail-core/` after that setup.
> Prefer the `evaluation.py` launcher for a first run.


**Experimental. No physical Microduck validation has been performed.** This independent
community integration is not endorsed by Pollen Robotics or Hugging Face.

The optional Microduck path uses the same PAIL Core as the ROS2 adapter. You do not need
ROS2, a robot, an Anchor SaaS account or a paid AI service for these software experiments.
The first build downloads public toolchains/crates and the pinned upstream Microduck source.

## Authorization boundary

Upstream `robotd` also serves `head_imu.stream` before its normal dispatch table.
Adapter v2 explicitly does **not** support this sensor stream; its rejection is a
PAIL support boundary, not a claim that upstream rejects it.

PAIL judges the commands a client sends over the robot socket. Motion the robot daemon
starts on its own — the pick-up pause (reported as `picked_up`, which PAIL treats as
UNSAFE), idle head and body motion, and the posture check before a policy starts
(not reported) — is outside this authorization boundary. PAIL does not stop that
motion and, except for `picked_up`, cannot observe it. The journal records decisions
on client commands during the interval, not the robot's autonomous movement.

Clearing `picked_up` restores the safety input only. It does not restore a revoked
plan: a new authorized plan is required. `robot.rest` and `robot.rebootMotors` require
ACTUATE authority; `robot.flashlight` is an expression command. A `robot.vetbookNote`
receipt is adapter-local audit, not proof of persistence in the PAIL blackbox.


## Try the demo

From the public source directory, with Python 3.9+ and Docker with the compose plugin v2 or newer:

```sh
python3 examples/microduck/run.py doctor
python3 examples/microduck/run.py demo --state /tmp/pail-duck-demo-1
```

Choose a NEW state directory outside the source tree. On Windows, use a WSL Linux home
filesystem, not `/mnt/c`. Only environments explicitly listed as tested in the release
compatibility information are validated; another Linux VM is not a WSL2 test.

The demo starts upstream `robotd --fake --no-policy`, a basic issuer, the robot agent and
`pail-duckd` linked with `libpail_gate`. It checks:

1. No token: an explicit refusal and no corresponding far-side command.
2. A valid grant: PERMIT and the expected far-side request.
3. A request above the configured speed bound: explicit refusal and no matching far-side request.

`RESULT=PASS` reports these software checks, not physical motion or safety certification.
`result.json`, `execution.log` and `services.log` live in your state directory. Runtime private keys and original journals are kept in the named private volume; the host-side `private/` mountpoint is not their storage. Initialization
creates fresh keys inside the task-scoped Linux Docker `private` volume, not a macOS bind mount. Do not publish or export that volume. Services stop at completion; task volumes
are retained. The source archive is never a place for generated keys or user state.

## Live demo console and dashboard

```sh
python3 examples/microduck/demo.py build --build-window-confirmed
python3 examples/microduck/demo.py start
python3 examples/microduck/demo_scenes.py      # optional, second terminal: runs and judges every scene
```

The same stack plus demo actors, a browser console like the TurtleBot3 one, and the
observation dashboard reading a mirror of this run's ledger. Step-by-step guide with
screenshots and every scene: [`DEMO.md`](DEMO.md) (한국어: [`DEMO.ko.md`](DEMO.ko.md)).
Positions are the integral of the velocity the fake reports as applied; the tag feed and
the safety-feed seam are synthetic; no live decision feed exists for this robot class.

## Full software conformance

```sh
python3 examples/microduck/run.py conformance --state /tmp/pail-duck-conformance-1
```

This adds isolated fault proxies and an observe-mode adapter. The host runner permits
only named operations on its own Compose project; the harness does not mount Docker's socket.
A reviewed CA-15 skip means the pinned fake cannot list built-in skills. It is a limitation,
not a passed test. Unexpected skips, missing cases and mismatched counters block acceptance.

```sh
python3 examples/microduck/run.py status --state /tmp/pail-duck-demo-1
python3 examples/microduck/run.py stop --state /tmp/pail-duck-demo-1
```

## Boundaries

- This is an isolated **development control transport** with unsigned local verification
  material. The adapter's production preflight enables its local enforcement checks, but
  does not make the entire development stack a production security deployment.
- No host ports, hardware devices, privileged mode or host network are requested.
- `robotd` fake is not a physics simulator. Applied velocity ramps after its deadman;
  software command refusal does not measure a real robot's stopping distance or time.
- The observe instance deliberately forwards would-BLOCK commands. It is not enforcement.
- Core runtime, RPC/protobuf schemas and the adapter must come from a compatible source
  snapshot. An existing image used with `--skip-build` is a developer shortcut, not evidence
  of a fresh source build.
- Physical board installation, firmware/update behavior, NFC access and remote per-user
  identity are separate validation work. Do not run this software demo against hardware.

## Troubleshooting

A BLOCK result alone is not success: check the named reason and whether the observer ran.
Read `prepare.log`/`startup.log` for prerequisite failures, and `execution.log` for failed
assertions. Do not fix permission errors with `chmod -R 777`. Preserve private key modes,
use a new state directory, and provide the non-secret report when requesting help.

See [한국어 안내](README.ko.md) and [adapter details](../../adapters/microduck/README.md).


## Build progress

The printed STATE directory contains `build.log`. If downloads appear idle, inspect that
file (for example `tail -f /tmp/pail-duck-demo-1/build.log`). Image layers and Rust crates
may wait on the network; an idle progress line alone is not a verdict. Preserve the log
and process exit rather than deleting the source or changing private-key permissions.
For native artifacts and OS/SONAME prerequisites, see [board installation](../../adapters/microduck/deploy/INSTALL.md).
