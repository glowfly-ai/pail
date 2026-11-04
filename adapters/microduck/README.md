# PAIL Microduck adapter

Experimental, software-only preview. Physical hardware validation is pending.

`pail-duckd` sits in front of Microduck's robotd Unix socket. It uses PAIL Core over
its C ABI to evaluate supported commands and forwards permitted NDJSON without rewriting it.
It does not replace robotd's control loop or its physical safety functions.

Start with [the robot-free demo](../../examples/microduck/README.md).
Microduck is optional: the normal Core/ROS2 workflow does not build this Rust crate.

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


## Building the adapter

The public tree provides `sdk/proto`; an internal developer tree may instead provide `proto`.
If both exist, explicitly set `PAIL_PROTO_DIR`. A bad explicit path is an error, never a reason
to silently use another schema. Canonical ABI schemas come from `libpail_gate/abi`.

For an independently installed Linux Core library and compatible build dependencies:

```sh
PAIL_GATE_LIB_DIR=/path/to/core/lib cargo build --locked --features libgate
```

Run that command from this directory. The public demo Dockerfile builds all prerequisites
from source; no private image or ROS distribution is needed. Building without `libgate`
produces the developer plumbing path, not an enforcing adapter. Production preflight refuses it.

The upstream IPC dependency is pinned in Cargo.toml. Upgrade it and the fake daemon together,
then rerun the software suite. No wildcard allow branch should hide a new upstream method.

Board deployment is separate: [installation](deploy/INSTALL.md). Paths checked in a staging
root do not establish actual board boot, update compatibility or physical stop performance.
[한국어 안내](README.ko.md)
