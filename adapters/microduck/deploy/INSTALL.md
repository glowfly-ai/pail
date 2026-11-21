> **Experimental: physical board validation is pending.** Start with the robot-free preview in `examples/microduck/`.

# Installing pail-duckd on a Microduck board

`pail-duckd` is the PAIL adapter for Microduck: an interposer that takes over the control
socket every client dials (`/run/robotd.sock`), asks the PAIL decision library whether each
intent is authorized by a token the issuer signed, and forwards the original bytes only on
PERMIT. Nothing here changes the robot's own daemons; one drop-in moves `robotd`'s socket
behind the adapter. This is a board installation procedure, not a hardware validation claim.

> 한국어판: [`INSTALL.ko.md`](INSTALL.ko.md). The English text governs.

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


## 1. What you need

| Item | Where from |
|---|---|
| `pail-duckd` (aarch64, built with `--features libgate`) | the public Microduck Dockerfile or a compatible release artifact |
| `libpail_gate.so` (aarch64) | the PAIL decision library, built **without ROS**: `cmake -S libpail_gate -B build && cmake --build build` (or `libpail_gate/Dockerfile.ci`) — the ABI is `libpail_gate/abi/pail_gate_abi.proto` |
| A board with the upstream daemons installed (`scripts/install.sh` of the microduck repo) | robotd, updaterd, padd, btd … under `/opt/robot/daemon/current` |
| Sealed PAIL configuration | `/etc/pail/policy.yaml`, `/etc/pail/keys/keyring.json` (or the signed bundle), provisioned from the issuer side — **not** written by this installer |
| The PAIL robot agent reachable from the board | `unix:/run/pail/agent.sock` (same board) or a dev bench address |

### 1a. Extract a traceable development artifact (no board)

Start at the **extracted public repository root**, with Docker and Python 3.9+.
Use a new state path. The demo builds from this source and records the exact image ID:

```sh
python3 examples/microduck/run.py demo --state /tmp/pail-duck-export-run
PAIL_EXPORT_IMAGE=$(python3 -c 'import json; print(json.load(open("/tmp/pail-duck-export-run/run.json"))["image_id"])')
PAIL_EXPORT_DIR=$(mktemp -d /tmp/pail-duck-artifacts.XXXXXX)
PAIL_EXPORT_CONTAINER=$(docker create "$PAIL_EXPORT_IMAGE")
docker cp "$PAIL_EXPORT_CONTAINER:/usr/local/bin/pail-duckd" "$PAIL_EXPORT_DIR/pail-duckd"
docker cp "$PAIL_EXPORT_CONTAINER:/opt/pail/lib/." "$PAIL_EXPORT_DIR/lib"
docker cp "$PAIL_EXPORT_CONTAINER:/opt/pail/upstream/updater.toml" "$PAIL_EXPORT_DIR/updater.toml"
docker rm "$PAIL_EXPORT_CONTAINER"
cp /tmp/pail-duck-export-run/run.json "$PAIL_EXPORT_DIR/origin-run.json"
docker run --rm --network none --entrypoint cat "$PAIL_EXPORT_IMAGE" /etc/os-release > "$PAIL_EXPORT_DIR/build-os.txt"
docker run --rm --network none --entrypoint ldd "$PAIL_EXPORT_IMAGE" /usr/local/bin/pail-duckd > "$PAIL_EXPORT_DIR/build-loader.txt"
printf '%s\n' "$PAIL_EXPORT_DIR"
```

`docker create` does not start the copied daemon. The upstream updater fixture is copied
from the same pinned build, not fabricated as a board configuration. Keep origin-run.json,
source/image hashes, build-os.txt and the loader report together. The `lib` directory copy
preserves both linker and SONAME names. It does **not** bundle all distribution libraries.

When moving artifacts to another host, copy the directory and set `PAIL_EXPORT_DIR` to
its absolute path there. Shell variables do not travel with the files.

### 1b. Check target OS and shared-library compatibility

| Environment | Meaning |
|---|---|
| Preview build/runtime | Debian 13 trixie containers (Debian 12 up to 0.2.2); artifacts are Linux ELF even on macOS |
| Debian 13 native loader | Requires compatible glibc/libstdc++, `libprotobuf32t64`, `libsodium23`, `libyaml-cpp0.8`. The arm64 artifacts built on 2026-11-18 ask for `GLIBC_2.38` and `GLIBCXX_3.4.32` at most; inspect the actual ELF dependencies of yours |
| Ubuntu 24.04 ARM64 host | Same yaml-cpp (0.8) and protobuf (32) SONAMEs, glibc 2.39. With those three packages installed the extracted `pail-duckd` loaded its staged library and answered `--help` in an Ubuntu 24.04.5 container (measured 2026-11-18). That is a loader observation, not a compatibility promise: run the checker, or use a Core built for this target |
| Debian 12 host | The extracted artifacts do not load: `GLIBC_2.38`, `GLIBCXX_3.4.32` and `libyaml-cpp.so.0.8` are missing (measured 2026-11-18). Use a Core built for this target |
| Actual Microduck board OS | Not certified by this preview; confirm the vendor image, `/etc/os-release`, architecture and runtime package versions before installation |

Same CPU architecture is **not** distribution ABI compatibility. On the intended Linux
host, use `file`, `readelf -d` and `ldd` to inspect artifacts you built/trust. For example:

```sh
file "$PAIL_EXPORT_DIR/pail-duckd"
readelf -d "$PAIL_EXPORT_DIR/lib/libpail_gate.so" | grep -E 'NEEDED|SONAME'
LD_LIBRARY_PATH="$PAIL_EXPORT_DIR/lib" ldd "$PAIL_EXPORT_DIR/pail-duckd"
```

Any `not found`, version mismatch or wrong architecture must be resolved before board
installation. Do not point a missing major SONAME at a different major with a symlink.
The image's successful loader check does not prove the host's loader will succeed.

For a native **Ubuntu 24.04** Core build (from the same public source root):

```sh
sudo apt-get install build-essential cmake pkg-config libprotobuf-dev protobuf-compiler \
  libsodium-dev libyaml-cpp-dev python3 systemd file binutils
cmake -S libpail_gate -B "$PAIL_EXPORT_DIR/native-core" -DBUILD_TESTING=OFF
cmake --build "$PAIL_EXPORT_DIR/native-core" -j2
```

Use `$PAIL_EXPORT_DIR/native-core/libpail_gate.so` as `--lib` on that host. This addresses
the target Core runtime ABI; it does not make an arbitrary foreign adapter executable
compatible. Inspect the complete loader output and C5 result. Build for the target OS
if the adapter itself requires unavailable glibc/libstdc++ versions.

## 2. Install

From the public root, enter the adapter directory. Only run this on a prepared board
with compatible artifacts and separately provisioned authorization configuration:

```sh
cd adapters/microduck
sudo sh deploy/install.sh --binary /absolute/artifacts/pail-duckd \
    --lib /absolute/compatible-core/libpail_gate.so
```

The script is idempotent and puts these files in place:

| Path | Role |
|---|---|
| `/opt/pail/bin/pail-duckd`, `/opt/pail/lib/libpail_gate.so` | the adapter and the decision library |
| `/etc/systemd/system/pail-duckd.service` | the adapter's unit — serves `/run/robotd.sock`, hands it to the `robot` group **by name** |
| `/etc/systemd/system/robotd.service.d/pail.conf` | drop-in: `robotd` listens on `/run/robotd/raw.sock` (root:pail 0660 inside `/run/robotd` 0750) |
| `/usr/lib/sysusers.d/pail.conf` | the `pail` group — the only principal that may open the raw socket |
| `/etc/pail/pail-duckd.env` | profile, agent endpoint, robot id (kept if it already exists) |
| `/etc/pail/duck_skills.yaml` | skill name table `name → MOVE\|MANIPULATE\|NONE` (kept if it already exists) — see §3 |
| `/etc/robot/updater.toml` | only `robot_socket` is changed, to the raw socket (§4) |

Then, under a running systemd: `systemd-sysusers`, `daemon-reload`, `enable pail-duckd`,
`restart robotd` (its socket moves), `start pail-duckd`. Check:

```sh
systemctl status pail-duckd
journalctl -u pail-duckd | grep -E 'S27|S28|S29|skill table|serving'
```

You want to read `S27 verified: raw socket closed to others`, `skill table loaded`, and
`serving`. Under `PAIL_PROFILE=production` (the default) the unit **refuses to start** on:

| Banner | Meaning | Fix |
|---|---|---|
| `S27 raw ingress reachable by others` | the raw socket or `/run/robotd` is open to "others" — the drop-in is not in effect | `systemctl daemon-reload && systemctl restart robotd`, then check `ls -la /run/robotd` |
| `S28 no enforcing gate linked` | the binary was built without `--features libgate` or `libpail_gate.so` did not load | rebuild; check `LD_LIBRARY_PATH=/opt/pail/lib` |
| `S29 skill name table missing` | `/etc/pail/duck_skills.yaml` absent, empty, or with an unknown class word | write the table (§3) |
| `--public-group names no group` | the `robot` group does not exist | `systemd-sysusers` (upstream's `robot.conf`) |

## 3. The skill name table

Upstream names skills by string (`robot.do {skill}`) and the list arrives at run time
(`robot.skills`). The adapter maps each name to the class the gate judges it as; a name not
in the table is **refused** at judgment (`ERR_ACTION_UNMAPPED`) — there is no default class.

At start the adapter asks the robot for its skills and prints the ones the table does not
map:

```
WARN skills the robot answers to that the table does not map — each will be refused (ERR_ACTION_UNMAPPED) unmapped=["roulade", "kick_left", "kick_right"]
```

Write those into `/etc/pail/duck_skills.yaml` with the class you decide, restart the unit,
and expect `skill table covers every skill the robot answers to`. The file is sealed
configuration; an empty table and an unknown class word are refused in every profile.

## 4. What survives an upstream update (R1)

The upstream updater installs `robotd.service` **from every release artifact**
(`updater/src/config.rs` requires `<unit>/systemd/<unit>.service` in the artifact) and
restarts it. That is why this package never edits that file: the drop-in
`robotd.service.d/pail.conf` is a separate file systemd merges on top of whatever the release
installs, and the updater's orphan check reads only `*.service` files
(`updater/src/orphan.rs`), never `.d/` directories. Verified by reading the pinned
upstream (`942e58e`), not yet on a board (MD-4).

Two things to re-check on every upstream release:

- the drop-in's `ExecStart=` override repeats upstream's command with `--socket
  /run/robotd/raw.sock`. If a release changes robotd's binary path or flags, this line must
  follow. The check below reports the line it would run.
- `updater.toml` is never rewritten by updates (upstream's own rule: "updates do not touch
  /etc"), so the `robot_socket` patch stays. `updaterd` runs as root and sends no intents,
  so it keeps talking to robotd directly — through the raw socket, which is why the patch is
  needed: an updater left on `/run/robotd.sock` would be asking the *adapter* about robotd's
  health.

## 5. Checking the package without a board

On a compatible Linux host with Python 3 and the systemd package, from the **adapter directory**:

```sh
sh deploy/check.sh --binary "$PAIL_EXPORT_DIR/pail-duckd" \
    --lib "$PAIL_EXPORT_DIR/native-core/libpail_gate.so" \
    --updater-toml "$PAIL_EXPORT_DIR/updater.toml" \
    --workdir /tmp/pail-duck-stage-first
```

The example above selects the Ubuntu-native library built in §1b. On a compatible
Debian 13 host, select `$PAIL_EXPORT_DIR/lib/libpail_gate.so` instead. Use a **new** workdir
outside the source tree; omitting it allocates a private temporary directory. No root
privilege or running systemd is required, and no real service is started.

- C1–C4 check staged paths, unchanged unit/drop-in shape, groups/socket paths and the
  updater patch's idempotence and scope. The upstream robotd executable remains a board prerequisite.
- C5 prepends the **staged** library path, preserves nonempty existing loader paths, reads
  flags from the staged unit and runs the staged ELF's `--help`. Compatible-host loader,
  permission and missing-flag errors are FAIL; unsupported host/architecture is NOT_RUN.
  Actual stderr, exit code and ELF/host architecture appear in `C5.json` and `C5.log`.
- C6 copies real packaged `.target`/`.slice` definitions from the host distribution into
  the verification root, retaining their hashes. It runs `systemd-analyze verify --man=no`
  against the **unchanged** adapter unit. No dummy targets or weakened dependencies are used.
  Host enablement symlinks, generators and unrelated services are deliberately not copied.
  Missing tools/definitions are NOT_RUN; actual unit/verification errors are FAIL.
- `C6.json` names the exact scope and unverified external dependencies. **Upstream robotd's
  unit, a booted board's service graph, live drop-in application, restarts and update survival
  are not verified by C6**; those require the actual board/system integration.

Every run prints `STAGE=...` and `MD3_RESULT=...`. The stage, `result.json`, C5/C6 JSON/logs
and install log are retained **including on failure**. `PASS_WITH_LIMITATIONS`/NOT_RUN is
not all-pass. Do not share the whole stage if a real updater configuration contains
operator information; select the reviewed reports. Do not make private keys world-readable.

## 6. Removing

```sh
sudo systemctl disable --now pail-duckd
sudo rm /etc/systemd/system/pail-duckd.service /etc/systemd/system/robotd.service.d/pail.conf /usr/lib/sysusers.d/pail.conf
sudo sed -i 's|robot_socket = "/run/robotd/raw.sock"|robot_socket = "/run/robotd.sock"|' /etc/robot/updater.toml
sudo systemctl daemon-reload && sudo systemctl restart robotd
```

Deliberately not scripted: removing the adapter puts the raw control path back in front of
every client, and that is a decision to type by hand.

## Installation evidence and backups

Existing replaced files are copied under `/var/lib/pail/install-backups/` before replacement.
Inspect current changes and the backup before manual restoration; do not overwrite later operator changes.
The loader SONAME alias `libpail_gate.so.1` is installed alongside the linker name.
An unavailable C5/C6 measurement is reported as NOT_RUN / PASS_WITH_LIMITATIONS, never all-pass.
An actual systemd verification error is a failure and its diagnostic must be reviewed.
