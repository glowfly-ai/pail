# Install, run, and understand one PAIL test

PAIL Core is an Apache-2.0 source archive. It builds and runs its Core tests
without private Issuer sources. For dynamic issuance and robot demos, use the
matching **PAIL Evaluation** bundle, which combines this Core with a separately
licensed Issuer executable. See [RELEASE.md](RELEASE.md).

Start in the evaluation directory (beside `pail-core/`):

```sh
python3 evaluation.py load                         # offline bundle: supplied local image archives
python3 evaluation.py doctor
python3 evaluation.py test-microduck --state /tmp/pail-eval-test-1
python3 evaluation.py microduck --state /tmp/pail-eval-demo-1
```

The bootstrap-only bundle requires the matching image archives supplied through
the evaluation delivery channel; use `load --images-dir /path/to/archives`.
It does not assume a published registry. Keep state outside the delivery and
choose new empty directories. No activation or telemetry upload is required.
The lower-level commands below run from `pail-core/` after the image lock and
images have been installed by the evaluation bundle. Core-only builds are not
represented as complete Issuer integration tests.

## Offline versus source build

| Path | Offline after evaluation load? |
|---|---|
| Evaluation launcher tests/demos, default low-level Microduck/TB3 runs | Yes; supplied images |
| Default E2E profile | Yes; supplied image is also the port probe |
| `--vault` variant | Not included; prepare its dependencies separately |
| Explicit `build`, Go/C++/Rust builds | Network or populated tool/dependency caches required |

Keep a pristine copy for supplied images and a working copy for source changes.
TB3 hardware setup uses the supplied binary Issuer and public Core images; see
examples/tb3/HARDWARE.md. Only the raised-wheel TB3 scope reported in VALIDATION
is claimed. Other historical hardware links are not newly validated.

## 1. Choose a supported path

| Host | Recommended path / evidence boundary |
|---|---|
| macOS, Apple Silicon | Docker Desktop using Linux containers; this platform has runtime evidence for the single-robot demos. Two-robot fleet scene verdicts have Linux evidence only |
| Linux | Docker Engine with Compose plugin v2 or newer (`docker compose`) plugin; intended path, validate the actual host/architecture |
| Windows native PowerShell/CMD | These POSIX runners are not supported natively |
| Windows with WSL2 Ubuntu | Candidate route with Docker integration, not validated as a supported recipe yet |

Install Python 3.9+, Docker Engine/Desktop + Compose plugin v2 or newer (`docker compose`) and OpenSSL. The TB3 runner
uses a private Linux-container network; allocate at least 4 GB Docker memory.
The macOS system `openssl` command backed by LibreSSL 3.3.6 has also been tested.
Start Docker before testing:

```sh
python3 --version
docker compose version
docker info
openssl version
```

A cold build including downloads can take 10–20 minutes or longer; cached images/layers
can reduce it to a few minutes. CPU, architecture and network affect this substantially.
The Core source ZIP and the offline evaluation ZIP are different deliveries. The latter includes runtime images. Explicit source builds still require toolchains and dependencies; disk use exceeds archive size.


### Windows with WSL2: filesystem matters

Use a WSL Ubuntu shell with Docker integration enabled, Python 3 and OpenSSL. Prefer
a checkout and state under the WSL Linux filesystem (`~/pail`, `/tmp/...`), not a
Windows drive path such as `/mnt/c` or `/mnt/d` for generated private state. Windows
drive mounts can present modes that cannot enforce 0600; the runtime access preflight
will refuse them. The same source ZIP is used on macOS, Linux and WSL2. Native Windows
PowerShell/CMD is not a runtime path for these POSIX runners. A successful probe on
one Docker Desktop version does not prove every host-networking setting works.

Before installing Docker, Python-only checks can already run from a pristine tree:

```sh
python3 scripts/check_public_content.py
python3 scripts/check_public_links.py
python3 spec/tools/spec_conformance_check.py
```

On native Windows use `python` instead of `python3` if that is the installed command.
Spec diagnostics escape characters the console cannot encode (for example `\u2014`)
instead of crashing. This changes presentation only, never checked vector bytes.
For UTF-8 redirected output, set `PYTHONIOENCODING=utf-8` in the calling environment.

## 2. Start with TB3 software verification

From the extracted repository root:

```sh
python3 examples/tb3/run.py
```

The [TB3 guide](examples/tb3/README.md) explains the eight checks and the separate
hardware path. The terminal prints `STATE=...`, each verdict, and `RESULT=PASS` or a
failure. The runner does not move a robot. In particular, `base_forward` means the
**mock base received commands**, not that wheels moved.

Open the printed state's `evidence/FINAL_RESULT.json` and `evidence/results.json`.
Each result records its expectation, observation and timestamp. Logs and raw JSONL are
beside them. `bridge_deadman` tests that gate loss stops forwarding despite a continuing
planner; it is not a physical emergency-stop certificate.

### 2a. Watch the same stack decide, live

```sh
python3 examples/tb3/demo.py build --build-window-confirmed   # from-source path (online); the evaluation delivery skips this
python3 examples/tb3/demo.py start
python3 examples/tb3/demo_scenes.py      # optional, second terminal: runs and judges every scene
```

If you received the **evaluation delivery**, do not build: its launcher starts the same
console on the supplied images, offline (`python3 evaluation.py tb3 --state /tmp/pail-tb3-live`,
see the delivery README §4). `demo.py build` is the path for a source checkout with internet.

`demo.py` keeps the same issuer, gate and motion bridge running, adds a simulated base and
serves a local page where you type commands such as `forward 1 m` and see each decision.
The [TB3 demo walkthrough](examples/tb3/DEMO.md) explains the page and every scene.
Positions are simulated and the tag/safety inputs are synthetic; a passing scene is a
software result, not a robot measurement. To run the same scenes on a physical TurtleBot3,
follow [`examples/tb3/HARDWARE.md`](examples/tb3/HARDWARE.md).

## 2b. Try Microduck without the robot or ROS

Run from the **same extracted root**; no host ROS installation is needed:

```sh
python3 examples/microduck/run.py doctor
python3 examples/microduck/run.py demo --state /tmp/pail-duck-first
python3 examples/microduck/run.py conformance --state /tmp/pail-duck-suite
```

Use a new state directory for each command that runs a test. The demo checks no-token
refusal, permitted command forwarding, and a speed-bound violation against the pinned
upstream fake. The conformance suite adds fault and actual permission checks. Its known
CA-15 skip is a fake skill-list limitation, not a successful hardware check. Read
[the Microduck guide](examples/microduck/README.md) for expected results and limitations.

For a browser console on the same stack plus the observation dashboard reading this run's
ledger, run `python3 examples/microduck/demo.py start` (a source checkout first builds with
`python3 examples/microduck/demo.py build --build-window-confirmed`; the evaluation delivery
instead uses `python3 evaluation.py microduck --state /tmp/pail-single` on its supplied images,
offline) and read the [Microduck demo walkthrough](examples/microduck/DEMO.md).
To run two simulated robots under one issuer and one dashboard, follow
[Software fleet](examples/microduck/DEMO.md#software-fleet-shared-issuer) in the same walkthrough.

Keep `result.json`, `run.json`, `source-manifest.json` and logs from the printed state.
The runner stops its own Compose services at the end, including failures; per-run
private volumes remain for inspection. Do not share private keys or whole private volumes.

For first evaluation, run TB3, Microduck demo, then Microduck conformance **sequentially**.
A first build downloads dependencies; ZIP size is not the required Docker disk space.
The local viewer described below consumes E2E state, not Microduck state; a Microduck
result is currently inspected as JSON/logs, not imported into that viewer.

## 3. The separate issuer/gate E2E

```sh
bash e2e/run_e2e.sh
```

This exercises issuance, gate enforcement, local journal, file anchoring and verification.
It prints `STATE=...` and `EVIDENCE=...`. Each invocation uses new state; specify a
**new/empty absolute directory** with `PAIL_E2E_STATE` if desired. Reusing nonempty state
is refused; older evidence is not deleted. The source checkout is not modified. Each run stages manager config under
`STATE/provision/config` and service-owned config under `STATE/runtime/config`.
Private keys remain 0600; do not chown the checkout or make keys world-readable.
Use a **new state** to run again from the same checkout, including after a failure.
Run E2E serially: host networking, ports and ROS domain 0 are still shared constraints.
The default E2E uses host networking in the Linux Docker environment; Docker Desktop
may require its host-networking feature. It provisions SROS2 domain 0; nonzero
`ROS_DOMAIN_ID` is refused. Prefer the isolated TB3 path if host networking is unavailable.

Before anything else, E2E checks both selected TCP ports in Docker's host network
namespace with the **services image itself** (the supplied evaluation image, or the one
a source checkout builds); no separate probe image is pulled, so the check also works
offline. On Docker Desktop this can differ from the macOS host's view. A busy or
unreadable probe exits 2; no existing listener is stopped.
E2E checks again with the same image before provisioning keys.
The first result is `evidence/ports-before-build.json`; the second is `evidence/ports.json`.
The real bind can still race the preflight, so startup logs are also inspected on failure.
To select different free ports:

```sh
PAIL_NORTHBOUND_PORT=50151 PAIL_CLOUD_PORT=50161 bash e2e/run_e2e.sh
```

For example (replace the path with an unused directory):

```sh
PAIL_E2E_STATE=/tmp/my-pail-e2e-first bash e2e/run_e2e.sh
```

| Output | How to read it |
|---|---|
| `evidence/run.log` | Per-check PASS/FAIL and the actual identifiers observed |
| `evidence/run.done` | `rc=0` means the runner completed successfully; absent means completion is unconfirmed |
| `evidence/services.log`, `observers.log` | Service and raw topic-observer diagnostics retained before shutdown |
| `evidence/ports.json` | The port pre-check observed on the Docker network before the run |
| `blackbox/` | This run's journal, retained independently of viewer indexes |
| `anchor/` | **Same-host file anchors**, not an independent external witness |
| `evidence/verification-keyring.json` | Public verification material saved for this run; not private signing keys |

A failed preflight can exit before evidence is created. Read the terminal message.
A nonzero exit is not a passing test. Keep failed-run evidence as well as successful runs.
Do not merge journals or viewer indexes across runs or delete evidence to make a badge green.
The complete state may contain private test material (especially bundle mode); share only
reviewed logs/verdicts/journal and public verification material, never an entire key/state tree.

## 4. What "demo" and "dashboard" mean here

- **CLI examples:** the E2E and TB3 commands above; included and runnable without hardware.
- **TB3 live demo console:** `examples/tb3/demo.py`, included; a local page with a
  simulated base, described in the [walkthrough](examples/tb3/DEMO.md). It is a
  demonstration requester, not an operations dashboard.
- **Microduck live demo console + dashboard:** `examples/microduck/demo.py`, included; the
  same kind of page on the official `robotd --fake`, and the observation dashboard
  (`pail_telemetryd`) on a mirror of that run's ledger — see the
  [Microduck walkthrough](examples/microduck/DEMO.md).
- **Offline robot-operations example:** `examples/robotops/`, included; builds the two
  offline declaration checkers and a fixture writer, runs them outside the tree, and
  makes them fail on purpose — [walkthrough](examples/robotops/README.md). Nothing in
  it talks to a robot, and a PASS is not an authority to apply anything.
- **Optional observation UI:** `cloud/cmd/pail_telemetryd` source is included in this
  release. It defaults to English; select 한국어 in the header for Korean. It is an observation view, not
  an authorization control plane. This inclusion does not settle future commercial UI scope.

Use CLI evidence first. You do not need a browser or a locally installed Go compiler
for the two Docker test paths.

### Optional: inspect a completed E2E locally

Run from the public source root on macOS or Linux/WSL2:

```sh
python3 examples/viewer/run.py --state /tmp/my-pail-e2e-first
```

Use the exact E2E `STATE=...` path (not a TB3 state). Docker builds a native viewer;
no host Go/protoc installation is needed. The tool verifies the exported snapshot,
runs `-reindex` and `-index-check`, connects the matching robot registry, then serves
`http://127.0.0.1:18090/dashboard/?tab=timeline&preset=6h`. Stop with Ctrl-C.
Use `--port 18091` if occupied, or `--check-only` for indexing checks without a browser.
`--skip-build` reuses this state's previously built viewer binary.

E2E cleanup stops its containers and exports `viewer-input/`, with file hashes in
`evidence/viewer-input-manifest.json`. The host user owns this snapshot. Runtime
private keys and root signing keys are **not** copied to it. The original journal
stays service-owned. The viewer reads a stopped-run snapshot, not a live tail. For
an older run, adjust the time window. The robot selector uses that run's
`evidence/robot_registry.yaml`; confirm the selected robot is resolved and applied.

If the view is empty, check the E2E result, snapshot export and read permissions,
reindex/index-check result, Timeline tab, time window and robot filter, in that order.
Permission denied and `chain_error` are failures, not empty successful input.
Index-origin agreement is not external anchoring or physical-action certification.
The basic E2E does not wire every live UDP feed; an empty live table can coexist with
a populated journal timeline. This helper opens only local loopback listeners.

**Authentication boundary:** the embedded HTML is public, while bearer-enabled APIs
require `Authorization: Bearer`. The current UI does not implement a bearer login
flow. This local helper therefore rejects an inherited `PAIL_TELEMETRY_TOKEN` rather
than opening a silently empty authenticated UI. Do not expose this local recipe on
another interface. Remote use requires a separately configured authentication/TLS
integration; a container port mapping alone does not supply browser authentication.

### Language selection

The observation dashboard defaults to **English**, independent of browser language.
Use **Language / 언어** in the header to select Korean. The choice is remembered in
this browser when local storage is available. `?lang=en` or `?lang=ko` overrides it
for a shared link. Switching language reloads the view while preserving the current
tab and applied URL filters; finish or discard unsaved input first.

`http://127.0.0.1:18090/dashboard/?tab=timeline&preset=6h&lang=en`

The local query helper accepts examples such as `last 1 hour robot 1 BLOCK` and
`최근 1시간 로봇 1 차단`. It is a limited rule-based helper, not an AI translator;
unknown words are shown as ignored. Review the parsed filter before clicking Apply.
Raw IDs, reason codes, hashes, API responses and journal bytes are not translated.
Unknown server/user-provided text is displayed unchanged rather than guessed.

### Images retained by TB3 tests

The runner records image IDs/tags in evidence and uses unique tags per invocation.
By default it retains these tags for reproducibility and prints exact cleanup commands.
`python3 examples/tb3/run.py --remove-images` removes only tags successfully built by
that invocation after evidence collection. Images supplied with `--skip-build` are
never removed. Build-cache layers may remain; no global prune is performed.
`evidence/image-cleanup.json` records the cleanup outcome separately from runtime verdicts.

## 5. Sending useful feedback

Include the ZIP name/hash, host CPU/OS, Docker/Python versions, exact command, printed
state path, return code, expected/observed behavior, and reviewed evidence. The test
runner's logs are stronger evidence than a summary saying "everything passed".
Use [SECURITY.md](SECURITY.md) for private vulnerability reporting.

For public documentation checks: `python3 scripts/check_public_links.py`.
For spec checks, run the `spec/tools/spec_*_check.py` tools. The final line reports
`PASS`/`FAIL`, `failures`, `skipped_groups`, `unmeasurable_groups` and `scope`.
The counts refer to skipped/unmeasurable observation groups, not individual assertions.
`PASS` means no findings in the performed scope, not that skipped checks ran.
A prerequisite failure exits 2 before a normal summary; findings exit 1 and successful
performed scope exits 0. Use exit codes/fields, not `grep -i fail`.
The ambiguous legacy `FAIL 0` counter line no longer exists (removed before the first public release).
Checker-owned diagnostics are English; quoted input text retains its original language.


### Public Go test scope

Run tests against the complete public tree, not a cloud-only builder layer. The
shared robot fingerprint TSV and site-model example are required inputs; missing or
unreadable copies are failures, not SKIP. The normal public run explicitly skips:

- `TestEmitRealRecord`: opt-in record export; needs the documented output/key inputs.
- `TestCommittedKeyMaterialIsListed`: audit of key files in earlier source history.
- `TestRenamedKeyStillRejected`: historical source-file relabeling audit.

The public run still checks TSV/compiled fingerprints, removed annotations, absence
of listed live certificates, fresh-key acceptance and rejection of every known
fingerprint under a renamed label. Historical private keys are not republished to
make the two source-history audits run. These test skips are distinct from the spec
checkers' skipped observation-group counts.


### Strict-umask runtime validation

TB3 declares shared-observation directory/file modes separately from private keys,
and performs a service-write/host-read probe before functional checks. For a stricter
Linux check, use a fresh state with `(umask 077; python3 examples/tb3/run.py)`.
Permission or clock prerequisites are reported separately from functional findings;
check `prerequisite-failure.json` when present. No runner changes system clock services.
