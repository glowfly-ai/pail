# Connect your adapter to the evaluation Issuer

This is a **software-only, localhost development** path using the real Issuer
executable and public gateway. No private Issuer source, internal images or company
server is needed. The sample does not move hardware or claim functional safety.

## 1. Start the Issuer and gateway

From the extracted evaluation directory, after `evaluation.py load`:

```sh
python3 evaluation.py issuer --state /tmp/my-adapter-rig
```

Everything below runs in a **second terminal**. Open it in the extracted `pail-evaluation/`
directory and record where that is — every later block starts from it and returns to it:

```sh
EVAL=$PWD      # the extracted pail-evaluation directory (contains evaluation.py and images.lock.json)
```

The foreground rig prints its project and endpoints, then `ENDPOINT_CHECK: PASS` once
both answered an HTTP/2 preface from this host. Defaults: Issuer `127.0.0.1:50061`,
gateway `127.0.0.1:50051`. Override with `--issuer-port 50161 --agent-port 50151`.
Ctrl-C, or `stop-microduck --state /tmp/my-adapter-rig` from another terminal, stops
only that owned rig. Existing listeners are never stopped.

Both listeners use **explicit plaintext development mode, loopback publishing**.
This is not the mTLS production deployment recipe. Do not expose these ports to a
network or disable a production system's TLS to use this example.

`run.json` records exact image IDs, endpoints and the endpoint check. `config/` contains
per-run keys, policy.yaml, site_model.yaml, robot_registry.yaml and
skills.<robot_class>.yaml. `journal/` and `agent-state/` persist after stopping. Never
share the private keys. Key generation is the public
`pail-core/scripts/gen_dev_keys.py --config-dir DIR`.

The rig uses `pail_cloud` as the Issuer entrypoint; `/etc/pail` is a read-only config
mount and `/var/log/pail_blackbox` is writable journal storage. The gateway uses
`pail_robot_agent`, reaches `issuer:50061` on the private network and keeps its
report queue outside the executable image. The generated `compose.json` is an
inspectable complete example of the required settings, not a hidden installer.

## 2. A new robot class and your own policy

```sh
python3 evaluation.py issuer --state /tmp/my-class-rig \
  --robot-id robot-17 --robot-class my_amr \
  --skills /absolute/skills.my_amr.yaml \
  --policy /absolute/policy.yaml
```

Use the public [skill schema](../../spec/SKILLS.md). The declared `robot_class`
must match the file, and skill action classes/envelopes must use supported names.
An optional `--site` supplies your site model; it must contain this robot/class.
Without it the rig generates a small synthetic bench/box-12 site with your ID/class.
Unsupported `params_schema` is rejected, not evaluated as arbitrary JSON Schema.
Changing a name does not add a new motion primitive or invent force-control support.

## 3. Try the minimal C ABI adapter

The public `minimal.py` demonstrates token polling, ABI version checking, safety/
evidence inputs, per-command judgment, periodic ticks, decision reporting and
STOP on exit. It uses NDJSON stdin/stdout as a **test sink**, never motor I/O.
A real port must implement transport ownership, real feeds, stop/deadman behavior,
and the complete [adapter contract](../../spec/ADAPTER_CONTRACT.md).

In the second terminal, read the rig's project name from its `run.json` (it is also printed
as `PROJECT=…`). Keep the adapter alive, wait for its execution handshake, then submit the plan. A restarted adapter must not inherit a previously delegated plan:

```sh
PROJECT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["project"])' /tmp/my-adapter-rig/run.json)
( set -e
  CMD_DIR=$(mktemp -d)
  mkfifo "$CMD_DIR/in"
  exec 3<>"$CMD_DIR/in"
  docker exec -i "$PROJECT-agent-1" python /opt/pail/adapter-reference/minimal.py --synthetic-inputs <"$CMD_DIR/in" 3>&- >"$CMD_DIR/out" 2>"$CMD_DIR/errors" &
  ADAPTER_PID=$!
  trap 'exec 3>&-; kill "$ADAPTER_PID" 2>/dev/null || true' EXIT
  for i in $(seq 1 60); do grep -q '"ready": true' "$CMD_DIR/out" && break; sleep 0.5; done
  grep -q '"ready": true' "$CMD_DIR/out" || { cat "$CMD_DIR/errors"; exit 1; }
  docker exec "$PROJECT-issuer-1" python /opt/pail/example/demo_probe.py submit --target box-12 --steps '[{"linear":0.1,"angular":0,"duration":5}]'
  printf '%s\n' '{"linear":0.1,"angular":0,"duration":1,"skill":"twist"}' >&3
  sleep 2
  exec 3>&-
  wait "$ADAPTER_PID"
  trap - EXIT
  cat "$CMD_DIR/out"
  echo "Adapter evidence: $CMD_DIR" )
```

Without a token the same command is BLOCK. Above the policy, it is BLOCK. The
`--synthetic-inputs` flag explicitly supplies fake OK safety and box-12 evidence;
without real or synthetic feeds the gate must not be assumed ready. A successful
stdout decision is **not a physical execution report**. For a custom class also
pass `--robot-id`, `--robot-class` and `--skills /etc/pail/skills.<class>.yaml`.
On start the sample prints one `{"startup": …}` line on stderr with the keyring mode
and key count the gate loaded; a gateway that answers but refuses the token request
(a robot id this rig does not bind) is reported there as `GATEWAY_REFUSED_TOKEN_REQUEST`,
while the stdout decision stays the gate's fail-closed `BLOCK ERR_ISSUER_UNREACHABLE`.
The gateway binds the robot **id**; the robot class is enforced by the skill file and
policy, not by that binding.

## 4. Test your replacement adapter, not our binary

`test-adapter` drives one concrete shape: the **Microduck-compatible UDS/CLI profile**,
written down in [the adapter contract, §5a](../../spec/ADAPTER_CONTRACT.md#5a-microduck-compatible-udscli-profile)
(sockets, command line, `hello`/`api_version`, gate-log lines, runtime image and
`libpail_gate` ABI). If your adapter keeps that shape, compile a Linux ARM64 executable
and keep it outside the delivered source tree:

```sh
python3 evaluation.py test-adapter --adapter-binary /absolute/my-pail-duckd \
  --state /tmp/my-adapter-conformance
```

The runner mounts **that exact file** into the enforcing adapter, observe adapter
and harness, records its SHA-256 in run.json, and runs CA-01..CA-15 through the
published backend. It does not silently substitute the supplied adapter. The
reference backend has CA-15 `NEEDS_UPSTREAM_BUILTIN_LIST` as SKIP, not PASS.
A path that does not exist or a file that is not a Linux ARM64 ELF is refused by
name (`CUSTOM_ADAPTER_NOT_FOUND`, `CUSTOM_ADAPTER_PLATFORM`); an ELF that does not
open the public socket makes the run `BLOCKED` at the adapter readiness deadline.

Three steps that turn this into evidence. Every block from here on is a subshell that
starts from `$EVAL` (§1), stops at its first error and leaves your shell where it was, so
the blocks can be pasted **in this order into one shell**; that is exactly how the
maintainers run them — as one script, before a release is packaged. Each step has its
own working directory and refuses to reuse one that already exists. The blocks are not
indented, so a copy from the raw `README.md` runs as well as one from a rendered page.

A word the results can carry besides PASS and FAIL: **`INCONCLUSIVE`**. It means the rig
could not decide a case from what it observed — no gate record reached the harness while
the far side showed the commands flowing, or the permit rate was measured while the
observer itself was starved. The runner reruns such a case once from a fresh reset; if
the word stays, the result is `RESULT=INCONCLUSIVE` (exit 4) with the reason in
`limitations`, and the right move is to run again on a quiet host with a new `--state`.
It is not a verdict on your adapter, and a healthy adapter does get it on a loaded host.
A refusal that *was* observed is a FAIL and stays one.

**Step 1 — take the reference binary out of the image** and test it, so you know the rig
is green before your code is in it:

```sh
( set -e; cd "$EVAL"
  IMG=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["images"]["microduck"]["id"])' images.lock.json)
  C=$(docker create "$IMG"); docker cp "$C:/usr/local/bin/pail-duckd" /tmp/reference-pail-duckd; docker rm "$C" >/dev/null
  python3 evaluation.py test-adapter --adapter-binary /tmp/reference-pail-duckd --state /tmp/ad-reference )
# PASS_WITH_LIMITATIONS 14 pass / 0 fail / 1 skip; run.json custom_adapter.sha256 == sha256sum of the file
```

**Step 2 — build your own from source** in a working copy (online; the delivered tree
stays pristine): the gate library first, then the adapter against it. Prerequisites on
Ubuntu 24.04: `cmake protobuf-compiler libsodium-dev libyaml-cpp-dev pkg-config
build-essential git python3-venv` from apt (`python3-venv` is for §5), and **Rust ≥ 1.89
via rustup** (`Cargo.toml` pins it; the apt `rustc` 1.75 is too old). `cargo build`
fetches the pinned upstream IPC crate from git on the first run. rustup puts `cargo` on `PATH` for new shells only; the blocks
below source `$HOME/.cargo/env` when `cargo` is not found, so they also run in the shell that
just installed rustup.

```sh
( set -e; cd "$EVAL"
  test ! -e /tmp/pail-adapter-work || { echo "/tmp/pail-adapter-work exists: remove it first"; exit 1; }
  cp -R pail-core /tmp/pail-adapter-work
  cmake -S /tmp/pail-adapter-work/libpail_gate -B /tmp/gate-build -DBUILD_TESTING=ON && cmake --build /tmp/gate-build -j
  command -v cargo >/dev/null || . "$HOME/.cargo/env"   # rustup puts cargo on PATH only for NEW shells
  cd /tmp/pail-adapter-work/adapters/microduck && PAIL_GATE_LIB_DIR=/tmp/gate-build cargo build --locked --features libgate
  python3 "$EVAL"/evaluation.py test-adapter --adapter-binary /tmp/pail-adapter-work/adapters/microduck/target/debug/pail-duckd --state /tmp/ad-built )
# PASS_WITH_LIMITATIONS 14 pass / 0 fail / 1 skip for a healthy build; INCONCLUSIVE (see above) is the host, not your code
```

A debug binary built on Ubuntu 24.04 (glibc 2.39, needing `GLIBC_2.34` at most) ran in
the bookworm image; that is an observation, not a compatibility promise — check `ldd`
against the image.

**Step 3 — inject a defect and watch the rig fail it** (the negative control that proves
the rig tests *your* bytes). The block replaces the `if !shared.judge(...) { continue; }`
of the MOVE arm in `adapters/microduck/src/relay.rs` with a call whose result is ignored,
builds, **copies the defective binary out of the working copy**, then restores the source
and rebuilds, so the working copy ends healthy and `/tmp/defective-pail-duckd` is the only
defective file. Expected: `RESULT=FAIL` (the block's exit status is 1 for that reason)
with **exactly these eight** cases red — CA-01..06, 09, 10, the ones where a BLOCK on a MOVE
must keep bytes from the robot. CA-13 stays green: it is a skill call (`robot.do`), and the
defect ignores BLOCK on the MOVE arm only (an earlier build listed it among the red cases
because the previous case's unspent lease leaked into it; each case is now isolated). CA-08
(deadman timing) can additionally come out red or `INCONCLUSIVE` on a loaded host for a
reason unrelated to the defect; it passes with the healthy binary. Keep both run.json files; their `custom_adapter.sha256` differ.

```sh
( set -e; cd /tmp/pail-adapter-work/adapters/microduck
  command -v cargo >/dev/null || . "$HOME/.cargo/env"   # rustup puts cargo on PATH only for NEW shells
  cp src/relay.rs /tmp/relay.rs.orig
  python3 - <<'EOF'
import pathlib
p = pathlib.Path("src/relay.rs"); s = p.read_text()
old = """                if !shared.judge(conn, &peer, &req.method, Some(class), None, lin, ang) {
                    reply_blocked(&c_wr,req.id.clone()).await;
                    continue;
                }"""
assert old in s, "MOVE arm not found"
p.write_text(s.replace(old, "                let _ = shared.judge(conn, &peer, &req.method, Some(class), None, lin, ang); // DELIBERATE DEFECT: ignore BLOCK", 1))
EOF
  PAIL_GATE_LIB_DIR=/tmp/gate-build cargo build --locked --features libgate
  cp target/debug/pail-duckd /tmp/defective-pail-duckd      # the defective binary lives OUTSIDE the working copy
  cp /tmp/relay.rs.orig src/relay.rs                          # the source is restored ...
  PAIL_GATE_LIB_DIR=/tmp/gate-build cargo build --locked --features libgate   # ... and so is target/debug/pail-duckd
  python3 "$EVAL"/evaluation.py test-adapter --adapter-binary /tmp/defective-pail-duckd --state /tmp/ad-defective )
```

### 4a. A robot that is not a Microduck: your own conformance backend

A transport-independent C ABI integration is **not automatically Microduck IPC**. For
a different controller protocol you implement a conformance **backend**: a class
implementing `pvs-public/runner/core/backend.py` (`setup`/`teardown`/`reset_state`, the
step methods `north_cmd`, `inject_evidence`, `inject_cmd_vel`, `inject_skill`,
`inject_safety`, `fault`, and the far-side observations `gate`, `bridge`, `drive`,
`permits`, `stop_request_asserted`; `enforcement_supported()` is `False` unless you
override it, and then the Enforcement axis is reported SKIP, never PASS), placed as a
module under `pvs-public/runner/adapters/`. Unsupported axes return `unsupported`;
nothing is faked. `pvs-public/runner/adapters/example_backend.py` shows the shape; it
re-uses the Microduck transport so the pipeline can be measured without a second robot,
and proves nothing about yours.

The harness runs the tree baked into the image it was built from, so a new backend
needs a **working-copy build** (online) and the delivered Issuer image beside it:

```sh
ISSUER=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["images"]["issuer"]["id"])' "$EVAL"/images.lock.json)
( set -e; cd "$EVAL"
  test ! -e /tmp/pail-backend-work || { echo "/tmp/pail-backend-work exists: remove it first"; exit 1; }
  cp -R pail-core /tmp/pail-backend-work && cd /tmp/pail-backend-work
  cp pvs-public/runner/adapters/example_backend.py pvs-public/runner/adapters/my_backend.py
  sed -i 's/class ExampleBackend/class MyBackend/; s/example_backend:ExampleBackend/my_backend:MyBackend/' pvs-public/runner/adapters/my_backend.py
  python3 examples/microduck/run.py conformance --build --issuer-image "$ISSUER" --backend my_backend:MyBackend --state /tmp/my-backend-ca )
```

`--build` builds the Core image from this copy (its source identity is recorded, so the
image and the tree you edited stay bound), `--issuer-image` names the delivered Issuer
image for a tree that has no `images.lock.json` of its own, and `--backend MODULE:CLASS`
selects your class; its rows are the Microduck column of `CA_MAP.yaml` until the map has
a column for your transport (`--rows-of microduck_uds` inside the harness), including its
two tool rows (CA-07, CA-15), which run the Microduck tools whatever the backend's name.
The report's `backend` field carries your name. The minimal stdout example is not
advertised as a full CA-conformant motor adapter.

**A robot that lacks a seam.** Most real robots cannot drive every axis; the honest
backend raises `Unsupported` there (`example_backend.ExampleBackendWithoutSafetyFeed`
does it for the safety feed, CA-10). The rig reports that row SKIP, never PASS, and on
its own the run is **`BLOCKED`** (`Unreviewed skip: CA-10`): the rig does not decide for
you that the gap is acceptable. You accept it, in writing, with `--reviewed-skip
"CA-NN:<why>"`; the row stays SKIP, the reason is recorded in the report and the result's
`limitations`, and the result is `PASS_WITH_LIMITATIONS`. A FAIL or a skip declared by the
map cannot be reviewed away.

```sh
( set -e; cd /tmp/pail-backend-work
  python3 examples/microduck/run.py conformance --build --issuer-image "$ISSUER" \
    --backend example_backend:ExampleBackendWithoutSafetyFeed \
    --reviewed-skip "CA-10:this robot exposes no safety-feed seam; the stale-feed refusal is covered by its own bench procedure" \
    --state /tmp/my-honest-ca )
# PASS_WITH_LIMITATIONS 13 pass / 0 fail / 2 skip; limitations name CA-10 and the reason. Without --reviewed-skip: RESULT=BLOCKED
```

The public rig wrapper `pail-core/pvs-public/conformance/rig_microduck.sh --state
/tmp/reference-ca` runs the reference; add `--adapter-binary /absolute/file` to
exercise your compatible replacement. It uses the evaluation images, not :dev tags.

## 5. From the host instead of inside the image

`evaluation.py issuer` publishes its two endpoints on `127.0.0.1` and refuses to hand
over until both answered an HTTP/2 preface **from the host** (`ENDPOINT_CHECK: PASS`).
To run `minimal.py` on the host against them you need the gate library from step 2 of
§4, generated Python messages, grpcio/protobuf (`python3-venv` from apt), and **the
keyring trust mode**. The block starts a fresh adapter, waits for its handshake and then submits its own plan; it does not depend on a previous process retaining authority:

```sh
( set -e; cd "$EVAL"
  python3 -m venv /tmp/v && /tmp/v/bin/pip install grpcio grpcio-tools protobuf   # measured with grpcio 1.84 / protobuf 7.36
  mkdir -p /tmp/py && /tmp/v/bin/python -m grpc_tools.protoc -I pail-core/sdk/proto -I pail-core/libpail_gate/abi \
    --python_out=/tmp/py --grpc_python_out=/tmp/py pail-core/sdk/proto/*.proto pail-core/libpail_gate/abi/pail_gate_abi.proto
  RIG=/tmp/my-adapter-rig
  PROJECT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["project"])' $RIG/run.json)
  CMD_DIR=$(mktemp -d)
  mkfifo "$CMD_DIR/in"
  exec 3<>"$CMD_DIR/in"
  PAIL_KEYRING_MODE=unsigned-dev PYTHONPATH=/tmp/py /tmp/v/bin/python pail-core/examples/adapter/minimal.py --library /tmp/gate-build/libpail_gate.so --gateway 127.0.0.1:50051 --policy "$RIG/config/policy.yaml" --keyring "$RIG/config/keys/keyring.json" --skills "$RIG/config/skills.microduck.yaml" --robot-id robot-1 --robot-class microduck --synthetic-inputs <"$CMD_DIR/in" 3>&- >"$CMD_DIR/out" 2>"$CMD_DIR/errors" &
  ADAPTER_PID=$!
  trap 'exec 3>&-; kill "$ADAPTER_PID" 2>/dev/null || true' EXIT
  for i in $(seq 1 60); do grep -q '"ready": true' "$CMD_DIR/out" && break; sleep 0.5; done
  grep -q '"ready": true' "$CMD_DIR/out" || { cat "$CMD_DIR/errors"; exit 1; }
  docker exec "$PROJECT-issuer-1" python /opt/pail/example/demo_probe.py submit --target box-12 --steps '[{"linear":0.1,"angular":0,"duration":5}]'
  printf '%s\n' '{"linear":0.1,"angular":0,"duration":1,"skill":"twist"}' >&3
  sleep 2
  exec 3>&-
  wait "$ADAPTER_PID"
  trap - EXIT
  cat "$CMD_DIR/out"
  echo "Adapter evidence: $CMD_DIR" )
```

`PAIL_KEYRING_MODE=unsigned-dev` is what lets the gate library accept the rig's
**unsigned development keyring**; without it the library requires a signed bundle,
loads zero keys and refuses every token with `BLOCK ERR_UNKNOWN_KEY_ID` even though the
Issuer issued it. The sample's `{"startup": …}` stderr line shows the loaded mode and key
count so this is visible before the first command. The mode is development-only: a
deployment uses a signed keyring bundle, never this flag. Inside the containers the same
variable is set by the compose files, which is why §3 needed nothing extra.

## Execution restart boundary

Deploy the gateway, Issuer and enforcement clients from the same bundle. Each client creates a fresh UUID per process and sends `pail-execution-instance` metadata on every GetActiveToken call. Do not use a response unless it carries exactly one acknowledgement matching that identity. Restarting the gateway or enforcement process terminates an active plan whose authority was already delegated; submit a fresh plan. A pending, never-delegated plan is preserved in lease mode. Run one enforcement process per robot; this is not duplicate-gate arbitration.

For software tests only, `--interactive-inputs` allows the NDJSON `synthetic_inputs` boolean to control synthetic-feed refresh. Turning refresh off does not erase observations; they age according to their normal deadlines. A command's optional `request_id` is echoed in its response to distinguish it from tick observations.
