# Changes

## 0.2.2

Security fixes and operating changes since 0.2.0; there is no public 0.2.1 release.
Read "Upgrading from 0.2.0" before you replace a running 0.2.0 deployment.

- Journal verification. `blackbox_verify --check-chain` prints `OK: chain verified`
  only when a key is given and every record is under a verified signed checkpoint.
  A journal without a signed checkpoint fails; records after the last checkpoint
  are reported as `UNATTESTED_TAIL` (exit 7, `-allow-unattested-tail` to accept);
  without a key the tool exits 2 unless `-structure-only` is given. `-expect-head`
  compares the journal with a head held outside it. The journal writer now writes a
  checkpoint when writes pause and when it is closed.
- Start-up replay. The Issuer verifies every checkpoint signature of its journal at
  start-up against the issuer keys of its keyring and refuses to start on a checkpoint
  that does not verify. Records after the last checkpoint are accepted only up to
  `PAIL_CHECKPOINT_EVERY_RECORDS` and are signed before the first request is served.
- Plaintext control plane. In the production profile `PAIL_GRPC_TLS=off` is refused
  (`S4`) whether or not `PAIL_GRPC_UDS_PATH` is set: the TCP listener is opened either way.
- Context events. With a requester registry loaded, `IngestContextEvent` is accepted
  only from a registered requester whose entry grants that event kind
  (`context_events`). Refused events are still journaled.
- Replay switch. `PAIL_REPLAY=off` is refused in the production profile (`S41`).
- Stopping. On SIGTERM or SIGINT the Issuer stops its servers (up to 5 s for requests
  in flight), closes the journal under a signed checkpoint and exits 0. The single-host
  entrypoint `pail_split_entrypoint.sh` (TB3 demo, E2E compose, NVIDIA example) waits for
  that sequence and exits with the Issuer's code.
- Verification receipt. `pail_verify` and `verify_evaluation.py` no longer write the
  verification receipt inside the delivery tree when the tree is reached through a
  symbolic link (for example a copy under `/tmp` on macOS) or when the receipt directory
  comes from `PAIL_VERIFICATION_RECEIPT_DIR`. A receipt there made the next tree check fail.
- Base images. The Issuer, Microduck and gate images are built on refreshed
  `debian:bookworm-slim` and `ros:humble-ros-base` bases that carry the fixed `apt`
  (CVE-2026-109518).
- Adapter contract. The gRPC step-deadline case is now `CA-19`; `CA-16` names only the
  API44 case of the case table.
- TurtleBot3 hardware example. `issuer_host.sh down` stops the Issuer with SIGTERM before
  removing it, so its stop sequence runs.
- Telemetry index. The collector's query index keeps a rolling window
  (`index_retain_days`, default 7) instead of growing until it stops; raw files are
  not affected. `/v1/telemetry/storage` reports the window, the daily rate and the
  disk room left. `db_max_bytes` now defaults to 0 (no fixed budget; room is set by
  free disk space).
- Repository hygiene. `.gitignore` no longer ignores the six bundled PVS gRPC stubs
  under `pvs-public/runner/live/`; with 0.2.0 a `git add -A` of the unpacked tree
  dropped them and `verify_release.py` reported them missing.
- Demo consoles. A plan or skill command sent while a raw drive is still running first
  ends the raw drive and waits for the planner's acknowledgement and its stop window;
  without an acknowledgement the command is refused (`RAW_STOP_UNCONFIRMED`) and no
  token is requested. Before, a leftover raw command could be permitted under the new
  token and start its time window early. The judges' scene 6 waits for the end of the
  raw drive.
- Adapter test. `test-adapter --adapter-binary` accepts an executable of the bundle's
  architecture (`architecture` in `images.lock.json`; the Docker daemon's in a
  Core-only tree). Before, only an ARM64 executable was accepted, also in the amd64
  bundle.
- End-to-end run. Under emulation (bundle and Docker daemon of different
  architectures) `run_e2e.sh` prints `EMULATION:`, records `evidence/platform.txt` and
  marks its result line as not a measurement of the bundle architecture.
- Readiness probe. A missing adapter or robot daemon socket is reported as
  `NOT_READY: <socket>: …` instead of a Python traceback.
- Tests. The collector index tests no longer depend on the free disk space of the
  machine that runs them (a test-only seam for the disk measurement).
- Documents. `SECURITY.md` section 4.5 lists the known limits of this release, and
  `docs/TRUST_OPERATIONS.md` section 5 gives the issuer key rotation and revocation
  rules. The measurement table in the README states what this release measured and
  names no single architecture; each bundle's validation record does.
  The evaluation README section 7 says how to delete a state directory that a Linux
  Docker Engine left with root-owned files.

### Upgrading from 0.2.0

- Keep the public half of every issuer key that signed a checkpoint still in the
  journal, under `keys` or `revoked_keys`. A checkpoint signed by a key absent from
  both is refused at start-up.
- Add a `context_events` grant to every requester entry that sends context events.
- Remove `PAIL_REPLAY=off` and any `PAIL_GRPC_TLS=off` from production configurations.
- Scripts that check `blackbox_verify` must handle exit 7 and, without a key,
  pass `-structure-only` explicitly.
- A container stop now exits 0, not 143. A restart policy that restarts only on
  failure will not restart a stopped Issuer.
- The start-up OK line names `S41`: `OK (S4,S5,S41,…)`.
- The first start of 0.2.2 on a 0.2.0 journal may log once that it adopted records
  written after the last checkpoint. That is expected.
- The telemetry index may now grow past 2 GiB on busy sites; it is bounded by the
  window and by free disk space.
