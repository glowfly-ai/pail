# libpail_gate

The PAIL decision library: *is this command, right now, authorized by a token the issuer
signed, under the safety and evidence the policy demands?* One function (`gate_core`),
strict token verification (`strict_verify`, Ed25519 via libsodium), the sealed-policy
loader (`policy_load`), the keyring trust path (`keyring_bundle`), and the permit / step /
single-use / ESTOP state machine (`gate_session`) — behind one C ABI
(`include/pail_gate/pail_gate.h`, protobuf-binary buffers of `abi/pail_gate_abi.proto`).

It is **transport-neutral**: no ROS, no gRPC, no sockets. Everything that carries a command
to it and its verdict back is an *adapter* (`spec/ADAPTER_CONTRACT.md`):

| Adapter | Where | Needs ROS? |
|---|---|---|
| ROS 2 gate node (`pail_pep_gate`) | `robot/pail_pep_gate` — compiles these sources in, `add_subdirectory`s this CMake | yes |
| Microduck (`pail-duckd`, Rust) | `adapters/microduck/`; links `libpail_gate.so` through the C ABI | **no** |

## Build (no ROS)

```sh
cmake -S libpail_gate -B build -DBUILD_TESTING=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Dependencies: a C++17 compiler, CMake ≥ 3.16, protobuf (`libprotobuf-dev protobuf-compiler`),
libsodium (`libsodium-dev`), yaml-cpp (`libyaml-cpp-dev`). The token and plan messages come
from `../sdk/proto` (`pail.proto`, `token_service.proto`); point `-DPAIL_PROTO_ROOT=` elsewhere
if you vendor them. `Dockerfile.ci` builds and tests exactly this on Debian bookworm without
a ROS installation — that image is the proof that a non-ROS port needs nothing from the
ROS workspace.

Outputs: `libpail_gate.so` (SONAME 1), the headers, and the ABI `.proto` a binding
generator needs. The ABI major is `pail_gate_abi_version()`; an adapter refuses to run
against a different major.

## Batteries

The same ctest names run here and inside the ROS workspace (see the distributed CMake test registrations):
`gate_core`, `gate_failclosed`, `gate_defaults`, `world_match`, `time_strict`, `clock_drift`,
`contract_golden` (the frozen token vectors under `../spec/vectors`), `ra_boundary`,
`token_v5`, `session_snapshot`, `skills_load`, `key_revocation`, `keyring_bundle`, `gate_two_doors` (the C++ session and the C ABI side by
side, `G-ADP-03/04/05`).

## Naming

Two residues of where the code grew, both deliberate so the move is provably behaviour-free:

- `strict_verify.cpp` and `keyring_bundle.cpp` guard their libsodium/protobuf paths with
  `#if PAIL_ENABLE_GRPC == 1` (the ROS package's build option). This CMake defines it
  unconditionally — the library always has both — and without it the crypto paths compile
  to stubs answering `ERR_GRPC_DISABLED` (measured 2026-09-06: 5 of 11 batteries red).
- The C++ namespace is still `pail_pep_gate` — the library grew inside the ROS 2 gate package
and was moved out with its sources unchanged so that the move is
provably behaviour-free. Renaming the namespace is a separate, mechanical change.

## Step clocks (GC-TIME-1)

A positive `max_duration_sec` is a local elapsed-time budget, measured from the first
permitted command for the consumption key. It uses Linux `CLOCK_BOOTTIME` or macOS
`mach_continuous_time`, including suspend. Wall-clock corrections cannot reset, shorten
or extend that budget. Repeated commands and unreachable-issuer grace do not restart it.
An adapter tick services ordinary completion before rechecking the now-ended permit,
so normal completion does not emit a spurious constraint error.
At the elapsed deadline, command, grace and recheck paths refuse; the step timer consumes
and reports completion once. A timer delay does not authorize further commands.

Signed absolute token validity, evidence/safety freshness and clock-drift checks still use
the existing wall-clock contract. Both token validity and duration must hold; duration is
not permission to ignore expiry. Zero duration retains the absolute `not_after` fallback.
An unavailable or reversed elapsed clock blocks with `ERR_CLOCK_DRIFT` (latched per session).
An invalid/unrepresentable duration, or positive duration below 1 ms, is refused.

`GateInputs::step_deadline_ms` and `GateSession::step_deadline_ms()` are only a wall
projection for positive-duration diagnostics. The authoritative pair is `elapsed_now_ms`
and `step_deadline_elapsed_ms`. Refusal detail names `clock=elapsed` or `clock=wall`.
No monotonic timestamp is serialized or recovered across process/host restarts. The C ABI,
protobuf messages, token format and issuer executable are unchanged; C++ users must rebuild.

Tests: `step_clock` reproduces wall shifts using the session seam; Linux-only
`step_clock_injection` interposes clocks in its own process and exercises real signed tokens,
C++ session and C ABI. It does not change host time. `gate_two_doors` also runs with the real
OS clock. A fresh session has no active permit; this is not a new persistent replay store.

## Signed-keyring remaining lifetime

The C++ loader checks `expires_at - now` at load against
`PAIL_KEYRING_MAX_LIFETIME_SEC` (default 86400 seconds when unset). Explicit
malformed/nonpositive/out-of-range values fail with `ERR_BUNDLE_POLICY`, and
an excessive remaining window with `ERR_BUNDLE_LIFETIME`, before version state
is persisted. This is not bundle age. Root signature, rollback and expiry
checks remain independent. The ROS wrapper refuses startup for these policy
errors. The Go loader requires an explicit policy; do not infer identical
unset-variable behavior across languages. Rebuild C++ clients with this library.
