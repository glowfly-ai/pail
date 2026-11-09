# Actual Isaac Sim / ROS 2 connection (v4) — measured on one Brev L40S VM

The v4 profile keeps the existing authorization gate and motion bridge and
replaces only the endpoint with a **headless rclpy connection inside Isaac
Sim**. It is not the NVIDIA OmniGraph ROS 2 bridge and does not fall back to
the mock endpoint. The v3 CPU synthetic rig is unchanged. Korean: [ISAAC.ko.md](ISAAC.ko.md).

## Measured support (full matrix 2026-11-03, 0.2.0 module on the 0.2.0 amd64 images)

| Item | Value |
|---|---|
| Verified combination | Nebius/Brev L40S 1 GPU, Ubuntu 24.04.5 (kernel 6.11.0-1016-nvidia), NVIDIA 580.173.02, Docker 29.9.2, Isaac Sim 6.0.1 security-candidate derivative image built with the [recipe](sim/sdk/SDK_IMAGE.md) against the 0.2.0 amd64 gate image, TurtleBot3 Waffle Pi USD imported with the [asset recipe](sim/assets/ASSETS.md) (normalized tree hash `3d46465d…`, semantics `87249d4e…`, both as documented there) |
| Matrix | `check_isaac_matrix.py` BS-01..12 / BP-01..12, one fresh state per case seeded with a compiled shader cache (`READY_LOCKED` in 37–41 s), two fresh-state repeats |
| Result | 14 of 14 cases PASS in two fresh-state repeats of the release run (the BP-11 positive control is DETECTED in both), 28 of 28 runs complete, suite verdict PASS, 0 unauthorized-motion samples in every judged case; an earlier run of the same images recorded one INCONCLUSIVE (`deadline`, repeat 2, post-stop reading jitter), never counted as PASS and disclosed on the release page. Rest is judged on position change per physics step (snapshot schema 3); the SDK-reported velocities, which spike after abrupt stops while the joints and body do not move (gate_kill: reported up to 0.17 rad/s on a wheel whose angle-derived rate stayed ≤0.03 rad/s, body coast ≤4 µm), are kept in every record as evidence |
| What a PASS means | the authorized plan starts observable motion (≥1 mm, ≥5 mm/s) and the cancel brings the body to rest; the matrix does **not** measure distance, trajectory accuracy or physical stopping |
| Rendering | a viewport capture with a test-scene light (non-black ratio 0.979, 2026-10-19 capture on the same SDK version; the matrix does not repeat it); the first capture without a light was a black frame |
| Not verified | physical robots, RTX 5080, other OS/SDK versions, the official OmniGraph ROS 2 bridge, streaming/viewer, 50 Hz worst-case latency, long single processes |

Measured during the 0.2.0 packaging on amd64 images built from the frozen 0.2.0
inputs; the images delivered with 0.2.0 are rebuilt from the same inputs plus this
documentation, with the judge, rig and runtime sources byte-identical. The delivered
bundle's own recipient replay repeats the matrix on the delivered images and records
it in the delivery report.

An independent recipient run on 2026-10-16 (same VM, fresh directory, bundle's
own `pail-core`) reproduced the single-session check and 4/4 of the matrix cases
it ran (normal, bridge_stall, endpoint_loss, orphan).

## Prerequisites

- Native Linux amd64 with an NVIDIA GPU; `brev_preflight.py` ([BREV.md](BREV.md)) checks the host.
- An immutable local SDK image built from the pinned digest with [`sim/sdk/`](sim/sdk/SDK_IMAGE.md) (NGC login + pull, two Dockerfiles). PAIL never ships the image.
- A reviewed asset tree built with [`sim/assets/import_waffle_pi.sh`](sim/assets/ASSETS.md) in a directory that contains nothing else (expected tree hash `cdcbdc47…` for Isaac Sim 6.0.1).
- The matching amd64 evaluation bundle loaded (`evaluation.py load`); `images.lock.json` must sit beside `pail-core`.
- The SDK EULA read and accepted; only then pass `--accept-sdk-eula` to the profile generator. No privacy opt-in is set for you.

## Run

```sh
cd pail-core/examples/nvidia
python3 make_isaac_profile.py --image <local image sha256 ID> --version 6.0.1 \
  --asset-dir /persistent/assets --usd pail_tb3_waffle_pi.usda \
  --wheel-joints wheel_left_joint wheel_right_joint --wheel-radius-um 33000 --wheel-base-um 288000 \
  --accept-sdk-eula --output /persistent/isaac-profile.json
python3 session.py doctor  --profile /persistent/isaac-profile.json --state /persistent/isaac-run1
python3 session.py prepare --profile /persistent/isaac-profile.json --core /path/pail-evaluation/pail-core --state /persistent/isaac-run1
python3 session.py serve   --state /persistent/isaac-run1          # terminal 1
python3 session.py status  --state /persistent/isaac-run1          # terminal 2: wait for READY_LOCKED
python3 check_isaac.py     --state /persistent/isaac-run1          # authorized motion, then cancel to rest
python3 session.py stop    --state /persistent/isaac-run1          # returns after the controller wrote its summary
python3 session.py export  --state /persistent/isaac-run1 --dest /persistent/isaac-export1
```

- **Cold start:** a fresh state compiles shaders; expect **about 9–10 minutes** to `READY_LOCKED` on the L40S. With a seeded compiled cache it took about 40–60 s. The matrix driver copies a cache with `--cache-seed <…/kit/cache>` (a cache from the same image/driver only; never settings, logs, identities or control state). For a single session, seed `<state>/sim-cache/kit/cache` the same way before `serve`.
- **One exercise per state.** After the cancel the controller status is `EXERCISE_COMPLETE` (an earlier build reported `FAULT_LOCKED` here, which looked like a failure in scripts). `stop` now waits for the durable summary, so `export` can follow immediately; `status` shows `STOPPED` when the controller has exited.
- **Image IDs** differ between Docker storage drivers (containerd store vs overlay2); compare through `load`/the lock, not by eye.

## Full matrix

```sh
python3 check_isaac_matrix.py --core /path/pail-core --profile /persistent/isaac-profile.json \
  --root /persistent/matrix1 --cases all --repeat 2 --with-fixture --cache-seed /persistent/cache/kit/cache
```

Read `suite.json` (`verdict`, `complete`) and each case's `isaac-matrix-case.json`
export; `NOT_APPLICABLE` and `DETECTED` never count as PASS. Fixture cases
(`prepare --fixture`) are Sim-only controls, carry `fixture_run: true` everywhere
and never count toward a support claim.

## Boundaries

- The endpoint holds only its own `/nv_endpoint` SROS2 keys and refuses to start without `Enforce`, Fast DDS and Humble. It subscribes to `/drive_cmd_vel` only, never to raw `/cmd_vel`.
- The coordinator compares the real mTLS issuance with the agent's active token (ID and signed-bytes hash) before it writes a grant into the read-only control file; that file is not a ROS permission API and the planner has no write mount to it.
- After idle/timeout/pause/reset/clock faults, stop and recreate the whole path in a **new state**. Nothing resumes automatically.
- Applied wheel targets and the physics pose/velocity are recorded separately; the physics read lives inside the trusted SDK process, so it is not an observation independent of an SDK administrator.
- Rest and motion are judged on position change over one physics step (`wheel_velocity_from_angle`, `speed_from_pose`, `yaw_rate_from_pose`; snapshot schema 3), not on the SDK-reported velocities: after an abrupt stop the solver reported one wheel at up to 0.3 rad/s and a yaw rate of 0.03 rad/s for samples in which the joint angle stayed within 1e-5 rad and the body coasted 14 µm. The reported velocities remain in every record as evidence, and the thresholds (0.05 rad/s, 0.005 m/s, 0.005 rad/s) are unchanged.
- The first profile rejects embedded OmniGraph nodes and nonzero initial drive targets; this is not proof against arbitrary SDK extensions or administrator Python.
- No public streaming is opened inside the secure namespace; a viewer needs a separate network design. No automatic root/privileged fallback. Only the SDK endpoint gets 8 CPU / 24 GiB / one GPU / a cache mount; every other role keeps its key, namespace and mount boundaries.

Known limits: the 60 Hz endpoint record grows about 5 MB per minute; the
official SDK image's HEALTHCHECK looks at a log directory that the portable root
moves, so Docker shows the container as unhealthy while the controller's own
readiness is what counts; stopping the Brev VM is a separate step and storage
is still billed while stopped.

## Post-stop observation limitation

The classifier label `body_reading_jitter` is a legacy observation category, **not a demonstrated cause**. The raw trajectory of the INCONCLUSIVE run shows a persistent pose micro-step with correlated SDK angular velocity and wheel-angle changes; contact/friction/solver cause is unverified. The original INCONCLUSIVE is retained. Another threshold exceedance at 2.817 s was outside the fixed two-second verdict window. That window is not a claim about the entire post-lock interval. Three later PASS trials do not erase the original event. Numerical criteria and authorization checks are unchanged.
