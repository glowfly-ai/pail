# Brev preparation tools

These tools do not create or bill GPU VMs. The measured scope and results of
the actual Isaac Sim connection are in [ISAAC.md](ISAAC.md); "unverified" below
refers only to combinations outside that table. Korean: [BREV.ko.md](BREV.ko.md).

## Host preflight (read-only)

```sh
python3 brev_preflight.py --state-parent /home/ubuntu/workspace --output /home/ubuntu/workspace/preflight.json
```

`preflight=PASS` still means `support_status=UNVERIFIED`. It checks one L40S
candidate, native Linux amd64 (the Docker daemon architecture, the same check
the evaluation CLI applies as `ARCH_MISMATCH`), at least 8 vCPU / 32 GiB RAM /
200 GiB free (recommended 16 vCPU / 64 GiB / 500 GiB), Compose and GPU
visibility. It requires a new output file and does not judge cost, port access,
rendering, ROS or certification.

## SDK smoke (physics/API only)

Run inside your derived SDK image ([recipe](sim/sdk/SDK_IMAGE.md)); it must
fail in plain Python. The script writes its verdict before Kit closes and uses a
local ground plane, so it needs no network:

```sh
docker run --rm --gpus all --network none -e ACCEPT_EULA=Y -e PRIVACY_CONSENT=N \
  --entrypoint /isaac-sim/python.sh -v "$PWD:/pail:ro" -v /persistent/smoke:/out \
  pail/isaac-sim:6.0.1-security-candidate /pail/sim/isaac_smoke.py --output /out/sdk-smoke.json
```

A PASS covers an actual physics pose change and a render step request only; it
proves nothing about pixels, streaming, PAIL authorization, ROS, SROS2 or a
physical stop, and it does not replace the v4 session or the matrix.

## Isaac session and matrix

Follow [ISAAC.md](ISAAC.md): profile → `doctor` → `prepare` → `serve` →
`status` (READY_LOCKED) → `check_isaac.py` → `stop` → `export`, then
`check_isaac_matrix.py` with `--cache-seed` to avoid the 9–10 minute cold
start per state. After a normal cancel the controller reports
`EXERCISE_COMPLETE`; `stop` returns after the summary is on disk.

## Operations

Keep state and evidence under a persistent path such as `/home/ubuntu/workspace`,
never `/tmp`. Export only the allowlisted summaries; private state directories
hold generated keys. Billing continues after the SSH session ends: Stop the VM
yourself (storage is still charged while stopped) and Delete only after the
evidence is safe — deleted data is not recoverable.
