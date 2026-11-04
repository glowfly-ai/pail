# Role-isolated synthetic reference v3

This is the recommended new preparation profile. v1/v2 remain reproducible legacy references; v2 shares credentials and is not a role-isolation example. Neither profile is NVIDIA hardware qualification.

## Boundary

Ten roles run in ten containers with distinct non-root UIDs, private PID/IPC namespaces, readonly roots, dropped capabilities and no-new-privileges. A credential-free netspace provides shared loopback networking. There is **no claim of L3 network separation or DoS resistance**, host/Docker/VM escape protection, hardware safety certification or actual Jetson/Isaac Sim verification.

Issuer and robot agent run their existing separate binaries. A dedicated requester holds its own mTLS client identity and submits plans directly to the cloud listener. Gate uses a separate client identity to the agent. Agent/cloud server keys are distinct. Existing robot identity and requester policy are reused; this does not invent a new RPC-method authorization model.

Each ROS role receives only its own enclave identity and signed permissions. CA private keys, root signing keys, operator unlock keys and unused issuer rotation private keys stay in offline setup state. Public trust material is copied explicitly; symlinks are materialized only from approved CA/governance targets. Role views are not copies of the full config. Never mount master config into a runtime role.

Each actor can write only its own logs/state. The planner sees controller input read-only and cannot edit the monitor's file. The host controller and trusted setup helper retain administrative access and remain in the TCB. A compromised role can still misuse its own authorized capability or lie through a trusted sensor feed; the isolation limits lateral credential/process access, not the truth of sensor data.

## Use

With evaluation images already loaded, run from this directory:

```sh
python3 session.py prepare --profile profiles/mock-humble-v3.json --core /path/to/pail-evaluation/pail-core --state /tmp/iso-run
python3 session.py serve --state /tmp/iso-run
```

From another terminal use status/exercise/idle/stop as in [managed reference](MANAGED.md). `exercise` is explicit and synthetic only. After stop or failure use a fresh state. A failed v3 view never falls back to shared v2 config. Provisioning is offline and uses a temporary trusted root setup container for certificate generation and ownership; runtime containers are non-root. No key bytes are printed.

The Jetson candidate is `profiles/jetson-orin-humble-v3.json`; it remains unverified and requires actual board/JetPack validation. Runtime views have one-day ephemeral development TLS leaves and the existing short-lived evaluation trust bundle; this is not production credential rotation or unattended uptime support.

## Tests

```sh
python3 check_isolation.py --core /path/to/pail-evaluation/pail-core --root /tmp/iso-matrix --repeat 3
python3 check_managed.py --profile profiles/mock-humble-v3.json --core /path/to/pail-evaluation/pail-core --root /tmp/iso-faults --case all --repeat 3
```

The isolation matrix checks own material positively, foreign material negatively (including different own keys at common filenames), absent CA/root/operator material, unique namespaces/UIDs, raw-socket refusal, cross-role/write boundaries, enclave impersonation and DDS denials with a live normal control.

v3 `--case all` runs normal, bridge stall, endpoint loss, monitor loss and supervisor orphan. The old trusted permit fixture is **not** in this role set; requesting it is rejected rather than granting planner extra gate credentials. `--case log_corruption` remains an explicit separate test. The legacy v2 fixture evidence is not relabeled as v3 execution.

Full state contains offline CA/private keys and must never be exported wholesale. `session.py export` adds only sanitized `isolation-checks.json` and `role-view-audit.json` to the existing public-summary allowlist. No credential views or projection key hashes are exported by that command. Existing delivered ZIPs are not modified by these commands.
