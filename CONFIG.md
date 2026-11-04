# Configuration of the evaluation and public Core

This is a recipient-facing overview, not a list of every internal maintenance setting.
Use the generated per-run `compose.json` / `fleet.compose.json` and `run.json` to inspect
exact mounts, identities, image IDs and values. Do not overwrite an existing installation.

## Software-only Issuer integration rig

`evaluation.py issuer` generates these files under a new external state directory:

| File | Meaning |
|---|---|
| `config/policy.yaml` | Limits, evidence requirements, token horizon and enforcement policy |
| `config/site_model.yaml` | Robot/class, zones, objects and site relationships |
| `config/skills.<robot_class>.yaml` | Supported skill classes, envelopes, feeds and completion signal |
| `config/robot_registry.yaml` | Robot identity declarations; the development rig's dummy TLS fingerprint is NOT enrollment |
| `config/keys/*.json` | Fresh local development keys; never include these in a report |
| `journal/` | Persistent Issuer journal |
| `agent-state/` | Gateway report queue |

The development profile explicitly uses `PAIL_PROFILE=dev`, `PAIL_GRPC_TLS=off`,
`PAIL_KEYRING_MODE=unsigned-dev`. It publishes loopback ports only. This is NOT a
production security profile and must not be exposed as an unauthenticated network service.

| Setting | Role in the rig |
|---|---|
| `PAIL_ROBOT_ID` | Robot bound to the gateway and test requests |
| `PAIL_CLOUD_PORT` | Issuer listener inside the network; default 50061 |
| `PAIL_NORTHBOUND_PORT` | Gateway listener; default 50051 |
| `PAIL_CLOUD_ADDR` | Gateway's upstream, `issuer:50061` on the private network |
| `PAIL_ISSUER_KEY_ID` | Identifier of the supplied local signing key |
| `PAIL_SITE_MODEL` | The mounted site model path |
| `PAIL_AGENT_KEY` | Gateway's local key file |
| `PAIL_REPORT_QUEUE_DIR` | Writable per-run report queue storage |

Do not move these paths into the source delivery. The executable has additional
startup requirements outside development mode; see [TRUST_BOUNDARY.md](TRUST_BOUNDARY.md)
and [ISSUER_EVALUATION.md](ISSUER_EVALUATION.md). Do not disable checks merely to pass startup.

## Policy and adapter contracts

- [SKILLS](spec/SKILLS.md): new robot class/skill files, supported fields and limits.
- [SITE_MODEL](spec/SITE_MODEL.md): robot/object/zone declarations.
- [ADAPTER_CONTRACT](spec/ADAPTER_CONTRACT.md): input, authority, stop and evidence obligations.
- [SUPPORTED_BEHAVIOR](spec/SUPPORTED_BEHAVIOR.md): what this version actually supports.
- [Adapter integration](examples/adapter/README.md): executable, source-free Issuer setup.

`horizon.max_steps` controls delegation depth; it is not a multiple of the gateway's
mirror timer. Preserve security timing assumptions when integrating real equipment.
`params_schema` is not a supported arbitrary schema-validation extension and is rejected.
