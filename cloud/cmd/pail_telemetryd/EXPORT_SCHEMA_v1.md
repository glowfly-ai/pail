# Observation export v1

This is the public integration contract for local observation consumers (FMS, BI and
monitoring tools). Display text, private development documents and container names are
not part of this contract. Sources in the public tree are `cloud/internal/telemetry/`
and `cloud/cmd/pail_telemetryd/`.

## Compatibility and trust

Records use `v: 1`. Consumers must tolerate added fields. Removing a field, changing
its meaning/type/name or narrowing its value domain requires a version change.
Historical records remain readable. Missing fields are not the same as zero, false or
an empty string. The collector may apply stricter parsing to its own files.

Observation is not authorization and is not a substitute for journal-chain verification.
UDP loss is not measured by collector coverage. A CHECKPOINT burst is a chain-head
notification, not an ALLOW decision. Correlation by token hash and nearby time is
approximate; see [../../../spec/ARCHITECTURE.md](../../../spec/ARCHITECTURE.md).

## JSONL records

`decisions-YYYYMMDD.jsonl` contains one object per line in receive order. Each kind has
its own shape; a burst does not carry zero-filled permit-only fields.

| Kind | Fields (all required unless stated otherwise) |
|---|---|
| `tick` | `v` integer; `kind="tick"`; `ms` uint64 collector-clock Unix milliseconds |
| `burst` | `v`, `kind="burst"`, `ms` uint64 receive time, `seq` uint32, `event` string, `reason_value` uint16, `robot` string, `token` string, `sig` string, `dup` bool, `raw` string |
| `permit` | `v`, `kind="permit"`, `ms` uint64 receive time, `robot`, `sig`, `mode`, `tick_ms` uint16, `permit_age_ms` uint32, `deadman_window_ms` uint16, `permit_seq` uint32, `mirror_seq` uint32, `raw` string |

For burst records:

- `event` retains the packet's event name, such as `BLOCK`, `ESTOP`, `CHAIN_REVOKED`,
  `OK`, `CHECKPOINT`; unknown values are exposed as `UNKNOWN_0xNN`.
- `reason_value` retains the numeric reason. Use the shipped reason dictionary for
  optional display explanations; never branch on translated prose.
- `robot` is `hex(sha256(robot_id)[:16])`, not plaintext identity.
- `token` is the 32-hex-character correlation hint from packet bytes 32:48.
- `sig` is `ok`, `bad` or `unverifiable` (no usable verification key), not a boolean.
- `dup` reports repeated receipt of the same signature class within a five-second window.
- `raw` carries all 120 packet bytes as hex for independent inspection.

For permit records:

- Only mirror-role keys establish the mirror signer; issuer/burst keys are not fallbacks.
- `mode` is `enforce`, `observe` or `""` (not observed).
- `tick_ms` is the mirror-declared interval; zero means undeclared. Silence limit is
  twice that interval.
- `permit_age_ms` is elapsed time on the mirror's clock, not a subtraction across clocks.
  `4294967295` means no permit has ever been received since boot, not a very old permit.
- `deadman_window_ms` is the observed permit deadline; zero means not observed.
- `raw` is the complete 120-byte PMIR packet in hex. ALLOW is not a burst event.

## HTTP query API

Default bind: `127.0.0.1:8090`. A non-loopback bind requires `PAIL_TELEMETRY_TOKEN` and
requests authenticate with a Bearer token. Responses are JSON. Error text is diagnostic,
not a stable contract; invalid parameters use HTTP 400 and load errors may use HTTP 500.

### Decisions and liveness filters

| Parameter | Type | Meaning |
|---|---|---|
| `from_ms` | uint64 | Inclusive window start on receive clock; default 0 |
| `to_ms` | uint64 | Window end; default request time |
| `event` | string | Exact burst event filter |
| `robot` | string | Exact robot hash filter |
| `reason` | uint16 | Exact reason code; zero is a real filter, not absence |
| `limit` | int | Latest N matching rows; zero/absent means unlimited, negative is HTTP 400 |

`GET /v1/telemetry/decisions` returns `rows` (burst array, never null), `matched`
(integer before limit), `truncated` (boolean) and `coverage`. Rows retain receive order
within the returned page; truncation retains the latest rows. A truncated page does not
establish that the entire window was free of blocking events.

`GET /v1/telemetry/liveness` returns coverage only:

| Field | Type | Meaning |
|---|---|---|
| `from_ms`, `to_ms` | uint64 | Assessed window |
| `gaps` | array | Intervals with `from_ms`, `to_ms` where the collector was not observed listening |
| `listened_ratio` | float | Observed fraction, 0.0–1.0; collector uptime only, not UDP delivery completeness |

Zero events with full collector coverage means no observed events in that window, not
proof that no physical event occurred.

### Permit liveness

`GET /v1/telemetry/permits` reports per-robot mirror statements. The documented display
states must remain distinct:

| Field | Type | Meaning |
|---|---|---|
| `robot` | string | Robot hash |
| `state` | string | `alive` (permission evidenced), `absent` (mirror reported no permit), `unknown` (insufficient observation/trust) |
| `key_role` | string | `mirror` or empty for unverified identity |
| `mirror_age_ms` | uint64 | Request time minus mirror receipt time |
| `permit_age_ms` | uint32 | Mirror's reported permit age; never-received sentinel as above |
| `deadman_window_ms` | uint16 | Observed deadline, zero when unknown |
| `mode` | string | Last reported effective mode |
| `why` | string | Server diagnostic text, possibly localized; branch on state/key_role, not this text |

### Registry

`GET /v1/telemetry/registry` returns `version:1`, `source` (`registry`, `absent`, `invalid`),
`path`, optional `error`, and `robots`. Each robot has `robot_id` and `robot_hash`.
Rows are ordered by robot_id; the orchestrator wildcard is not a robot. Absent or invalid
registry with an empty array is not proof that no robots exist.

### Software identity

`GET /v1/telemetry/software` reads chain evidence and local SBOM files rather than
inferring deployed software from the running viewer. Its envelope has `version:1`,
`source` (`chain` or `unreadable`), `sbom_dir`, `components` and `errors`.

The five component names are `pep_gate`, `issuer`, `robot_agent`, `telemetryd`,
`permit_mirror`. Each row contains `component`, `build_info`, `build_info_state`
(`valid`, `invalid`, `absent`), `source` (`sealed`, `unsealed`), `kind`, `seq`, `unix_ms`,
optional `error`, and `sbom`. Unsealed rows use empty strings/zero rather than being
omitted. Build claims follow the `pail-build:v1` format recorded in the chain.

`sbom` contains `file`, `sha256`, `format` (`cyclonedx-json`) and `state`: `present`,
`hash_mismatch`, `absent`, or `unclaimed`. A file whose hash was not claimed by the
build is not evidence of a matching SBOM. Unreadable chain data returns HTTP 503 and
`source=unreadable`. Do not report missing identity as verified.

## Offline checking

`pail_telemetryd -check <JSONL-file>` outputs `records`, `bad_lines`, `max_gap_ms`,
`from_ms`, `to_ms`, `gaps`. Malformed lines are listed, not silently treated as no data.
Use [EXPORT_SCHEMA_v2.md](EXPORT_SCHEMA_v2.md) for derived journal queries and reindexing.

## Optional external-service notifications

An independently deployed Anchor service may deliver JSON webhooks. This does not mean
its server or deployment configuration ships here. Notification fields are `type`,
`tenant_id`, `unix_ms`, `notice`, with optional `robot_id`, `count`, `detail`, `sig_base64`.
`detail` is display prose, not a branching contract. Scoped tenant/robot alerts may be
signed; global operational notices are not automatically signed evidence.

Types include `ANCHOR_GAP_ROLLUP` (count of silent robots), `FORK`, `REWIND`,
`WORM_VIOLATION`, `RESTORE_REHEARSAL`, `SLA_BUDGET` (count is threshold percent).
A notification is not a substitute for verifying underlying evidence. Billing and
private console APIs are outside this local observation specification.
