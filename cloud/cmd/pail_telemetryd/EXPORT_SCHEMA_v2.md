# Observation export v2 — journal query

v2 adds `GET /v1/ledger/events`; it does not change v1 fields. Read
[EXPORT_SCHEMA_v1.md](EXPORT_SCHEMA_v1.md) for the local observation trust boundary.
Public implementation: `cloud/internal/ledgerq/` and `cloud/cmd/pail_telemetryd/`.

## Meaning and limits

The SQLite index is derived data, not the authoritative journal. Chain rows identify
an `origin` so `-index-check` can reproduce them. Rebuilding an index must not delete
the original journal. `chain_ok` describes the checked chain position and a fresh walk,
not physical truth. `anchored` is reserved and not asserted by this version.

Zone resolution uses the value recorded at issuance or the snapshot named by that
issuance, never the current model as a substitute. Permit mirror ticks remain in the
v1 permit endpoint; only bursts enter the telemetry portion of this timeline.

## GET /v1/ledger/events

Authentication is the same as v1. Rows are newest first by `ms`, then `seq` descending.
The maximum page size is 5,000; a nonempty `next_cursor` indicates another page.

### Query parameters (all optional)

| Field | Type | Meaning |
|---|---|---|
| `from_ms`, `to_ms` | uint64 | Window start/default 0 and end/default request time |
| `around_ms`, `span_ms` | uint64 | Center and half-width (default 60000ms), overriding from/to |
| `robot` | string | Plaintext name or 32-hex hash; unknown names yield zero rows and unresolved status, never an unfiltered query |
| `plan_id`, `step_id` | string | Exact match |
| `token_id` | string | Match chain token_id and the corresponding truncated hash on telemetry rows |
| `target`, `outcome`, `action_name`, `zone` | string | Exact match; zone uses recorded issuance data, not a later model |
| `src` | string | `chain` or `telemetry` |
| `action_class` | uint64 | Bitmask intersection; MOVE=1, MANIPULATE=2, ACTUATE=4, NONE=8 |
| `registered` | string | `true` or `false`, based on the recorded site-model action registration |
| `requester` | string | `kind:id` or `id` on recorded plan acceptance/rejection |
| `limit` | uint64 | Page size; zero or excessive values select 5000 |
| `cursor` | string | Prior next_cursor |

### Response envelope

Required fields: `rows` array, `coverage` object, `verify` object, `resolution` object,
`index` object, `next_cursor` string. An empty array means no indexed rows matching the
query; interpret it with coverage, verification and index freshness.

### Row fields

All fields below are present. Empty values and nulls have distinct meanings.

| Field | Type | Meaning |
|---|---|---|
| `seq` | int64 | Index row identifier/cursor input, not the authoritative journal sequence |
| `ms` | uint64 | Timestamp carried by the event |
| `src` | string | `chain` or `telemetry` |
| `robot_id` | string | Plaintext from chain payload or registry resolution; empty if unresolved |
| `robot_hash` | string | `hex(sha256(robot_id)[:16])`, empty when no robot is associated |
| `kind` | string | Chain record type or `burst` |
| `plan_id`, `step_id`, `token_id` | string | Payload values; empty if absent (token_id applies to chain rows) |
| `token_hash` | string | Truncated token-ID correlation hash; not an authorization identity |
| `target` | string | target_object_id, empty if absent |
| `zone` | string | Recorded zone or resolution from that issuance's model snapshot; otherwise empty |
| `action_class` | int64 | Class mask for applicable TOKEN_ISSUED records; legacy/other rows use zero |
| `action_name` | string | Recorded action name, otherwise empty |
| `registered` | bool/null | Site-model action registration; null means legacy unknown, not false |
| `outcome` | string | Original chain/burst event name; unknown chain types remain `TYPE_<n>` |
| `reason_value` | int64 | Telemetry numeric reason; chain rows use zero |
| `requester` | object/null | Recorded `{kind,id}` on applicable plan records; legacy/telemetry rows use null |
| `origin` | object | `{seg,off}`: source filename plus chain byte offset or JSONL 1-based line number |
| `sig` | string | Telemetry `ok`, `bad`, `unverifiable`; empty on chain rows whose verification is reported separately |
| `robot_resolved` | bool | Whether a plaintext identity was resolved |
| `reject_code` | string | Recorded plan rejection code, otherwise empty |
| `target_unverified` | bool/null | Unknown target allowed by policy / declared-or-no target / legacy unknown |
| `site_model_hash` | string | SHA-256 of the serving model bytes, naming `<hash>.yaml`; empty when unavailable |
| `zone_resolution` | string | `recorded` (zone written at issuance), `snapshot` (resolved from the kept site-model snapshot named by `site_model_hash`, its content verified against its name), `unresolved`, `none` |

Known chain outcomes include TOKEN_ISSUED, PLAN_ACCEPTED, CONTEXT_SEALED, PLAN_REJECTED,
GATE_DECISION, CHAIN_REVOKED, CHECKPOINT, RECOVERY_TRUNCATE, SAFE_STOP, OPERATOR_EVENT,
GRAPH_MUTATION, CONTEXT_PROVENANCE, ATTESTATION, CONFIG_SEALED, LEASE_GRANTED,
LEASE_RECONCILED, FLEET_CENSUS, LEASE_RETRACTED, HA_MEMBERSHIP, IDENTITY_REFUSED,
CORE_OPERATION and CORE_REPORT (the C1 basic-communication receipts, kinds 100 and 101,
rows an older mirror indexed as TYPE_100 or TYPE_101 take these
names on re-index). Unknown types are retained, not discarded.

Requester identity comes from the transport identity mapped by the requester registry,
not a requester claim in an arbitrary request body. This surface exposes kind/id;
read the original journal record for the underlying caller identity evidence.

### Verification

`verify` contains `state`, `checked_to_seq`, `checked_to_ms`, `walk_ms`, optional `error`,
and `anchor_seq` (always null in this version).

- `chain_ok`: the reader checked the relevant chain position and the walk is fresh.
- `chain_error`: the reader encountered a broken/error chain, with error detail.
- `unverified`: verification prerequisites are not established; a walk older than
  60 seconds is unverified. Zero checked position means no completed walk.
- `anchored`: reserved, not claimed here.

### Resolution, coverage and index

`resolution.robot`: `registry`, `hash_only`, `unresolved`, `none`.
`resolution.zone`: `snapshot`, `unresolved`, `none`; `current_model` is reserved.
At response scope, snapshot means all targeted rows could use recorded values or the
appropriate historical snapshot. An unresolved row prevents a blanket resolved claim.

Coverage has `from_ms`, `to_ms`, `gaps` and `listened_ratio` with the same meaning as v1.
The interval before the first observed collector tick is a gap, not evidence of quiet.

`index` includes `path`, `chain_rows`, `telemetry_rows`, `ticks`, `last_ingest_ms`,
`chain_state` (`ok`, `chain_error`, `absent`, `never`), optional `chain_error`,
`checked_to_seq`, `checked_to_ms`, `chain_walk_ms`, `telemetry_files`.
Index freshness must not be confused with zero events.

## Offline commands

- `pail_telemetryd -reindex [-index <path>] [-blackbox-dir <dir>] [-dir <JSONL-dir>]`
  rebuilds only the derived index and prints JSON. Exit 0: chain acceptable; 1: error.
- `pail_telemetryd -index-check [-index <path>] [-blackbox-dir <dir>]` reproduces
  chain rows from origins. JSON fields: `checked`, `mismatches`, `missing`, `extra`.
  Exit 0 only when all compared rows reproduce; otherwise 1.

The UI DOM, external Anchor verification and private service management APIs are not
part of this endpoint's contract. See [../../../TRY_IT.md](../../../TRY_IT.md) for a
complete local execution and viewing example.
