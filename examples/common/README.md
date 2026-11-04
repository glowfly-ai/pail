# Shared demo observation primitives

`observation.py` and `run_record.py` retain their existing roles. `eventlog.py`
adds the MOBS in-process storage and input-decoding foundation (Apache-2.0).
It does not issue tokens, send robot commands, serve HTTP, authenticate clients,
or infer motion from missing records. The two demo consoles now use `console_feed.py` for HTTP/SSE and runtime
history; changing these files does not restart an already running demo.

## BoundedEventLog

Create **one instance per console process**, shared by all robot feeds. `append`
accepts an observation object, serializes it once into immutable JSON bytes and
returns an absolute decimal sequence string. Retention enforces **both 5,000
records and 16 MiB**. Events larger than **64 KiB** raise `payload_oversize`,
increment the rejection counter and consume no sequence. Raw evidence is never
truncated or modified by this module. Non-finite/invalid JSON is rejected.
There is no external configuration surface in this foundation version.

`snapshot(filters)` atomically samples retention bounds/counters and a cursor at
high sequence; it is log metadata, **not a robot-state snapshot**. The console
adapter must atomically coordinate its own small current-state snapshot with the
log when implementing the snapshot-to-live handoff.

`page(cursor, filters=..., limit=200)` returns event objects, matching absolute
`sequences`, retention metadata, `next` and `next_cursor`. Limits are 1..1,000
records and 1 MiB of compact JSON response including framing/metadata. Filtering
supports exact `robot_id`, `source`, and `event` values; unknown/empty/oversized
filters fail instead of widening the selection. `next_cursor` points to the last
**returned** event, not high sequence. A page without matches keeps its cursor;
high sequence is informational. Page serialization is outside the writer lock.
The returned events are fresh decodes; clients cannot mutate retained bytes.

Cursors are bounded base64url objects binding version, UUID epoch, decimal
sequence and filter digest. They are **not signed authorization capabilities**;
HTTP adapters must authenticate and enforce allowed scope on every request.
Malformed/noncanonical/schema-invalid cursors return `INVALID_CURSOR` (400),
changed filters `FILTER_CHANGED` (400), future sequences `CURSOR_AHEAD` (400),
old epochs `EPOCH_CHANGED` (409), and evicted positions `CURSOR_EXPIRED` (409).
409 details include current epoch, low/high bounds, gap and snapshot URL.
`EventLogError.status` and `.details` are available to the HTTP adapter.

`page(after_seq="N")` is the same-epoch v1 compatibility primitive: N is the last
consumed absolute sequence, never a retained-array index. Bare v1 numbers cannot
detect server restarts; use v2 cursors for epoch checking. Clients must consume
pages until caught up and handle 409 by showing a gap and resynchronizing.

## BoundedJSONLines

Create one decoder per logical file UUID; its caller owns file identity,
rotation/truncation detection, permissions, scheduling and the live/backfill
barrier. `read(binary_stream)` performs **one 256 KiB read**. `feed(bytes)` accepts
at most that amount and returns `(rows, faults)`. Each row contains `event` and
an `origin` with logical `file_id` and absolute decimal **byte** offset. Do not
pass host paths as file IDs. This parser does not strip sensitive event fields;
the observation adapter must construct the approved public schema before append.

Partial UTF-8/JSON lines remain buffered until newline, at most **1 MiB**.
Oversized lines report `line_oversize` once at the original byte offset, then
bounded-discard until newline. Invalid UTF-8, JSON, duplicate keys, non-finite
numbers and non-object records produce `invalid_json`; the following valid line
remains readable. Faults have count/origin but no raw payload. Call `finish()`
only on a confirmed closed/truncated/replaced file, never ordinary live EOF;
it reports a remaining partial record as `partial_line` and resets buffering.
Aggregate/report faults in the consuming adapter rather than silently dropping
these results. Disk retention, replay/live classification, SSE queues and aging
are not implemented by this decoder.


## Console HTTP/SSE and runtime history (MOBS M1-02)

Both TB3 and Microduck use one `ConsoleFeed` and the same HTTP adapter. Get
`/api/v2/snapshot`, then connect `/api/v2/events/stream?cursor=<snapshot.cursor>`.
SSE emits `id` cursors and accepts `Last-Event-ID`. There are at most eight
subscribers; a ninth receives 429 `TOO_MANY_CLIENTS`. Each subscriber has at most
256 events / 1 MiB. Overflow discards its queue, emits a named `gap` with a
snapshot URL and closes. Socket writes have a two-second deadline and never hold
the producer lock. A socket too blocked to accept the gap is closed instead;
its reconnect cursor is still checked for eviction/epoch changes. Consumers must
show disconnection/UNKNOWN, not interpret silence as zero motion. The included
pages resnapshot after disconnection/gap and do not render replayed or rejected
old observations as current motion. Last completed `moved` results are restored
with their original timestamp on a web refresh, not on a process restart.

`GET /api/v2/events?cursor=...&limit=200` and the original
`GET /api/events?from=N` use bounded pages. The v1 `next` stays numeric but is now
an **absolute sequence**, not an array length. Clients must follow every page;
evicted positions return 409. `/events` remains an SSE alias, now live-only when
no cursor is supplied. It no longer replays the entire process history. v2
cursors detect a process restart; bare v1 numbers cannot. These local-console
endpoints expose the fixed unfiltered feed; unknown query/filter keys are
rejected, never silently ignored. No authentication capability is added by a
cursor. The existing loopback console binding remains required.

At Console construction each existing runtime JSONL has an open-file identity
and EOF barrier. One 256 KiB live chunk and one 256 KiB backfill chunk per role
are processed per poll. Pre-barrier records enter SQLite with `replayed=true`,
never the live ring, pose or completion/cancel callbacks. A line crossing the
barrier is not promoted: the historical partial line is diagnosed and the live
suffix is discarded to newline. Replacement/truncation opens a new barrier and
reports `source_gap`; its logical file generation persists across reader restart.
Local path/socket/raw/credential fields are excluded from public actor events;
error strings redact local paths. The raw files are never modified. A post-barrier legacy record still needs a
nonrepeated clock/monotonic sample and a recent, nonfuture, post-start timestamp
before it can update the console's last pose or completion handling. This is
**receiver-only legacy evidence**, not authenticated producer freshness; snapshot
motion status remains UNKNOWN. A changed clock instance does not silently revive
an established current-state sample.

Runtime history is `console-history.sqlite3` beside the runtime directory.
It uses WAL, unique `(file_id,offset)`, an event ID and original producer/run/time
fields in the payload. Origin inserts and the contiguous backfill offset commit
in the same transaction; a fast live reader cannot skip an unfinished backfill
on restart. `GET /api/v2/history?limit=200` returns bounded keyset pages with an
opaque cursor and frozen `upper_ingest_id`. Concurrent backfill/live inserts do
not move an existing pagination window. `history_complete=false` distinguishes
unfinished backfill. Actor history does not claim to include console-only
commands that have no raw JSONL origin. DB errors are `INDEX_UNAVAILABLE` (503),
not an empty successful page or a full-file request fallback. The 512 MiB history
budget stops ingestion with `HISTORY_BUDGET_EXCEEDED` rather than deleting existing
history/raw files; the last bounded transaction can overshoot the threshold.
There is no automatic retention policy or new user configuration in this step.

Tests use isolated local files and loopback HTTP servers, not Docker actors or
existing robot endpoints. Long-duration aging, physical/WSL execution, production
retention and the full fleet UI remain separate measurements.

## Collector storage policy (MOBS)

`pail_telemetryd --observability-config FILE` accepts strict JSON schema v1.
Unknown or duplicate keys, trailing documents, fractional integer fields and
invalid limits are refused. This is collector observation policy, **not** a
robot safety policy or authorization input. The new flag and all JSON keys are
listed in `spec/CONFIG_REGISTRY.tsv` with the `observability.` prefix.

An explicit **new fake-profile** example (not an audit-retention recommendation):

```json
{
  "schema_version": 1,
  "retention_mode": "managed",
  "raw_max_bytes": 2147483648,
  "retain_days": 7,
  "trash_grace_seconds": 3600,
  "db_max_bytes": 2147483648,
  "wal_max_bytes": 268435456
}
```

Defaults: `schema_version=1`, `retention_mode="retain_no_delete"`,
`raw_max_bytes=0` (no configured raw quota), `retain_days=0`,
`trash_grace_seconds=3600`, DB 2GiB and WAL 256MiB. Schema version must be
explicit in a supplied document. Managed deletion requires positive explicit
raw bytes and days. Grace is 1..31,536,000 seconds; days are 0..36,500.
No file is automatically deleted when the configuration is absent.

The writer creates `decisions-YYYYMMDD-NNNNNN.jsonl`, rolling at the UTC day
boundary or before exceeding 64MiB. It takes a directory-scoped OS writer lock
and never appends to a previous process's file. Legacy daily names remain
readable. Lines are at most 1MiB including their newline; embedded newlines and
invalid JSON are rejected. A 4MiB/256-item ingress bounds producer memory,
including the in-flight write; overflow is counted without blocking the producer.

Only manifest-owned **closed and completely indexed** observation files are
eligible for age/byte retention. Maintenance rotates through at most 64 candidates and two file operations per pass.
Raw quota reserves one segment of headroom;
active, trash and existing legacy raw bytes still count. Unmanaged/legacy files and signed blackbox
files are never deletion candidates. A file's committed offset, inode identity,
size and closed SHA-256 must agree. An fsync'ed atomic manifest and parent
fsync commit deletion intent before rename into `.observation-trash`. Trash is
synced and retained for the configured grace interval. Tombstones and raw-loss
boundaries remain; restart reconciles interrupted intent/rename/unlink before
the writer is opened. A directory conflict, replaced file, failed intent write
or failed purge is an error, never successful cleanup. Do not edit this manifest
or move managed files while the collector is running.

`GET /v1/telemetry/storage` (same authentication as other telemetry endpoints)
reports cached writer/index state, cumulative loss, raw deletion revision and
`raw_removed_through_ms` (a planned-or-removed range upper boundary, **not** a promise that
all earlier history is missing). Derived history can remain available after raw
retention, but its raw origin is explicitly incomplete. HTTP queries do not scan
raw files. v1 responses link the diagnostic via `X-PAIL-Storage-Status` and explicitly
set `X-PAIL-Raw-Complete=false` for planned/retained-away raw origins.
Index unavailability, DB pressure or blocked WAL checkpoint returns 503 on the
Live endpoints. Writer loss returns 503 `OBSERVATION_LOSS`; `/healthz` is only
process liveness, not observation completeness. Loss is sticky across restart
when its manifest could be persisted. ENOSPC can prevent even the loss manifest
write: the returned error and in-memory status report this, and a torn raw tail
is preserved and declared on recovery. This does **not** claim an exact count
of kernel/network packet loss or power-loss durability for every raw append.

SQLite schema 6 records file generations and retained-origin diagnostics.
Old schemas require explicit offline `-reindex` into a side-by-side database;
no in-place clearing or silent fallback. A detected inode replacement,
truncation or changed indexed prefix produces `INPUT_REPLACED` and a 503 pass;
the next pass starts a new generation at offset zero, preserving earlier
origins and a persistent replacement count. This is observation-file change
detection, **not** a cryptographic verification of an arbitrary rewritten whole
file. The signed blackbox verifier remains independent.

DB budget exhaustion does not delete the index or blackbox. WAL checkpoint
checks its returned busy/result values with a 100ms busy wait; pinned-reader
failure is `WAL_BUSY`. Increase an explicitly reviewed budget or arrange
maintenance; do not delete raw/blackbox data to make a dashboard green. The
2GB dense-input benchmark from M2-01 used about 6GB of index storage and cannot
be assumed to fit the default 2GiB derived-DB budget. Operator diagnosis and
explicit recovery are required after persistent observation loss.


### MOBS ledger verification and Timeline

The collector now uses index schema 7. Preserve the source journal and use the
explicit offline `pail_telemetryd -reindex` side-by-side path for an older index;
rebuilding is not source repair. The read-only Timeline offers Events / Plan
summaries, Next page, First / refresh, and per-plan event drill-down. A page full
of checkpoints is not evidence that there are no plans in the selected range.

Read `verify.diagnostic` for `OK/CHAIN_ERROR/ABSENT/VERIFYING/UNVERIFIED`, the
verified frontier and source/verification error. A changing mirror, torn tail,
stale pass, or worker budget failure does not certify the chain. One pass is
bounded to 4096 files / 128 MiB per file / 2 GiB snapshot and a 30 s cooperative
deadline. Scratch copies reside beside the index; originals are never removed.
The `/v1/ledger/plans` endpoint uses the event API's authentication and filters,
with at most 200 summaries per page. Counts are matching events, not proof of
robot execution. See the collector's `EXPORT_SCHEMA_v2.md` for field semantics.

## Collector identity snapshots (MOBS M3-01)

The read-only collector accepts an optional `source_map` object inside the
existing `--observability-config FILE` JSON. Storage keys remain unchanged;
without this object v2 observation endpoints return `503 SOURCE_MAP_UNCONFIGURED`
instead of inventing a deployment or silently treating missing data as idle.
No deletion policy is enabled by this addition. All keys (including nested keys)
are strict: duplicates, unknown fields, unknown providers, relative file paths,
noncanonical UUIDs and oversized documents are rejected. Startup exits 2 for
invalid configuration. Do not put credentials into this document.

Minimal example for an **existing verified legacy burst receiver**:

```json
{
  "schema_version": 1,
  "source_map": {
    "schema_version": 1,
    "source_id": "c68d3bdd-62b0-4721-9aec-9ea0d4ab0301",
    "deployment_id": "5e8b24a0-2319-4a53-b5cf-a03afc977301",
    "providers": [{
      "provider_id": "robot-1-burst", "kind": "legacy_burst",
      "expected_deployment_id": "5e8b24a0-2319-4a53-b5cf-a03afc977301",
      "expected_robot_id": "robot-1", "expected_identity": "device-1",
      "path_ref": "", "endpoint_ref": "", "allowed_event_kinds": ["gate"],
      "expected_owner": "", "expected_run_id": "", "expected_stream_id": "",
      "trust_basis": "verified_signature", "role": "primary"
    }]
  }
}
```

`source_id` is an installer-assigned stable collector UUID. A new process gets a
new `collector_instance_id`. An empty deployment ID means legacy/unknown, not an
inferred production deployment. The structured `(deployment_id, robot_id)` key
keeps names from different deployments separate. `expected_identity` is a
bounded installation identity label; conflicting labels on the same key stay
CONFLICT. Multiple providers retain their own values and primary/secondary
labels; the latest response never becomes an automatic authority election.
These are observation declarations (`DECLARED_OBSERVATION_ONLY`), **not new
authorization registry entries or proof of device identity**.

Provider kinds currently available:

- `legacy_burst`: consumes the existing verified Dispatcher; only `gate` allowed.
- `legacy_permit`: same receiver, only `permit` allowed. Legacy packets lack a
  producer boot/clock and per-device key binding. Their receipt can be recent,
  but current execution quality remains UNKNOWN with an explicit limitation.
- `normalized_jsonl`: a fixed installer-selected absolute regular-file path,
  local-self-report trust, expected robot/deployment/identity/owner/run/stream.
  Initial EOF, truncation and replacement are live barriers. Reads are bounded
  to 256 KiB per poll; events/partial lines to 64 KiB (the normalized-event
  ceiling is stricter than the generic raw-line ceiling). Invalid/oversized
  input is named in provider health. No HTTP query can choose a file or URL.
  This adapter expects the normalized schema below, **not arbitrary existing
  Microduck actor log lines**. Official actor/manifest generation is M4 work.

A normalized gate event example (written only by a configured software source):

```json
{"schema_version":1,"deployment_id":"5e8b24a0-2319-4a53-b5cf-a03afc977301","robot_id":"robot-1","identity":"device-1","owner":"actor","run_id":"5e8b24a0-2319-4a53-b5cf-a03afc977301","kind":"gate","producer_instance_id":"2457dd0a-d7b1-42f6-b089-6ce0d5b2d8c3","stream_id":"ec054792-0db0-4162-83c1-ce2b7c401782","producer_seq":"1","observed_at_ms":null,"clock_id":"2457dd0a-d7b1-42f6-b089-6ce0d5b2d8c3","replayed":false,"value":{"state":"PERMIT","physical_stop_proven":false}}
```

The normalized provider uses `trust_basis: local_self_report`, an absolute
`path_ref`, `expected_owner: actor`, and matching expected run/stream UUIDs.
Allowed event kinds are plan/gate/permit/motion/pose. A local file cannot assert
verified ledger or management state: those facets remain UNSUPPORTED pending a
qualified provider. Invalid identity stays on the expected row as CONFLICT and
never reroutes itself. The producer generation and decimal uint64 sequence are
required; same/backward sequences do not refresh age, replay does not update
current values, and a new producer starts UNKNOWN until it progresses again.
Retired producer generations cannot reappear (64 retained generations per
facet; overflow refuses further generation changes). Past/future producer wall
timestamps are conservative limitations, not proof of clock synchronization.

`GET /v2/observation/capabilities` and `GET /v2/observation/robots` use the existing
collector HTTP authentication. The latter allows exact source_id, deployment_id,
robot_id filters, `limit` 1..1000 (default 200), and `cursor`. Responses are at
most 1 MiB; immutable page snapshots are limited to 8 / 16 MiB / 30 seconds.
A filter change is 400; an expired/evicted snapshot is 409 SNAPSHOT_EXPIRED.
Restart loses the old cache. Follow `next_cursor` only with the same filters;
show `as_of_ms`, `served_at_ms`, scope, completeness and unresolved overflow.
Expected rows are capped at 1024, providers at 2048, unresolved verified hashes
at 1000 for 24 hours. Declared rows survive disconnect and unresolved overflow.

Every facet includes source/trust/freshness basis, original observation/receipt
clock/producer/sequence, age, quality/reason, last observation and active
observation (nullable). Receipt uses the collector's monotonic clock. Freshness
is only receiver progress, not producer-time attestation. Motion/pose without
clock-binding proof remain UNKNOWN, even for recently received fake samples;
zero never proves physical stop. Plan acceptance and ledger history never imply
current execution. Facet TTLs are 1s motion/pose, 3s gate/permit/plan, 30s ledger,
300s management. Queries and HTTP 304 do not advance producer timestamps. TTL
transitions change snapshot revision/ETag **before** conditional handling, and
cached pages downgrade old FRESH values. The existing v1 management projection
also includes stale/clock-uncertain quality in ETags, preserving its schema and
its membership-only behavior for non-quality diagnostic changes.

No command, issuer RPC, token, private path or Docker capability is added to
these endpoints. This stage does not claim a browser fleet UI, verified
producer-clock motion, official two-robot lifecycle, physical/WSL validation or
long-run aging; those have separate task gates.

## Observation record version 2, liveness and permit reports (OPSVIEW)

The collector accepts normalized records with `schema_version` 1 **and** 2.
Version 1 is closed: a record that calls itself version 1 and carries a version
2 field is refused. Version 2 adds:

- `observed_mono_ns`: the producer's monotonic clock in nanoseconds, a canonical
  decimal string from 1 to 2^63-1. Optional. It is used for age only while a
  clock binding is confirmed for that record (see "Clock binding" below);
  otherwise age is receiver progress only.
- `value.step_index`, `value.step_count`: progress of a permit or a plan, counted
  from 1, `1 <= step_index <= step_count <= 1024`. Both or neither. When the
  producer cannot tell the step it leaves both out; nothing is guessed.
- `kind: "liveness"` with `value.state: "ALIVE"` and `value.component`
  (`adapter` or `observer`, a closed list). Expiry is 3 s.

```json
{"schema_version":2,"deployment_id":"514a97fa-6a8a-4e32-bc51-cb8b43f2583a","robot_id":"robot-1","identity":"robot-1","owner":"00000000-0000-4000-8000-000000000001","run_id":"00000000-0000-4000-8000-000000000001","kind":"liveness","producer_instance_id":"26aa46e1-6ec5-43fd-af99-cbfd521c7ae9","stream_id":"8be30882-0700-4297-89d4-2ef81fa19a4c","producer_seq":"412","observed_at_ms":1790675925934,"observed_mono_ns":"1905336045613083","clock_id":"mono-5f0c","replayed":false,"value":{"state":"ALIVE","component":"adapter","physical_stop_proven":false}}
```

**What liveness means.** The observer is running and the adapter answered one
of the observer's own questions on the adapter's public socket within the last
second. It does **not** mean the gate judges correctly, that a permit exists or
that the robot is safe. There is no value for "not alive": a component that
stopped cannot report it. The **missing record** is the signal, and the
collector turns the facet `STALE` 3 s after the last record.

A liveness facet and the `liveness` entry of the capability document appear
only when a provider declares `liveness` in `allowed_event_kinds`. A source map
that does not declare it gets the same documents as before.

**Permit reports** are the observer's self-report of the adapter's own gate
log, trust `local_self_report`. They are not the signed permit statement of a
`legacy_permit` provider, even when both appear in the same column.

| state | written |
|---|---|
| `RECEIVED` | once per second while the adapter's last outcome says a permit is held and the adapter answers |
| `EXPIRED` | once, when the step ended or the permit is gone |

A command refused inside a held permit is not an expiry. When the adapter does
not answer, no permit report is written either; the facet goes `STALE` by
itself. The Microduck observer asks `robot.health` (a query the adapter
forwards without judging) every 0.5 s; it sends no command on that connection.
`observation.py` holds these rules without a socket or a clock of its own, so
they can be tested with a virtual time.

## Clock binding (OPSVIEW)

Motion and pose used to be `UNKNOWN` even for a record 0.2 s old, because the
collector had no reason to believe the producer's time. When producer and
collector read **the same monotonic clock of the same kernel**, the collector
can compare the producer's time with its own.

A provider of kind `normalized_jsonl` may ask for it in the source map:

```json
{"provider_id": "robot-1", "kind": "normalized_jsonl", "clock_binding": "shared_kernel_monotonic", "...": "..."}
```

**Asking is not binding.** `shared_kernel_monotonic` is the only accepted value
(anything else, or the field on a signed legacy source, is refused with
`SOURCE_MAP_CLOCK_BINDING`). At start the collector reads its own boot id
(`/proc/sys/kernel/random/boot_id`) and the monotonic offset of its time
namespace (`/proc/self/timens_offsets`) and hashes them the way the producer
does. Every record is then compared with that name:

| Case | Motion / pose | `reason` |
|---|---|---|
| not asked for | `UNKNOWN`, as before | `PRODUCER_CLOCK_NOT_BOUND` |
| asked, record names another clock | `UNKNOWN` | `CLOCK_BINDING_MISMATCH` |
| asked, collector cannot read its own identity or clock | `UNKNOWN` | `CLOCK_BINDING_UNAVAILABLE` |
| asked, record has no `observed_mono_ns` | `UNKNOWN` | `PRODUCER_CLOCK_NOT_BOUND` |
| asked, same clock, age inside the expiry | `FRESH` | `PRODUCER_CLOCK_BOUND` |
| asked, same clock, age at or beyond the expiry | `STALE` | `OBSERVATION_OLD` |
| asked, same clock, time in the future or older than 10 expiries | `UNKNOWN`, binding dropped | `CLOCK_UNCERTAIN` |

A bound facet has `freshness_basis: "producer_clock_bound"` and
`producer_age_ms` = collector monotonic time - `observed_mono_ns`. `age_ms`
keeps its meaning (time since receipt). The other kinds of a bound provider
(gate, permit, liveness) are judged by the producer age as well, with their own
expiry; when the binding is refused they keep the receipt judgement
(`RECEIVER_PROGRESS_ONLY`) they had before. The earlier rules stay in force and
come first: receipt expiry (`TTL_EXPIRED`), the first record of a new producer
(`NEW_PRODUCER_BASELINE`), and a wall-clock time that is in the future or old.

Where it applies: containers on one computer (they share the kernel). A robot
and a collector on **different computers cannot be bound** this way; motion and
pose stay "last observed" there. The binding changes what the observation view
shows and nothing else: the gate's clock tolerance, permit deadlines and token
expiry do not read it. It is still a `local_self_report`: a producer that lies
about its time inside the accepted window is not detected, and a fresh zero
velocity never proves a physical stop.

## Multi-robot observation dashboard (MOBS)

With a configured collector SourceMap, `/dashboard/` now opens **Robot
observations**. `?tab=status`, `?tab=timeline`, and `?tab=robotops` retain the
existing views. Without v2 capability the new view explicitly says unsupported
or unavailable; it does not invent robot health. This default-tab change does
not change v1 data APIs or grant command authority.

Each declared robot/provider has independent plan, gate, motion, ledger and
management facets. Expand **Evidence** for trust, producer sequence, clock and
observation/receipt times. ACCEPTED is a recorded plan fact, not proof of current
execution. Blue FRESH describes evidence age, not a safety verdict. Missing data
is UNKNOWN/UNSUPPORTED. On a failed poll, last observations remain visible but
cannot become active. A connection response or 304 never resets producer age.

The scope bar names the configured collector and deployment; provider connection
counts are page-local, not organization totals. **Next snapshot page** replaces
the current bounded page; it does not accumulate DOM history. Paging pauses live
refresh on that page. **Refresh first page** returns to live polling. Expired
cursors restart at page one with at most two retries, without stitching snapshots.
Live/Timeline time filters apply only to those tabs, not this current snapshot.

Pose cards are independent local frames. They retain source kind (simulation,
wheel odometry or map localization), frame, coordinates and quality. A single
last-observed point is never a shared global map or a cross-frame trajectory.
UNKNOWN clock binding is not promoted to current motion; zero is not physical
stop proof. The coordinate glyph uses a nonlinear display scale with exact
numeric coordinates beside it; it is not navigation or localization software.


## Explicit builds and resource observation

`build_runtime.py` owns only its uniquely named Buildx docker-container worker.
It verifies effective limits, leaves a prepared image/native-artifact receipt,
and never changes the default builder. Start resolves local images to immutable
config IDs and refuses missing/stale artifacts with BUILD_REQUIRED. Build needs
an explicit operating-window acknowledgement; it is not an automatic fallback.

`resource_budget.py` bounds native HTTP workers and provides process RSS/CPU and
owned-container cgroup samples. UNMEASURED remains distinct from measured zero.
Container memory.current includes cache and is not process RSS. These helpers
are observation/build controls, not robot authorization or physical-stop proof.

## Read-only trust inspection and controlled renewal

`trust_observation.py` separates configured trust mode, signature-checked file
metadata, runtime-loaded metadata and time validity. A valid signature on an
expired bundle does not make it usable. Without a verified clock observation,
remaining lifetime is unknown; without a bound runtime probe, loaded state is
`NOT_OBSERVED`. `unsigned-dev` means unsigned development trust, not permanent
production trust. The operating procedure around these tools — the six stages of applying
a renewed bundle, what expiry does per component, and the key registration rules — is
[`docs/TRUST_OPERATIONS.md`](../../docs/TRUST_OPERATIONS.md).

Two bases appear in `/api/v2/trust` (`configuration_basis`): `LAUNCHER` — what the demo
launcher knows about its own run (TB3: the bundle it generated, declared with root fingerprint,
version, validity and the host-clock time left, signature **not** verified by the console;
Microduck: `unsigned-dev`, development trust not judged as signature trust) — and
`OPERATOR_MANIFEST`, your profile, where the pinned native helper verifies the signature. The
operator profile replaces the launcher view when configured.

A single-robot console accepts `--trust-profile /absolute/operator/profile.json`.
Use [the profile template](trust_observation.manifest.example.json), replacing
all placeholders with existing deployment values. The profile must be owned by
the current operator or root, not group/world writable, and must not use symlink
paths. It pins a locally installed **native** `pail-keyring-sign` executable by
SHA-256. A path inside a Docker image is not a native host executable. The Core
source includes this helper under `cloud/tools/pail-keyring-sign`; the container
tooling images also include it for inspection inside their own environment.

The console exposes only `GET /api/v2/trust`. It takes no file path or signing key
from HTTP. Inspection runs in a separate bounded worker; HTTP reads a cached
snapshot. Changed profile bytes require explicit reconfiguration. A missing
profile is reported as unconfigured. A fleet-wide profile is refused because it
would silently attribute one target's trust to other robots. Per-robot runtime
integration remains deployment-specific.

The console cannot sign, apply, restart, release holds or issue plans through
this endpoint. Root private keys must stay in the existing offline signer or
protected signing integration. Do not generate a replacement root to work
around an expired bundle.

For an operator-owned profile and fresh consumer observations:

```sh
python3 examples/common/trust_admin.py inspect --profile /absolute/profile.json
python3 examples/common/trust_admin.py plan-renewal \
  --profile /absolute/profile.json --state /absolute/private-operations \
  --operation-id renewal-1 --consumers /absolute/observations.json \
  --issued-at ISSUED_UNIX --expires-at EXPIRES_UNIX
```

The plan fixes the baseline hash, root fingerprint, original keys/roles/revocations,
consumer generation/floor/remaining-lifetime ceilings and the exact new payload.
Each consumer must also supply its actual loaded `root_fingerprint_sha256` and
`material_digest_sha256` plus its supported `max_bundle_version`; copying them from the proposed file is not runtime
verification. The digest covers active and revoked keys, IDs, roles and ordering.
A higher floor with different loaded material is not a validity-only renewal:
stop and use the existing separately authorized key-change process.
Only version and validity times may change. Sign that payload with the existing
root using the existing offline signer; then `stage-renewal --candidate ...
--approved-plan-digest ...` validates the exact candidate against the plan.
Same operation ID with changed inputs is a conflict. Staging does not install
trust or advance any runtime rollback floor.

**The standalone demo does not install a management execution-window provider.**
Its `apply-renewal` command therefore refuses application. The shared
`trust_transaction.py` implementation can be used only by an installed, trusted
management integration implementing `RenewalWindowProvider`. That integration
must authenticate fresh consumer probes, hold a real exclusive execution window,
keep consumers quiesced/fenced with automatic start inhibited, and serialize
release/adopt/restart while the transaction runs. It must fence every writer of
the target bundle, including gateway bundle pulls and other renewal tools.
A checkbox or a historical
STOPPED observation is not this guarantee.

The conditional transaction rechecks scope, generation, floor, time limits,
approval expiry and baseline hash; preserves the previous file; then performs
fsync and atomic replacement. A crash or directory-sync failure produces an
unknown outcome until the actual file hash is reconciled. It never rolls a floor
back, releases a hold or starts a service. `FILE_UPDATED` is a file result, not
proof of runtime loading or permission to move; runtime remains `NOT_OBSERVED`
until the existing bound probe confirms the loaded bytes.

## Observation history and raw retention

The console's live reader does not wait for the derived SQLite history index.
Its existing 512 MiB DB+WAL limit is unchanged: warning begins at80%, indexing
pauses at90%, and raw observations can remain live. A full existing index can be
queried read-only. Missing/corrupt storage is not returned as an empty successful
history. Current pose, last-known pose and historical replay are separate states.

New live-demo states declare `raw-policy.json`: 64 MiB segments, 1 GiB total raw
budget for the declared `demo-<role>.jsonl` files, and no automatic deletion. One
maximum active segment per role is reserved in that budget. The blackbox and
other files are outside this policy; this is not a whole-filesystem quota.

The existing ownership preparation allocates empty replacement slots with each
writer's UID/GID. The base/observer rotates near90% outside command callbacks,
preserving the planner's inability to rename directory entries or write another
role's log. Writers recheck the locked inode before appending. Archive hashing
happens after releasing append locks. Pending renames are recorded durably;
ambiguous recovery is refused rather than overwriting an unknown generation.

The index retains an opened old generation to EOF, verifies sealed archive
hashes, preserves its logical origin across byte-identical archive restoration,
and backfills only as replay. Missing or altered archives leave coverage
incomplete. Selecting a new index creates a new cursor epoch; old cursors are
not silently interpreted against the new database. Existing indexes and raw
files are not deleted as part of that operation.

When the archive budget is exhausted, the policy reports `LIMIT_REACHED`. The
writer may then reach its active-file limit and observation can become
unavailable; unlimited retention on finite storage is not promised. This code
never submits a plan, restarts a robot or calls a movement/stop API. Existing
states without this policy retain their former append behavior and are marked
unconfigured. They are not silently migrated, compressed or cleaned up.
