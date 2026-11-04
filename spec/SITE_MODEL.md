# Site model (`PAIL_SITE_MODEL`)

A site model is the one file with which an operator describes their own site to
the PAIL issuer: the zones, the objects, the robots, and the rules that hold
over them. The issuer compiles it at boot into the context graph it authorizes
against, and binds a hash of the relevant slice of that graph into every token
it signs.

> 한국어판: [`SITE_MODEL.ko.md`](SITE_MODEL.ko.md). The English document is
> canonical; if the two diverge, the English text governs.

## 1. Why a file and not code

The world model has to be adopted by people who did not write the issuer. If
describing a site required a code change, then every site would carry a private
fork, and the thing a fork is most likely to modify is the part that refuses.

So the site model is declarative, and the compiler is the only thing that reads
it. The evidence contract does not live in YAML — it lives in the graph model
and its canonical encoder, so the same logical site produces the same snapshot
hashes regardless of the order keys were written in, and a different front end
(JSON, an API) could produce a byte-identical graph.

## 2. Loading, and what happens when it fails

<!-- source: cloud/internal/graph/compile.go -->

`PAIL_SITE_MODEL` holds the path. If it is unset, no site model is loaded and
the issuer falls back to a per-request ephemeral graph — the pre-site-model
behavior.

If it is set and the file cannot be read or cannot be compiled, the issuer
**starts and refuses every issuance**. It does not fall back to the ephemeral
graph. A site that declared a world and got a typo must not be served as though
it had declared nothing: the fallback would be quieter than the failure and
strictly less safe than it.

Parsing is strict in the same spirit:

<!-- pin: cloud/internal/graph/compile.go -->
```go
// strict parsing (fail-closed): unknown top-level keys, unknown struct fields,
// unknown constraint types, and dangling references all abort compilation. A
// silently-dropped constraint is a safety incident, so a typo must stop
// issuance, not be ignored.
```

An unknown key is not ignored, a misspelled constraint type is not skipped, and
a reference to a zone that was never declared is not resolved to nothing. Each
of those aborts the compile. The failure mode being avoided is specific: a rule
you believe you wrote, that no longer exists, and that nothing tells you about.

### 2.1 Snapshots of the serving model

When the Issuer loads `PAIL_SITE_MODEL` it keeps the exact bytes under their SHA-256 —
`PAIL_SNAPSHOT_DIR/<hash>.yaml` (default `/var/log/pail_blackbox/snapshots`) — before the
model serves, and refuses to start when it cannot (`S23`). Every `TOKEN_ISSUED` record names
that hash (`site_model_hash_hex`), so a question about an earlier permit is answered from the
model of that day, never from the model of today. The name is the content: a file whose bytes
do not hash to its name is not a snapshot.

| Responsibility | Who | How |
|---|---|---|
| Creation | Issuer, at site-model load | content-addressed write (temp file, fsync, rename); `S23` when the directory is unusable |
| Retention | Operator | same directory family and retention as the journal (`spec/DURABLE_STORES.tsv`); nothing in PAIL deletes a snapshot; a removed snapshot makes the rows that name it `unresolved`, never guessed |
| Integrity | Issuer when storing, collector when reading | the Issuer refuses to start when different bytes are already stored under the name (`S23`, the file is not overwritten); the collector (`pail_telemetryd`) re-hashes every snapshot it reads and treats a mismatch as "cannot resolve" |
| Lookup | Ledger query | `site_model_hash` on every row; `zone_resolution` says `recorded`, `snapshot` (content verified against its name), `unresolved` or `none` |
| Independent check | Anyone, with no PAIL code | `sha256sum <hash>.yaml` must print the file's own name; the snapshot compiles with the public site-model compiler |
| Regression data | Release tests | the collector refuses a snapshot whose content does not match its name; the Issuer store refuses different bytes under one name |

A snapshot cannot tell you whether the move succeeded, whether a sensor told the truth, or
whether a key had expired: it is the declaration the permit was judged against, not a record
of the execution.

## 3. Top-level keys

<!-- vocab: top -->

| key | required? | meaning |
| --- | --- | --- |
| `site` | required | Site identifier. Recorded; the compile fails without it. |
| `schema` | optional | The operator's declared token schema version for the site. **Recorded only** — it is written to the boot log and no issuance path reads it, so a value here neither raises nor caps the `schema_version` of an issued token. |
| `zones` | optional | Zone declarations (§4.1). |
| `objects` | optional | Object declarations (§4.2). |
| `robots` | optional | Robot declarations (§4.3). |
| `constraints` | optional | Rule declarations (§5). |
| `actions` | optional | Registered action names with their classes (§4.4). |
| `policy` | optional | Issuer dispositions the site declares (§4.5). |
| `custom_events` | optional | Customer-defined context event names mapped to built-in kinds (§4.6). |

Every section is optional, and each one that is absent is absent — not
defaulted. A model with no `robots` compiles, and then every issuance request
is refused with `AGENT_NOT_IN_MODEL`, because the issuer has no world state to
authorize the request against. That is the intended shape of the failure, but
it is worth stating plainly: an empty model is a strict model, not a permissive
one.

## 4. Entities

### 4.1 `zones`

<!-- vocab: zones -->

| field | required? | meaning |
| --- | --- | --- |
| `id` | required | Local zone id. Becomes node `zone:<id>`. Duplicates abort the compile. |
| `type` | optional | Free-form label carried as a node attribute. The compiler does not interpret it and no refusal reads it; it is evidence in the snapshot, not a rule. |
| `adjacent` | optional | Ids of neighbouring zones. |

`adjacent` is **existence-checked only**. Each named zone must be declared, but
symmetry is not required: `a: [b]` without `b: [a]` compiles. Adjacency is
carried as a sorted node attribute — evidence — and is not a routing edge, so an
asymmetric declaration cannot mislead an issuance decision. Do not read it as a
navigation graph.

### 4.2 `objects`

<!-- vocab: objects -->

| field | required? | meaning |
| --- | --- | --- |
| `id` | required | Local object id. Becomes node `object:<id>`. Duplicates abort the compile. |
| `at` | optional | Zone the object is in. Emits a `LOCATED_IN` edge to `zone:<at>`; the zone must be declared. |

An object's location can change at runtime through the context-event API. Its
existence cannot: an object not declared here is not in the world.

### 4.3 `robots`

<!-- vocab: robots -->

| field | required? | meaning |
| --- | --- | --- |
| `id` | required | Local robot id. Becomes agent node `robot:<id>` plus executor node `executor:<id>` and an `OPERATES` edge between them. Duplicates abort the compile. |
| `capabilities` | optional | Sorted node attribute. Recorded as evidence; no issuance path reads it, so listing a capability neither grants nor withholds anything. |
| `schema` | optional | Node attribute, per robot. Recorded as evidence; nothing reads it. |
| `home` | optional | Zone the robot is in. Emits a `LOCATED_IN` edge to `zone:<home>`; the zone must be declared. |
| `robot_class` | optional | The robot's class word from `spec/SKILL_VOCAB.tsv` (`diff_drive_amr`, `humanoid`, …). It picks the skill registry the issuer matches this robot's plan steps against (`skills.<robot_class>.yaml`, `spec/SKILLS.md`). Recorded as a node attribute when present; absent means "no registry" — a production issuer refuses to serve such a robot (S39), a dev issuer issues on the legacy path and says so in the journal (`skill_matched: false`). |

`home` is optional in the parser but it is what places the agent in a zone, and
**zone-scoped rules only reach agents that are in a zone.** The evaluated
subgraph for a request is built outward from the agent: its zone, then the
constraints on that zone, then the humans in that zone. A robot with no `home`
has no zone, so no zone constraint and no co-located human is ever pulled in for
it. It can still be refused for its own lifecycle state (§6), but a
`human_exclusion` rule written over `"*"` will not cover it.

There is no runtime event that moves a robot between zones. A robot's zone is
whatever `home` said, for the life of the loaded model.

### 4.4 `actions`

<!-- vocab: actions -->

| field | required? | meaning |
| --- | --- | --- |
| `name` | optional | The action name a plan step may carry in `ActionSpec.name`. Duplicates abort the compile. The parser does not refuse an empty name; an empty name matches no step. |
| `classes` | optional | One or more of `MOVE`, `MANIPULATE`, `ACTUATE`, `NONE`. A step that names this action and declares other classes is refused (`ERR_ACTION_CLASS_MISMATCH`). The parser does not refuse an empty list; an entry without classes registers a name with no class. |
| `description` | optional | Free text, recorded. |

The `actions` registry is the declaration of names the site knows. It is
not the skill registry (`spec/SKILLS.md`): the skill registry is per robot class,
is the allow-list the issuer matches every step against, and carries the
envelope, feeds and safe state. A name in `actions` but not in the robot's skill
registry is still refused (`skill not registered`).

### 4.6 `custom_events`

<!-- vocab: custom_events -->

| field | | meaning |
| --- | --- | --- |
| `id` | required | The event name a `ContextEvent{kind: CUSTOM}` carries in `custom_kind`: `<namespace>.<name>`, both sides lowercase `[a-z0-9_]`, 1–32 characters each. Duplicates abort the compile. |
| `effect` | required | The built-in kind this name is applied as: one of `HUMAN_ENTER`, `HUMAN_LEAVE`, `OBJECT_MOVE`, `MAINTENANCE_ON`, `MAINTENANCE_OFF`, `CORDON_ON`, `CORDON_OFF`. Any other value aborts the compile. `node_id`/`arg` follow the effect's convention (`spec/API_SURFACES.md` §5.1). |
| `description` | optional | Free text, recorded. |

A custom event does not extend the vocabulary of graph mutations; it names one.
The journal keeps both the effect (`GRAPH_MUTATION.mutation_kind`, so replay is
unchanged) and the declared name (`custom_kind`). A `CUSTOM` event whose
`custom_kind` this section does not declare is refused; nothing is mapped by
guess.

### 4.5 `policy`

| field | required? | meaning |
| --- | --- | --- |
| `unverified_targets` | optional | `refuse` (default) — a step whose `target_object_id` is not a declared object is refused (`ERR_TARGET_UNKNOWN`); `allow` — it is issued with `target_unverified: true` on the `TOKEN_ISSUED` record. |

## 5. Constraints

<!-- source: cloud/internal/graph/constraints.go -->

A constraint type is one entry in a registry — a function that compiles its own
declaration into constraint nodes and `CONSTRAINS` edges over the generic node
model. Adding a rule vocabulary is an additive registration rather than scattered
edits, and the evidence contract does not move: a constraint is always a node
with attributes, encoded by the same canonical encoder.

<!-- pin: cloud/internal/graph/constraints.go -->
```go
// Fail-closed is the invariant: an unknown constraint type is a compile error,
// never a silent skip. You cannot sign off on a rule you cannot compile — a
// typo'd rule must stop issuance, not quietly disappear.
```

Each declaration is a mapping with a `type` key. The remaining keys are
validated against that type's own whitelist; an unexpected field aborts the
compile rather than being dropped.

### 5.1 Registered types

<!-- ctypes -->

| type | what it does |
| --- | --- |
| `human_exclusion` | Records the human-exclusion rule for a zone as a constraint node (§5.2). |
| `speed_limit` | **Refused** since 2026-09-09 (§5.3) — per-zone bounds live in `policy.yaml` `guardrails.zones`. |
| `exclusive` | Marks an object as exclusively occupiable (§5.4). |

`zone` and `object` fields accept `"*"`, which expands over every declared zone
or object respectively. The expansion happens at compile time against what was
declared, so a zone added later is not covered by an earlier `"*"` unless the
model is recompiled — which, since the model is compiled at boot, means a
restart.

### 5.2 `human_exclusion`

<!-- vocab: constraint/human_exclusion -->

| field | required? | meaning |
| --- | --- | --- |
| `zone` | required | Zone id, or `"*"` for every declared zone. |

Emits one constraint node per target zone with a `CONSTRAINS` edge to it.

Read the effect carefully, because it is not what the name suggests. The
refusal on a human sharing the agent's zone is **structural**: the evaluator
looks for a `HUMAN` node located in a zone the agent is in, and does not consult
the constraint node at all. Declaring `human_exclusion` therefore does not
switch that refusal on, and omitting it does not switch it off. What the
declaration does is put the rule in the snapshot as evidence — the token records
which rules the site declared over the zone it was issued for.

### 5.3 `speed_limit`

<!-- vocab: constraint/speed_limit -->

| field | required? | meaning |
| --- | --- | --- |
| `zone` | required | Zone id, or `"*"` for every declared zone. |
| `max_linear_speed_mps` | optional | Linear speed ceiling, metres per second. |
| `max_angular_speed_rps` | optional | Angular speed ceiling, radians per second. |

**This constraint is refused (compile error) since 2026-09-09.** Until then the
compiler recorded it as a constraint node that nothing read: the gate compares
the commanded speed against the *token's* limit, and that limit came from
`policy.yaml` `motion:` alone — a site model that "set" a zone limit set nothing,
while this page said the gate would enforce it. The honest fix was not to wire
the node in but to move the bound to the one place the issuer already reads:

```yaml
# policy.yaml (issuer)
guardrails:
  common:            # absolute ceilings, by GUARDRAILS.tsv name
    sls.linear_mps: 1.0
    sls.angular_rps: 1.0
    step.max_duration_s: 30
  zones:             # may only tighten `common` (S34)
    z7:
      sls.linear_mps: 0.5
```

The issuer resolves the target object's zone (`objects[].at`) at issuance and
bakes `min(common, zone)` into the token's constraints, which the gate enforces
against the actual command. The field table above is kept so an old file is
diagnosed by name; a model that still carries `speed_limit` does not load.

**A request above that bound is refused, not shortened.** The issuer compares
what the plan step asks for — the twist's linear and angular speed magnitudes
(so reverse and diagonal motion meet the same bound), its `duration_sec`, and any
numeric `params_json` key named after an envelope entry — against
`min(common, zone)`. If any value is above it, or is not a finite number, the
plan is rejected with `ERR_ENVELOPE_EXCEEDED` and no token is issued; the
`Denial.exceeded` list carries one `{name, requested, max}` entry per bound, so
a client can tell the user which limit was hit (units: `GUARDRAILS.tsv`). The
issuer never issues a shorter or slower version of the request — a partial
motion the requester did not plan is a correction of the command, which PAIL
does not make. A request within the bound gets a token carrying the bound for
speed and the requested duration.

### 5.4 `exclusive`

<!-- vocab: constraint/exclusive -->

| field | required? | meaning |
| --- | --- | --- |
| `object` | required | Object id, or `"*"` for every declared object. |

Sets an `exclusive` attribute on the object node — no constraint node is
created. This is a forward hook. Issuance **does not evaluate occupancy**:
marking an object exclusive today records the intent in the snapshot and refuses
nothing. Do not deploy it as a mutual-exclusion mechanism.

## 6. What the compiled model can refuse

A site model shapes issuance in exactly four ways. Everything else it declares
is evidence.

| refusal | when |
| --- | --- |
| compile abort | The file is unreadable or invalid. The issuer starts and refuses all issuance (§2). |
| `AGENT_NOT_IN_MODEL` | The request names a robot the model never declared. |
| `NODE_MAINTENANCE` / `NODE_CORDONED` | The agent node is in that lifecycle state (set at runtime, not in this file). |
| `HUMAN_IN_ZONE` | A human is located in a zone the agent is in (§5.2). |

The distinction matters when reading the tables above: `type`, `capabilities`,
`schema`, and `adjacent` are recorded and hashed, and are therefore auditable
after the fact — but nothing in the issuer branches on them. A model is not made
safer by filling them in.

## 7. A complete model

<!-- example: config/site_model.example.yaml -->

The shipped example at `config/site_model.example.yaml` compiles as-is. Its
header and constraint section:

<!-- pin: config/site_model.example.yaml -->
```yaml
site: warehouse-A        # required
schema: v3               # recorded only (boot log); no issuance path reads it
```

<!-- pin: config/site_model.example.yaml -->
```yaml
constraints:
  - type: human_exclusion   # a human in the zone forbids issuance for robots there
    zone: "*"               # "*" = every declared zone
  # speed_limit was removed on 2026-09-09 (SK-1, G-POL-11): the site model never
  # enforced it. Per-zone bounds live in policy.yaml `guardrails.zones.<zone>` and
  # ride in the token envelope; a speed_limit constraint here is now refused.
  - type: exclusive         # CG4/P4 hook: marks the object; v1 issuance does not yet evaluate occupancy
    object: box-12
```

## 8. Keeping this document honest

Everything above is measured rather than asserted. `spec/tools/spec_site_model_check.py`
reads the compiler source and the shipped example and compares three
vocabularies:

```
this document  ==  compiler source  ==  shipped example
```

Two would not be enough. Document and example alone could agree on a spelling
the parser has never accepted; document and parser alone could agree while the
example quietly rots and the first thing a reader runs fails. Every quoted block
is checked as a byte substring of the file it names, and every file this document
points at is checked to actually ship — a quote the reader cannot verify against
something in their own hands is not a quote, it is a claim.
