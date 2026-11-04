# Subgraph snapshot hash — the world slice a token was issued against

Every action token carries a 32-byte value, `subgraph_snapshot_hash`, inside
the signed bytes. It commits the token to the slice of the world model the
issuer authorized against at issuance time. This document defines that value
completely: which slice is selected, how the slice is encoded, and which hash
is taken — so that an implementation built from this text alone produces the
same 32 bytes as the issuer, and a verifier can recompute the number instead
of trusting it.

> 한국어판: [`SUBGRAPH_HASH.ko.md`](SUBGRAPH_HASH.ko.md). The English document
> is canonical; if the two diverge, the English text governs.

**The canonical source is not this document but the vectors** under
[`spec/subgraph-vectors/`](subgraph-vectors/). Every value quoted below is a
copy from those frozen files, and `tools/spec_subgraph_check.py` re-derives
every case from the rules written here with its own encoder, its own selection
and its own compiler. If the document is insufficient, that checker is the
first thing that finds out.

---

## 1. What the number is and where it travels

<!-- vocab: format -->

| name | value |
| --- | --- |
| `magic` | `PAILSG` |
| `format_version` | `1` |
| `hash` | `sha256` |
| `token_field` | `61` |
| `response_field` | `5` |

- **In the token.** `ActionToken.subgraph_snapshot_hash` is field `61` of
  `sdk/proto/pail.proto`. It is present for `schema_version >= 3` and is
  covered by the token signature because the signature is computed over the
  serialized token bytes. It is distinct from `policy_hash` (static rules);
  this value commits **world state**.
- **In the serving response.** `GetActiveTokenResponse.current_subgraph_hash`
  is field `5` of `sdk/proto/token_service.proto`: the issuer re-derives the
  served step's hash in the **current** world with the issuance epoch pinned
  (§6.4) and serves it beside the token. `graph_epoch` (field 6) is
  diagnostic and is not compared.
- **At the gate.** The gate compares the token's value with the served value
  before it asks the consumption question, and again on every periodic
  re-check while a permit is held. The comparison has three outcomes, not two:

<!-- vocab: gate_reason -->

| reason | code |
| --- | --- |
| `ERR_WORLD_CHANGED` | `0x14` |
| `ERR_WORLD_INDETERMINATE` | `0x19` |

  Equal → the world question is answered. Both present and different →
  `ERR_WORLD_CHANGED`, a fatal refusal that revokes the chain. **Either side
  empty** → `ERR_WORLD_INDETERMINATE`, a refusal that is *not* fatal: an empty
  hash is an infrastructure signal (no site model loaded, a re-derivation that
  failed), not evidence that the world changed, and treating it as fatal would
  turn an issuer fault into a self-inflicted denial of service. "Could not
  compare" is never reported as "compared and equal". The codes are the ones
  registered in `spec/vectors/contract/reason_dict.vec`.
- **In the ledger.** The issuance record (`TOKEN_ISSUED`) carries
  `subgraph_snapshot_hash_hex`, the `graph_epoch` the chain was issued at, and
  `node_refs` — the selected node ids with their versions (`id@version`). Each
  accepted context event is a `GRAPH_MUTATION` record with `mutation_kind`,
  the event as received (`event_node_id`, `arg`), the mutated `node_id`,
  `old_version`, `new_version` and the resulting `epoch` (§6.2).

---

## 2. The data model

A world is a **graph**: a global mutation counter (`epoch`), a set of
**nodes** keyed by id, and a list of directed **edges**. A **subgraph** is a
slice of one: the epoch it was cut at, some of its nodes (deep-copied, so later
mutation cannot change the snapshot), and some edges.

A node has an `id` (the `kind:local` convention, e.g. `zone:z7`), a `kind`, a
`state`, a per-node `version` (unsigned 64-bit, bumped on every mutation of
that node), and a map of typed attributes.

<!-- vocab: kind -->

| kind | value |
| --- | --- |
| `agent` | `1` |
| `executor` | `2` |
| `object` | `3` |
| `zone` | `4` |
| `human` | `5` |
| `constraint` | `6` |

Kind `0` (unspecified) is not encodable; a node carrying it makes the whole
subgraph unencodable (§3.5).

<!-- vocab: state -->

| state | value |
| --- | --- |
| `active` | `0` |
| `maintenance` | `1` |
| `cordoned` | `2` |

An edge is `(from, rel, to)` over node ids.

<!-- vocab: rel -->

| rel | value |
| --- | --- |
| `located_in` | `1` |
| `targets` | `2` |
| `constrains` | `3` |
| `operates` | `4` |
| `occupies` | `5` |

Attribute values are tagged. The tag is what makes the map canonically
encodable: there is no coercion between strings, numbers and booleans.

<!-- vocab: tag -->

| tag | value |
| --- | --- |
| `string` | `0x01` |
| `int64` | `0x02` |
| `double` | `0x03` |
| `bool` | `0x04` |

---

## 3. Canonical encoding

<!-- source: cloud/internal/graph/encode.go -->

The encoding is deterministic: the same logical subgraph produces the same
bytes whatever order nodes, edges or attributes were inserted in. Protocol
Buffers serialization is never used for this purpose because it is not
canonical.

### 3.1 Primitives

```
u32(v)   4 bytes, big-endian
u64(v)   8 bytes, big-endian
i64(v)   8 bytes, big-endian two's complement
f64(v)   8 bytes, big-endian IEEE 754 binary64; -0.0 is written as +0.0
LP(s)    u32(len(NFC(s))) ‖ NFC(s)        — UTF-8 after Unicode NFC normalization
```

`LP` is the same length-prefixed framing used elsewhere in the canon
specification. NFC applies to **every** string: node ids, attribute keys and
string values. Two spellings of one id (a precomposed `é` and `e` followed by a
combining acute) are the same id; the vectors carry both spellings and they
encode to the same bytes (`SG-04a`, `SG-04b`) — and listing both in one
subgraph is a duplicate id (`SG-95`).

### 3.2 Node

```
node(n) = LP(id) ‖ u8(kind) ‖ u8(state) ‖ u64(version) ‖ attrs(n.attrs)

attrs(m) = u32(count) ‖ for each key in ascending byte order of NFC(key):
             LP(key) ‖ u8(tag) ‖ value

value: string → LP(s)      int64 → i64(i)
       double → f64(f)     bool   → u8(1) or u8(0)
```

An absent attribute map and an empty one both encode as `u32(0)` (`SG-10`).

### 3.3 Edge

```
edge(e) = LP(from) ‖ u8(rel) ‖ LP(to)
```

The encoder does not resolve ids: an edge may name an id that is not a node
of the subgraph (`SG-09`), and two identical edges are both kept (`SG-06`).

### 3.4 Subgraph

```
subgraph = "PAILSG" ‖ u8(1) ‖ u64(epoch)
         ‖ u32(node_count) ‖ nodes sorted by ascending byte order of node(n)
         ‖ u32(edge_count) ‖ edges sorted by ascending byte order of edge(e)
```

The sort key is the **encoded bytes**, and every encoding begins with a
length-prefixed id. Order is therefore length-major: `zone:b` (6 bytes) sorts
before `zone:aa` (7 bytes) although `a` < `b` (`SG-05`). An implementation
that sorts by id string will produce a different hash on exactly such inputs.

A whole graph is encoded the same way with the magic `PAILCG` instead of
`PAILSG`; that value is used for the graph hash of the world vectors (§7) and
is not what a token carries.

### 3.5 What cannot be encoded

The encoder refuses rather than guesses. Refusal means **no bytes and no
hash**; the issuer does not sign a token for an unencodable world.

<!-- vocab: reject -->

| reason | cases |
| --- | --- |
| `kind_unspecified` | `1` |
| `non_finite_double` | `3` |
| `duplicate_node_id` | `2` |
| `unknown_attr_tag` | `1` |

- `kind_unspecified` — a node with kind `0`.
- `non_finite_double` — a double attribute that is NaN, +Inf or −Inf.
- `duplicate_node_id` — two nodes whose ids are equal **after NFC**.
- `unknown_attr_tag` — an attribute tag outside §2.

The vectors carry each of these as an `expect: reject` case with its reason,
so a second implementation can check that it refuses the same inputs, not only
that it accepts the same ones.

---

## 4. The hash

```
subgraph_snapshot_hash = SHA-256(subgraph)
```

32 bytes; in the ledger and in this document written as 64 lowercase hex
characters. The reference case is the legacy golden subgraph `SG-01`: three
nodes, two edges, one attribute of every type.

<!-- sample: encoding -->

```json
{"id": "SG-01", "sha256": "58b631c03edf4600000aec54715c022b0c5505d29b1639af021abf79d1474aa1"}
```

Its canonical bytes, quoted from the frozen file:

<!-- pin: spec/subgraph-vectors/cases.json -->

```
5041494c534701000000000000000700000003000000077a6f6e653a7a3704000000000000000001000000020000000e61646a6163656e745f636f756e7402000000000000000200000004747970650100000009776f726b5f6172656100000009726f626f743a746231010000000000000000030000000000000013636f6e73747261696e743a7370656564407a37060000000000000000010000000200000004686172640401000000146d61785f6c696e6561725f73706565645f6d7073033fe00000000000000000000200000009726f626f743a74623101000000077a6f6e653a7a3700000013636f6e73747261696e743a7370656564407a3703000000077a6f6e653a7a37
```

Read from the left: `5041494c5347` is `PAILSG`, `01` the format version,
`0000000000000007` the epoch, `00000003` three nodes; the first node is
`zone:z7` (7 bytes) because its encoding is the shortest, then `robot:tb1`,
then `constraint:speed@z7`; then `00000002` two edges.

---

## 5. Which slice a request selects

<!-- source: cloud/internal/graph/build.go -->

A request names an acting robot (`robot_id`, bare local id) and optionally a
target object (`target_object_id`). The selected subgraph is built from the
world in this order. "Add node" means: copy the node if the world has it;
otherwise nothing. Edges are appended regardless of whether both ends exist.

1. Add the agent node `robot:<robot_id>`.
2. For every world edge from the agent: `located_in` → add the zone and the
   edge; `operates` → add the executor and the edge. Call the zones added here
   the **agent zones**.
3. For every `constrains` edge whose target is the agent or one of the agent
   zones: add the constraint node and the edge.
4. For every `located_in` edge into one of the agent zones whose source is a
   `human` node: add the human and the edge.
5. If a target object is named: add `object:<target_object_id>`, append the
   **synthetic** edge `(agent, targets, object)` — it is emitted even when the
   object is not in the world (`SEL-05`) — and for every `located_in` edge
   from the object, add its zone and the edge. Humans in the object's zone are
   **not** selected: step 4 ran over the agent zones only (`SEL-02`).
6. The subgraph's epoch is the world's epoch.

Selection does not decide anything. The issuer then evaluates the slice — an
agent in `maintenance` or `cordoned` state, or a human in an agent zone,
refuses issuance (`SEL-03` carries `HUMAN_IN_ZONE`) — and only then hashes
it. The hash is nevertheless a total function of the slice: the vectors
carry the hash of refused and even empty selections (`SEL-04`, an agent the
world does not know) so that a verifier can recompute any of them.

<!-- sample: selection -->

```json
{"id": "SEL-02", "node_ids": ["constraint:human_excl@z7", "constraint:payload@tb1", "executor:tb1", "object:box1", "robot:tb1", "zone:z7", "zone:z8"], "sha256": "933fcc152c1fc10e892e36d98fa3971323d339dd960097b42d9efc4a0c76a0ae"}
```

---

## 6. The world cut

The hash commits a slice of a world. To recompute it, a verifier needs the
world as it stood at the issuance epoch. This section states how that world
comes to exist and how it changes, so that the ledger records suffice to
rebuild it.

### 6.1 Compiling a site declaration

<!-- source: cloud/internal/graph/compile.go -->

[`SITE_MODEL.md`](SITE_MODEL.md) describes the operator's file. The compiled
graph is defined over the **declaration**, not over YAML syntax — a JSON or API
front end producing the same declaration produces the same graph. The world
vectors therefore carry each declaration both as the YAML text and as plain
JSON. The compiled graph is at epoch `0` and every node is at version `0`,
state `active`:

- zone `z` → node `zone:z`, kind `zone`; attribute `type` (string) if
  declared; attribute `adjacent` (string) = the declared adjacent ids sorted
  and joined with `,`, if any were declared.
- object `o` → node `object:o`, kind `object`; if `at: z` is declared, edge
  `(object:o, located_in, zone:z)`.
- robot `r` → node `robot:r`, kind `agent`; attribute `capabilities` (string)
  = sorted ids joined with `,` if declared; attribute `schema` (string) if
  declared; attribute `robot_class` (string) if declared. Always a node
  `executor:r`, kind `executor`, and the edge `(robot:r, operates,
  executor:r)`. If `home: z` is declared, edge `(robot:r, located_in,
  zone:z)`.
- constraint `human_exclusion` with `zone: z` → node
  `constraint:human_excl@z`, kind `constraint`, attribute `ctype` =
  `human_exclusion`, edge `(constraint:human_excl@z, constrains, zone:z)`.
  `zone: "*"` expands over every declared zone, in ascending id order.
- constraint `exclusive` with `object: o` → attribute `exclusive` (bool
  `true`) on `object:o`. `"*"` expands over every declared object.
- `actions` and `policy` are declarations the issuer enforces; they are not
  world state and produce no node.

Compilation refuses, and the issuer then refuses every issuance: an unknown
top-level key, an unknown constraint type (`WLD-91`), a reference to an
undeclared zone or object (`WLD-92`), a duplicate id, an empty `site`, and the
`speed_limit` constraint (`WLD-90`) — per-zone limits live in the gate policy
and are carried in the token envelope; the site model never enforced one.

### 6.2 Mutating the world

<!-- source: cloud/internal/graph/mutate.go -->

Each accepted context event bumps the target node's version and the global
epoch by exactly one, and is journaled as a `GRAPH_MUTATION` record carrying
the event as received — `mutation_kind`, `event_node_id` (the `node_id` of
the event: the zone for `HUMAN_*`, the object for `OBJECT_MOVE`, the node for
the state events) and `arg` — together with the mutated `node_id` and the
versions below. Replaying the records over the compiled graph rebuilds the
world at any epoch. The vectors use the same three input fields per event.
Records written before `event_node_id` and `arg` were added (2026-09-18)
carry only the mutated node; for those, `HUMAN_ENTER`, `HUMAN_LEAVE` and
`OBJECT_MOVE` cannot be replayed from the ledger alone and the operator's own
event log is needed.

<!-- vocab: event -->

| kind | cases |
| --- | --- |
| `HUMAN_ENTER` | `2` |
| `HUMAN_LEAVE` | `1` |
| `OBJECT_MOVE` | `1` |
| `MAINTENANCE_ON` | `1` |
| `MAINTENANCE_OFF` | `0` |
| `CORDON_ON` | `1` |
| `CORDON_OFF` | `1` |

- `MAINTENANCE_ON` / `MAINTENANCE_OFF` / `CORDON_ON` / `CORDON_OFF` on
  `node_id`: set the state to `maintenance` / `active` / `cordoned` / `active`;
  `old_version` = the version before, `new_version` = `old_version + 1`.
- `HUMAN_ENTER` on `node_id = zone:z` with `arg = h`: if `human:h` does not
  exist, create it (kind `human`, version `0`) — the record then shows
  `old_version 0, new_version 0`; if it exists, bump its version. Add the edge
  `(human:h, located_in, zone:z)` if it is not already present.
- `HUMAN_LEAVE` on `zone:z` with `arg = h`: remove the edge `(human:h,
  located_in, zone:z)`. If the human is still `located_in` some other zone,
  bump its version; otherwise **delete the node**, and the record reports
  `new_version = old_version + 1` for a node that no longer exists.
- `OBJECT_MOVE` on `node_id = object:o` with `arg = z`: remove every
  `located_in` edge from the object, add `(object:o, located_in, zone:z)`,
  bump the object's version.

An event naming an unknown node, zone or human is refused and journals
nothing; the epoch does not move.

### 6.3 The ephemeral world

<!-- source: cloud/internal/graph/ephemeral.go -->

When no site model is loaded the issuer has no standing world. It authorizes
against a per-request world at epoch `0` built from what it knows:

- `robot:<robot_id>`, kind `agent`, version `1`;
- if any of the token's limits `max_linear_speed_mps`,
  `max_angular_speed_rps`, `max_duration_sec` is positive: a node
  `constraint:speed@<robot_id>`, kind `constraint`, version `1`, carrying
  **only the positive** limits as double attributes, and the edge
  `(constraint:speed@<robot_id>, constrains, robot:<robot_id>)`;
- `object:<target_object_id>`, kind `object`, version `1`, if a target is
  named.

Selection (§5) then runs over that world (`SEL-EPH-01` … `SEL-EPH-03`). In
this mode the issuer serves **no** `current_subgraph_hash`, so the gate reads
the comparison as indeterminate and refuses motion (§1): the token is valid,
the world question cannot be answered, and the deployment that means to
enforce must load a site model.

### 6.4 Epoch pinning

The epoch is inside the hashed bytes (§3.4). When the issuer re-derives a
step's hash in the current world — to serve `current_subgraph_hash`, or to
decide after a mutation which chains to revoke — it selects the slice from
the **current** world but pins the epoch to the chain's **issuance** epoch
before hashing. Left unpinned, every mutation anywhere would change every
chain's hash; pinned, the hash differs exactly when this chain's own nodes or
edges changed. A verifier recomputing a token's value must do the same:
world at the issuance epoch, or the current world with the issuance epoch
written into the header.

---

## 7. Files and fields

<!-- vocab: file -->

| file | array key | rows |
| --- | --- | --- |
| `cases.json` | `cases` | `18` |
| `selection.json` | `cases` | `9` |
| `world.json` | `cases` | `5` |

All three are UTF-8 JSON, indented by two spaces, with a trailing newline.
Hashes are lowercase hex, 64 characters. `cases.json` additionally carries
the top-level strings `format` and `format_version`.

A subgraph or world in JSON is `{epoch, nodes, edges}`; a node is
`{id, kind, state, version, attrs}` with the numeric values of §2; an attribute
is `{t, v}` with `t` one of `string`, `int64`, `double`, `bool` — **double
values are JSON strings** (`"0.5"`, `"-0"`, `"1e+308"`, `"5e-324"`) so that
negative zero and the non-finite reject inputs survive JSON — or `{t:
"unknown", tag}` for the unknown-tag reject case. An edge is
`{from, rel, to}`.

- `cases.json` — `{id, title, expect, subgraph, canonical_hex, sha256}` for
  accept cases; `{id, title, expect, reason, subgraph}` for rejects.
- `selection.json` — `{id, title, mode, world, request, selected, evaluate,
  canonical_hex, sha256}`; `mode` is `site` or `ephemeral`, and ephemeral
  cases also carry the `ephemeral` input (`robot_id`, `target_object_id`, the
  three limits) the world was built from. `selected` is `{node_ids, edges}`
  with ids sorted and edges sorted by `(from, rel, to)`; `evaluate` is
  `{violated, reason}`.
- `world.json` — `{id, title, expect, site_yaml, site, events, graph,
  graph_sha256, requests}`; `events` are in the order applied and carry the
  journaled `epoch`, `old_version`, `new_version`; `graph_sha256` is the
  `PAILCG` hash of the final world; each request carries the selected
  `node_ids` and the `sha256` of its slice. Reject cases carry `reason` and
  no graph.

<!-- sample: world -->

```json
{"id": "WLD-01", "epoch": 7, "graph_sha256": "104448dfd7810f059dc27366aab64cc7573e85385725326e657b287dd98708fc"}
```

---

## 8. What this set actually reaches

Every number below is re-derived from the frozen bytes by the checker.

<!-- vocab: coverage -->

| name | count |
| --- | --- |
| `accept_cases` | `11` |
| `reject_cases` | `7` |
| `selection_site` | `6` |
| `selection_ephemeral` | `3` |
| `world_accept` | `2` |
| `world_reject` | `3` |
| `nfc_pairs` | `1` |
| `length_major_cases` | `4` |
| `duplicate_edge_cases` | `1` |
| `empty_subgraph_cases` | `1` |
| `evaluate_violations` | `1` |

- `nfc_pairs` — pairs of accept cases whose inputs differ only in Unicode
  composition and whose canonical bytes are identical.
- `length_major_cases` — accept cases in which sorting nodes by id string
  would give a different order than sorting by encoded bytes.
- `duplicate_edge_cases` — accept cases carrying two identical edges.
- `empty_subgraph_cases` — accept cases with no nodes and no edges.
- `evaluate_violations` — selection cases whose slice the issuer would refuse.

---

## 9. Manifest and set hash

`spec/subgraph-vectors/MANIFEST.sha256` lists the SHA-256 of each file and
then a `set_sha256` line over the whole set, computed over the
`"<hex>  <name>\n"` lines only, sorted by file name; comment lines and the
`set_sha256` line itself are not inputs.

<!-- vocab: claim -->

| name | value |
| --- | --- |
| `subgraph_set_sha256` | `2ab87f04885b82dcf22a67d5b565d0fed057abb3e9a4d95ea9f613bd80e4c752` |
| `canon_set_sha256` | `bbddff16fb5997faeff47bf6913e64d9675178d2ddffd5828aa898a235688701` |
| `golden_g1_sha256` | `58b631c03edf4600000aec54715c022b0c5505d29b1639af021abf79d1474aa1` |

This set is a different plane from `spec/vectors/canon/` (how strings are
written down) and from `spec/merkle-vectors/` (the log arithmetic). It has its
own manifest because it is revised for unrelated reasons. `golden_g1_sha256`
is the single subgraph vector that existed before this set; `SG-01` carries it
unchanged so that continuity is measured rather than assumed.

The conformance claim in [`CONFORMANCE.md`](CONFORMANCE.md) covers the
serialization plane, `canon_set_sha256`. Passing this set is not part of that
claim today. If that changes, it changes in `CONFORMANCE.md` and in the checker
that measures it, not in this paragraph.

---

## 10. Using the set

For an implementation under test:

1. Encode every accept case of `cases.json` with §3 and compare
   `canonical_hex` first, then `sha256`. A byte mismatch names the rule;
   a hash mismatch with equal bytes means the hash primitive is wrong.
2. Feed every reject case; the encoder must refuse with the same `reason`.
3. For each case of `selection.json`, select from `world` with §5 (building
   the ephemeral world with §6.3 first where `mode` is `ephemeral`), compare
   `selected`, then hash and compare `sha256`.
4. For each accept case of `world.json`, compile `site` with §6.1, apply
   `events` with §6.2 checking each journaled triple, hash the world and
   compare `graph_sha256`, then answer each request.
5. To verify a real token: rebuild the world at the chain's issuance epoch
   from the site declaration and the `GRAPH_MUTATION` records, select the
   slice for the token's robot and target, hash it, and compare with the
   token's field `61` and the ledger's `subgraph_snapshot_hash_hex`.

The shipped tool `cmd/pail-recompute` performs all five steps
(`vectors` mode for 1–4, `ledger` mode for 5). It reads the signed
`action_token_bytes` for field `61`, the robot and the target, follows the
issuer's epoch through the journal — a mutation with `epoch` `1` after a
higher epoch means the issuer reloaded the site model — and reports each
token as verified, mismatch, or cannot (a site file whose hash is not the
journaled `site_model_hash_hex`, an epoch the ledger does not let it reach,
or an event record without `event_node_id`).

---

## 11. How this document is maintained

| What | Check |
| --- | --- |
| Do the frozen files match the manifest, and the set hash match §9 | `tools/spec_subgraph_check.py` `S1` `S2` |
| Are the vocabularies of §1, §2 the values the vectors actually use | ibid. `S3` |
| Does an encoder written from §3 reproduce every accept case and refuse every reject case | ibid. `S4` |
| Does §4's quote come from the frozen bytes, and is `SG-01` the legacy golden | ibid. `S5` |
| Does a selector written from §5 and §6.3 reproduce every selection case | ibid. `S6` |
| Does a compiler and replayer written from §6.1 and §6.2 reproduce every world case | ibid. `S7` |
| Do the quoted samples exist in the frozen cases | ibid. `S8` |
| Do the coverage counts of §8 match what the vectors reach | ibid. `S9` |
| Are the gate reasons of §1 the registered codes, and the proto fields of §1 the shipped ones | ibid. `S10` |
| Does the Korean edition teach the same vocabularies and samples | ibid. `S11` |
| Do the generator's and the encoder's constants agree with §1 | ibid. `S12` |

If the checker cannot establish its own premises (no vectors, no manifest, a
document with no vocabulary tables), it stops with **rc=2**, not `FAIL 0`. A
run that read nothing and a run with no violations must not emit the same
bytes.
