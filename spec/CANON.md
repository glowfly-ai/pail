# PAIL canon specification — the canonical bytes that are signed and hashed

**This document exists for the second implementation.** Assemble exactly what
is written here and you must get the same values as the frozen bytes under
[`vectors/`](vectors/); if you do not, one of the two is wrong.

**The canonical source is not this document but the vectors.** The quoted
blocks in each section below are **byte-for-byte copies** from the frozen
files under `vectors/canon/`, and `tools/spec_canon_check.py` measures on
every CI run that each quote really is a substring. Editing only the document
is impossible — a quote that diverges from the vectors goes red.

> 한국어판: [`CANON.ko.md`](CANON.ko.md). The English document is canonical;
> if the two diverge, the English text governs.

The failure this document aims at is a hand-written spec outliving the code.
A clean-room implementation built from the spec never looks at our code, so
if the spec goes stale, that implementation ends up implementing a format we
never even shipped.

---

## 1. The unit of a conformance claim

It is the pair of the profile name **`PAIL-CORE-2026.1`** and the set hash
`set_sha256  bbddff16fb5997faeff47bf6913e64d9675178d2ddffd5828aa898a235688701`.
The canonical source is
[`spec/vectors/canon/MANIFEST.sha256`](vectors/canon/MANIFEST.sha256), and how
it is computed is written in that file's preamble.

If even one vector changes, the set hash changes, and if the set hash changes,
**it is a different profile.** A conformance claim that does not state both
values together has no defined subject — the rule is in
[`CONFORMANCE.md`](CONFORMANCE.md).

---

## 2. Assembly rules common to all canons

### 2.1 `R-A` — identifier fields cannot contain the delimiter

In canonical strings joined with `:`, identifier fields (`tenant`,
`robot_id`, `key_id`, etc.) **must not contain the delimiter `:` and must not
be empty.** Violations are **rejected at the assembly point.**

Blocking only at the boundary (HTTP handlers, ingest) leaves every path that
calls the assembly function directly undefended. This is exactly the property
the `expect=reject` records in the vectors pin down, and those records
**carry no bytes** — rejection means "emitted nothing", not "emitted an empty
string".

### 2.2 `R-B` — free text uses length-prefixed framing (LP)

Free text coming from users or the environment is not joined with `:` but
wrapped in LP.

```
LP(x) = u32BE(len(NFC(x))) ‖ NFC(x)
```

Normalization is NFC. Under LP a value is safe even if it contains `:`, which
is why `R-A` does not apply to free-text fields.

### 2.3 `R-C` — escaping in line-based canonical strings

Only `pail-config-seal:*` assembles by lines rather than by `:`. Characters
inside values are escaped as `'\\'→'\\\\'`, LF→`'\\n'`, CR→`'\\r'`.

### 2.4 Hex and floating point

Binary values are carried as **lowercase hex**. Floating-point values are
carried as `x1e6` integers — `'%f'` follows the locale, and the moment the
decimal point becomes a comma, the digest changes.

### 2.5 Old editions are frozen, not retired (`F8`)

The `v1` prefixes have **ended generation, and parsing is kept forever.** A
conforming implementation must not produce new `v1` bytes, but must remain
able to verify `v1` bytes it receives. Becoming unable to read a journal that
was already written would be the evidence layer negating itself.

In the vectors, old editions live as `expect=parse_only` records.

---

## 3. Prefix registry

**There are 23.** The list of sections below *is* the registry, and every
prefix observed under `vectors/` must have a section — a missing one turns
`tools/spec_canon_check.py` red with `B1`. Omissions are always silent, which
is why a check in this direction is needed separately.

| What is signed or hashed | Prefix |
|---|---|
| Journal anchor | `pail-anchor:v1` · `pail-anchor:v2` |
| Transparency-log leaf | `pail-saas-anchor:v1` · `pail-saas-anchor:v2` |
| Verification verdict | `pail-verdict:v1` · `pail-verdict:v2` · `pail-verdict:v3` · `pail-verdict-evidence:v1` |
| Operational alert | `pail-alert:v1` · `pail-alert:v2` · `pail-alert-detail:v1` |
| Segment checkpoint | `pail-checkpoint:v2` |
| Operator command | `pail-unlock:v1` · `pail-unlock:v2` · `pail-revoke-issuer:v1` · `pail-revoke-issuer:v2` |
| Single-use consumption key | `pail-tokenkey:v1` |
| Context provenance | `pail-context:v1` · `pail-ctxbody:v1` |
| Deployment config seal | `pail-config-seal:v1` · `pail-config-seal:v2` · `pail-config-seal:v3` |
| Burst chain correlation value | `pail-burstchain:v1` |
| Retry-floor identity key | `pail-planhash:v1` |

**Two of them have no frozen vector** — `pail-burstchain:v1` and
`pail-planhash:v1`. That fact is not hidden: it is recorded in
[`vectors/canon/UNPINNED.tsv`](vectors/canon/UNPINNED.tsv) together with the
reason, the owner, and the resolution condition, and in this document they
are written as `pin: none`. The checker compares that declaration against the
registry (`B5`) — an unregistered "no pin" is not a record but an exemption.

**Having no frozen vector means not being a subject of conformance claims.**
The set hash of §1 does not cover these two.

---

## 4. Canonical strings per prefix

The quoted block in each section is byte-for-byte from the frozen vector it
points at. `#` is the vector file's comment marker, and the quotes are kept
in that form to **make substring comparison possible** — the moment a quote
is polished in transit, it becomes a sentence that cannot be falsified.

### `pail-anchor:v2`

The value a robot signs when pinning the head of its own journal to an
external reference point. The `tenant` and `robot` that `v1` omitted are now
inside the signature — without them, robot A's anchor signature can be reused
as robot B's anchor.

<!-- pin: spec/vectors/canon/anchor_v2.vec -->
```
# canon: pail-anchor:v2:<tenant_id>:<robot_id>:<head_hash_hex>:<segment_seq>:<record_count>:<unix_ms>
```

### `pail-anchor:v1`

Legacy edition. The current public M9 producer (`cloud/internal/anchor/anchor.go`) still generates v1; v2 vectors define a newer format, not a completed producer migration. Preserve parsing of existing records (§2.5). v1 has no scope
identifiers, so the signatures of two deployments sharing the same head are
indistinguishable. The vector's `parse_only` record pins those bytes.

<!-- pin: spec/vectors/canon/anchor_v2.vec -->
```
canon	pail-anchor:v1:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:7:42:1700000000000
```

### `pail-saas-anchor:v2`

The leaf bytes that enter the transparency log. **Not a signing target but
the value carried in the log itself**, so the vector has no `sig` column.

<!-- pin: spec/vectors/canon/saas_anchor_v2.vec -->
```
# leaf: pail-saas-anchor:v2:<tenant>:<robot>:<key_id>:<server_seq>:<server_recv_ms>
#       :<anchor_sha256>:<segment_seq>:<record_count>:<head_hash_hex>
```

For the existing Anchor service wire contract, `anchor_sha256` is the lowercase
SHA-256 hex digest of the **exact received AnchorRecord JSON bytes**, including
whitespace and the signature field. It is not the digest of the signing canon or
of re-serialized JSON. A proof verifier authenticates inclusion of the leaf; it
does not by itself validate this record-to-leaf binding. The frozen leaf vector
uses a supplied digest to test field assembly, not a complete ingest exchange.
The public M9 HTTP client sends `PUT BaseURL/<name>`; a server accepting only
`POST /v1/anchor/{tenant}` needs an adapter and is not a drop-in upload endpoint.

### `pail-saas-anchor:v1`

Old edition. Segment/record counts and the head were outside the leaf.

<!-- pin: spec/vectors/canon/saas_anchor_v2.vec -->
```
# v1  : pail-saas-anchor:v1:<tenant>:<robot>:<key_id>:<server_seq>:<server_recv_ms>:<anchor_sha256>
```

### `pail-verdict:v3`

The signing target of a verification verdict. It continues over two lines,
and the leading `:` of the second line is part of the concatenation, not the
start of a new field.

<!-- pin: spec/vectors/canon/verdict_v3.vec -->
```
# canon: pail-verdict:v3:<tenant>:<robot>:<generated_ms>:<verdict>:<head_hex>:<segments>:<records>
#        :<anchors_checked>:<anchors_found>:<log_consistency>:<log_root_hex>:<log_size>:<evidence_hash_hex>
```

`log_consistency` is a **three-valued string** (`ok` · `fail` · `none`). Not
a boolean — if "could not check" and "checked and it is fine" share one bit,
the unverified reads as passing.

### `pail-verdict:v2`

Old edition. The three `log_*` fields and `evidence_hash_hex` were outside
the signature.

<!-- pin: spec/vectors/canon/verdict_v3.vec -->
```
canon	pail-verdict:v2:acme:robot-1:1700000000000:MATCH:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:3:128:5:5:true
```

### `pail-verdict:v1`

Old edition. Without `tenant`, `robot`, and `generated_ms`, the signature
could not say when, or about whom, the verdict was.

<!-- pin: spec/vectors/canon/verdict_v3.vec -->
```
canon	pail-verdict:v1:MATCH:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:3:128:5:5:true
```

### `pail-verdict-evidence:v1`

The **hash-input** prefix that produces `evidence_hash_hex` of
`pail-verdict:v3`. It never appears in the value string.

<!-- pin: spec/vectors/canon/verdict_v3.vec -->
```
# evidence_hash = SHA-256("pail-verdict-evidence:v1:" ‖ LP(first_div) ‖ LP(proofs) ‖ LP(errors))
```

Lists are **wrapped twice** — `proofs = LP( LP(item₀) ‖ LP(item₁) ‖ … )`, in
ascending `leaf_index` order. `errors` has the same shape, in order of
occurrence. Without writing down the rule by which lists are joined, a third
party cannot produce the same hash.

### `pail-alert:v2`

The signing target of an operational alert. The detail body enters the
signature as a hash.

<!-- pin: spec/vectors/canon/alert_v2.vec -->
```
# canon: pail-alert:v2:<type>:<tenant>:<robot>:<count>:<ms>:<detail_hash_hex>
```

The value space of `type` is `ANCHOR_GAP_ROLLUP` · `FORK` · `REWIND` ·
`WORM_VIOLATION`.

### `pail-alert:v1`

Old edition. The detail was outside the signature, so the body could be
changed while the signature stayed valid.

<!-- pin: spec/vectors/canon/alert_v2.vec -->
```
# v1   : pail-alert:v1:<type>:<tenant>:<robot>:<count>:<ms>   (상세가 서명 밖)
```

### `pail-alert-detail:v1`

The hash-input prefix that produces `detail_hash_hex` of `pail-alert:v2`.

<!-- pin: spec/vectors/canon/alert_v2.vec -->
```
# detail_hash = SHA-256("pail-alert-detail:v1:" ‖ LP(detail))
```

### `pail-checkpoint:v2`

The signing target of a segment checkpoint. Not a `:`-joined string but a
**binary concatenation**.

<!-- pin: spec/vectors/canon/checkpoint_v2.vec -->
```
# 서명 대상: "pail-checkpoint:v2:" ‖ head(32B) ‖ record_count(u64BE) ‖ segment_seq(u64BE)
# 레코드 페이로드(112B): head(32) ‖ count(u64BE) ‖ seg_seq(u64BE) ‖ sig(64)  / record_type=31
```

### `pail-unlock:v2`

The signing target of the command by which an operator releases `SAFE_STOP`.
Signed with the **operator key**, not the issuer key. `operator_key_id` must
be inside the canon so that "who pressed it" remains in the signature.

<!-- pin: spec/vectors/canon/unlock_v2.vec -->
```
# canon: pail-unlock:v2:<robot_id>:<unix_ms>:<b64std(nonce)>:<operator_key_id>
```

The nonce uses the base64 standard alphabet (padding included).

### `pail-unlock:v1`

Old edition. Without `operator_key_id`, even this reversible command had an
empty accountability subject.

<!-- pin: spec/vectors/canon/unlock_v2.vec -->
```
canon	pail-unlock:v1:robot-1:1700000000000:AAECAwQFBgcICQoLDA0ODw==
```

### `pail-revoke-issuer:v2`

The signing target of the issuer-key revocation command. A sibling of
`unlock`, and heavier — unlock can be reversed, but revocation is a permanent
command that goes to `LOCKDOWN`.

<!-- pin: spec/vectors/canon/revoke_issuer_v2.vec -->
```
# canon: pail-revoke-issuer:v2:<issuer_key_id>:<unix_ms>:<b64std(nonce)>:<operator_key_id>
```

**This is a different event from chain revocation.** It takes down the trust
root of issuance; it does not invalidate a specific chain.

### `pail-revoke-issuer:v1`

Old edition. Missing `operator_key_id` — the same defect in the same shape as
`pail-unlock:v1`, present separately in two places.

<!-- pin: spec/vectors/canon/revoke_issuer_v2.vec -->
```
canon	pail-revoke-issuer:v1:dev-key-1:1700000000000:AAECAwQFBgcICQoLDA0ODw==
```

### `pail-tokenkey:v1`

The consumption key that enforces single use. The input is **the exact
original bytes used for verification**, not re-serialized bytes.

<!-- pin: spec/vectors/canon/tokenkey_v1.vec -->
```
# consumption_key = SHA-256("pail-tokenkey:v1:" ‖ action_token_bytes)
```

The envelope's `token_id` field must not be used as the consumption key. That
field is outside the signing target, so an attacker can rewrite it — and then
the same token passes twice.

### `pail-context:v1`

The leading literal of the context provenance record's (`record_type=51`)
payload.

<!-- pin: spec/vectors/canon/context_v1.vec -->
```
# record_type=51 / payload = "pail-context:v1:" ‖ LP(event_kind) ‖ LP(caller_kind) ‖ LP(caller_id)
#                            ‖ u8(context_verified) ‖ LP(event_body_hash_hex)
```

`context_verified` is a single u8 byte. **A value of 0 means "did not
verify", not "verified and it failed"** — writing both as the same value
makes the unverified read as a verdict.

### `pail-ctxbody:v1`

The hash-input prefix that produces the above record's `event_body_hash`.

<!-- pin: spec/vectors/canon/context_v1.vec -->
```
# event_body_hash = SHA-256("pail-ctxbody:v1:" ‖ LP(node_id) ‖ LP(kind_name) ‖ LP(arg) ‖ u64BE(claimed_unix_ms))
```

It is safe for `arg` to contain `:` — it is under LP (§2.2). The vector's
frozen body deliberately using `zone:z7` is the proof.

### `pail-config-seal:v3`

The seal of the deployment configuration, current edition (SK-4). Assembled
**by lines**, key names and order frozen; v2's 31 keys plus
`skills_file_sha256` inserted right after `policy_file_sha256` — the content
digest of the skill registry the gate read (`config/skills.<robot_class>.yaml`).
Its vocabulary is the policy digest's: 64 lowercase hex (read and hashed),
`unknown` (a registry was named but could not be read — also a `degraded`
axis, S21), empty (no registry configured). The issuer compares it with its
own copy and journals both digests with a three-valued verdict
(`skills_registry_match`: match / mismatch / unknown, S38).

<!-- pin: spec/vectors/canon/config_seal_v3.vec -->
```
# canon: "pail-config-seal:v3\n" 다음에 고정 순서 32줄의 `<key>=<escape(value)>\n`.
# 키 순서(동결): component robot_id profile use_sim_time ros_security_enable ros_security_strategy ros_security_keystore enclave_provisioned effective_enclave
#              token_provider_mode use_token_service grpc_built verifies_authorization token_service_addr keyring_mode control_transport control_trust_anchors
#              trusted_key_fingerprints evidence_conf_threshold_x1e6 evidence_window_ms safety_stale_ms clock_skew_ms permit_grace_n permit_recheck_ms
#              permit_rate_hz permit_deadline_ms motion_deadman_ms policy_file policy_file_sha256 skills_file_sha256 human_safety_enabled degraded
```

v2 is frozen, not retired: its assembler and key table stay (F8).

### `pail-config-seal:v2`

The seal of the deployment configuration. Assembled **by lines**, not by
`:`, with the key names and order frozen. The digest is the SHA-256 of the
canonical bytes; it is not a signing target but a value carried in the
journal and in transport.

<!-- pin: spec/vectors/canon/config_seal_v2.vec -->
```
# canon: "pail-config-seal:v2\n" 다음에 고정 순서 31줄의 `<key>=<escape(value)>\n`.
# 키 순서(동결): component robot_id profile use_sim_time ros_security_enable ros_security_strategy ros_security_keystore enclave_provisioned effective_enclave
#              token_provider_mode use_token_service grpc_built verifies_authorization token_service_addr keyring_mode control_transport control_trust_anchors
#              trusted_key_fingerprints evidence_conf_threshold_x1e6 evidence_window_ms safety_stale_ms clock_skew_ms permit_grace_n permit_recheck_ms
#              permit_rate_hz permit_deadline_ms motion_deadman_ms policy_file policy_file_sha256 human_safety_enabled degraded
```

**The five v2 keys were not appended at the end but inserted at their logical
positions.** List fields (`control_trust_anchors`,
`trusted_key_fingerprints`, `degraded`) are sorted, deduplicated, and joined
with `,`.

### `pail-config-seal:v1`

Old edition, 26 keys. Frozen, not retired; the parser is kept forever (§2.5).

<!-- pin: spec/vectors/canon/config_seal_v1.vec -->
```
# canon: "pail-config-seal:v1\n" 다음에 고정 순서 26줄의 `<key>=<escape(value)>\n`.
```

### `pail-burstchain:v1`

The hash-input prefix used to derive the chain correlation value of burst
packets. The same 16-byte slot carries both the token hash and the chain
hash, so **the two derivations must differ** for domain separation to hold.

<!-- pin: none -->

**There is no frozen vector.** Burst v2 was ruled unfrozen, so there is no
pinned vector at all, and therefore it is not carried in the conformance
claim of §1. The reason and resolution condition are in
[`vectors/canon/UNPINNED.tsv`](vectors/canon/UNPINNED.tsv).

### `pail-planhash:v1`

The hash-input prefix of the identity key used when judging the retry floor.

<!-- pin: none -->

**There is no frozen vector.** This value is neither signed nor circulated —
an internal value with no external observer of drift — so it is not part of
the interoperability profile. If it ever starts circulating, it becomes a
freeze target at that point.

---

### `pail-ctx:v1`

SHA-256 input domain for the original context payload bytes. Embedded requester claims do not replace transport identity.

The existing contract vector is pinned by its own `spec/vectors/contract/MANIFEST.sha256`; it is not an addition to the canon profile set.

<!-- pin: spec/vectors/contract/ledger_v2.vec -->
```
hash	CX2-02	pail-ctx:v1:	{"job":"j1"}	c5b0c87c78e38182140541a19b2ca309088c2c46cf536e5332625fe768648fb6
```

### `pail-constraints:v1`

SHA-256 input domain for the constraints payload bytes. The trailing colon belongs to the hash prefix.

The existing contract vector is pinned by its own `spec/vectors/contract/MANIFEST.sha256`; it is not an addition to the canon profile set.

<!-- pin: spec/vectors/contract/ledger_v2.vec -->
```
hash	CN2-02	pail-constraints:v1:	{"job":"j1"}	a8409ccc71d0cfcfc0d5c7ac7b6f49602f8f15d0c4f62f4687781a7e6be0fa92
```

### `pail-params:v1`

SHA-256 input domain for the original action-parameter bytes; this hash does not itself authorize an action.

The existing contract vector is pinned by its own `spec/vectors/contract/MANIFEST.sha256`; it is not an addition to the canon profile set.

<!-- pin: spec/vectors/contract/ledger_v2.vec -->
```
hash	PM2-02	pail-params:v1:	{"l":2}	e40c68aeb1df6deb1b5344e9762d3d62a31ed7b769a57d411aaedfbca7a2538c
```

## 5. How this document is maintained

| What | Check |
|---|---|
| Does every prefix in the shipped vectors have a section | `tools/spec_canon_check.py` `B1` |
| Do the sections contain no invented prefix | ibid. `B2` |
| Is every quote a byte substring of a frozen vector | ibid. `B3` |
| Is every pin target registered (frozen) in the manifest | ibid. `B4` |
| Is every `pin: none` backed by the unpinned registry | ibid. `B5` |
| Do the profile and set hash of §1 match the shipped manifest | `tools/spec_conformance_check.py` |

If the checker cannot establish its own premises (zero vectors, zero
sections, missing manifest), it dies with **rc=2**, not `FAIL 0`. A run that
read nothing and a run with no violations emit the same bytes.
