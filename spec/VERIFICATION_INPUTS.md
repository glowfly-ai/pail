# Verification inputs

This document freezes the three wire formats an independent verifier consumes
to check that a PAIL anchor log is append-only and that a given record is in it:
the signed checkpoint note, the inclusion-proof response, and the
consistency-proof response.

> 한국어판: [`VERIFICATION_INPUTS.ko.md`](VERIFICATION_INPUTS.ko.md). The English
> document is canonical; if the two diverge, the English text governs.

## 1. The one rule

**Deriving a root is not verifying a root.**

Every RFC 6962 proof algorithm in this document terminates by producing a
32-byte value. It produces one for a valid proof, and it produces one for a
proof that has been rewritten wholesale. The value is only evidence if it is
then compared against a root that a key you trust has vouched for.

This is not a hypothetical failure. It is the defect this project's own
transparency-log harness shipped with: it split the checkpoint on newlines and
took the size and the root on faith, so a log that published a structurally
perfect Merkle tree with a checkpoint nobody had signed passed every check. The
arithmetic was correct throughout. Arithmetic is the one thing an adversary has
no reason to get wrong.

Two consequences run through the rest of this document:

1. **Authenticate the checkpoint before reading any of its bytes** (§2).
2. **Neither proof response carries a trustworthy root** (§5). The inclusion
   response echoes one only when it can vouch for it, and the consistency
   response carries none at all. Both are inputs you must already hold.

## 2. The signed checkpoint note

The checkpoint is a signed note in the `golang.org/x/mod/sumdb/note` format,
served as `text/plain; charset=utf-8`.

### 2.1 Wire format

<!-- sample: spec/proof-vectors/checkpoint.note -->

```
glowfly-anchor-log\n      <- line 0: origin
4\n                       <- line 1: tree size, decimal
3qvyBdwNhKy/…SkxVU=\n     <- line 2: base64(root), standard alphabet, padded
\n                        <- blank line: end of body
— glowfly-anchor-log <base64>\n   <- one or more signature lines
```

The signature lines begin with **U+2014 EM DASH**, not a hyphen. An
implementation that splits on `"- "` will not find the signature and will
report the note as unsigned — which, if unsigned is treated as a soft failure,
is indistinguishable from a note it never checked.

The body returned by a successful `note.Open` is lines 0–2 with their trailing
newline. The signature block is not part of it.

<!-- vocab: checkpoint_line -->

| name | line |
| --- | --- |
| `origin` | 0 |
| `size` | 1 |
| `root_b64` | 2 |

### 2.2 Two gates, deliberately separate

Opening the note is two checks, and they answer different questions:

<!-- pin-internal: anchor-checkpoint-implementation -->
```go
	// ErrSignature is gate 1: nobody we trust wrote this.
	ErrSignature = errors.New("checkpoint: signature not from a trusted log key")
	// ErrOrigin is gate 2: a trusted key wrote it, about a different log.
	ErrOrigin = errors.New("checkpoint: note is for another log")
```

The signature says *someone we trust wrote this*. The origin says *and they
wrote it about this log*. With only the first, a sibling log run by the same
operator — whose checkpoint is perfectly valid — is accepted as yours.

Both the verifier key and the expected origin must reach the verifier **out of
band**. A verifier that reads the origin out of the note it is checking, or
that fetches the key from the log it is auditing, has asked the subject to
grade its own paper.

A third state matters as much as the two verdicts: *no trust anchor was
configured* must not reach the caller as *the signature checked out*. An empty
verifier list is a refusal, not a verifier that accepts everything.

### 2.3 Parsing, after authentication

Only the authenticated body is parsed. Two width rules apply:

<!-- pin-internal: anchor-checkpoint-implementation -->
```go
	if len(root) != sha256.Size {
		return 0, nil, fmt.Errorf("%w: root is %d bytes, want %d", ErrMalformed, len(root), sha256.Size)
	}
```

The root width is checked at parse time rather than at the call site for a
specific reason. A truncated note — `"origin\nsize\n"` — splits into three
fields whose last is empty, and base64 decodes the empty string without
complaint. Without the width check the caller receives a zero-length root and a
nil error, and *no root* travels onward as *a root*.

### 2.4 The signature, byte by byte

Everything above §2.3 describes the note's *shape*. Shape is not what gate 1
checks. An earlier edition of this document named `note.Open` and stopped there,
which left the one operation it calls most important — *is this signed by a key
we trust* — specified only by a Go library. A verifier written in any other
language could reproduce every rule in §2.1 and still have no way to check a
signature, and the fallback available to it is the exact defect §1 opens with:
read the size and the root out of the note and proceed.

The six facts below are what `note.Open` knows and this document did not say.

<!-- vocab: sig_element -->

| name | value |
| --- | --- |
| `key_encoding` | `name ‖ "+" ‖ hex(hint) ‖ "+" ‖ base64(algid ‖ pubkey)` |
| `key_algid` | `0x01` |
| `hint_input` | `name ‖ 0x0A ‖ algid ‖ pubkey` |
| `hint_width` | `4` |
| `blob_layout` | `hint ‖ signature` |
| `sig_message` | `body` |

`‖` is concatenation. `name`, `algid`, `pubkey`, `hint`, `signature` and `body`
are the values named in this section and §2.1; quoted runs and `0x` literals are
themselves.

`key_encoding` is a rule for *writing* the key file, and reading it back is not
the mirror image. The separator `+` belongs to base64's own alphabet, so the key
body carries it: of the 44 characters in a body, about three keys in four
contain at least one. A reader that splits on every `+` and demands three fields
therefore rejects most legitimate trust roots — and a verifier that refuses the
key it was given is not fail-closed, it is a wall. Cut twice, from the left, and
take the rest as the body.

`hint` is the first `hint_width` bytes of `SHA-256(hint_input)`, rendered
lowercase hex in the key file and carried raw in the signature blob. It selects
which key to try. It is **not** a check: two keys can collide on four bytes,
and an adversary who wants a collision may have one. Matching the hint narrows
the candidate set; only the ed25519 verification decides.

`sig_message` is the authenticated body of §2.1 — lines 0–2 including the
trailing newline, and nothing else. Not the whole file: the blank line and the
signature block are outside it. This is worth stating because both choices
produce a 32-byte-rooted note that parses, and only one of them verifies. A
verifier that signs-checks the wrong span rejects every honest note, which
under a soft-failure policy reads as *unsigned* — §2.1's failure mode reached
from the other side.

Concretely, against the frozen vector of §7:

```
key file : glowfly-anchor-log+7f93d626+AczZJ3Eob4eEopbRhtqoseh3r4Pc1cOdjAWw/Z6jF9X0
hint     : SHA-256("glowfly-anchor-log" || 0x0A || 0x01 || pubkey)[:4] = 7f93d626
blob     : 68 bytes = 4 (hint) + 64 (ed25519 signature)
message  : "glowfly-anchor-log\n4\n3qvyBdwNhKy/…SkxVU=\n"   (66 bytes, body only)
```

The shipped checker re-derives each row rather than matching the text: it
recomputes the hint from `hint_input` and compares it against the key file's
own hex, and it verifies the signature over `sig_message` **and** confirms it
fails over the whole file. A row that merely agreed with itself would say
nothing.

## 3. Inclusion-proof response

`GET /v1/proof/inclusion/{tenant}?leaf_index=L[&tree_size=T]` →
`application/json`. When `tree_size` is omitted the latest published checkpoint
size is used.

<!-- vocab: inclusion_field -->

| field | type |
| --- | --- |
| `status` | `string` |
| `tenant_id` | `string` |
| `leaf_index` | `uint64` |
| `tree_size` | `uint64` |
| `root_b64` | `string` |
| `leaf_b64` | `string` |
| `proof_b64` | `string[]` |

`leaf_b64` is the exact leaf byte string the log committed to. For proof
verification it is **opaque**: the RFC 6962 leaf hash is
`SHA-256(0x00 || leaf_bytes)` over those bytes as received, and nothing about
their internal structure enters the computation. Their structure is specified
separately under `pail-saas-anchor:v2` in [`CANON.md`](CANON.md), and is needed
only to interpret a proven leaf, never to prove it.

`proof_b64` is ordered leaf-to-root. An empty array is legitimate: a tree of
size 1 has no siblings.

<!-- sample: spec/proof-vectors/inclusion_size4_idx0.json -->
<!-- sample: spec/proof-vectors/inclusion_size4_idx3.json -->
<!-- sample: spec/proof-vectors/inclusion_size2_idx0.json -->

## 4. Consistency-proof response

`GET /v1/proof/consistency/{tenant}?from=T1&to=T2` → `application/json`.

<!-- vocab: consistency_field -->

| field | type |
| --- | --- |
| `status` | `string` |
| `tenant_id` | `string` |
| `from` | `uint64` |
| `to` | `uint64` |
| `proof_b64` | `string[]` |

<!-- sample: spec/proof-vectors/consistency_2_4.json -->
<!-- sample: spec/proof-vectors/consistency_1_4.json -->

## 5. What the responses do not carry

This is the section most likely to be skipped and most likely to cause a silent
false green.

### 5.1 `root_b64` is empty at a historical tree size

The server echoes a root only when it can vouch for it — that is, only when the
requested `tree_size` is the latest published checkpoint size:

<!-- pin-internal: services/anchor_saas/internal/proofapi/proofapi.go -->
```go
	// Only echo a root the server can vouch for (latest checkpoint).
	echoRoot := ""
	if size == latest {
		echoRoot = b64(root)
	}
```

At any earlier size the field is the empty string. `spec/proof-vectors/inclusion_size2_idx0.json`
is such a response, frozen so the case cannot be dismissed as theoretical.

An empty `root_b64` is not an error and is not a degraded response. It is the
server correctly declining to assert something it has not signed. The verifier
must supply the root from a checkpoint it authenticated at that size.

### 5.2 The consistency response carries no root at all

Not an empty one — none. Verifying consistency requires two roots, and both
come from checkpoints the verifier authenticated separately.

There is a sharper trap inside this one. For a `from` size that is an exact
power of two, `root@from` is not merely the value you compare against at the
end: **it is an input to the algorithm**, because the left tree's root is not
carried in the proof. Supply the wrong one and the derivation still completes
and still yields a 32-byte value.

`spec/proof-vectors/consistency_2_4.json` (`from=2`) and
`consistency_1_4.json` (`from=1`) are both power-of-two cases, frozen precisely
because an implementation that treats the proof as self-contained passes its own
tests and fails here.

### 5.3 Two spellings for the same concept

The proof-hash array is spelled differently on two surfaces of this system.
Neither is wrong; an implementer moving between them needs to know both.

<!-- vocab: proof_key -->

| key | surface |
| --- | --- |
| `proof_b64` | `proof_plane` |
| `proof_base64` | `verdict_bundle` |

## 6. Status codes and reasons

Errors are `application/json` with exactly two fields, `status` (always
`"error"`) and `reason`.

The `reason` set below is derived from the emitter and from the middleware in
front of it. The `disposition` column is a four-value answer to "can a third
party actually see this?", and it exists because the honest answer is not
binary:

- `observed` — present in the frozen vectors under `spec/proof-vectors/`.
- `shadowed` — the handler emits it, but the deployed wiring intercepts the
  same condition earlier and answers differently. A third party never sees it.
- `auth_only` — reachable only where credential enforcement is on. The frozen
  vectors were captured from a deployment with it off.
- `state_only` — reachable only in a log or tenant state the frozen vectors do
  not contain.

<!-- vocab: reason -->

| reason | http | disposition |
| --- | --- | --- |
| `bad_leaf_index` | 400 | `observed` |
| `bad_range` | 400 | `observed` |
| `bad_tree_size` | 400 | `observed` |
| `method_not_allowed` | 405 | `observed` |
| `not_found` | 404 | `observed` |
| `proof_error` | 422 | `observed` |
| `bad_path` | 404 | `shadowed` |
| `auth_fail` | 401 | `auth_only` |
| `no_credential` | 401 | `auth_only` |
| `revoked` | 403 | `auth_only` |
| `scope_mismatch` | 403 | `auth_only` |
| `tenant_mismatch` | 403 | `auth_only` |
| `tenant_suspended` | 403 | `state_only` |
| `checkpoint_unavailable` | 503 | `state_only` |

Three notes a client implementer needs:

**`bad_path` is shadowed.** The handler answers `404 bad_path` when the path
does not resolve to exactly one tenant segment, but the middleware in front of
every proof route applies an identical predicate first and answers
`404 not_found`. Do not branch on `bad_path`; you will never receive it. It is
documented here rather than deleted because it is still emitted in source, and
a reason that exists in code but not in the specification is how the next
divergence starts.

**`tenant_mismatch` has two causes.** The middleware emits it when the
credential's tenant differs from the path's tenant; the handler emits it when
the requested leaf belongs to a different tenant than the caller. The response
is byte-identical. A client cannot distinguish "wrong token" from "not your
leaf", and must not retry as though it could.

**`proof_error` is deliberately coarse.** A leaf index past the end of the
tree, a `tree_size` beyond the latest checkpoint, and a backwards or zero
consistency range all produce it. It means "the log will not build this proof",
never "the log is inconsistent". A verifier that treats `422` as evidence of
tampering will report an incident every time it asks a badly-formed question.

The proof plane carries no rate-limit reason: the limiter guards the ingest and
verify front doors, not these read-only routes.

## 7. The frozen vectors

`spec/proof-vectors/` holds a captured snapshot of one real run, with
`RESPONSES.tsv` recording each response's HTTP status and content type. They
are captured bytes, not hand-written examples — a hand-written example proves
only that its author believed the format.

The shipped checker re-derives every proof in them with its own RFC 6962
implementation, written independently of the Go library that produced them. If
it had reused that library the agreement would have been an identity rather
than evidence.

> **`checkpoint.vkey` is not a trust anchor.** It is the public half of a
> throwaway keypair minted for one test run and discarded; the private half was
> never written to disk. It is here so the frozen note can be opened. Pinning it
> as a trust root for any real log would be pinning a key nobody holds and
> nobody rotates. It is registered as `not-anchor` in `spec/trust-roots.tsv`,
> and [`spec/TRUST_ROOT.md`](TRUST_ROOT.md) is where trust roots for real logs
> are defined, obtained and rotated. That document also records the present
> anchor count, which is zero.

These vectors are deliberately **not** under `spec/vectors/`. That directory is
governed by the canon freeze window, which protects the signature and hash
*inputs* whose modification is a versioning event. These files are captured
outputs. Filing them there to borrow the freeze machinery would be evading a
rule rather than complying with one, and would make a routine re-capture look
like a canon change.

## 8. Out of scope: the verdict bundle

`POST /v1/verify/{tenant}/{robot}` returns a bundle containing `verdict`,
`log_consistency`, `log_root_hex`, `log_size`, and `inclusion_proofs[]`. It is
not a verification input; it is the server's **claim**, and an independent
verifier that reads `verdict` or `log_consistency` out of it has reproduced §1's
defect one layer up — trusting the audited party's summary of its own audit.

If a verifier uses the bundle at all, it may use it only as a transport for
proof material: `inclusion_proofs[].proof_base64` and `sth_tree_size`, each
re-verified against a checkpoint authenticated per §2. Note the second spelling
from §5.3 applies here.

## 9. What is measured, and what the shipped checker cannot see

`spec/tools/spec_verification_inputs_check.py` measures this document rather
than asserting it. Every check prints its own line, including the ones it
skips: a check that is silently absent is indistinguishable from a check that
passed.

Publicly, it measures **document against frozen vectors**: the field tables
against the vector bodies, the reason table against `RESPONSES.tsv` and the
frozen error bodies, the note parse rules against `checkpoint.note`, and every
frozen proof re-derived from the frozen root.

It cannot measure **document against emitter source**, because the anchor
service is not part of the public snapshot. That comparison — the response
structs, the full reason set, and the `disposition` column — runs in the
internal tree only, and its results reach you as this document's contents
rather than as something you can re-run. Where you can check us, check us; the
sections above are arranged so that the parts you cannot check are the parts
that describe our wiring, and the parts that describe *your* verifier's
obligations are all backed by vectors you hold.
