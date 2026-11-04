# Merkle conformance vectors

`spec/merkle-vectors/` freezes an exhaustive RFC 6962 known-answer set for
tree sizes 0 through 9: ten roots, forty-five inclusion proofs, thirty-six
consistency proofs. It exists so that an independent implementation can find
out whether its Merkle arithmetic is correct **before** it is pointed at a
live log.

> 한국어판: [`MERKLE_VECTORS.ko.md`](MERKLE_VECTORS.ko.md). The English
> document is canonical; if the two diverge, the English text governs.

## 1. Why an exhaustive set

`spec/proof-vectors/` (see [`VERIFICATION_INPUTS.md`](VERIFICATION_INPUTS.md))
freezes captured wire bytes: what a real anchor log actually answered. It
pins the *format*. It does not pin the *arithmetic*, and the reason is a
property of the sample rather than of the format — every proof in that capture
lives at tree size 1, 2 or 4. All powers of two.

That is not a small gap, and it was measured rather than guessed. On
2026-08-30, against the eighteen captured vectors:

- deleting the entire border-folding loop from an RFC 6962 inclusion verifier —
  the `while` that keeps halving while the index is even — left every check
  green;
- collapsing the consistency verifier's non-power-of-two seed selection, so
  that the seed is always taken to be the old root rather than the first proof
  hash, also left every check green.

Both branches are unreachable when the tree size is a power of two. A third
party could therefore ship a verifier that is wrong on **every** tree whose
size is not a power of two, run everything we publish, and see no failure. A
log that never crossed a non-power-of-two size would never expose it; a log
that did would be accepted or rejected on arithmetic that had never once run.

This set closes that. Size 9 is the last size on purpose: its split point
`k = 8` leaves a right subtree of a single leaf, the shape most often gotten
wrong. Section 8 states, and the checker re-measures, exactly how many of the
frozen cases reach each of the two branches above.

## 2. Hash primitives

Two domain-separation prefix bytes, and one special case.

<!-- vocab: hash -->

| name | prefix | pinned value |
| --- | --- | --- |
| `leaf_hash` | `0x00` | `40b7deebc2f81803101885048466500bf310719859ee5b241885940f08dad99d` |
| `node_hash` | `0x01` | `645388217c67cbb482cba29ef06a913f7ad69cb8a12320174137514bea0cffed` |
| `empty_root` | `none` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

- `leaf_hash(d) = SHA-256(0x00 ‖ d)`. The pinned value is `leaf_hash` of leaf 0
  of the corpus in §3.
- `node_hash(l, r) = SHA-256(0x01 ‖ l ‖ r)`. The pinned value is
  `node_hash(leaf_hash(leaf 0), leaf_hash(leaf 1))`, which is also the root at
  size 2.
- `empty_root = SHA-256("")`, the hash of the empty byte string, taken with no
  prefix at all. It is the root at size 0.

The prefixes are what make a leaf hash and an internal node hash live in
different spaces. An implementation that omits them produces a tree in which a
leaf can be presented as an interior node.

## 3. The leaf corpus

The leaves are generated from a printable rule so that a reader can rebuild
every input from this document alone, without trusting the bytes we shipped.

<!-- vocab: corpus -->

| name | value |
| --- | --- |
| `leaf_prefix` | `pail-merkle-vector:` |
| `max_size` | `9` |

Leaf `i`, for `0 <= i < max_size`, is the ASCII string `leaf_prefix` followed
by the decimal representation of `i` with no padding: leaf 0 is
`pail-merkle-vector:0`, leaf 8 is `pail-merkle-vector:8`. Leaf data is hashed
as-is, with no trailing newline.

`leaves.json` carries the same data verbatim alongside its hash, so a reader
who disagrees with our reading of this paragraph can see immediately which of
the two is wrong.

## 4. The tree

`MTH(D[n])`, the Merkle Tree Hash over the first `n` leaves, is RFC 6962 §2.1:

```
MTH({})     = empty_root
MTH({d0})   = leaf_hash(d0)
MTH(D[n])   = node_hash( MTH(D[0:k]), MTH(D[k:n]) )      for n > 1
```

where `k` is **the largest power of two strictly less than `n`**. For `n = 8`,
`k = 4`; for `n = 9`, `k = 8`. The common error is to use the largest power of
two less than *or equal to* `n`, which is a different tree for every power of
two and identical for every other size — so it passes a set that only contains
powers of two, and only that.

`roots.json` carries `MTH(D[n])` for every `n` from 0 to `max_size`
inclusive — no gaps, because a gap in a known-answer set is a size nobody
checked, which reads the same as a size that passed.

## 5. Inclusion proofs

`inclusion.json` carries one case for every `(size, index)` pair with
`1 <= size <= max_size` and `0 <= index < size`: forty-five cases in total.
Each case is the RFC 6962 `PATH(index, D[size])` audit path.

A verifier takes `leaf_hash`, `index`, `size` and `proof`, folds the proof
hashes in the RFC 6962 order, and obtains a 32-byte value. The case passes only
if that value equals the root **it computed itself** for that size — not the
`root` field. The `root` field is present so that a reader can see the expected
answer, not so that a verifier can compare against a number it was handed.
Deriving a root is not verifying a root.

<!-- sample: inclusion -->

```json
{
  "size": 3,
  "index": 2,
  "leaf_hash": "2a6a2cedd03e2d0037b2ab63727611cdbb58ab60aaee9685aa4b3de9179d75e3",
  "proof": [
    "645388217c67cbb482cba29ef06a913f7ad69cb8a12320174137514bea0cffed"
  ],
  "root": "6df12a6a277a1f96aa471f6568822d77ad0deec81f006f1da093c1399a038175"
}
```

This is the smallest case that reaches the border-folding branch of §1: the
last leaf of a three-leaf tree, whose sibling is a two-leaf subtree.

The case at `size = 1, index = 0` has an empty proof. It serializes as `[]`
and never as `null`: an implementation that cannot tell "no hashes are needed"
from "the field is absent" has to guess, and this is the one case where the
correct answer is the empty proof.

## 6. Consistency proofs

`consistency.json` carries one case for every `(size1, size2)` pair with
`1 <= size1 < size2 <= max_size`: thirty-six cases in total. Each is the
RFC 6962 `SUBPROOF(size1, D[size2], true)`.

A verifier takes `size1`, `size2`, `proof` and the old root, and derives two
values: the root at `size1` and the root at `size2`. **Both** must be checked.
Checking only the second accepts a proof that silently substitutes a different
history for the prefix; checking only the first accepts any future at all.

Neither `root1` nor `root2` in the frozen case is an authenticated input. In
production both arrive from signed checkpoints (`VERIFICATION_INPUTS.md` §2);
here they are the expected answers, and the checker compares against roots it
derived from the corpus.

<!-- sample: consistency -->

```json
{
  "size1": 3,
  "size2": 5,
  "proof": [
    "2a6a2cedd03e2d0037b2ab63727611cdbb58ab60aaee9685aa4b3de9179d75e3",
    "809821060e34c816d7488f0c00f80109b0b43bd26b6deeba0d9734bc43305ccc",
    "645388217c67cbb482cba29ef06a913f7ad69cb8a12320174137514bea0cffed",
    "9333a5dd822b95cc8507a7d095c21b5f2df595e11ca8bb5c8eecc13e34bf81fe"
  ],
  "root1": "6df12a6a277a1f96aa471f6568822d77ad0deec81f006f1da093c1399a038175",
  "root2": "9e060c6832f2babb22ea7ad34e718e9fa90b217861d709badd96f6c1c73315b2"
}
```

`size1 = 3` is not a power of two, so the seed of the fold is `proof[0]` and
the remaining hashes start at index 1. That is the second branch of §1.

## 7. Files and fields

<!-- vocab: file -->

| file | array key | rows |
| --- | --- | --- |
| `leaves.json` | `leaves` | `9` |
| `roots.json` | `roots` | `10` |
| `inclusion.json` | `cases` | `45` |
| `consistency.json` | `cases` | `36` |

All four are UTF-8 JSON, indented by two spaces, with a trailing newline. All
hashes are lowercase hex, 64 characters, unpadded. `leaves.json` additionally
carries the top-level string `leaf_prefix`.

<!-- vocab: leaf_field -->

| name | type |
| --- | --- |
| `index` | `int` |
| `data` | `string` |
| `leaf_hash` | `hex32` |

<!-- vocab: root_field -->

| name | type |
| --- | --- |
| `size` | `int` |
| `root` | `hex32` |

<!-- vocab: inclusion_field -->

| name | type |
| --- | --- |
| `size` | `int` |
| `index` | `int` |
| `leaf_hash` | `hex32` |
| `proof` | `hex32[]` |
| `root` | `hex32` |

<!-- vocab: consistency_field -->

| name | type |
| --- | --- |
| `size1` | `int` |
| `size2` | `int` |
| `proof` | `hex32[]` |
| `root1` | `hex32` |
| `root2` | `hex32` |

## 8. What this set actually reaches

A coverage claim that nobody measures decays into a coverage claim that is
false. Every number below is re-derived from the frozen bytes by the checker,
which instruments its own verifier to record which branches ran.

<!-- vocab: coverage -->

| name | count |
| --- | --- |
| `roots` | `10` |
| `inclusion_cases` | `45` |
| `consistency_cases` | `36` |
| `border_fold_cases` | `6` |
| `nonpow2_seed_cases` | `15` |
| `empty_proof_cases` | `1` |

- `border_fold_cases` — inclusion cases in which the border-folding loop of §1
  executes at least once. In `spec/proof-vectors/` this count is zero. Here it
  is six: sizes 3, 5, 6, 6, 7 and 9.
- `nonpow2_seed_cases` — consistency cases whose `size1` is not a power of two,
  so the seed is `proof[0]` rather than the old root. In `spec/proof-vectors/`
  this count is zero.
- `empty_proof_cases` — inclusion cases whose proof is the empty list.

## 9. Manifest and set hash

`spec/merkle-vectors/MANIFEST.sha256` lists the SHA-256 of each file and then a
`set_sha256` line covering the whole set. The set hash is computed over the
`"<hex>  <name>\n"` lines only, sorted by file name; comment lines and the
`set_sha256` line itself are not inputs.

<!-- vocab: claim -->

| name | value |
| --- | --- |
| `merkle_set_sha256` | `b67f0bee29e86466f37a7b98cd345071a6db4b40a01eae50c897fe08e477aeb6` |
| `canon_set_sha256` | `bbddff16fb5997faeff47bf6913e64d9675178d2ddffd5828aa898a235688701` |

These are two different sets with two different manifests, and the separation
is deliberate. `canon_set_sha256` covers `spec/vectors/canon/` — how bytes are
written down — and it is the set hash named by the conformance claim in
[`CONFORMANCE.md`](CONFORMANCE.md). `merkle_set_sha256` covers this set — the
log arithmetic computed over those bytes. They change for unrelated reasons.
Merging them into one manifest would mean that revising either one invalidates
every published conformance claim about the other.

The consequence is worth stating plainly rather than leaving for a reader to
discover: **the conformance claim in `CONFORMANCE.md` covers the serialization
plane only.** Passing this Merkle set is not part of that claim today.
An implementation may therefore be entitled to the compatibility statement
while getting §5 and §6 wrong. If that changes, it changes in `CONFORMANCE.md`
and in the checker that measures it, not in this paragraph.

## 10. Using the set

For an implementation under test:

1. Rebuild the corpus from §3. Compare each `leaf_hash` in `leaves.json`.
   A mismatch here means the prefix bytes of §2 are wrong and nothing further
   is meaningful.
2. Compute `MTH(D[n])` for every `n` in `roots.json`. A mismatch only at
   non-power-of-two sizes means the `k` rule of §4 is wrong.
3. For each case in `inclusion.json`, verify against the root **you** computed
   in step 2. A failure only on the six cases of §8 means the border-folding
   branch is wrong or absent.
4. For each case in `consistency.json`, derive both roots and check both
   against step 2. A failure only on the fifteen cases of §8 means the seed
   selection is wrong.

Failing at step 3 or 4 while passing `spec/proof-vectors/` is the expected
signature of the defect this set was built to expose.

## 11. What the shipped checker cannot see

`spec/tools/spec_merkle_vectors_check.py` runs against the frozen bytes and
this document. It re-derives all ninety-one answers with an implementation
written from the RFC 6962 definitions, independent of the one that produced
them. That is the load-bearing part, and it ships.

The program that generated the set is internal and does not ship. When the
checker runs inside this repository it also pins §3's `leaf_prefix` and
`max_size` to that program's source; in the public snapshot it prints that
check as skipped rather than passing it silently. A check that is quietly
absent is indistinguishable from a check that passed.

One further boundary, stated because it is easier to find here than to
rediscover: `spec/tools/spec_verification_inputs_check.py` carries its own
RFC 6962 implementation, and the vectors it is pointed at are the
power-of-two-only captures of §1. Its arithmetic is guarded by known-answer
values drawn from this set, not by those captures.
