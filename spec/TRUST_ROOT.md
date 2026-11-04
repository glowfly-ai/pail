# Trust roots for PAIL anchor logs (`trust-roots.tsv`)

`spec/VERIFICATION_INPUTS.md` §2.2 requires that the verifier key and the
expected origin reach a verifier **out of band**, and `cmd/pail-verify` gives
them no default for that reason. This document is where that requirement ends:
it defines what a trust root is, how you obtain one, how rotation is recorded,
and what the present state actually is.

> 한국어판: [`TRUST_ROOT.ko.md`](TRUST_ROOT.ko.md). The English document is
> canonical; if the two diverge, the English text governs.

## 1. An origin is not an identity

A checkpoint note is signed under a key whose public half is published as one
line:

```
<origin>+<key hash>+<base64 of the algorithm byte and the 32-byte public key>
```

All three parts are the identity. The origin alone is not, and the mistake is
not hypothetical: the throwaway key that opens the frozen vectors in
`spec/proof-vectors/` carries the origin `glowfly-anchor-log`, which is the
same name a production log would use. Two different keys can claim the same
origin, and each will produce notes that parse perfectly.

This is why `-origin` and `-vkey` are separate flags rather than one. The
origin check answers *did they write it about this log*; it cannot answer *who
are they*. Pinning an origin and accepting whichever key presents itself is not
a weaker version of pinning a trust root — it is not pinning one at all.

Reading a vkey line, splitting it, and re-deriving its key hash tells you the
line is well-formed. It tells you nothing about whether the key behind it is
one you should trust. **Parsing a trust root is not obtaining one.**

## 2. The registry

<!-- registry: spec/trust-roots.tsv -->
```
# 칸: kind	vkey	key_sha256	listed	retired	label
```

- TAB-separated, six columns. Lines beginning with `#` and blank lines are not
  entries.
- `vkey` is the whole line from §1, verbatim. It is the entry's identity.
- `key_sha256` is the SHA-256 of the **32-byte public key alone** — the base64
  decoded to 33 bytes with the leading algorithm byte removed. This is the same
  fingerprint namespace `spec/KNOWN_DEV_KEYS.md` uses, so a key that appears in
  both lists is recognisably the same key.
- `listed` is the date the row entered this file. It is not the date the key was
  created, and the file does not claim to know that.
- `retired` is `-` or a date (§5).

Neither `key_sha256` nor the key hash inside `vkey` is trusted as written. The
checker re-derives both from the `vkey` column and compares. A registry that
merely restates its own columns would agree with itself no matter what it said.

## 3. Two kinds of row

<!-- vocab: kind -->

| `kind` | meaning |
| --- | --- |
| `anchor` | The trust root of a real log. This is a value an auditor pins. |
| `not-anchor` | A vkey that ships in this tree and is **not** a trust root. |

The second kind exists because of a failure mode we measured rather than
imagined. `spec/proof-vectors/checkpoint.vkey` is a well-formed trust root line
in a file of its own. Run the shipped verifier against the shipped note with it
and you get:

```
trust root : glowfly-anchor-log origin=glowfly-anchor-log hint=7f93d626
checkpoint  OK   gate1=signature gate2=origin size=4 root=3qvyBdwNhKy/wBLdfv5yyKxlbi2Kzlr0nLzyuSSkxVU=
```

Verified — against a key whose private half was never written to disk, which
nobody holds and nobody will ever rotate. The warning that says so lived in one
section of one other document, and **files do not travel with the documents
that describe them.** So the registry is a *total* inventory instead: every
vkey-shaped byte string in the public tree appears here classified, and the
checker fails on any that does not. A future file that ships a key without a
row cannot ship quietly.

## 4. The present state: zero anchors

There are **no `anchor` rows today.** No PAIL anchor log is operating, so there
is no trust root to publish.

<!-- anchors: 0 -->

That marker is this document's own claim about the count, and the checker fails
if it disagrees with the rows. A sentence saying "zero anchors" outlives the
zero: the first real anchor lands in the registry, and the prose keeps teaching
a reader that none exists. Printing the count was not enough, because a number
printed beside a paragraph that contradicts it is read as agreement.

Zero is a measurement, not an omission, and the checker prints the anchor count
on every run so it stays a number somebody reads. The alternative — writing a
plausible placeholder row so the file looks complete — would be worse than an
empty file. A placeholder is a key nobody holds, and pinning it produces a
verifier that can never say `verified` about anything. That verifier is not
fail-closed; it is a wall, and a wall teaches its operator to stop looking.

The practical consequence for a reader today: everything in `spec/` can be
verified end to end, and none of it says anything about a production log,
because there is not one. The vectors demonstrate that our published format and
arithmetic are checkable. They are not evidence about any operating service.

## 5. Rotation

Rotation is **adding a row and writing a date in `retired` on the old one.** A
row never leaves this file.

Deletion is the tempting shortcut and it destroys the only thing the list is
for. Checkpoints signed under a retired key were signed; auditors hold them;
they must remain verifiable. If the row is gone, an auditor holding such a note
cannot distinguish *this key was ours and has since been rotated* from *this key
was never ours* — and those two need opposite responses.

Two things rotation does **not** do, and no wording here should let them be
assumed:

- **It does not re-sign history.** A checkpoint signed under the old key stays
  signed under the old key. An auditor spanning a rotation boundary keeps both
  trust roots and checks each note against the one that signed it.
- **It is not revocation.** A note carries an origin, a size, and a root — and
  no timestamp. So no verifier can tell whether a note signed by a retired key
  was produced before or after the retirement date. A `retired` date is an
  operational record for humans, not a check a verifier can apply.

That limitation is load-bearing, so the honest procedure for a **compromised**
key is different from rotation and is stated here rather than left to be
inferred: a compromised log key cannot be un-trusted by editing this file.
What contains the damage is the log's own arithmetic — a consistency proof from
a checkpoint you held *before* the compromise to any checkpoint offered
afterwards. If that proof does not verify, the log forked, and it forked
regardless of which key signed which side. An auditor who kept no earlier
checkpoint has nothing to appeal to, which is the argument for keeping them.

## 6. Obtaining a trust root

When an `anchor` row exists, this file is **one** channel, not the channel. A
trust root obtained solely from the tree published by the party operating the
log has the defect §1 of `VERIFICATION_INPUTS.md` describes one layer up: the
audited party supplied the standard it is audited against.

What an auditor should do with a candidate trust root, in order:

1. Obtain the `key_sha256` from at least one channel not controlled by the log
   operator, and compare. Comparing the whole `vkey` line is better; comparing
   the origin is not a comparison.
2. Re-derive the key hash from the key material rather than reading the eight
   characters in the middle of the line. `cmd/pail-verify` prints what it
   derived, so a mismatch shows up as a refusal rather than as agreement.
3. Record the checkpoint you first pinned. §5 is why: the earliest checkpoint
   you hold is what a later fork is measured against, and it cannot be obtained
   retroactively.

We commit to publishing any future `anchor` row here **and** through a channel
we do not control, and to writing the second channel into this section when it
exists. Naming a channel we have not yet established would be the same defect as
a placeholder key.

## 7. What the checker measures

`spec/tools/spec_trust_root_check.py` runs on every CI build.

<!-- vocab: observation -->

| id | observation |
| --- | --- |
| `T1` | The registry parses: six columns, known `kind`, dates well-formed. |
| `T2` | Every `vkey` re-derives its own key hash and its own `key_sha256`. |
| `T3` | Every vkey-shaped byte string in the public tree has a row. |
| `T4` | No `key_sha256` is registered as both `anchor` and `not-anchor`. |
| `T5` | Rows are monotone: no row that was listed has since disappeared. |
| `T5r` | Whether `T5` could be measured at all, reported as its own value. |
| `T6` | Quotes in this document are byte substrings of the registry. |
| `T7` | The forward reference in `VERIFICATION_INPUTS.md` names this document. |
| `T8` | The `anchor` count is printed, and both editions declare the same count. |
| `T9` | The ids in this table are exactly the ids the checker implements. |
| `T10` | The Korean edition teaches the same two tables. |

`T3` is the one that closes §3, and it is derived rather than listed: the scan
walks the shipped file list and finds vkey shapes, so a file added tomorrow is
covered by a rule written today. The checker prints the number of files it read,
because a scan that silently matched nothing produces the same green as a tree
with nothing to find.

`T5` needs the file's own past, which is history the checker cannot read from a
snapshot — an exported copy of this tree has no revision data in it. So `T5`
reports three values rather than two, and `T5r` says which: measured against
history, or not measurable here. A monotonicity check that quietly passes
wherever it cannot look is worse than none, because the place it cannot look is
exactly the copy somebody else received.

`T9` is why this table is a table and not prose. A checker may grow an
observation the document never mentions, or lose one the document still
advertises, and both drifts read as green everywhere else. So the ids are
compared in both directions and the count is printed.

A `not-anchor` row asserts that the key **ships here**, so `T3` is checked both
ways: a vkey in the tree with no row fails, and a `not-anchor` row whose vkey
appears nowhere outside the registry and these two documents fails as well. The
second direction is what keeps the list from outliving the files it classifies.
