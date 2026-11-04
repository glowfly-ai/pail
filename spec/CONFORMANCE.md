# PAIL conformance claims

> 한국어판: [`CONFORMANCE.ko.md`](CONFORMANCE.ko.md). The English document is
> canonical; if the two diverge, the English text governs.

This page defines what a statement such as "implements PAIL-CORE-2026.1" or
"PAIL-compatible" must name, what it covers, and what it does not. It is a
technical rule about the frozen formats in this directory; it grants no rights
and adds no conditions to [`LICENSE`](../LICENSE).

## 1. The unit of a claim: profile name plus set hash

A conformance claim names **both** values:

- the canonical profile: **`PAIL-CORE-2026.1`**
- the frozen vector set hash of
  [`spec/vectors/canon/MANIFEST.sha256`](vectors/canon/MANIFEST.sha256):
  `set_sha256 bbddff16fb5997faeff47bf6913e64d9675178d2ddffd5828aa898a235688701`

If one vector changes, the set hash changes, and a changed set hash is a
different target. A claim that states the profile name without the set hash
has no defined subject. `spec/tools/spec_conformance_check.py` rule A1 refuses a
document that writes the name without the hash.

## 2. What the claim covers

The claim covers the **serialization plane only**: an implementation produces
byte-identical output for the complete canon vector set. It does not cover the
Merkle set ([`MERKLE_VECTORS.md`](MERKLE_VECTORS.md) §5 and §6), the subgraph
set ([`SUBGRAPH_HASH.md`](SUBGRAPH_HASH.md)), or any runtime behavior. An
implementation may therefore satisfy the claim while getting the log arithmetic
wrong; if that scope ever changes, it changes here and in the checker that
measures it, not in the pages that describe those sets.

## 3. Behavioral statements are separate

Canonical byte agreement is not evidence that an implementation enforces
signature verification, issuer-first ordering, single use or fail-closed
behavior — the four claims in [`TRUST_BOUNDARY.md`](../TRUST_BOUNDARY.md) §2.
A statement about those properties is a separate statement that needs its own
evidence (the measured validation report of a release, or the implementer's own
tests), and it should carry the same boundary disclosures.

## 4. No certification exists

The project runs no certification, approval or badge procedure. Conformance is
a self-assessment against the public vectors with the public checker. Do not
describe an implementation as certified, approved or evaluated by the project.

## 5. Names

Apache-2.0 grants no trademark rights except as stated in its Section 6. State
facts: "implements PAIL-CORE-2026.1, set `bbddff16…`", "derived from PAIL",
"integrates the PAIL gate". Do not present a modified implementation as the
project's own release, and do not imply the project's sponsorship or approval.
