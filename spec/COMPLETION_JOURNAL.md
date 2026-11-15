# Completion journal contract — semantic version 10

한국어: [COMPLETION_JOURNAL.ko.md](COMPLETION_JOURNAL.ko.md).
This changes completion interpretation; an older reader ignoring new JSON fields
is **not** operationally compatible. Segment framing and signed token bytes are
unchanged. Use [COMPATIBILITY.md](COMPATIBILITY.md) for deployment boundaries.

## Report, acceptance and consumption

`decision`, `step_complete`, `detail` are the gate's original report.
They are not rewritten to conceal a rejected completion.
For `GATE_DECISION` journal v10 the issuer additionally records:

| Field | Meaning |
|---|---|
| `completion_result` | `not_requested`, `rejected`, `accepted` |
| `completion_reason` | Stable issuer result reason, distinct from the gate's `reason_code` |
| `consumed_sequence_index` | Required only for accepted completion; actual consumed token index |
| `next_expected_index` | Required only for accepted completion; consumed index + 1 |
| `lease_reported_at_after` | Required only for accepted completion; 0 for no lease, otherwise the consumed index |

A valid accepted record must be an attributed, nonfatal `PERMIT` completion.
Absent or inconsistent required fields and future semantic versions are refused.
A legacy record without acceptance information is **unknown**, not accepted.

The issuer checks token/chain/lease bounds and the skill completion rule BEFORE
writing an accepted consumption record. Rejected signal reports remain in the
journal with `completion_result: rejected` and no consumption indices.

## One authoritative state effect

The accepted `GATE_DECISION` carries the entire completion effect, including the
lease consumption position. A second `LEASE_RECONCILED OK` is not required or
emitted for that v10 completion. Historical lease records and `OVER_LEASE`
revocations retain their read semantics.

The accepted completion uses an explicit local fsync boundary before success.
Other report writes retain their existing batching/flush policy; do not read this
as changing the durability guarantee of every PAIL record.

An append can fail AFTER bytes have been written. The issuer then
returns an unavailable/indeterminate RPC error and enters its existing journal
failure guard; it does not claim that consumption definitely did not happen.
Reconcile before assuming whether to retry. A crash after a valid completion
record but before the response can legitimately replay ahead of old memory.
A definitive rejection for an invalid completion signal never consumes a step.

`TOKEN_ISSUED` v10 also stores `completion_signal`: the issuance-time skill rule.
An empty string is permitted only for the explicit legacy/no-skill path. The
restorer uses the recorded rule rather than silently reinterpreting the old
plan using today's edited skill registry.

## Reading and display

Operational replay checks token/index binding, authorized range and exact
resulting position. Replaying the same committed effect does not increment
again. Read-side plan completion uses issuer acceptance, not the gate's boolean.
Decision history distinguishes accepted/rejected/unknown completion.
An accepted completion is a supported protocol result, not proof of physical
success, braking performance or the truth of an external sensor.

The UIR report counts issuer-confirmed completion only. Old reported completions
without that result are not silently included in a confirmed denominator.
