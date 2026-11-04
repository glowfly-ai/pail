# Audit — delegated cases

## TC-AU-03 — logrotate copytruncate regression

This case has two halves and neither fits the runtime timeline DSL cleanly:

1. **Static config assertion** — `deploy/docker-compose.yml` (and any systemd
   unit) must NOT configure `logrotate` with `copytruncate` on the blackbox
   segment files. copytruncate would zero-fill a segment mid-write and silently
   break the hash-chain. This is a file/config assertion, so it lives as a
   pytest unit check in `tests/test_audit_logrotate.py` (added in the pytest
   integration task), not a scenario.

2. **Chain-intact-across-rotation** — the segment writer's own rotation
   (segment roll on size/count) must keep the chain linked. That property is the
   subject of `au01_cross_segment_chain.yaml` and the cross-segment unit test in
   `tests/test_verifiers.py`.

Delegating the static half keeps scenarios purely about observable runtime
behavior and avoids a config-grep verb that would only ever be used once.
