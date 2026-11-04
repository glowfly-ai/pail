# Survivability — delegated cases

## TC-SV-03 — forged burst injection rejected

Injecting a forged/unsigned UDP packet at the receiver has no timeline verb (the
DSL emits bursts only as a side effect of real gate decisions, never as a raw
attacker packet). The property — a non-issuer-signed or v1/unsigned (32B) packet
is classified `valid=False` and never surfaces as an event — is proven directly
at unit level in `tests/test_mocks.py::test_burst_listener_rejects_forged` and
`tests/test_verifiers.py::test_burst_forged_key_rejected`.

Every scenario `expect_burst: {signature: valid}` also transitively depends on
this: the receiver only reports events whose signature verified, so a forged
packet can never satisfy a burst expectation even if injected.
