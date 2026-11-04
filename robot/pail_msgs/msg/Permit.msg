# Permit heartbeat (M4, LLD-v2 §2.1).
# Published by pep_gate_node at PAIL_PERMIT_RATE_HZ while in PERMIT state.
# Absence of this message IS the stop signal (deadman) — there is no explicit
# "stop" message.
builtin_interfaces/Time stamp
string active_token_id
uint32 permit_seq        # monotonically increasing — replay detection aid
