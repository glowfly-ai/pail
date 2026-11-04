# PAIL gate state

builtin_interfaces/Time stamp
string state      # PERMIT|BLOCK|ESTOP
string reason     # use GateReason code string (phase 1)
string active_chain_id
string active_token_id

# SD4: sha256 hex of the canonical effective security configuration this gate
# is running under. Constant for the life of the process — a live reader can
# see WHICH configuration produced these decisions without waiting for an
# audit. Empty when the digest could not be computed (PAIL_ENABLE_GRPC=0).
string config_digest

# implementation contract (D-S5): the mode this decision was made under —
# "enforce" | "observe". Always stamped, never empty: a shadow PERMIT and an
# enforce PERMIT must not be the same bytes (H-B2). Defined per-decision so a
# future rule-level override (§5.7 reserved) never changes this message.
string effective_mode

# Human-readable diagnostic only; branch on reason, never this text.
string detail

# Advisory actual step budget, only present for an active elapsed-time grant.
# A planner must match the boot/time namespace; these fields grant no authority.
int64 step_deadline_elapsed_ms
string step_clock_id
# Local session consumption, NOT proof of Issuer acceptance or physical success.
string completed_token_id
