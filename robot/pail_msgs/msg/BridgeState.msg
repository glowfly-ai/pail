# Motion bridge state (M4, LLD-v2 §2.3).
builtin_interfaces/Time stamp
string state  # FORWARDING|HOLD
# D §7.6 (F-CPP-7, U-D1): the silence window this bridge actually holds motion
# to, in ms — 2 x its own permit_deadline_ms, the same expression the watchdog
# enforces. The gate seals this reported value (canon v2 key 27); its own
# permit_deadline_ms is a different number with the same name (key 26) and must
# not stand in for it. 0 = not reported (pre-field publisher): consumers read 0
# as "unobserved", never as a window.
int32 deadman_window_ms
