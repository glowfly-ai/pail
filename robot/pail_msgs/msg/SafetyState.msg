# OEM safety-layer state input (LLD-v2 4.1, M8)

builtin_interfaces/Time stamp
string level    # OK | WARN | UNSAFE (D §4.1, C-B7) — anything else parses
                # kUnknown at the gate: new permits blocked, E-STOP latch held.
                # ("SAFE" was the pre-C-B7 wording; the old gate released the
                # E-STOP on every non-UNSAFE string, so the comment and the
                # defect matched each other. Comments do not enter the ROS type
                # hash — this line is documentation, not a canon change.)
string source   # safety layer id (e.g. SAFETY_PLC, LIDAR_ZONE)
string detail
