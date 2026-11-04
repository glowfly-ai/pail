# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

"""Timeline scheduler .

Executes sorted `t`(sec) steps on a monotonic clock and dispatches each verb.
Injectable `clock`/`sleep` keep it deterministic under unit test (no wall-clock
flake). Observation verbs (`expect_*`) are handled inside the dispatch callable,
which is expected to poll until its own deadline.
"""

from __future__ import annotations

import time
from typing import Callable, List, Optional

from .model import Step


class Timeline:
    def __init__(self, steps: List[Step], clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep,
                 skip_nightly: bool = True):
        self.steps = sorted(steps, key=lambda s: (s.t, s.index))
        self.clock = clock
        self.sleep = sleep
        self.skip_nightly = skip_nightly

    def play(self, dispatch: Callable[[Step], None]) -> List[Step]:
        """Run the timeline. Returns the steps that were actually dispatched."""
        t0 = self.clock()
        dispatched: List[Step] = []
        for st in self.steps:
            if self.skip_nightly and st.only == "nightly":
                continue
            target = t0 + st.t
            while True:
                now = self.clock()
                if now >= target:
                    break
                self.sleep(min(0.02, target - now))
            dispatch(st)
            dispatched.append(st)
        return dispatched
