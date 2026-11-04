# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
"""Example of a custom conformance backend, selected as ``--backend example_backend:ExampleBackend``.

This file exists to show, and to let the maintainers measure end to end, the plumbing a robot
that is not a Microduck uses to get CA-01..CA-15 run against its own adapter:

1. put a module under ``pvs-public/runner/adapters/`` with a class implementing
   ``runner.core.backend.Backend`` (``setup``/``teardown``/``reset_state``, the step methods
   ``north_cmd``, ``inject_evidence``, ``inject_cmd_vel``, ``inject_skill``, ``inject_safety``,
   ``fault``, and the far-side observations ``gate``, ``bridge``, ``drive``, ``permits``,
   ``stop_request_asserted``; ``enforcement_supported()`` is False unless overridden, and then the
   Enforcement axis is reported SKIP, never PASS);
2. build the Core image from that working copy (``examples/microduck/run.py conformance --build``),
   because the harness runs the backends baked into the image it was built from;
3. run with ``--backend MODULE:CLASS`` and ``--rows-of microduck_uds`` to use the Microduck column of
   ``CA_MAP.yaml`` until the map has a column of its own.

This example deliberately re-uses the Microduck transport by subclassing the reference backend,
so it can be executed on the software rig with no second robot. It is therefore NOT a second
transport and proves nothing about your robot: a real port replaces every transport method with
its own ingress and its own far-side observation, and reports unsupported axes as "unsupported"
rather than faking them.
"""
from .microduck_backend import MicroduckBackend, Unsupported


class ExampleBackend(MicroduckBackend):
    """Same wire as the reference backend; only the name differs. Replace the methods, keep the shape."""

    def __init__(self):
        super().__init__()
        self.name = "example_backend:ExampleBackend"


class ExampleBackendWithoutSafetyFeed(MicroduckBackend):
    """The honest shape of a robot that lacks one seam: ``inject_safety`` (CA-10) raises ``Unsupported`` and says why.

    The runner reports that row as SKIP, never PASS. On its own such a SKIP makes the run ``BLOCKED``
    (``Unreviewed skip: CA-10``) — the rig does not decide for you that the gap is acceptable. The backend's
    maintainer accepts it with a written reason, ``--reviewed-skip "CA-10:<why>"``, and the run becomes
    ``PASS_WITH_LIMITATIONS`` with that reason in the result's ``limitations``. A FAIL and a map-declared skip
    cannot be reviewed away; only a SKIP the backend raised itself can.

    Subclasses the reference backend directly (not ``ExampleBackend``), so the guide's one-line rename of this
    file (``sed 's/class ExampleBackend/class MyBackend/…'``) still leaves an importable module."""

    def __init__(self):
        super().__init__()
        self.name = "example_backend:ExampleBackendWithoutSafetyFeed"

    def inject_safety(self, args):
        raise Unsupported("this robot exposes no safety-feed seam: the stale-feed case cannot be driven from the harness")
