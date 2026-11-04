#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
# Public Microduck-compatible adapter rig. Full evaluation bundle, not private build images.
set -eu
core=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
launcher="$core/../evaluation.py"
if [ ! -f "$launcher" ]; then
  echo 'EVALUATION_REQUIRED: obtain the matching evaluation bundle and load its images.' >&2
  exit 2
fi
# --adapter-binary is optional for the reference; required for testing your own replacement.
exec python3 "$launcher" test-conformance "$@"
