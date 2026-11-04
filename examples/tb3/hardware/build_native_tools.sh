#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
# Build public-only console tools on the operator host. Go + dependencies required.
# Run from a writable Core working copy, never the verified delivery directory.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${1:?usage: build_native_tools.sh /absolute/output-directory}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
command -v go >/dev/null || { echo 'Go 1.27.2+ required on the operator host' >&2; exit 2; }
cd "$ROOT/cloud"
# A temporary package under this module may import its public internal libraries.
TMP=$(mktemp -d "$PWD/tb3-probe-build.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
cp "$ROOT/examples/tb3/probe.go" "$TMP/main.go"
go build -mod=readonly -tags pail_generated -o "$OUT/tb3-probe" "$TMP/main.go"
go build -mod=readonly -tags pail_generated -o "$OUT/blackbox_verify" ./cmd/blackbox_verify
echo "NATIVE_TOOLS_READY $OUT (host architecture; not an offline dependency kit)"
