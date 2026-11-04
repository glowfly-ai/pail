#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

set -euo pipefail

cd "$(dirname "$0")/.."

echo "[1/4] Running proto codegen..."
make proto

echo "[2/4] Checking generated directories..."
ls -d proto/pailv1 >/dev/null
ls -d proto/tokenv1 >/dev/null

echo "[3/4] Grep for generated files..."
ls proto/pailv1/*.go | head -n 5
ls proto/tokenv1/*.go | head -n 5

echo "[4/4] Building (no tags)..."
go build ./issuer/cmd/pail_services || true

echo "[4b] Building (with pail_generated tag)..."
go build -tags pail_generated ./issuer/cmd/pail_services || true

echo "OK (some builds may fail until you adjust import paths in wire_generated.go)"
