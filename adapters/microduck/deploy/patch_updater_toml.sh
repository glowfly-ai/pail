#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# Point the upstream updater at robotd's RAW socket (LLD §9, D11).
#
#   patch_updater_toml.sh [/etc/robot/updater.toml]
#
# updaterd asks robotd for health and `safeToRestart` over `robot_socket` and restarts
# robotd on apply (updater/src/config.rs `robot_socket`). It runs as root and sends no
# intents, so it keeps talking to robotd directly — but robotd now listens on
# /run/robotd/raw.sock, and an updater left on /run/robotd.sock would be asking the
# ADAPTER for robotd's health: a wrong answer about the wrong process, and an update
# health gate that judges the interposer instead of the daemon.
#
# Idempotent: a file already pointing at the raw socket is left untouched (rc 0). A file
# with no `robot_socket` line is refused (rc 2) — this script edits a value, it does not
# invent the key; the upstream file (deploy/updater.toml in the microduck repo) carries it.
# Nothing else in the file is touched: updates never rewrite /etc, and neither do we.
set -eu
FILE="${1:-/etc/robot/updater.toml}"
RAW='/run/robotd/raw.sock'

if [ ! -f "$FILE" ]; then
    echo "patch_updater_toml: $FILE does not exist — install the upstream daemon first (scripts/install.sh)" >&2
    exit 2
fi
if ! grep -Eq '^[[:space:]]*robot_socket[[:space:]]*=' "$FILE"; then
    echo "patch_updater_toml: $FILE has no robot_socket line — refusing to invent one" >&2
    exit 2
fi
if grep -Eq "^[[:space:]]*robot_socket[[:space:]]*=[[:space:]]*\"$RAW\"" "$FILE"; then
    echo "patch_updater_toml: $FILE already points at $RAW"
    exit 0
fi
tmp="$FILE.pail.$$"
sed -E "s|^([[:space:]]*robot_socket[[:space:]]*=[[:space:]]*)\"[^\"]*\"|\1\"$RAW\"|" "$FILE" > "$tmp"
if ! grep -Eq "^[[:space:]]*robot_socket[[:space:]]*=[[:space:]]*\"$RAW\"" "$tmp"; then
    rm -f "$tmp"
    echo "patch_updater_toml: rewrite did not take — $FILE left untouched" >&2
    exit 1
fi
# Keep the original mode; replace atomically.
chmod --reference="$FILE" "$tmp" 2>/dev/null || chmod 644 "$tmp"
mv "$tmp" "$FILE"
echo "patch_updater_toml: $FILE robot_socket -> $RAW"
