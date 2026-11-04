#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# CA-07 (contract I-3) for the socket transport: a permitted line reaches the raw side byte for
# byte. Runs a second, non-enforcing adapter instance (NoGate, dev profile) in front of a
# recording tap and runs tools/bytes_tap.py (the byte-identity measurement).
# Non-enforcing on purpose: this case measures the relay, not the verdict (CA-01/05/06 do that).
set -u
BIN=${PAIL_DUCKD_BIN:-/t/debug/pail-duckd}
TAP=/tmp/ca07_tap.sock
PUB=/tmp/ca07_pub.sock
rm -f "$TAP" "$PUB"
PAIL_PROFILE=dev "$BIN" --gate none --public "$PUB" --raw "$TAP" >/tmp/ca07_adapter.log 2>&1 &
APID=$!
for i in $(seq 1 30); do [ -S "$PUB" ] && break; sleep 0.1; done
python3 "$(dirname "$0")/bytes_tap.py" "$TAP" "$PUB"
rc=$?
kill $APID 2>/dev/null
wait $APID 2>/dev/null
exit $rc
