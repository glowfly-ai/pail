#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# CA-15 (SK-2, implementation contract, S33 on the socket transport): a skill table that names a skill
# the robot does not answer to is refused at start in production — never a table that could
# put a token envelope on a skill this robot cannot run. Runs a second enforcing adapter
# instance against the rig's fake robotd with the deployment table plus one ghost row, and
# reads its exit: 78 with an S33 banner is the PASS. An adapter that keeps running is the
# defect (FAIL); an adapter that dies for another reason is "could not probe" (exit 2) —
# not a PASS (H-B2).
set -u
BIN=${PAIL_DUCKD_BIN:-/t/debug/pail-duckd}
RAW=${PAIL_DUCK_RAW:-/run/duck/robotd.sock}
AGENT=${PAIL_DUCK_AGENT:-http://duck-seam:50052}
CONF=${PAIL_DUCK_CONF:-/work/config}
TABLE=/tmp/ca15_table.yaml
PUB=/tmp/ca15_pub.sock
EVID=/tmp/ca15_evidence.sock
LOG=/tmp/ca15_adapter.log
rm -f "$PUB" "$EVID" "$LOG"
if [ ! -S "$RAW" ]; then echo "CA-15: raw socket $RAW absent — could not probe"; exit 2; fi
{ cat "$CONF/duck_skills.yaml"; printf '  ghost_skill_nobody_has: MOVE\n'; } > "$TABLE"
PAIL_PROFILE=production PAIL_KEYRING_MODE=unsigned-dev "$BIN" \
  --public "$PUB" --raw "$RAW" --agent "$AGENT" --robot-id robot-1 \
  --policy "$CONF/policy.yaml" --keyring "$CONF/keys/keyring.json" --evidence "$EVID" \
  --skills "$TABLE" --gate-log /tmp/ca15_gate.ndjson --build-info "pail-build:v1:pep_gate:0.1.0-ca15:-:-:-" \
  >"$LOG" 2>&1 &
APID=$!
rc=""
for i in $(seq 1 100); do
  if ! kill -0 "$APID" 2>/dev/null; then wait "$APID"; rc=$?; break; fi
  sleep 0.1
done
if [ -z "$rc" ]; then
  echo "CA-15 FAIL: adapter still running 10 s after start with a table naming a skill the robot lacks"
  sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -E "skill|S33" | tail -5
  kill "$APID" 2>/dev/null; wait "$APID" 2>/dev/null
  exit 1
fi
if [ "$rc" -eq 78 ] && sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -q "S33"; then
  echo "CA-15 PASS: exit 78 with S33 banner"
  sed 's/\x1b\[[0-9;]*m//g' "$LOG" | grep "S33" | tail -1 | cut -c1-200
  exit 0
fi
echo "CA-15: adapter exited rc=$rc without an S33 banner — could not probe (another refusal came first?)"
sed 's/\x1b\[[0-9;]*m//g' "$LOG" | tail -6 | cut -c1-200
exit 2
