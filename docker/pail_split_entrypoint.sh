#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

# D1 split (배치형상 §7.3): run cloud-services and robot-agent as separate
# processes inside the single-host compose profile, so PVS/demos keep their
# external interfaces (:50051 front door, UDP 46000 bursts) unchanged.
#
# This shell is PID 1 of the container: when it exits, the kernel SIGKILLs
# whatever is left. So it never exits before pail_cloud has finished its stop
# sequence (stop serving, close the journal under a signed checkpoint) — no
# `set -e`, every wait is handled explicitly (P021R-L1).
#   stop signal (TERM/INT): both children get TERM; exit with pail_cloud's code.
#   a child ends by itself: stop the other one, wait for it, exit non-zero
#   (fail-closed: one half of the pair ending is never a clean stop).

/usr/local/bin/pail_cloud &
CLOUD=$!
/usr/local/bin/pail_robot_agent &
AGENT=$!

STOPPING=0
on_stop() { STOPPING=1; kill -TERM "$CLOUD" "$AGENT" 2>/dev/null; }
trap on_stop TERM INT

# wait_for PID: wait until PID is gone; its exit code is left in WAITED. A wait
# cut by a signal returns 128+n, which is not the child's code: wait again.
# (Not run in $(...): a subshell cannot wait for this shell's children.)
wait_for() {
  while :; do
    wait "$1"; WAITED=$?
    kill -0 "$1" 2>/dev/null || break
  done
}

wait -n "$CLOUD" "$AGENT"
FIRST=$?
if [ "$STOPPING" = 1 ]; then
  wait_for "$CLOUD"; CODE=$WAITED
  wait_for "$AGENT"
  exit "$CODE"
fi
# A child ended by itself. Which one is gone decides who must still be stopped.
if kill -0 "$CLOUD" 2>/dev/null; then
  kill -TERM "$CLOUD" 2>/dev/null
  wait_for "$CLOUD"
else
  kill -TERM "$AGENT" 2>/dev/null
  wait_for "$AGENT"
fi
[ "$FIRST" = 0 ] && FIRST=1
exit "$FIRST"
