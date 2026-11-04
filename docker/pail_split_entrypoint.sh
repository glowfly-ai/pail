#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

# D1 split (배치형상 §7.3): run cloud-services and robot-agent as separate
# processes inside the single-host compose profile, so PVS/demos keep their
# external interfaces (:50051 front door, UDP 46000 bursts) unchanged.
set -e

/usr/local/bin/pail_cloud &
CLOUD=$!
/usr/local/bin/pail_robot_agent &
AGENT=$!

trap 'kill $CLOUD $AGENT 2>/dev/null' TERM INT

# If either half dies, bring the container down loudly (fail-closed).
wait -n $CLOUD $AGENT
EXIT=$?
kill $CLOUD $AGENT 2>/dev/null || true
wait 2>/dev/null || true
exit $EXIT
