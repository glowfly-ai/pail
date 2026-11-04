#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

set -euo pipefail

PERMIT_DEADLINE_MS="${PAIL_PERMIT_DEADLINE_MS:-100}"

set +u
source /opt/ros/humble/setup.bash
if [ -f /opt/pail_ws/install/local_setup.bash ]; then
  source /opt/pail_ws/install/local_setup.bash
elif [ -f /opt/pail_ws/install/setup.bash ]; then
  source /opt/pail_ws/install/setup.bash
fi
export AMENT_PREFIX_PATH="/opt/pail_ws/install:${AMENT_PREFIX_PATH:-}"
set -u

# BG (PAIL-BG-LLD-v1 §3): refuse to start with DDS protections off unless
# PAIL_PROFILE=dev says so explicitly.
# shellcheck source=/dev/null
. /usr/local/bin/_pail_preflight.sh
pail_preflight motion_bridge
# S19 : 개인키 모드. `pail_preflight` 옆이지 안이 아니다 —
# 그쪽은 dev 에서 배너로 내려가고 S15~S20 은 면제 대상이 아니다.
pail_preflight_key_modes

# SROS2 (M7, LLD-v2 §3): run inside the motion_bridge enclave when security is on.
ROS_ARGS=( --ros-args -p permit_deadline_ms:=${PERMIT_DEADLINE_MS} )

# C3-C3 : the silence watchdog must be measured under
# simulated time too. Unset means "do not pass the parameter", not "false".
if [ -n "${PAIL_USE_SIM_TIME:-}" ]; then
  ROS_ARGS+=( -p use_sim_time:=${PAIL_USE_SIM_TIME} )
fi
if [ "${ROS_SECURITY_ENABLE:-false}" = "true" ]; then
  ROS_ARGS+=( --enclave /motion_bridge )
  echo "[motion_bridge_entrypoint] SROS2 enabled: enclave=/motion_bridge strategy=${ROS_SECURITY_STRATEGY:-} keystore=${ROS_SECURITY_KEYSTORE:-}"
fi

exec ros2 run pail_motion_bridge motion_bridge_node "${ROS_ARGS[@]}"
