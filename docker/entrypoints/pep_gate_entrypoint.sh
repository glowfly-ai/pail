#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

set -euo pipefail

# Map env vars -> ROS2 params for pep_gate_node.
# Defaults are aligned with compose env.

TOKEN_MODE="${PAIL_TOKEN_PROVIDER_MODE:-notoken}"
STATIC_TARGET="${PAIL_STATIC_TARGET_OBJECT_ID:-}"
ROBOT_ID="${PAIL_ROBOT_ID:-robot-1}"
EVID_CONF="${PAIL_EVIDENCE_CONF_THRESHOLD:-0.90}"
# 노드의 `policy_file` 기본값과 같아야 한다. 여기서 넘겨 주므로 실제로는 이쪽이
# 정본이고 노드의 리터럴은 이 스크립트를 지나지 않는 경로용 대비값이다.
POLICY_FILE="${PAIL_POLICY_FILE:-/etc/pail/policy.yaml}"
TOKEN_SERVICE_ADDR="${PAIL_TOKEN_SERVICE_ADDR:-127.0.0.1:50051}"
PERMIT_RATE_HZ="${PAIL_PERMIT_RATE_HZ:-20}"
PERMIT_RECHECK_MS="${PAIL_PERMIT_RECHECK_MS:-100}"
PERMIT_DEADLINE_MS="${PAIL_PERMIT_DEADLINE_MS:-100}"
CLOCK_SKEW_MS="${PAIL_CLOCK_SKEW_MS:-500}"
# AV1 (AV LLD §1.2): consecutive unanswered rechecks tolerated before the
# permit heartbeat stops. 0 = pre-AV1 behaviour (stop on the first failure).
PERMIT_GRACE_N="${PAIL_PERMIT_GRACE_N:-3}"

# D4 skew seam hygiene: compose always defines the seam vars, but libfaketime
# treats an *empty* FAKETIME as "set" and then ignores FAKETIME_TIMESTAMP_FILE
# (measured, 0.9.12) — file-controlled rewinds silently never fire. An inert
# seam must be absent, not empty.
for _v in LD_PRELOAD FAKETIME FAKETIME_TIMESTAMP_FILE; do
  if [ -z "$(printenv ${_v} 2>/dev/null || true)" ]; then unset ${_v} 2>/dev/null || true; fi
done

# ROS 2 setup scripts may reference optional env vars that are unset.
# With `set -u`, that can cause "unbound variable" errors (observed on AMENT_TRACE_SETUP_FILES).
set +u
source /opt/ros/humble/setup.bash
# Prefer local_setup if present; fall back to setup.bash
if [ -f /opt/pail_ws/install/local_setup.bash ]; then
  source /opt/pail_ws/install/local_setup.bash
elif [ -f /opt/pail_ws/install/setup.bash ]; then
  source /opt/pail_ws/install/setup.bash
fi

# Defensive: ensure the overlay prefix is present so ament index lookup works.
export AMENT_PREFIX_PATH="/opt/pail_ws/install:${AMENT_PREFIX_PATH:-}"

set -u

# Debug (helps diagnose "Package 'pail_pep_gate' not found")
echo "[pep_gate_entrypoint] ROS_PACKAGE_PATH=${ROS_PACKAGE_PATH:-}" || true
echo "[pep_gate_entrypoint] AMENT_PREFIX_PATH=${AMENT_PREFIX_PATH:-}" || true
ls -la /opt/pail_ws/install || true
ls -la /opt/pail_ws/install/share || true
ls -la /opt/pail_ws/install/share/ament_index/resource_index/packages || true
# Note: ripgrep(rg) may not be installed in the container. Avoid piping to prevent BrokenPipe.
ros2 pkg list || true

# Build ros2 args; avoid invalid "-p name:=" when value is empty.
ROS_ARGS=(
  --ros-args
  -p robot_id:=${ROBOT_ID}
  -p token_provider_mode:=${TOKEN_MODE}
  -p policy_file:=${POLICY_FILE}
  -p evidence_conf_threshold:=${EVID_CONF}
  -p token_service_addr:=${TOKEN_SERVICE_ADDR}
  -p permit_rate_hz:=${PERMIT_RATE_HZ}
  -p permit_recheck_ms:=${PERMIT_RECHECK_MS}
  -p permit_deadline_ms:=${PERMIT_DEADLINE_MS}
  # `evidence_window_ms` · `safety_stale_ms` 는 더 이상 ROS 파라미터가 아니다
  # (단계 6, implementation contract). 값은 정책의 `preconditions[].freshness_ms` 에서
  # 노드가 직접 읽는다. 여기 남겨 두면 ROS 는 선언되지 않은 파라미터를 **조용히
  # 무시**하고, 그 침묵이 "설정이 적용됐다"와 같은 로그를 낸다.
  -p clock_skew_ms:=${CLOCK_SKEW_MS}
  -p permit_grace_n:=${PERMIT_GRACE_N}
)

# Optional robot-class registry selection. Empty preserves existing deployments.
if [ -n "${PAIL_ROBOT_CLASS:-}" ]; then
  ROS_ARGS+=( -p robot_class:="${PAIL_ROBOT_CLASS}" )
fi

if [ -n "${STATIC_TARGET}" ]; then
  # Force string type (otherwise numeric-looking ids may be parsed as integers)
  # Use YAML single-quoted string.
  ROS_ARGS+=( -p static_target_object_id:="'${STATIC_TARGET}'" )
fi

# SD5 / C-B3 (implementation contract, §5): the live tier brings the gate up with
# use_sim_time set — simulation is legitimate, and the config seal records it.
# Unset means "do not pass the parameter" (rclcpp's implicit default), not
# "pass false".
if [ -n "${PAIL_USE_SIM_TIME:-}" ]; then
  ROS_ARGS+=( -p use_sim_time:=${PAIL_USE_SIM_TIME} )
fi

# BG (PAIL-BG-LLD-v1 §3): refuse to start with DDS protections off unless
# PAIL_PROFILE=dev says so explicitly.
# shellcheck source=/dev/null
. /usr/local/bin/_pail_preflight.sh
pail_preflight pep_gate
# S19 : 개인키 모드. `pail_preflight` 옆이지 안이 아니다 —
# 그쪽은 dev 에서 배너로 내려가고 S15~S20 은 면제 대상이 아니다.
pail_preflight_key_modes
# SD1 (PAIL-SD1-LLD-v1 §2.2): S7 token provider mode. The node re-checks this.
pail_preflight_token_mode "${TOKEN_MODE}"
# 단계 6 : 창을 옮긴 자리에 남은 env 는 조용히 무시된다.
# S10 보다 **먼저** 부른다 — 설정이 도착하지 않는다는 사실이 임계값 판정보다
# 앞선 문제이고, 뒤에 두면 dev 배치에서 S10 배너에 묻힌다.
pail_preflight_dead_threshold_env

# SD2 (PAIL-SD2-LLD-v1 §4.2): S10 on the values this script is about to pass.
# The node re-checks them, and also sees the launch/parameter-file path.
#
# 신선도 창 둘만 출처가 다르다: env 가 아니라 정책 파일이다(단계 6). 못 읽으면
# 여기서 멈춘다 — 노드도 같은 파일에 대해 기동을 거부하므로(D-L2) 잃는 배치는
# 없고, 얻는 것은 "S10 이 무엇을 못 봤는지"가 로그에 남는 것이다.
if ! pail_preflight_policy_freshness "${POLICY_FILE}"; then
  echo "PAIL PREFLIGHT FAIL: S10 could not read preconditions[safety_feed].freshness_ms and preconditions[evidence_claim].freshness_ms from ${POLICY_FILE} — the two freshness windows were not checked, and a check that did not run is not a check that passed [profile=${PAIL_PROFILE:-production} component=pep_gate_entrypoint]" >&2
  exit "$PAIL_PREFLIGHT_EXIT_CONFIG"
fi
pail_preflight_thresholds "${EVID_CONF}" "${PAIL_POLICY_EVIDENCE_WINDOW_MS}" \
  "${PAIL_POLICY_SAFETY_STALE_MS}" \
  "${CLOCK_SKEW_MS}" "${PERMIT_GRACE_N}" "${PERMIT_RECHECK_MS}"

# EC-2 (EUC D2): 설치 SW 식별 문자열을 조립해 게이트가 Attest 로 보내게 한다.
# 판·git 은 이미지가 구울 때 /usr/share/pail/build_info.env 에 적고(SBOM 옆 —
# /etc/pail 은 모든 compose 프로파일이 config 트리를 바인드 마운트하는 자리라
# 그 아래 둔 파일은 배치에서 가려졌다: 맨 `docker run` 은 판·git 을 보이고
# compose 는 `-:-` 를 증명했다, 실측 2026-09-06), SBOM 해시는 지금 여기서
# 잰다(파일이 바뀌면 문자열도 바뀐다 — 그것이 이 칸의 뜻이다). 이미지 digest 는
# 이미지 자신이 알 수 없으므로 배치가 PAIL_IMAGE_DIGEST 로 준다(없으면 `-`).
# 배치가 PAIL_ATTEST_BUILD_INFO 로 통째로 덮을 수도 있다 — 그래도 S26 은 형식을
# 본다.
PAIL_BUILD_VERSION="-"; PAIL_BUILD_GIT_SHA="-"
_build_info_file="${PAIL_BUILD_INFO_FILE:-/usr/share/pail/build_info.env}"
if [ -f "${_build_info_file}" ]; then
  # shellcheck source=/dev/null
  . "${_build_info_file}"
fi
_sbom_file="${PAIL_SBOM_FILE:-/usr/share/pail/sbom/pep_gate.cdx.json}"
_sbom_sha="-"
if [ -f "${_sbom_file}" ]; then
  _sbom_sha="$(sha256sum "${_sbom_file}" | cut -c1-64)"
fi
_digest="${PAIL_IMAGE_DIGEST:--}"
ATTEST_BUILD_INFO="${PAIL_ATTEST_BUILD_INFO:-pail-build:v1:pep_gate:${PAIL_BUILD_VERSION:--}:${PAIL_BUILD_GIT_SHA:--}:${_digest//:/%3A}:${_sbom_sha}}"
pail_preflight_build_info "${ATTEST_BUILD_INFO}"
ROS_ARGS+=( -p attest_build_info:="${ATTEST_BUILD_INFO}" )

# SROS2 (M7, LLD-v2 §3): run inside the pep_gate enclave when security is on.
if [ "${ROS_SECURITY_ENABLE:-false}" = "true" ]; then
  ROS_ARGS+=( --enclave /pep_gate )
  echo "[pep_gate_entrypoint] SROS2 enabled: enclave=/pep_gate strategy=${ROS_SECURITY_STRATEGY:-} keystore=${ROS_SECURITY_KEYSTORE:-}"
fi

exec ros2 run pail_pep_gate pep_gate_node "${ROS_ARGS[@]}"
