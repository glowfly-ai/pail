#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# TB3 live demo on a real TurtleBot3 — robot side. Runs on the robot's computer.
#
#   start_demo_rig.sh up             agent + demo participants + bridge + gate, then the vendor base driver
#   start_demo_rig.sh down           stop and remove this rig's containers (nothing else)
#   start_demo_rig.sh status         one line per container
#   start_demo_rig.sh restart-gate   the console's "restart robot side"
#   start_demo_rig.sh restart-agent  after the issuer address changed
#
# Required environment:
#   PAIL_HW_CONFIG          robot-side configuration directory (HARDWARE.md, section 3): policy.yaml,
#                           skills.diff_drive_amr.yaml, keys/{keyring_bundle.json,root_pub.b64,agent_ed25519.json},
#                           grpc_certs/{ca.crt,<robot>/client.crt,<robot>/client.key}, sros2_keystore/
#   PAIL_HW_CLOUD_ADDR      issuer host:port on the operator PC (mTLS), e.g. 192.0.2.10:50064
#   PAIL_HW_SERVICES_IMAGE  image that contains pail_robot_agent (the public Core services image, loaded on the robot)
#   PAIL_HW_GATE_IMAGE      gate image with the vendor driver packages (built from hardware/Dockerfile)
# Optional:
#   PAIL_HW_DIR             directory holding this script, demo_hw_io.py, tb3_base_driver.launch.py,
#                           fastdds_loopback.xml, control/ and state/ (default: the script's directory)
#   PAIL_HW_ROBOT_ID        robot-01      PAIL_HW_TARGET   sample-box (tag reported before the first instruction)
#   PAIL_HW_MODEL           waffle_pi     PAIL_HW_PARAMS_FILE  vendor parameter file inside the image for that model
#   PAIL_HW_USB_PORT        /dev/ttyACM0  PAIL_HW_PROFILE  production
#   PAIL_HW_MAX_STEP_S      30            the issuer policy's step.max_duration_s (the planner never runs longer)
#   PAIL_HW_KEYRING_MAX_LIFETIME_SEC  86400   maximum remaining signed-bundle validity at load (not bundle age)
#   PAIL_HW_DEPLOYMENT_ID   (unset)       robotops deployment id: when set, the gate and bridge serve their read-only
#                           status probe on /state/{gate,bridge}_status.sock and the agent serves its
#                           self-probe on /state/agent.sock (gate/bridge sockets 0600, agent socket 0660;
#                           uid/gid 10001; see spec/ROBOT_OPERATIONS.md §2); unset = no gate/bridge probes
#
# The motor driver starts only after control/hardware_confirmed records the operator's placement
# statement: `raised` (wheels off the ground) or `clear-floor` (floor space and an immediate stop
# capability confirmed). The file is a record of a statement that was made, not a substitute for it.
set -euo pipefail

D=${PAIL_HW_DIR:-$(cd "$(dirname "$0")" && pwd)}
# `up` records its parameters in rig.env (paths and image names, no secrets) so that a later
# restart-gate / restart-agent — the console calls them over ssh, without your shell — starts
# the container exactly as `up` did. Variables set in the environment take precedence.
if [ "${1:-}" != up ] && [ -f "$D/rig.env" ]; then
  set -a; . "$D/rig.env"; set +a
fi
# restart-gate is the console's "restart robot side": the gate container is started again exactly as `up` did and the
# command ends with GATE_RESTARTED once the gate's IO readiness is observed. There is one restart path (0.2.0-preview.41).
case "${1:-}" in
up|restart-gate|restart-agent)
  : "${PAIL_HW_CONFIG:?set PAIL_HW_CONFIG to the robot-side configuration directory}"
  : "${PAIL_HW_CLOUD_ADDR:?set PAIL_HW_CLOUD_ADDR to the issuer host:port}"
  : "${PAIL_HW_SERVICES_IMAGE:?set PAIL_HW_SERVICES_IMAGE}"
  : "${PAIL_HW_GATE_IMAGE:?set PAIL_HW_GATE_IMAGE}"
  ;;
esac
C=${PAIL_HW_CONFIG:-}
CLOUD=${PAIL_HW_CLOUD_ADDR:-}
S=${PAIL_HW_SERVICES_IMAGE:-}
G=${PAIL_HW_GATE_IMAGE:-}
ROBOT=${PAIL_HW_ROBOT_ID:-robot-01}
MODEL=${PAIL_HW_MODEL:-waffle_pi}
PARAMS=${PAIL_HW_PARAMS_FILE:-/opt/ros/humble/share/turtlebot3_bringup/param/humble/$MODEL.yaml}
USB=${PAIL_HW_USB_PORT:-/dev/ttyACM0}
PROFILE=${PAIL_HW_PROFILE:-production}
L=pail.example=tb3-hardware
NAMES=(pailhw-base pailhw-gate pailhw-bridge pailhw-planner pailhw-robot pailhw-drive pailhw-safety pailhw-evidence pailhw-agent pailhw-net)

# one communication contract (0.2.0-preview.40): no selecting setting; the message is the one of spec/CORE_COMM.md.
# The variable being set at all refuses, an empty value included (0.2.0-preview.41, P40-L2): ${VAR+x} tests presence.
[ -z "${PAIL_CORE_COMM_CONTRACT+x}" ] || { echo "CORE_COMM_CONTRACT_SETTING_REMOVED: PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); unset it"; exit 78; }
COMMON=(--label "$L" --network container:pailhw-net --ipc container:pailhw-net --cap-drop ALL --log-opt max-size=30m --log-opt max-file=2
        -v "$C":/etc/pail:ro -v "$D":/demo:ro -v "$D/control":/control:ro -v "$D/state":/state
        -v "$D/fastdds_loopback.xml":/etc/fastdds_udp_only.xml:ro)
ROS=(-e ROS_DOMAIN_ID=0 -e ROS_SECURITY_ENABLE=true -e ROS_SECURITY_STRATEGY=Enforce
     -e ROS_SECURITY_KEYSTORE=/etc/pail/sros2_keystore -e FASTRTPS_DEFAULT_PROFILES_FILE=/etc/fastdds_udp_only.xml)

helper() { # name role enclave
  docker run -d --name "$1" "${COMMON[@]}" "${ROS[@]}" -e ROS_SECURITY_ENCLAVE_OVERRIDE="$3" -e DEMO_ROLE="$2" \
    -e DEMO_TARGET="${PAIL_HW_TARGET:-sample-box}" -e DEMO_MAX_STEP_S="${PAIL_HW_MAX_STEP_S:-30}" \
    --entrypoint /bin/bash "$G" -c 'source /opt/ros/humble/setup.bash; source /opt/pail_ws/install/setup.bash; exec python3 -u /demo/demo_hw_io.py' >/dev/null
}

agent() {
  docker run -d --name pailhw-agent --user 10001:10001 "${COMMON[@]}" -e PAIL_PROFILE="$PROFILE" -e PAIL_NORTHBOUND_PORT=50051 -e PAIL_CLOUD_ADDR="$CLOUD" \
    -e PAIL_BURST_ADDR=127.0.0.1:46000 -e PAIL_ROBOT_ID="$ROBOT" -e PAIL_GRPC_TLS=on \
    -e PAIL_GRPC_CLIENT_CERT="/etc/pail/grpc_certs/$ROBOT/client.crt" -e PAIL_GRPC_CLIENT_KEY="/etc/pail/grpc_certs/$ROBOT/client.key" \
    -e PAIL_GRPC_CERT="/etc/pail/grpc_certs/$ROBOT/server.crt" -e PAIL_GRPC_KEY="/etc/pail/grpc_certs/$ROBOT/server.key" \
    -e PAIL_TOKEN_MIRROR_MS=200 -e PAIL_OPS_DEPLOYMENT_ID="${PAIL_HW_DEPLOYMENT_ID:-}" -e PAIL_GRPC_UDS_PATH=/state/agent.sock "$S" /usr/local/bin/pail_robot_agent >/dev/null
}

status_env() {
  STATUS_ENV=()
  if [ -n "${PAIL_HW_DEPLOYMENT_ID:-}" ]; then
    [[ "$PAIL_HW_DEPLOYMENT_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] || { echo 'REFUSED: PAIL_HW_DEPLOYMENT_ID must be a UUID'; return 78; }
    STATUS_ENV=(-e "PAIL_ROBOTOPS_STATUS_SOCKET=/state/${1}_status.sock" -e "PAIL_OPS_DEPLOYMENT_ID=$PAIL_HW_DEPLOYMENT_ID")
  fi
}

wait_ready() {
  local name=$1 marker=$2
  for ((i=0; i<120; i++)); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then
      preserve_logs failed || echo 'RIG_LOGS_NOT_SAVED'
      echo "RIG_FAILED: $name exited before readiness"; docker logs --tail 20 "$name" 2>&1; return 1
    fi
    if docker logs "$name" 2>&1 | grep -F "$marker" >/dev/null; then return 0; fi
    sleep 1
  done
  preserve_logs failed || echo 'RIG_LOGS_NOT_SAVED'
  echo "RIG_FAILED: $name readiness timeout ($marker)"; return 1
}

wait_gate_io() {
  local latest bridge participant
  for ((i=0; i<120; i++)); do
    for participant in pailhw-gate pailhw-bridge pailhw-base; do
      if [ "$(docker inspect -f '{{.State.Running}}' "$participant" 2>/dev/null || true)" != true ]; then
        preserve_logs failed || echo 'RIG_LOGS_NOT_SAVED (diagnostics only; the failure below stands on its own)'
        echo "RIG_FAILED: $participant exited before IO readiness"
        return 1
      fi
    done
    latest=$(docker logs --since 3s pailhw-gate 2>&1 | grep 'PAIL_GATE_IO ' | tail -1 || true)
    bridge=$(docker logs --since 3s pailhw-bridge 2>&1 | grep 'PAIL_BRIDGE_IO ' | tail -1 || true)
    if [[ "$latest" == *'PAIL_GATE_IO serving=1 '* &&
          "$bridge" =~ safe_publishers=[1-9][0-9]* &&
          "$bridge" =~ permit_publishers=[1-9][0-9]* &&
          "$bridge" =~ drive_subscribers=[1-9][0-9]* ]]; then return 0; fi
    if [ "$(docker inspect -f '{{.State.Running}}' pailhw-gate)" != true ]; then break; fi
    sleep 1
  done
  preserve_logs failed || echo 'RIG_LOGS_NOT_SAVED (diagnostics only; the failure below stands on its own)'
  echo 'RIG_FAILED: gate IO readiness timeout (matching/fresh input unavailable)'
  return 1
}

# Logs are archived under the operator-owned rig directory, never under state/: state/ belongs to the
# gate (uid 10001, mode 700) and the operator cannot enter it (preview.35 evaluation P35-H1: on a rig
# installed as documented every console restart and `down` died here). This function returns non-zero
# instead of exiting; each caller decides what an unarchived log means for its own step.
# Each archive holds only what was logged since the previous archive (`--since` the stamp in restart-logs/.last;
# the first archive copies everything). Only ordinary run.* archives rotate (latest ten);
# readiness failures go under failed/ and require explicit operator archival/removal.
# Previously, copying every container's
# cumulative log on every restart grew by the robot's uptime (preview.36 evaluation P36-L1: 31 restarts, 53 MB).
preserve_logs() {
  local archive since stamp archive_root
  archive_root="$D/restart-logs"
  case "${1:-}" in
    '') ;;
    failed) archive_root="$D/restart-logs/failed" ;;
    *) echo 'RIG_LOGS_NOT_SAVED: invalid archive class'; return 2 ;;
  esac
  mkdir -p "$archive_root" || return 1
  archive=$(mktemp -d "$archive_root/run.XXXXXXXX") || return 1
  since=$(cat "$D/restart-logs/.last" 2>/dev/null || true)
  stamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  for name in pailhw-gate pailhw-bridge pailhw-planner pailhw-drive pailhw-base pailhw-agent pailhw-safety pailhw-evidence pailhw-robot; do
    if docker inspect "$name" >/dev/null 2>&1; then
      if [ -n "$since" ]; then
        docker logs --timestamps --since "$since" "$name" >"$archive/$name.log" 2>&1 || return 1
      else
        docker logs --timestamps "$name" >"$archive/$name.log" 2>&1 || return 1
      fi
      docker inspect "$name" >"$archive/$name.inspect.json" || return 1
    fi
  done
  echo "$stamp" > "$D/restart-logs/.last" || return 1
  if [ "${1:-}" != failed ]; then
    ls -1dt "$D"/restart-logs/run.* 2>/dev/null | tail -n +11 | xargs rm -rf
  fi
  echo "RIG_LOGS_SAVED $archive since=${since:-start}"
}


gate() {
  status_env gate
  docker run -d --name pailhw-gate "${COMMON[@]}" "${ROS[@]}" -e PAIL_PROFILE="$PROFILE" -e PAIL_ROBOT_CLASS=diff_drive_amr \
    -e PAIL_GRPC_TLS=on -e PAIL_GRPC_CERT="/etc/pail/grpc_certs/$ROBOT/client.crt" -e PAIL_GRPC_KEY="/etc/pail/grpc_certs/$ROBOT/client.key" \
    -e PAIL_KEYRING_MODE=bundle -e PAIL_KEYRING_MAX_LIFETIME_SEC="${PAIL_HW_KEYRING_MAX_LIFETIME_SEC:-86400}" \
    -e PAIL_KEYRING_BUNDLE=/etc/pail/keys/keyring_bundle.json -e PAIL_ROOT_PUBKEY_FILE=/etc/pail/keys/root_pub.b64 -e PAIL_KEYRING_STATE=/state/keyring_state.json \
    -e PAIL_TOKEN_PROVIDER_MODE=grpc -e PAIL_ROBOT_ID="$ROBOT" -e PAIL_TOKEN_SERVICE_ADDR=127.0.0.1:50051 \
    -e PAIL_PERMIT_RATE_HZ=20 -e PAIL_PERMIT_RECHECK_MS=100 -e PAIL_PERMIT_DEADLINE_MS=100 -e PAIL_PERMIT_GRACE_N=3 -e PAIL_RPC_DEADLINE_MS=50 \
    ${STATUS_ENV[@]+"${STATUS_ENV[@]}"} \
    "$G" >/dev/null
}

case "${1:-}" in
up)
  status_env gate  # validate before creating any runtime resources
  for n in "${NAMES[@]}"; do
    if docker inspect "$n" >/dev/null 2>&1; then echo "$n already exists; run '$0 down' first (after RIG_DOWN_INCOMPLETE: '$0 down --discard-logs')"; exit 2; fi
  done
  case "$(cat "$D/control/hardware_confirmed" 2>/dev/null || true)" in
    raised|clear-floor) ;;
    *) echo "REFUSED: write 'raised' or 'clear-floor' to $D/control/hardware_confirmed after the operator confirmed the placement"; exit 78;;
  esac
  for f in demo_hw_io.py tb3_base_driver.launch.py fastdds_loopback.xml control/demo.json; do
    [ -f "$D/$f" ] || { echo "missing $D/$f (HARDWARE.md, section 4)"; exit 2; }
  done
  [ -e "$USB" ] || { echo "no OpenCR device at $USB"; exit 2; }
  if [ ! -d "$D/state" ] || [ "$(stat -c %u "$D/state")" != 10001 ]; then
    # the gate (uid 10001) keeps its keyring anti-rollback state here; created once, privately
    sudo -n install -d -o 10001 -g 10001 -m 700 "$D/state" || { echo "create $D/state owned by uid 10001 (mode 700) and run again"; exit 2; }
  fi
  # public demo inputs must be readable by the container user; private keys are never touched
  chmod 755 "$D" "$D/control"; chmod 644 "$D/demo_hw_io.py" "$D/tb3_base_driver.launch.py" "$D/fastdds_loopback.xml" "$D/control/demo.json"
  {
    for v in PAIL_HW_CONFIG PAIL_HW_CLOUD_ADDR PAIL_HW_SERVICES_IMAGE PAIL_HW_GATE_IMAGE PAIL_HW_ROBOT_ID PAIL_HW_TARGET PAIL_HW_MODEL \
             PAIL_HW_PARAMS_FILE PAIL_HW_USB_PORT PAIL_HW_PROFILE PAIL_HW_MAX_STEP_S PAIL_HW_KEYRING_MAX_LIFETIME_SEC PAIL_HW_DEPLOYMENT_ID; do
      [ -n "${!v:-}" ] && printf '%s=%q\n' "$v" "${!v}"
    done
  } > "$D/rig.env"
  chmod 644 "$D/rig.env"
  docker network inspect pailhw-isolated >/dev/null 2>&1 || docker network create --label "$L" pailhw-isolated >/dev/null
  docker run -d --name pailhw-net --label "$L" --network pailhw-isolated --ipc shareable --cap-drop ALL --entrypoint /usr/bin/sleep "$S" infinity >/dev/null
  agent
  helper pailhw-planner planner /oem_planner
  helper pailhw-robot base /robot_state_publisher
  helper pailhw-drive drive /driver
  helper pailhw-safety safety /safety_adapter
  helper pailhw-evidence evidence /perception
  status_env bridge
  docker run -d --name pailhw-bridge "${COMMON[@]}" "${ROS[@]}" -e PAIL_PROFILE="$PROFILE" -e PAIL_PERMIT_DEADLINE_MS=100 \
    ${STATUS_ENV[@]+"${STATUS_ENV[@]}"} -e PAIL_ROBOT_ID="$ROBOT" \
    --entrypoint /usr/local/bin/motion_bridge_entrypoint.sh "$G" >/dev/null
  gate
  # Constructor-complete marker, not S33 (which precedes optional status setup).
  # No OpenCR container starts on failure; stop our participants and preserve logs.
  if [ "$(docker inspect -f '{{.State.Running}}' pailhw-agent)" != true ]; then
    echo 'RIG_FAILED: agent exited'; docker logs --tail 20 pailhw-agent 2>&1
    for n in "${NAMES[@]}"; do docker stop "$n" >/dev/null 2>&1 || true; done
    exit 1
  fi
  if ! wait_ready pailhw-gate PAIL_GATE_READY || ! wait_ready pailhw-bridge 'motion bridge up'; then
    for n in "${NAMES[@]}"; do docker stop "$n" >/dev/null 2>&1 || true; done
    exit 1
  fi
  # The vendor base driver is the only container that receives the OpenCR device. It subscribes
  # /drive_cmd_vel (remapped by tb3_base_driver.launch.py) in the /driver enclave. No lidar, no arm.
  docker run -d --name pailhw-base --label "$L" --network container:pailhw-net --ipc container:pailhw-net --cap-drop ALL \
    --device "$USB:$USB" -v "$C":/etc/pail:ro -v "$D":/demo:ro "${ROS[@]}" \
    -e FASTRTPS_DEFAULT_PROFILES_FILE=/etc/fastdds_udp_only.xml -v "$D/fastdds_loopback.xml":/etc/fastdds_udp_only.xml:ro \
    --entrypoint /bin/bash "$G" -c "source /opt/ros/humble/setup.bash && source /opt/pail_ws/install/setup.bash && exec ros2 launch /demo/tb3_base_driver.launch.py enable_hardware:=true params_file:=$PARAMS usb_port:=$USB" >/dev/null
  if ! wait_gate_io; then
    for n in "${NAMES[@]}"; do docker stop "$n" >/dev/null 2>&1 || true; done
    exit 1
  fi
  echo 'RIG_UP'
  ;;
restart-agent)
  docker rm -f pailhw-agent >/dev/null 2>&1 || true
  agent
  echo "AGENT_RESTARTED $S"
  ;;
restart-gate)
  # The console's restart is an operating action; an unarchived log is reported, not a reason to refuse it.
  LOGS_NOTE=saved
  preserve_logs || { echo 'RIG_LOGS_NOT_SAVED'; LOGS_NOTE=unsaved; }
  status_env gate
  docker rm -f pailhw-gate >/dev/null 2>&1 || true
  gate
  wait_ready pailhw-gate PAIL_GATE_READY
  wait_gate_io
  echo "GATE_RESTARTED logs=$LOGS_NOTE"
  ;;
status)
  docker ps -a --filter "label=$L" --format '{{.Names}} {{.Status}}'
  ;;
down)
  # Even when evidence storage fails, do not leave a moving rig running.
  # Keep stopped containers intact if their logs cannot be archived, say so, and name the way out:
  # `down --discard-logs` removes them without archiving (the operator's explicit choice).
  case "${2:-}" in
    '') DISCARD=0;;
    --discard-logs) DISCARD=1;;
    *) echo "usage: $0 down [--discard-logs]"; exit 2;;
  esac
  for n in "${NAMES[@]}"; do docker stop "$n" >/dev/null 2>&1 || true; done
  LOGS_NOTE=saved
  if [ "$DISCARD" = 1 ]; then
    LOGS_NOTE=discarded
  elif ! preserve_logs; then
    echo "RIG_DOWN_INCOMPLETE logs=unsaved; stopped containers kept; run: $0 down --discard-logs"
    exit 3
  fi
  for n in "${NAMES[@]}"; do docker rm -f "$n" >/dev/null 2>&1 || true; done
  # `docker rm -f` kills the nodes before their destructors unlink the robotops status
  # endpoints (PAIL_HW_DEPLOYMENT_ID); the nodes reclaim a stale self-owned socket on
  # the next start, and this keeps the private state directory clean regardless.
  if [ -d "$D/state" ]; then sudo -n find "$D/state" -maxdepth 1 -type s -name '*.sock' -delete 2>/dev/null || true; fi
  echo "RIG_DOWN logs=$LOGS_NOTE"
  ;;
*) echo "usage: $0 up|down [--discard-logs]|status|restart-gate|restart-agent"; exit 2;;
esac
