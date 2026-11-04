#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# TB3 live demo on a real TurtleBot3 — issuer on the operator PC, and the robot-side subset of a
# configuration that examples/tb3/demo.py generated.
#
#   issuer_host.sh up                 start the issuer (pail_cloud) on PAIL_HW_ISSUER_IP:PAIL_HW_ISSUER_PORT
#   issuer_host.sh down               stop it
#   issuer_host.sh status
#   issuer_host.sh robot-config DIR   write the robot-side configuration subset to a new directory DIR
#
# Environment by command (down/status require none):
#   PAIL_HW_STATE        up/robot-config: state directory of a `demo.py up` run (its runtime/config holds keys, certificates,
#                        SROS2 keystore, policy, site model and requester registration)
#   PAIL_HW_CLOUD_IMAGE  up: the cloud image that run built (evidence/console.json → cloud_image)
#   PAIL_HW_ISSUER_IP    up: this PC's address on the robot's network; added to the server certificate
# Optional:
#   PAIL_HW_ISSUER_PORT  50064     PAIL_HW_ROBOT_ID  robot-01     PAIL_HW_PROFILE  dev
#
# `up` re-signs the demo's server certificate with the demo CA when its subject alternative names
# do not contain PAIL_HW_ISSUER_IP (the demo issued it for `localhost` inside Docker). Nothing else
# in the state directory is changed. Private keys stay where demo.py put them.
#
# The cloud image's default entrypoint (pail_split_entrypoint.sh) ignores its argument and starts
# pail_cloud AND pail_robot_agent together; the agent has no client certificate on the operator PC,
# exits, and takes the container down (measured 2026-09-23 on the real rig). The issuer is started
# with --entrypoint so only pail_cloud runs here.
set -euo pipefail

PORT=${PAIL_HW_ISSUER_PORT:-50064}
ROBOT=${PAIL_HW_ROBOT_ID:-robot-01}
PROFILE=${PAIL_HW_PROFILE:-dev}
NAME=pailhw-issuer

case "${1:-}" in
up)
  ST=${PAIL_HW_STATE:?set PAIL_HW_STATE to a demo.py state directory}
  CFG=$ST/runtime/config
  IMG=${PAIL_HW_CLOUD_IMAGE:?set PAIL_HW_CLOUD_IMAGE}
  IP=${PAIL_HW_ISSUER_IP:?set PAIL_HW_ISSUER_IP}
  [ -f "$CFG/grpc_certs/server.crt" ] || { echo "not a demo state: $CFG/grpc_certs/server.crt missing"; exit 2; }
  if docker inspect "$NAME" >/dev/null 2>&1; then echo "$NAME already exists; run down first"; exit 2; fi
  # one communication contract (0.2.0-preview.40): no selecting setting — the robot agent still checks the Issuer's
  # protocol version on its first census (P36-M1); the message is the one of spec/CORE_COMM.md. The variable being
  # set at all refuses, an empty value included (0.2.0-preview.41, P40-L2): ${VAR+x} tests presence, not emptiness.
  [ -z "${PAIL_CORE_COMM_CONTRACT+x}" ] || { echo "CORE_COMM_CONTRACT_SETTING_REMOVED: PAIL_CORE_COMM_CONTRACT has no meaning (there is one communication contract); unset it"; exit 78; }
  if ! openssl x509 -in "$CFG/grpc_certs/server.crt" -noout -text | grep -q "IP Address:$IP\b"; then
    echo "server certificate lacks IP $IP; re-signing with the demo CA"
    cp -p "$CFG/grpc_certs/server.crt" "$CFG/grpc_certs/server.crt.before-$(date +%Y%m%d%H%M%S)"
    ext=$(mktemp)
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:%s\nextendedKeyUsage=serverAuth\n' "$IP" > "$ext"
    openssl x509 -x509toreq -in "$CFG/grpc_certs/server.crt" -signkey "$CFG/grpc_certs/server.key" -out "$ext.csr" >/dev/null 2>&1
    openssl x509 -req -in "$ext.csr" -CA "$CFG/grpc_certs/ca.crt" -CAkey "$CFG/grpc_certs/ca.key" -CAcreateserial \
      -days 30 -sha256 -extfile "$ext" -out "$CFG/grpc_certs/server.crt" >/dev/null 2>&1
    rm -f "$ext" "$ext.csr"
    openssl verify -CAfile "$CFG/grpc_certs/ca.crt" "$CFG/grpc_certs/server.crt" >/dev/null
  fi
  docker run -d --name "$NAME" --label pail.example=tb3-hardware -p "$IP:$PORT:50061" --cap-drop ALL \
    -v "$CFG":/etc/pail:ro -v "$ST/blackbox":/var/log/pail_blackbox -v "$ST/keyring-state":/var/lib/pail_keyring \
    -e PAIL_PROFILE="$PROFILE" -e PAIL_CLOUD_PORT=50061 -e PAIL_ROBOT_ID="$ROBOT" -e PAIL_ISSUER_KEY_ID=dev-key-1 -e PAIL_GRPC_TLS=on \
    -e PAIL_KEYRING_MODE=bundle -e PAIL_KEYRING_BUNDLE=/etc/pail/keys/keyring_bundle.json -e PAIL_ROOT_PUBKEY_FILE=/etc/pail/keys/root_pub.b64 \
    -e PAIL_KEYRING_STATE=/var/lib/pail_keyring/state.json -e PAIL_KEYRING_MAX_LIFETIME_SEC=86400 -e PAIL_KEYRING_POLL_SEC=0 \
    -e PAIL_SITE_MODEL=/etc/pail/site_model.yaml -e PAIL_REQUESTERS=/etc/pail/requesters.yaml -e PAIL_CHECKPOINT_EVERY_RECORDS=10 \
    --entrypoint /usr/local/bin/pail_cloud "$IMG" >/dev/null
  for i in $(seq 1 30); do
    if docker logs "$NAME" 2>&1 | grep -q "listening\|serving\|started"; then break; fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != true ]; then docker logs "$NAME" 2>&1 | tail -20; echo 'ISSUER_FAILED'; exit 1; fi
    sleep 1
  done
  echo "ISSUER_UP $IP:$PORT image=$IMG journal=$ST/blackbox"
  ;;
down)
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  echo 'ISSUER_DOWN'
  ;;
status)
  docker ps -a --filter "name=^$NAME$" --format '{{.Names}} {{.Status}} {{.Ports}}'
  ;;
robot-config)
  ST=${PAIL_HW_STATE:?set PAIL_HW_STATE to a demo.py state directory}
  CFG=$ST/runtime/config
  OUT=${2:?give the output directory}
  [ -e "$OUT" ] && { echo "$OUT exists; choose a new directory"; exit 2; }
  # Refuse incomplete input before creating the destination or minting a certificate.
  for f in policy.yaml skills.diff_drive_amr.yaml sros2_policy.xml robot_registry.yaml \
           keys/keyring_bundle.json keys/root_pub.b64 keys/agent_ed25519.json \
           grpc_certs/ca.crt grpc_certs/ca.key grpc_certs/$ROBOT/client.crt grpc_certs/$ROBOT/client.key; do
    [ -f "$CFG/$f" ] || { echo "missing configuration: $CFG/$f" >&2; exit 2; }
  done
  for d in enclaves public; do
    [ -d "$CFG/sros2_keystore/$d" ] || { echo "missing keystore: $d" >&2; exit 2; }
  done
  umask 077
  mkdir -p "$OUT/keys" "$OUT/grpc_certs/$ROBOT" "$OUT/sros2_keystore"
  cp "$CFG/policy.yaml" "$CFG/skills.diff_drive_amr.yaml" "$CFG/sros2_policy.xml" "$OUT/"
  # The agent refuses to start without the robot registry (RG-4) — it is the fingerprint→robot_id
  # table its own northbound listener answers from, and it holds public fingerprints only.
  cp "$CFG/robot_registry.yaml" "$OUT/"
  cp "$CFG/keys/keyring_bundle.json" "$CFG/keys/root_pub.b64" "$CFG/keys/agent_ed25519.json" "$OUT/keys/"
  cp "$CFG/grpc_certs/ca.crt" "$OUT/grpc_certs/"
  cp "$CFG/grpc_certs/$ROBOT/client.crt" "$CFG/grpc_certs/$ROBOT/client.key" "$OUT/grpc_certs/$ROBOT/"
  # The agent is a server too: the gate dials it at 127.0.0.1:50051 with mTLS, so it presents a
  # certificate of its own. It is minted here, where the demo CA key lives, and the robot never
  # receives the issuer's server key — that key answers for the issuer's own address.
  # (Measured 2026-09-19 on a real TurtleBot3: with no server certificate at all the agent exits
  # with "grpc mTLS init: server cert/key: open /etc/pail/grpc_certs/server.crt: no such file".)
  ext=$(mktemp)
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > "$ext"
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/grpc_certs/$ROBOT/server.key"
  openssl req -new -key "$OUT/grpc_certs/$ROBOT/server.key" -subj "/CN=$ROBOT-agent" -out "$ext.csr" >/dev/null 2>&1
  openssl x509 -req -in "$ext.csr" -CA "$CFG/grpc_certs/ca.crt" -CAkey "$CFG/grpc_certs/ca.key" -CAcreateserial \
    -days 30 -sha256 -extfile "$ext" -out "$OUT/grpc_certs/$ROBOT/server.crt" >/dev/null 2>&1
  rm -f "$ext" "$ext.csr"
  openssl verify -CAfile "$CFG/grpc_certs/ca.crt" "$OUT/grpc_certs/$ROBOT/server.crt" >/dev/null
  cp -R "$CFG/sros2_keystore/enclaves" "$CFG/sros2_keystore/public" "$OUT/sros2_keystore/"
  # readable by the container user on the robot (uid 10001); private material stays 0600
  find "$OUT" -type d -exec chmod 755 {} +
  find "$OUT" -type f -exec chmod 644 {} +
  chmod 600 "$OUT/grpc_certs/$ROBOT/client.key" "$OUT/grpc_certs/$ROBOT/server.key" "$OUT/keys/agent_ed25519.json"
  find "$OUT/sros2_keystore/enclaves" -name 'key.pem' -exec chmod 600 {} +
  echo "ROBOT_CONFIG $OUT — minted: $ROBOT agent server certificate (localhost/127.0.0.1) — excluded: issuer/operator/mirror keys, CA key, issuer server key, sros2 CA private keys, requesters, site model"
  find "$OUT" -type f | sort
  ;;
*) echo "usage: $0 up|down|status|robot-config DIR"; exit 2;;
esac
