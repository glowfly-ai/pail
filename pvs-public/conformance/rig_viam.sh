#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# Viam conformance rig (implementation contract, SK-6): viam-server with fake components on an
# INTERNAL network only, the gRPC interposer bridging it to a REQUESTER network, a dev
# issuer, and the Go rig driver (cmd/rigcheck) playing the requester.
#
#   tests/adapter_conformance/rig_viam.sh up      # start viam-server, issuer, interposer
#   tests/adapter_conformance/rig_viam.sh run     # run cmd/rigcheck → report_viam.json
#   tests/adapter_conformance/rig_viam.sh down
#
# Prerequisites: pail/viam-fake:dev (tests/adapter_conformance/viam/Dockerfile.viam),
# pail/interposer-build:dev + volume pail-interposer-bin (adapters/grpc_interposer/dev/build.sh),
# the issuer image (default pail/services:dev), libpail_gate.so in adapters/microduck/dev/lib.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
INT=pail-viam-int   # robot side: viam-server + interposer only (CB-1: requesters cannot reach it)
REQ=pail-viam-req   # requester side: interposer + issuer + rigcheck
cmd=${1:-run}

up() {
  for n in $INT $REQ; do docker network inspect $n >/dev/null 2>&1 || docker network create $n >/dev/null; done
  docker rm -f viam-fake viam-issuer viam-interposer >/dev/null 2>&1 || true
  docker volume create viam-issuer-bb >/dev/null; docker volume create viam-run >/dev/null
  # Fresh issuer state every `up`: a chain left by the previous run would still be active and
  # CA-01 ("no token") would read as "a token" (seen 2026-09-09 on the second run).
  docker run --rm -v viam-issuer-bb:/y -v viam-run:/r alpine sh -c 'rm -rf /y/* /y/.[!.]* 2>/dev/null; chown 10001:10001 /y; chmod 0770 /y; rm -f /r/gate.ndjson; chmod 777 /r' >/dev/null
  docker run -d --name viam-fake --network $INT -v "$ROOT/tests/adapter_conformance/viam/fake.json":/etc/viam/fake.json:ro pail/viam-fake:dev >/dev/null
  docker run -d --name viam-issuer --network $REQ -v "$ROOT/config":/etc/pail:ro -v viam-issuer-bb:/var/log/pail_blackbox \
    -e PAIL_PROFILE=dev -e PAIL_GRPC_TLS=off \
    -e PAIL_NORTHBOUND_PORT=50051 -e PAIL_CLOUD_PORT=50061 -e PAIL_CLOUD_ADDR=127.0.0.1:50061 -e PAIL_BURST_ADDR=127.0.0.1:46000 \
    -e PAIL_ROBOT_ID=robot-1 -e PAIL_ROBOT_REGISTRY=/etc/pail/robot_registry.yaml -e PAIL_SITE_MODEL=/etc/pail/site_model.demo.yaml \
    -e PAIL_REQUESTERS=/etc/pail/requesters.none.yaml -e PAIL_SIGNER=local -e PAIL_ISSUER_KEY_ID=dev-key-1 -e PAIL_KEYRING_MODE=unsigned-dev \
    "${PAIL_VIAM_ISSUER_IMAGE:-pail/services:dev}" >/dev/null
  sleep 4
  docker run -d --name viam-interposer --network $INT -v pail-interposer-bin:/bin/pail:ro -v "$ROOT/adapters/microduck/dev/lib":/lib/pail:ro \
    -v "$ROOT/config":/etc/pail:ro -v "$ROOT/adapters/grpc_interposer/interposer.yaml":/etc/pail-int/interposer.yaml:ro -v viam-run:/run/viam \
    -e PAIL_PROFILE=production -e PAIL_KEYRING_MODE=unsigned-dev -e LD_LIBRARY_PATH=/lib/pail \
    pail/interposer-build:dev sh -lc '/bin/pail/interposer --listen :9090 --upstream viam-fake:8080 --agent viam-issuer:50051 --robot-id robot-1 \
      --policy /etc/pail/policy.yaml --keyring /etc/pail/keys/keyring.json --table /etc/pail-int/interposer.yaml --skills-dir /etc/pail --robot-class viam_base \
      --gate-log /run/viam/gate.ndjson 2>&1' >/dev/null
  docker network connect $REQ viam-interposer
  sleep 3
  docker logs viam-fake 2>&1 | grep -E 'serving|constructed resource' | cut -c1-140 | tail -3
  docker logs viam-interposer 2>&1 | grep -E 'PREFLIGHT|libpail_gate|serving|FAIL' | cut -c1-200
}

run() {
  docker run --rm --name viam-rigcheck --network $REQ -v pail-interposer-bin:/bin/pail:ro -v "$ROOT":/work -v viam-run:/run/viam:ro -w /work \
    pail/interposer-build:dev sh -lc "/bin/pail/rigcheck --interposer viam-interposer:9090 --issuer viam-issuer:50051 --robot-direct viam-fake:8080 \
      --robot-id robot-1 --gate-log /run/viam/gate.ndjson --report tests/adapter_conformance/report_viam.json $*"
}

down() {
  docker rm -f viam-rigcheck viam-interposer viam-issuer viam-fake >/dev/null 2>&1 || true
  echo "rig down (volumes kept: pail-interposer-bin viam-issuer-bb viam-run)"
}

case "$cmd" in
  up) up ;;
  run) shift; run "$@" ;;
  down) down ;;
  *) echo "usage: $0 up|run|down" >&2; exit 2 ;;
esac
