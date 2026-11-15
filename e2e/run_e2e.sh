#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

# PAIL end-to-end run — the "Try it" path for this tree.
#
#   bash e2e/run_e2e.sh                    # E2E-A (cloud chain) + E2E-B (enforcement)
#   bash e2e/run_e2e.sh --a-only           # cloud chain only (no ROS gate)
#   bash e2e/run_e2e.sh --vault            # cloud chain signed through Vault Transit
#   bash e2e/run_e2e.sh --keyring bundle   # trust arrives as a root-signed bundle
#
# E2E-A walks the full custody chain on one host and JUDGES each link by the
# identifiers the tools print — not by "it did not crash":
#
#   dev keys -> provisioning -> issue (submit_plan status=ACCEPTED)
#   -> read back (get_active_token, same chain_id) -> journal segments exist
#   -> anchor records appear in the file anchor -> blackbox_verify
#      "OK: chain verified" against the issuer public key.
#
# E2E-B brings the ROS 2 gate up under SROS2 Enforce and measures enforcement
# from the topics a planner and a bridge are allowed to see:
#
#   no token   -> /pail/gate_state state=BLOCK reason=ERR_NO_TOKEN,
#                 nothing on /safe_cmd_vel
#   token      -> state=PERMIT active_token_id=<the token just issued>,
#                 motion observed on /safe_cmd_vel
#
# --vault swaps the issuer's signing backend for HashiCorp Vault's Transit
# engine, where the private key is generated and stays. It adds two judgments
# to E2E-A and implies --a-only (the gate's keyring trusts the local dev key,
# so stage B would refuse vault-signed tokens for a reason unrelated to this):
#
#   signer identity -> the same journal must NOT verify against the local key
#   vault stopped   -> issuance is refused, never locally re-signed
#
# --keyring bundle replaces the unsigned config/keys/keyring.json with the KM2
# trust path: this script mints a root key OUTSIDE the tree the services mount,
# signs a payload built from the dev keyring, and both the issuer and the gate
# load that bundle instead. It runs both stages — the claim under test is that
# the same chain still works when trust arrives signed — and adds:
#
#   mode named    -> issuer and gate each log keyring trust path: mode=bundle
#   forged bundle -> a bundle signed by a DIFFERENT root is refused at startup,
#                    and the refusal names the signature
#
# Judgment discipline: every PASS below names the identifier it read. A step
# that cannot read its identifier is a FAIL, not a "probably fine" (a check
# that cannot fire is decoration). Absence is never a pass on its own — the
# BLOCK window's silence is only accepted after the same observer is proven to
# see traffic.
#
# rc: 0 all judged PASS · 1 a judgment failed · 2 usage / missing prerequisite
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/docker-compose.e2e.yml"
STATE="${PAIL_E2E_STATE:-}"
ROBOT="${PAIL_ROBOT_ID:-robot-1}"

# Ports are env-parameterized in the compose file; the CLIs below must dial
# the SAME values or a port override silently tests a different stack.
NB_ADDR="127.0.0.1:${PAIL_NORTHBOUND_PORT:-50051}"
# The cloud port and the address the robot-agent dials are one fact in two
# variables — override the port and the pair must move together.
export PAIL_CLOUD_ADDR="${PAIL_CLOUD_ADDR:-127.0.0.1:${PAIL_CLOUD_PORT:-50061}}"

A_ONLY=0
VAULT=0
KEYRING_MODE=unsigned-dev
while [ "$#" -gt 0 ]; do
  case "$1" in
    --a-only) A_ONLY=1 ;;
    --keyring)
      shift
      [ "$#" -gt 0 ] || { echo "--keyring needs a value (unsigned-dev|bundle)" >&2; exit 2; }
      case "$1" in
        unsigned-dev|bundle) KEYRING_MODE="$1" ;;
        *) echo "unknown --keyring value: $1 (want unsigned-dev|bundle)" >&2; exit 2 ;;
      esac ;;
    # Vault implies A-only: the gate trusts the keyring baked into ./config,
    # whose issuer entry is the local dev key. Under the vault the issuer is a
    # different key, so stage B would refuse every token — correctly, and for a
    # reason that has nothing to do with what --vault is measuring.
    --vault) VAULT=1; A_ONLY=1 ;;
    -h|--help)
      # Print the header block itself rather than a line range: a hard-coded
      # range goes stale the first time the header grows and then the help
      # stops mid-sentence without anything reporting it.
      awk 'NR > 1 && !/^#/ { exit } NR > 1 { print }' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)
      # Unknown arguments are refused, not ignored — an ignored argument turns
      # the command you asked about into the command that runs.
      echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# Refused rather than silently resolved. The vault overlay hands the issuer the
# unsigned self-check keyring that vault-init wrote; under bundle mode that path
# is not read at all, so the run would fail for a reason that belongs to neither
# flag — and the log would name the bundle, which is the wrong explanation.
if [ "$VAULT" = 1 ] && [ "$KEYRING_MODE" = bundle ]; then
  echo "--vault and --keyring bundle cannot be combined (see the header)" >&2
  exit 2
fi

# The shipped SROS2 permission generation targets domain 0. Refuse an override
# instead of failing much later when DDS denies discovery publishers.
if [ "${ROS_DOMAIN_ID:-0}" != 0 ]; then
  echo "This E2E provisions SROS2 domain 0; unset ROS_DOMAIN_ID or use the isolated TB3 reference. Custom domains require matching permissions." >&2
  exit 2
fi

for bin in docker python3; do
  command -v "$bin" > /dev/null || { echo "missing prerequisite: $bin" >&2; exit 2; }
done
docker compose version > /dev/null 2>&1 || { echo "missing prerequisite: docker compose v2" >&2; exit 2; }
docker info > /dev/null 2>&1 || { echo "Docker is installed but its daemon is unavailable. Start Docker Desktop/Engine and check your Docker context and permissions." >&2; exit 2; }

# Resolve immutable local images before provisioning; no source overlay or implicit pull.
PAIL_E2E_SERVICES_IMAGE="$(python3 "$ROOT/examples/common/evaluation_runtime.py" --root "$ROOT" --role issuer)"
PAIL_E2E_GATE_IMAGE="$(python3 "$ROOT/examples/common/evaluation_runtime.py" --root "$ROOT" --role tb3_gate)"
export PAIL_E2E_SERVICES_IMAGE PAIL_E2E_GATE_IMAGE
# 0.2.2 F5: a run on another architecture than the bundle's (emulation) says so here, in the state and in the result line.
E2E_PLATFORM_NOTE="$(python3 "$ROOT/examples/common/evaluation_runtime.py" --root "$ROOT" --platform)" || exit 2
[ "$E2E_PLATFORM_NOTE" = native ] || echo "EMULATION: $E2E_PLATFORM_NOTE — this E2E run is not a measurement of the bundle architecture"

# Each run owns fresh state. Never erase a previous run or its evidence.
STATE="$(python3 - "$STATE" "$ROOT" <<'PYSTATE'
from pathlib import Path
import sys,tempfile
root=Path(sys.argv[2]).resolve()
p=Path(sys.argv[1]).expanduser().resolve() if sys.argv[1] else Path(tempfile.mkdtemp(prefix='pail-e2e-')).resolve()
if p == root or root in p.parents:
    raise SystemExit('State must be outside the source tree.')
if p.exists() and (not p.is_dir() or any(p.iterdir())):
    raise SystemExit('State must be a new or empty directory; existing evidence is never deleted.')
p.mkdir(parents=True,exist_ok=True)
print(p)
PYSTATE
)" || exit 2
export PAIL_E2E_STATE="$STATE"
mkdir -p "$STATE/evidence" "$STATE/blackbox" "$STATE/anchor"
printf '%s\n' "$E2E_PLATFORM_NOTE" > "$STATE/evidence/platform.txt"
# The source is read-only input; all generated material belongs to this run.
CONFIG="$STATE/provision/config"
mkdir -p "$CONFIG"
export PAIL_E2E_CONFIG="$STATE/runtime/config"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
RUNTIME_READY=0
runtime_files() {
  docker run --rm --network none -u 0:0 -v "$STATE":/state \
    -v "$ROOT/e2e/runtime_files.py":/runtime_files.py:ro \
    --entrypoint python3 "$PAIL_E2E_GATE_IMAGE" /runtime_files.py "$@"
}
exec > >(tee "$STATE/evidence/run.log") 2>&1
TEE_PID=$!
printf 'STATE=%s\nEVIDENCE=%s/evidence\n' "$STATE" "$STATE"


PROJECT="pail-e2e-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:12])')"
printf '%s\n' "$PROJECT" > "$STATE/evidence/compose-project.txt"
COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")
if [ "$VAULT" = 1 ]; then
  COMPOSE+=(-f "$ROOT/docker-compose.vault.yml")
fi
cleanup() {
  local rc=$?
  trap - EXIT
  "${COMPOSE[@]}" logs --no-color > "$STATE/evidence/services.log" 2>&1 || true
  # Retain raw observers before removing this run's containers.
  "${COMPOSE[@]}" exec -T pail-pep-gate bash -c 'for f in /tmp/obs_*.log /tmp/feed_*.log /tmp/cmd_*.log; do [ ! -f "$f" ] || { echo "FILE=$f"; cat "$f"; }; done' > "$STATE/evidence/observers.log" 2>&1 || true
  if ! "${COMPOSE[@]}" down --timeout 5 > /dev/null 2>&1; then
    echo "CLEANUP: containers may still be running; journal snapshot not exported" >&2
    RUNTIME_READY=0
    [ "$rc" != 0 ] || rc=1
  fi
  if [ "$RUNTIME_READY" = 1 ]; then
    if [ "$KEYRING_MODE" = bundle ]; then
      runtime_files good >> "$STATE/evidence/runtime-cleanup.log" 2>&1 || rc=1
    fi
    runtime_files export --uid "$HOST_UID" --gid "$HOST_GID" > "$STATE/evidence/viewer-export.log" 2>&1 || rc=1
  fi
  if [ "$rc" = 0 ] && [ "$KEYRING_MODE" = bundle ] && [ "$A_ONLY" = 0 ]; then
    python3 "$ROOT/e2e/check_samples.py" --root "$ROOT" --log "$STATE/evidence/verdicts.log" > "$STATE/evidence/readme-samples.log" 2>&1 || rc=1
    cat "$STATE/evidence/readme-samples.log"
  fi
  printf 'rc=%s\n' "$rc" > "$STATE/evidence/run.done"
  printf 'RESULT=%s; evidence=%s/evidence; journal=%s/blackbox\n' "$rc" "$STATE" "$STATE"
  # Drain tee before exiting (also when this runner is container PID 1).
  exec 1>&- 2>&-
  wait "$TEE_PID" || true
  exit "$rc"
}
trap cleanup EXIT

# TLS material inside the containers (per-robot client cert — the flat
# client.crt default has no registry entry and would be refused as unbound).
CLI_TLS=(-ca /etc/pail/grpc_certs/ca.crt
         -cert "/etc/pail/grpc_certs/$ROBOT/client.crt"
         -key "/etc/pail/grpc_certs/$ROBOT/client.key")

PASS_N=0
pass() {
  PASS_N=$((PASS_N + 1))
  echo "PASS [$PASS_N] $*"
  printf 'PASS [%s] %s\n' "$PASS_N" "$*" >> "$STATE/evidence/verdicts.log"
}
fail() {
  echo "FAIL $*" >&2
  # Both services, because by stage B a failure can live on either side and a
  # dump of the wrong one reads as "nothing was wrong here".
  "${COMPOSE[@]}" logs --no-color --tail 80 pail-services pail-pep-gate > "$STATE/evidence/startup-errors.log" 2>&1 || true
  python3 "$ROOT/e2e/check_ports.py" --diagnose "$STATE/evidence/startup-errors.log" || true
  cat "$STATE/evidence/startup-errors.log"
  # Stage B evidence lives in files inside the gate container, and the EXIT trap
  # tears the stack down — dumped here or lost before anyone can read it.
  "${COMPOSE[@]}" exec -T pail-pep-gate bash -c '
    for f in /tmp/obs_*.log /tmp/feed_*.log /tmp/cmd_*.log; do
      [ -f "$f" ] || continue
      echo "--- $f ($(wc -l < "$f") lines)"; tail -8 "$f"
    done' 2>/dev/null || true
  exit 1
}

# Negative control for --keyring bundle. Called LAST on whichever path is
# running: it deliberately kills the issuer, and a killed issuer is only free
# once nothing else needs it.
forged_bundle_control() {
  [ "$KEYRING_MODE" = bundle ] || return 0
  local gone=0
  echo
  echo "-- forged bundle: a bundle signed by a DIFFERENT root must be refused"
  runtime_files forged
  "${COMPOSE[@]}" up -d --force-recreate pail-services > /dev/null 2>&1 || true
  # The container is expected to DIE. This waits for a state rather than
  # sleeping for a duration: a fixed sleep that is too short reads as "still
  # starting", which is the same bytes as "started fine".
  for _ in $(seq 1 30); do
    if ! "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx pail-services; then
      gone=1; break
    fi
    sleep 1
  done
  OUT="$("${COMPOSE[@]}" logs --tail 30 pail-services 2>&1)"
  # Put the good bundle back before judging: a FAIL exits from inside fail(),
  # and leaving a forged bundle on disk would make the NEXT run fail for a
  # reason that belongs to this one.
  runtime_files good
  [ "$gone" = 1 ] || { echo "$OUT"; fail "the issuer is still running on a forged keyring bundle"; }
  # Exiting is not the judgment — a missing file, a bad port or a typo in the
  # path all exit too. The refusal has to name the signature.
  case "$OUT" in
    *"root signature verification failed"*) : ;;
    *) echo "$OUT"; fail "the issuer refused, but not on the bundle signature — this measures nothing" ;;
  esac
  # Printed, not just matched: a PASS that names only the rule leaves the reader
  # trusting this script's grep. The line itself is the evidence.
  # Grepped on the string the case above already proved present, so this cannot
  # quietly print nothing the way a second, narrower pattern could.
  printf '%s\n' "$OUT" | grep "root signature verification failed" | head -1 | sed 's/^/   /'
  pass "forged keyring bundle refused at startup (root signature verification failed)"
}

# ── stage 0: build + keys + provisioning ───────────────────────────────────
cd "$ROOT"

echo "== early Docker-network port check (uses the services image; nothing is downloaded)"
python3 "$ROOT/e2e/check_ports.py" --image "$PAIL_E2E_SERVICES_IMAGE" --ports "${PAIL_NORTHBOUND_PORT:-50051}" "${PAIL_CLOUD_PORT:-50061}" --report "$STATE/evidence/ports-before-build.json" || exit 2

echo "== using verified local evaluation images (no build or pull)"

# Probe the SAME Docker host namespace used by this stack, not the macOS host.
# Recheck after the potentially long build; the earlier observation may be stale.
python3 "$ROOT/e2e/check_ports.py" --image "$PAIL_E2E_SERVICES_IMAGE" --ports "${PAIL_NORTHBOUND_PORT:-50051}" "${PAIL_CLOUD_PORT:-50061}" --report "$STATE/evidence/ports.json" || exit 2

echo "== isolated per-run configuration"
for file in policy.yaml site_model.example.yaml sros2_policy.xml skills.diff_drive_amr.yaml; do
  cp "$ROOT/config/$file" "$CONFIG/$file"
done
python3 scripts/gen_dev_keys.py --config-dir "$CONFIG"

# The standing context graph, staged where the compose mount can reach it
# (./config -> /etc/pail). This is not optional: without it the issuer runs
# CG1 and answers GetActiveToken with an EMPTY current_subgraph_hash, and one
# empty side makes the gate's world comparison indeterminate — so stage B
# would block every command while stage A still looked perfect.
echo "== site model (config/site_model.yaml <- e2e/site_model.yaml)"
cp "$ROOT/e2e/site_model.yaml" "$CONFIG/site_model.yaml"

# The KM2 trust path: instead of trusting config/keys/keyring.json because it is
# on disk, both processes trust a bundle because a root key signed it.
KR_ROOT="$STATE/keyring-root"
if [ "$KEYRING_MODE" = bundle ]; then
  # The root private key is minted OUTSIDE ./config. That directory is what the
  # containers mount, and a root key sitting in it would demonstrate the
  # opposite of what a root key is for — the whole point is that the signer is
  # somewhere the running system cannot reach.
  mkdir -p "$KR_ROOT"
  echo "== keyring bundle (KM2; root private key kept in $KR_ROOT, never mounted)"

  # The signer runs in the image: the public tree assumes no Go toolchain on
  # the host. It reads no network and takes no clock input beyond the payload.
  keyring_sign() {
    docker run --rm -u "$(id -u):$(id -g)" \
      -v "$CONFIG":/config -v "$KR_ROOT":/root-keys \
      --entrypoint pail-keyring-sign "$PAIL_E2E_SERVICES_IMAGE" "$@"
  }

  ROOT_PUB="$(keyring_sign gen-root --out /root-keys/root.json --key-id e2e-root-1 \
              | sed -n 's/^ROOT_PUBKEY_B64=//p')"
  [ -n "$ROOT_PUB" ] || { echo "gen-root did not print ROOT_PUBKEY_B64" >&2; exit 1; }
  printf '%s\n' "$ROOT_PUB" > "$CONFIG/keys/root_pub.b64"

  # A second root, whose public half nobody is given. The forged bundle below is
  # signed with it, so the negative control measures "signed by the wrong root"
  # — the failure an attacker can actually produce — rather than "corrupt
  # bytes", which any parser rejects and which proves nothing about signatures.
  keyring_sign gen-root --out /root-keys/root_evil.json --key-id e2e-root-evil > /dev/null

  # Payload = the dev keyring's entries, dated. bundle_version stays 1 across
  # runs: the loader keeps a monotonic floor in a volume that outlives the
  # stack, and re-reading the same version is a reload, not a rollback.
  python3 - "$CONFIG/keys/keyring.json" "$CONFIG/keys/payload.json" <<'PY'
import json, sys, time
now = int(time.time())
with open(sys.argv[1]) as f:
    keys = json.load(f)["keys"]
with open(sys.argv[2], "w") as f:
    json.dump({"bundle_version": 1, "issued_at_unix": now,
               "expires_at_unix": now + 86400, "keys": keys}, f, indent=2)
PY
  keyring_sign sign --root /root-keys/root.json --payload /config/keys/payload.json \
    --out /config/keys/keyring_bundle.json
  keyring_sign sign --root /root-keys/root_evil.json --payload /config/keys/payload.json \
    --out /config/keys/keyring_bundle.forged.json > /dev/null
  # Kept as the restore source: the negative control overwrites the live bundle.
  cp "$CONFIG/keys/keyring_bundle.json" "$CONFIG/keys/keyring_bundle.good.json"

  export PAIL_KEYRING_MODE=bundle
  export PAIL_KEYRING_BUNDLE=/etc/pail/keys/keyring_bundle.json
  export PAIL_ROOT_PUBKEY_FILE=/etc/pail/keys/root_pub.b64
  # No default exists for the ceiling: unset is a startup refusal, not
  # "unlimited". A week is longer than the 24 h payload above on purpose — the
  # ceiling is what bounds how late a revocation can land, not the expiry.
  export PAIL_KEYRING_MAX_LIFETIME_SEC="${PAIL_KEYRING_MAX_LIFETIME_SEC:-604800}"
  # Pulling is declared OFF, not left unset. Unset is a startup refusal
  # precisely because revocation reach is "bundle lifetime + poll interval" and
  # an unset term would let a bound be claimed that nobody chose. Off is the
  # honest value HERE: the puller would place the new bundle at
  # PAIL_KEYRING_BUNDLE, which in this stack is the read-only /etc/pail mount,
  # and there is no gate-restart command inside the container to apply it.
  # Rotation with pulling on is exercised elsewhere, not by this demo.
  export PAIL_KEYRING_POLL_SEC="${PAIL_KEYRING_POLL_SEC:-0}"
fi

echo "== provisioning (SROS2 keystore + mTLS certs + robot registry)"
# Provision as the manager UID, mounting source read-only and only this run config writable.
docker run --rm -v "$ROOT":/repo:ro -v "$CONFIG":/run-config -e HOME=/tmp -u "$HOST_UID:$HOST_GID" \
  --entrypoint bash "$PAIL_E2E_GATE_IMAGE" -lc \
  "source /opt/ros/humble/setup.bash && bash /repo/scripts/sros2_provision.sh /run-config $ROBOT" \
  || { echo "provisioning failed" >&2; exit 1; }

# Fresh journal/anchor state per run: a segment left over from an older key
# generation would fail chain verification for reasons that are not this
# run's — the judgment must measure THIS run.
# State was checked empty before provisioning; previous runs stay untouched.
cp "$CONFIG/keys/keyring.json" "$STATE/evidence/verification-keyring.json"
cp "$CONFIG/robot_registry.yaml" "$STATE/evidence/robot_registry.yaml"
runtime_files prepare > "$STATE/evidence/runtime-ownership.log" 2>&1 || { cat "$STATE/evidence/runtime-ownership.log"; exit 2; }
RUNTIME_READY=1
# Inspect and actually read as the service UID, never as the root preparer.
docker run --rm --network none -u 10001:10001 -v "$PAIL_E2E_CONFIG":/cfg:ro \
  -v "$STATE/blackbox":/bb -v "$STATE/anchor":/an \
  --entrypoint python3 "$PAIL_E2E_GATE_IMAGE" -c '
import os,stat
from pathlib import Path
for name in ["issuer_ed25519.json","agent_ed25519.json"]:
 p=Path("/cfg/keys")/name
 if stat.S_IMODE(p.stat().st_mode)!=0o600:raise SystemExit("Private key mode must be 0600; use a POSIX Linux state directory, not a Windows drive mount")
 with p.open("rb") as f:f.read(1)
for name in ["robot_registry.yaml","site_model.yaml","policy.yaml"]:
 with (Path("/cfg")/name).open("rb") as f:f.read(1)
for name in ["/bb","/an"]:
 p=Path(name)/".access-probe"
 with p.open("xb") as f:f.write(b"probe")
 p.unlink()
print("RUNTIME_ACCESS: PASS uid="+str(os.getuid()))
' > "$STATE/evidence/runtime-access.log" 2>&1 || { cat "$STATE/evidence/runtime-access.log"; exit 2; }
mkdir -p "$STATE/blackbox" "$STATE/anchor"

# ── stage A: cloud chain ────────────────────────────────────────────────────
# 60 s is the production anchor cadence; the demo should not stare at a wall
# clock for a minute to observe one record.
export PAIL_ANCHOR_INTERVAL_S="${PAIL_ANCHOR_INTERVAL_S:-2}"
# Checkpoint every 2 records instead of 1000: a 4-record demo run would
# otherwise verify a chain with ZERO checkpoints — the signature check would
# pass without ever firing.
export PAIL_CHECKPOINT_EVERY_RECORDS="${PAIL_CHECKPOINT_EVERY_RECORDS:-2}"



echo "== E2E-A: up pail-services"
"${COMPOSE[@]}" up -d pail-services

echo "-- waiting for the northbound ($NB_ADDR) to answer"
up=0
for _ in $(seq 1 30); do
  if "${COMPOSE[@]}" exec -T pail-services \
       get_active_token -addr "$NB_ADDR" -robot "$ROBOT" "${CLI_TLS[@]}" \
       > /dev/null 2>&1; then
    up=1; break
  fi
  sleep 1
done
[ "$up" = 1 ] || fail "service did not become ready in 30s"
pass "northbound up (get_active_token answered over mTLS)"

if [ "$KEYRING_MODE" = bundle ]; then
  # "It started" is not "it used the bundle": the issuer would also start on the
  # unsigned dev keyring, and the run below would look identical. The mode is
  # read from the line the loader prints, and keys=0 is a distinct value from a
  # line that never appeared.
  KRLOG="$("${COMPOSE[@]}" logs pail-services 2>&1 \
           | sed -n 's/.*\(keyring trust path: mode=[a-z-]* keys=[0-9]*\).*/\1/p' | head -1)"
  case "$KRLOG" in
    *"mode=bundle"*) : ;;
    *) fail "issuer did not load the signed bundle (read: ${KRLOG:-<no keyring trust path line>})" ;;
  esac
  pass "issuer trusts a root-signed keyring bundle ($KRLOG)"
fi

echo "-- submit_plan"
OUT="$("${COMPOSE[@]}" exec -T pail-services \
        submit_plan -addr "$NB_ADDR" -robot "$ROBOT" "${CLI_TLS[@]}" 2>&1)" \
  || fail "submit_plan: $OUT"
echo "$OUT"
case "$OUT" in *"status=ACCEPTED"*) : ;; *) fail "submit_plan did not print status=ACCEPTED" ;; esac
CHAIN_ID="$(printf '%s\n' "$OUT" | sed -n 's/.*chain_id=\([^ ]*\).*/\1/p' | head -1)"
TOKEN_ID="$(printf '%s\n' "$OUT" | sed -n 's/.*token_id=\([^ ]*\).*/\1/p' | head -1)"
[ -n "$CHAIN_ID" ] && [ -n "$TOKEN_ID" ] || fail "could not read chain_id/token_id from submit_plan output"
pass "plan accepted (status=ACCEPTED chain_id=$CHAIN_ID token_id=$TOKEN_ID)"

echo "-- get_active_token (read back what was issued)"
OUT="$("${COMPOSE[@]}" exec -T pail-services \
        get_active_token -addr "$NB_ADDR" -robot "$ROBOT" "${CLI_TLS[@]}" 2>&1)" \
  || fail "get_active_token: $OUT"
echo "$OUT"
case "$OUT" in
  *"chain_id=$CHAIN_ID"*) : ;;
  *) fail "active token does not carry the issued chain_id ($CHAIN_ID)" ;;
esac
pass "active token readable (same chain_id)"

echo "-- journal segments observed as the service UID"
seg="$("${COMPOSE[@]}" exec -T pail-services sh -c '
  test -r /var/log/pail_blackbox && test -x /var/log/pail_blackbox || exit 2
  n=0; for f in /var/log/pail_blackbox/*.seg; do [ ! -s "$f" ] || n=$((n + 1)); done
  printf "%s" "$n"
')" || fail "cannot examine journal as runtime UID"
[ "$seg" -ge 1 ] || fail "no non-empty segment under $STATE/blackbox"
pass "journal wrote $seg segment(s) under $STATE/blackbox"

echo "-- anchor records (file anchor, interval ${PAIL_ANCHOR_INTERVAL_S}s)"
anch=0
for _ in $(seq 1 30); do
  n="$("${COMPOSE[@]}" exec -T pail-services sh -c '
    test -r /var/lib/pail_anchor && test -x /var/lib/pail_anchor || exit 2
    n=0; for f in /var/lib/pail_anchor/anchor_*.json; do [ ! -e "$f" ] || n=$((n + 1)); done
    printf "%s" "$n"
  ')" || fail "cannot examine file anchor as runtime UID"
  if [ "$n" -ge 1 ]; then anch="$n"; break; fi
  sleep 1
done
[ "$anch" -ge 1 ] || fail "no anchor_*.json appeared under $STATE/anchor in 30s"
pass "anchor emitted $anch record(s) under $STATE/anchor"

echo "-- blackbox_verify (hash chain + checkpoint signatures)"
# Which public key the chain is verified AGAINST is the whole judgment. Under
# --vault the local key file is not the signer, so verifying with it would
# measure a key nothing used. The vault's public half is in the self-check
# keyring that vault-init wrote into the shared volume.
VERIFY_KEY=(-keyfile /etc/pail/keys/issuer_ed25519.json)
if [ "$VAULT" = 1 ]; then
  VAULT_PUB="$("${COMPOSE[@]}" exec -T pail-services sh -c \
    "grep -o '\"ed25519_public_key_base64\":\"[^\"]*\"' /pail-vault/keyring.json \
     | head -1 | sed 's/.*:\"//; s/\"$//'" 2>/dev/null | tr -d '\r')"
  [ -n "$VAULT_PUB" ] || fail "could not read the transit public key from /pail-vault/keyring.json"
  VERIFY_KEY=(-pubkey "$VAULT_PUB")
fi
# Exit 7: the newest records are not yet under a signed checkpoint. The Issuer
# covers them once its writes pause for about a second, so wait for that rather
# than accept records outside every signature.
for attempt in 1 2 3 4 5 6; do
  VRC=0
  OUT="$("${COMPOSE[@]}" exec -T pail-services \
          blackbox_verify --check-chain -dir /var/log/pail_blackbox \
          "${VERIFY_KEY[@]}" 2>&1)" || VRC=$?
  [ "$VRC" = 7 ] && [ "$attempt" != 6 ] || break
  sleep 1.5
done
[ "$VRC" = 0 ] || fail "blackbox_verify (rc=$VRC): $OUT"
echo "$OUT"
case "$OUT" in *"OK: chain verified"*) : ;; *) fail "blackbox_verify did not print 'OK: chain verified'" ;; esac
CKPTS="$(printf '%s\n' "$OUT" | sed -n 's/.*OK: chain verified (.*records, \([0-9]*\) checkpoints).*/\1/p' | head -1)"
# "verified with 0 checkpoints" means the signature check never fired — that
# is a vacuous pass, not a pass.
[ -n "$CKPTS" ] && [ "$CKPTS" -ge 1 ] || fail "chain verified but with $CKPTS checkpoints — signature check never fired"
pass "journal verifies against the issuer public key ($CKPTS checkpoint signature(s) checked)"

if [ "$VAULT" = 1 ]; then
  # ── vault judgments ───────────────────────────────────────────────────────
  # The pass above says the chain verifies against the key we handed it. On its
  # own that does not say WHICH key signed — the same PASS would print if the
  # local key had signed and we had handed it the local key. So the next step
  # hands it the OTHER key and requires a refusal.
  echo "-- signer identity: the same chain must NOT verify against the local dev key"
  if OUT="$("${COMPOSE[@]}" exec -T pail-services \
             blackbox_verify --check-chain -dir /var/log/pail_blackbox \
             -keyfile /etc/pail/keys/issuer_ed25519.json 2>&1)"; then
    echo "$OUT"
    fail "the journal ALSO verifies against the local dev key — the vault is not the signer"
  fi
  # A non-zero exit is not the judgment: a missing key file exits non-zero too,
  # and that would let "the tool could not find a key" stand in for "the wrong
  # key was rejected". The refusal has to name the signature.
  case "$OUT" in
    *"CHECKPOINT ed25519 signature invalid"*) : ;;
    *) echo "$OUT"; fail "the local key was refused, but not on the signature — this measures nothing" ;;
  esac
  pass "vault transit key is the signer (local dev key fails the checkpoint signature)"

  # Issuance is fail-closed on its signing backend: a vault that cannot be
  # reached must cost issuance, not produce an unsigned or locally-signed token.
  echo "-- vault outage: stopping the vault, then asking for a plan"
  "${COMPOSE[@]}" stop vault > /dev/null 2>&1 \
    || fail "could not stop the vault container"
  if OUT="$("${COMPOSE[@]}" exec -T pail-services \
             submit_plan -addr "$NB_ADDR" -robot "$ROBOT" "${CLI_TLS[@]}" 2>&1)" \
     && case "$OUT" in *"status=ACCEPTED"*) true ;; *) false ;; esac; then
    echo "$OUT"
    fail "a plan was ACCEPTED with the vault down — issuance is not fail-closed on its signer"
  fi
  echo "$OUT" | tail -3
  pass "issuance refused while the vault is down (fail-closed on the signing backend)"
fi

# Written as a statement, not `[ "$A_ONLY" = 1 ] && forged_bundle_control`:
# under `set -e` a trailing false test in an && list ends the script, so the
# one-line form would exit 0 here on every full run.
if [ "$A_ONLY" = 1 ]; then
  forged_bundle_control
fi

echo
if [ "$VAULT" = 1 ]; then
  echo "E2E-A GREEN (vault signer) — issue, read-back, journal, anchor, verify," \
       "signer identity, outage: $PASS_N judgments"
elif [ "$KEYRING_MODE" = bundle ]; then
  echo "E2E-A GREEN (signed keyring bundle) — issue, read-back, journal, anchor," \
       "verify: $PASS_N judgments"
else
  echo "E2E-A GREEN — issue, read-back, journal, anchor, verify: $PASS_N judgments"
fi

if [ "$A_ONLY" = 1 ]; then
  exit 0
fi

# ── stage B: enforcement (gate BLOCK -> PERMIT) ─────────────────────────────
# What this measures: motion is refused while nothing authorizes it, and the
# SAME token issued below is what the gate names when motion is allowed.
#
# Probes run inside the gate container — same image (ROS 2 plus the message
# types), same host network and IPC namespace (FastDDS carries same-host data
# over shared memory), same mounted keystore.
#
# Under ROS_SECURITY_STRATEGY=Enforce every participant needs an enclave, and
# the generated permissions grant rights per ENCLAVE (the node name does not
# appear in the grant), so a ros2 CLI probe borrows the enclave whose rights
# the probe legitimately needs:
#
#   /oem_planner     publish cmd_vel, subscribe pail/gate_state
#   /safety_adapter  publish pail/evidence, pail/safety_state
#   /motion_bridge   subscribe safe_cmd_vel
#
# On Humble the enclave is selected with ROS_SECURITY_ENCLAVE_OVERRIDE; the
# `--ros-args --enclave` form is rejected by the CLI's own argument parser
# before rcl ever sees it.
probe_bg() {  # enclave, shell command — detached inside the gate container
  "${COMPOSE[@]}" exec -d -e "ROS_SECURITY_ENCLAVE_OVERRIDE=$1" pail-pep-gate \
    bash -c "source /opt/ros/humble/setup.bash \
             && source /opt/pail_ws/install/setup.bash && $2"
}
in_gate() { "${COMPOSE[@]}" exec -T pail-pep-gate bash -c "$1"; }
count_in_gate() { in_gate "grep -c '$1' '$2' 2>/dev/null || true" | tr -d '\r' | head -1; }

echo
echo "== E2E-B: enforcement (BLOCK -> PERMIT)"

# Stage A left an ACTIVE token (1 h TTL, 5 steps). With it alive the gate would
# PERMIT the first command and the BLOCK half would be unobservable — so the
# issuer is restarted (issuance is ephemeral without a site model) and the
# clearing is JUDGED, not assumed.
echo "-- restarting the issuer so nothing authorizes motion yet"
"${COMPOSE[@]}" restart pail-services > /dev/null
up=0
for _ in $(seq 1 30); do
  if OUT="$("${COMPOSE[@]}" exec -T pail-services \
             get_active_token -addr "$NB_ADDR" -robot "$ROBOT" "${CLI_TLS[@]}" 2>&1)"; then
    up=1; break
  fi
  sleep 1
done
[ "$up" = 1 ] || fail "issuer did not come back after restart"
echo "$OUT"
case "$OUT" in *"status=NO_TOKEN"*) : ;; *) fail "issuer restarted but still reports a token" ;; esac
pass "issuer holds no token (status=NO_TOKEN) — the BLOCK below is observable"

# The gate dials the issuer; this must move with any port override exactly as
# the CLIs above did.
export PAIL_TOKEN_SERVICE_ADDR="$NB_ADDR"
echo "-- up pail-pep-gate (SROS2 Enforce)"
"${COMPOSE[@]}" up -d pail-pep-gate

echo "-- waiting for the gate to seal its configuration"
# >>> wait_gate_seal
# Sets SEAL="config seal vN digest=<hex>" (the identifier the PASS below names and
# e2e/check_samples.py reads) and SEAL_SOURCE=gate-log|issuer-record, or returns 1.
#
# Why not `compose logs | grep -q` once a second (the previous wait): on a loaded
# host (preview.39 Mac replay run1, 2026-10-28) 90 such polls missed a seal the
# gate had logged 2 s after start — the line was in the full log captured at
# cleanup, with its own timestamp. A poll whose `compose logs` errors or returns
# short under load reads as "not yet" when its stderr is folded into the grep, and
# an iteration count is not a time bound. This wait
#   1. streams the gate log once (`logs -f`) into a file and reads that file,
#   2. also accepts the issuer's own record of the gate's SealConfig RPC — the
#      gate sends it right after sealing and the issuer journals CONFIG_SEALED
#      — counting only records newer than the baseline taken before `up`,
#   3. is bounded by wall time (PAIL_E2E_SEAL_TIMEOUT, default 90 s), and
#   4. keeps every poll error in evidence/gate-seal-wait.err and names both
#      sources on timeout, so a false negative is diagnosable rather than silent.
wait_gate_seal() {
  local baseline=${1:-0} timeout="${PAIL_E2E_SEAL_TIMEOUT:-90}" t0=$SECONDS iss="" n=0
  local glog="$STATE/evidence/gate-seal-wait.log" gerr="$STATE/evidence/gate-seal-wait.err"
  : > "$glog"; : > "$gerr"
  "${COMPOSE[@]}" logs -f --no-color --no-log-prefix pail-pep-gate >> "$glog" 2>> "$gerr" &
  local tail_pid=$!
  SEAL=""; SEAL_SOURCE=""
  sleep 0.5   # let the stream deliver what the gate already printed before the first read
  while [ $((SECONDS - t0)) -lt "$timeout" ]; do
    SEAL="$(sed -n 's/.*\(config seal v[0-9]* digest=[0-9a-f]*\).*/\1/p' "$glog" 2>/dev/null | head -1)"
    if [ -n "$SEAL" ]; then SEAL_SOURCE=gate-log; break; fi
    if iss="$("${COMPOSE[@]}" logs --no-color --no-log-prefix pail-services 2>> "$gerr")"; then
      n="$(printf '%s\n' "$iss" | grep -c "TokenService\.SealConfig robot_id=$ROBOT component=pep_gate .*verdict=SEALED" || true)"
      if [ "$n" -gt "$baseline" ]; then
        SEAL="$(printf '%s\n' "$iss" \
          | sed -n "s/.*TokenService\.SealConfig robot_id=$ROBOT component=pep_gate seal_v=\([0-9]*\) digest=\([0-9a-f]*\) .*verdict=SEALED.*/config seal v\1 digest=\2/p" \
          | tail -1)"
        [ -z "$SEAL" ] || { SEAL_SOURCE=issuer-record; break; }
      fi
    else
      printf '%ss: issuer log poll failed rc=%s\n' "$((SECONDS - t0))" "$?" >> "$gerr"
    fi
    sleep 1
  done
  kill "$tail_pid" 2>/dev/null || true
  wait "$tail_pid" 2>/dev/null || true
  if [ -z "$SEAL" ]; then
    echo "seal wait: neither the gate log stream ($(wc -l < "$glog" | tr -d ' ') lines in $glog) nor the issuer's SealConfig record for $ROBOT/pep_gate (records=$n baseline=$baseline) showed a seal in ${timeout}s; poll errors: $(wc -l < "$gerr" | tr -d ' ') (see $gerr)" >&2
    return 1
  fi
}
# <<< wait_gate_seal
SEAL_BASELINE=0
wait_gate_seal "$SEAL_BASELINE" || fail "gate did not report a config seal in ${PAIL_E2E_SEAL_TIMEOUT:-90}s (gate log stream and issuer record both silent)"
echo "   seal observed via $SEAL_SOURCE"
pass "gate up under SROS2 Enforce ($SEAL)"

if [ "$KEYRING_MODE" = bundle ]; then
  # The gate is the asymmetric half: where the issuer refuses to start, the gate
  # WARNs and comes up with an empty trust map — so a bundle it failed to load
  # produces a running gate that rejects every token, which stage B would report
  # as an enforcement result rather than a trust-path failure.
  # The trust-path line precedes the seal in the gate's startup, so the streamed
  # log of the wait above has it; a fresh read is only the fallback.
  GKR="$(sed -n 's/.*\(keyring trust path: mode=[a-z-]* keys=[0-9]* revoked=[0-9]*\).*/\1/p' \
         "$STATE/evidence/gate-seal-wait.log" 2>/dev/null | head -1)"
  [ -n "$GKR" ] || GKR="$("${COMPOSE[@]}" logs --no-color pail-pep-gate 2>&1 \
         | sed -n 's/.*\(keyring trust path: mode=[a-z-]* keys=[0-9]* revoked=[0-9]*\).*/\1/p' | head -1)"
  case "$GKR" in
    *"mode=bundle"*) : ;;
    *) fail "gate did not load the signed bundle (read: ${GKR:-<no keyring trust path line>})" ;;
  esac
  pass "gate trusts the same root-signed bundle ($GKR)"
fi

# Feeders. Both windows are short (policy: safety 1000 ms, evidence 2000 ms) and
# both are judged on the message stamp, so this is a stamping node rather than
# `ros2 topic pub` — see e2e/feeders.py for why an unstamped feed blocks forever
# in a way that reads like a correct refusal.
echo "-- feeders: /pail/safety_state (level OK) + /pail/evidence (RFID 880123 @0.99)"
# Piped in rather than `compose cp`, which lands the file owned by root while
# the gate runs unprivileged — the feeder then dies on open() and its silence
# is indistinguishable from a world the gate refused to trust.
"${COMPOSE[@]}" exec -T pail-pep-gate bash -c 'cat > /tmp/feeders.py' \
  < "$ROOT/e2e/feeders.py" || fail "could not stage e2e/feeders.py in the gate container"
probe_bg /safety_adapter "python3 /tmp/feeders.py > /tmp/feed_world.log 2>&1"
sleep 3
in_gate "pgrep -f '/tmp/feeders.py' > /dev/null" \
  || { in_gate "cat /tmp/feed_world.log" || true; fail "the world feeder is not running"; }
pass "world feeder live (stamped safety + evidence at 5 Hz)"

# --no-daemon: `ros2 topic echo` resolves the message type through the shared
# ros2 CLI daemon, and the daemon keeps the enclave of whichever command
# started it — so a daemon would let the "bridge" observer read the graph with
# the planner's authorization and quietly void the distinction being measured.
# --spin-time: with its own participant the echo must complete an SROS2
# handshake before it can resolve the type, and the default window is too short
# — it then exits 0 with an empty log, which reads exactly like "the gate
# published nothing".
ECHO_OPTS="--no-daemon --spin-time 12"
echo "-- observers: /pail/gate_state (as planner) + /safe_cmd_vel (as bridge)"
probe_bg /oem_planner   "ros2 topic echo $ECHO_OPTS /pail/gate_state > /tmp/obs_gate_state.log 2>&1"
probe_bg /motion_bridge "ros2 topic echo $ECHO_OPTS /safe_cmd_vel   > /tmp/obs_safe_cmd_vel.log 2>&1"

# A new SROS2 participant's handshake takes seconds; commanding before the
# observers have matched would measure the handshake, not the gate.
sleep 14

# Prove the observers exist before anything is judged on what they did not see.
for f in obs_gate_state obs_safe_cmd_vel; do
  if in_gate "grep -q 'does not appear to be published yet' /tmp/$f.log" 2>/dev/null; then
    fail "observer $f never resolved its topic type — it is not watching anything"
  fi
done
ECHO_N="$(in_gate "pgrep -fc 'bin/ros2 topic echo' || true" | tr -d '\r' | head -1)"
[ "${ECHO_N:-0}" -ge 2 ] || fail "expected 2 live observers, found ${ECHO_N:-0}"
pass "both observers live, each under its own enclave (planner, bridge)"

# ---- B-1: BLOCK (nothing authorizes motion) --------------------------------
echo "-- commanding /cmd_vel with no token (6 s)"
probe_bg /oem_planner \
  "timeout 6 ros2 topic pub -r 10 /cmd_vel geometry_msgs/msg/Twist \
   '{linear: {x: 0.1}}' > /tmp/cmd_block.log 2>&1"
sleep 9

BLOCK_N="$(count_in_gate 'reason: ERR_NO_TOKEN' /tmp/obs_gate_state.log)"
STATE_N="$(count_in_gate 'state: BLOCK' /tmp/obs_gate_state.log)"
# Judged on what the gate PRINTED, not on what failed to arrive: an absent
# /safe_cmd_vel is the same bytes as a gate that never started, a probe that
# never published, and a transport that dropped the data.
if [ "${BLOCK_N:-0}" -lt 1 ] || [ "${STATE_N:-0}" -lt 1 ]; then
  in_gate "tail -5 /tmp/cmd_block.log /tmp/obs_gate_state.log" || true
  fail "no BLOCK/ERR_NO_TOKEN on /pail/gate_state (state=$STATE_N reason=$BLOCK_N)"
fi
# Held for the final judgment: this count only means something once the SAME
# observer has been proven to see traffic (below).
SAFE_AT_BLOCK="$(count_in_gate '^---$' /tmp/obs_safe_cmd_vel.log)"
pass "command refused with no authorization (state=BLOCK reason=ERR_NO_TOKEN x$BLOCK_N)"

# ---- B-2: PERMIT (token issued, evidence + safety live) --------------------
# Stage A's operation (submit_plan's default plan/operation id) is COMMITTED in
# the issuer's durable operation journal, and that journal outlives the restart
# above. Under the core-comm v1 contract a repeat of a committed operation id is
# answered with its historical receipt — the original chain_id and NO token list
# (operation_outcome=HISTORICAL_ONLY) — never with a fresh token. That is judged
# first, on what the CLI printed; the motion below is then authorized as a NEW
# operation under its own id.
echo "-- submit_plan again under stage A's operation id (history expected, not a token refresh)"
OUT="$("${COMPOSE[@]}" exec -T pail-services \
        submit_plan -addr "$NB_ADDR" -robot "$ROBOT" "${CLI_TLS[@]}" 2>&1)" \
  || fail "submit_plan (stage A operation id, repeated): $OUT"
echo "$OUT"
case "$OUT" in
  *"operation_outcome=HISTORICAL_ONLY"*"chain_id=$CHAIN_ID "*"tokens=0 "*) : ;;
  *) fail "repeating the committed operation did not return its historical receipt (expected chain_id=$CHAIN_ID, tokens=0)" ;;
esac
pass "repeated operation id answered with history only (chain_id=$CHAIN_ID tokens=0), no token refresh"

B_PLAN="pvs-plan-e2e-b"
echo "-- submit_plan -plan $B_PLAN (target 880123 — the object the evidence feeder claims)"
OUT="$("${COMPOSE[@]}" exec -T pail-services \
        submit_plan -addr "$NB_ADDR" -robot "$ROBOT" -plan "$B_PLAN" "${CLI_TLS[@]}" 2>&1)" \
  || fail "submit_plan (stage B): $OUT"
echo "$OUT"
case "$OUT" in *"operation_outcome=AUTHORIZED"*) : ;; *) fail "stage B submit_plan was not AUTHORIZED (new operation $B_PLAN)" ;; esac
B_TOKEN="$(printf '%s\n' "$OUT" | sed -n 's/.*token_id=\([^ ]*\).*/\1/p' | head -1)"
[ -n "$B_TOKEN" ] || fail "could not read token_id from the stage B submit_plan"

echo "-- commanding /cmd_vel under that token (6 s)"
probe_bg /oem_planner \
  "timeout 6 ros2 topic pub -r 10 /cmd_vel geometry_msgs/msg/Twist \
   '{linear: {x: 0.1}}' > /tmp/cmd_permit.log 2>&1"
sleep 9

PERMIT_N="$(count_in_gate "active_token_id: $B_TOKEN" /tmp/obs_gate_state.log)"
# The identifier is the point: "something was permitted" is not "the token I
# just issued is what authorized this motion".
if [ "${PERMIT_N:-0}" -lt 1 ]; then
  in_gate "tail -20 /tmp/obs_gate_state.log; tail -5 /tmp/cmd_permit.log" || true
  fail "gate never named the issued token ($B_TOKEN) on /pail/gate_state"
fi
pass "gate permitted under the issued token (active_token_id=$B_TOKEN x$PERMIT_N)"

SAFE_AT_PERMIT="$(count_in_gate '^---$' /tmp/obs_safe_cmd_vel.log)"
SAFE_DELTA=$(( ${SAFE_AT_PERMIT:-0} - ${SAFE_AT_BLOCK:-0} ))
if [ "$SAFE_DELTA" -lt 1 ]; then
  in_gate "tail -5 /tmp/obs_safe_cmd_vel.log" || true
  fail "no motion reached /safe_cmd_vel under a valid permit (delta=$SAFE_DELTA)"
fi
pass "motion reached /safe_cmd_vel under the permit ($SAFE_DELTA message(s))"

# Only now is the BLOCK-window silence evidence: the same observer, the same
# process, the same subscription has since been proven to see this topic.
[ "${SAFE_AT_BLOCK:-0}" = 0 ] \
  || fail "motion had already reached /safe_cmd_vel during the BLOCK window ($SAFE_AT_BLOCK)"
pass "no motion passed during the BLOCK window (observer proven live afterwards)"

echo
echo "E2E-B GREEN — refused without authorization, permitted under the issued token"

# Last, and only under --keyring bundle: it takes the issuer down for good.
forged_bundle_control

echo
echo "E2E GREEN — $PASS_N judgments, each naming the identifier it read$( [ "$E2E_PLATFORM_NOTE" = native ] || printf ' (%s; not a measurement of the bundle architecture)' "$E2E_PLATFORM_NOTE")"
