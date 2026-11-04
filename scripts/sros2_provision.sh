#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

# PAIL provisioning (LLD-v2 §3, HLD-v2 §2.1 + implementation contract `DC-1`):
#   1) SROS2 keystore + **세 신뢰근 분리** + per-node enclaves + permissions
#   2) gRPC mTLS server cert + **per-robot** client certs signed by a **separate** CA
#   3) robot_registry.yaml co-emitted with issuance — sha256(leaf DER) → robot_id
#
# Requires ros2 + sros2 + openssl. Typical run (repo mounted into pep_gate image):
#   docker run --rm -v "$PWD":/repo --entrypoint bash pail/pep_gate:dev -lc \
#     "source /opt/ros/humble/setup.bash && /repo/scripts/sros2_provision.sh /repo/config robot-1"
set -euo pipefail

# --- 0) 로봇 목록 — 프로비저닝에 닿기 전에 거부한다 (§2.2 ①) ----------------
#
# 인자 없는 호출이 예전처럼 공유 인증서 한 장을 내는 것이 가장 위험한 실패다:
# 조용히 옛 상태로 복귀하고, caller_id(지문)는 함대 상수가 된다(§1.1). 그래서
# 목록이 비면 **아무것도 만들기 전에** 죽는다. "개발 중에는 공유 인증서 허용"
# 스위치는 만들지 않는다 — `O-2` 위반이고, 그 스위치가 공개본의 기본 사용법이
# 된다(`C-B10`). 개발 편의는 로봇 1대짜리 레지스트리로 충분하다(§2.2 ③).
CONFIG_DIR="${1:-}"
shift || true
ROBOTS=("$@")
if [ -z "$CONFIG_DIR" ] || [ "${#ROBOTS[@]}" -eq 0 ]; then
  echo "ERROR: robot list required; certificates are issued per robot, not only per role" >&2
  echo "usage: $(basename "$0") <config_dir> <robot_id> [<robot_id>...]" >&2
  echo "  per-robot cert: <config_dir>/grpc_certs/<robot_id>/client.{key,crt}  (CN=pail-robot-<robot_id>)" >&2
  echo "  registry:       <config_dir>/robot_registry.yaml  (sha256(leaf DER) to robot_id, generated with certificates)" >&2
  exit 64
fi
for rid in "${ROBOTS[@]}"; do
  case "$rid" in
    *[!A-Za-z0-9._-]*)
      echo "ERROR: invalid robot_id '$rid' (allowed: A-Za-z0-9._-)" >&2
      exit 64 ;;
  esac
done

KEYSTORE="$CONFIG_DIR/sros2_keystore"
POLICY="$CONFIG_DIR/sros2_policy.xml"
GRPC_DIR="$CONFIG_DIR/grpc_certs"
REGISTRY="$CONFIG_DIR/robot_registry.yaml"
if [ ! -f "$POLICY" ]; then
  echo "ERROR: policy not found: $POLICY" >&2
  exit 1
fi

# enclave 목록은 **정책에서 유도한다**. 예전에는 여기에 배열로 한 벌이 더 있었고,
# 그러면 두 목록이 조용히 어긋난다 — 정책에만 있으면 인증서가 없어 그 노드가
# 기동조차 못 하고, 배열에만 있으면 create_permission 이 "unable to find enclave"
# 로 죽는다. 어느 쪽도 "정책을 고쳤는데 왜 안 되지"로 읽힌다. 관리하지 말고
# 범주를 없앤다 (B5-2, 2026-08-21).
#
# 빈 목록은 성공이 아니라 실패다: 루프가 0회 돌면 아무 enclave 도 안 만들어진
# 채로 스크립트가 rc=0 을 낸다 — "권한을 다 발급했다"와 바이트가 같다.
# 프로세스 치환(`< <(...)`)으로 읽으면 파서가 죽어도 mapfile 이 rc=0 을 내서
# **부분 목록이 완전한 목록처럼** 통과한다. 명령 치환은 종료코드를 대입에
# 전파하므로 그쪽을 쓴다.
ENCLAVE_LIST="$(python3 - "$POLICY" <<'PY'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
for e in root.iter('enclave'):
    p = (e.get('path') or '').strip()
    if not p.startswith('/') or p.count('/') != 1 or p == '/':
        sys.exit(f"ERROR: 다룰 수 없는 enclave path: {p!r}")
    print(p[1:])
PY
)" || { echo "ERROR: cannot read enclave list from policy: $POLICY" >&2; exit 1; }

if [ -z "$ENCLAVE_LIST" ]; then
  echo "ERROR: policy contains no enclaves: $POLICY" >&2
  exit 1
fi
ENCLAVES=()
while IFS= read -r _e; do
  [ -n "$_e" ] && ENCLAVES+=("$_e")
done <<< "$ENCLAVE_LIST"
echo "policy enclaves (${#ENCLAVES[@]}): ${ENCLAVES[*]}"

# --- 1) SROS2 keystore ------------------------------------------------------
if [ ! -f "$KEYSTORE/public/ca.cert.pem" ] && [ ! -f "$KEYSTORE/public/identity_ca.cert.pem" ]; then
  ros2 security create_keystore "$KEYSTORE"
fi

# --- 1b) 신뢰근 분리 — identity / permissions (기준선 `L3`) -------------------
#
# `ros2 security create_keystore` 는 CA 를 **한 장** 만들고 `identity_ca` 와
# `permissions_ca` 를 그 파일을 가리키는 심볼릭 링크로 놓는다 — inode 하나,
# 이름 셋. 그래서 「신뢰 루트 분리」는 도입사가 고르기 전에 이미 깨져 있었다.
# 도입사가 다르게 할 수 없는 것은 위임이 아니므로, 분리를 여기서 만든다
# (실측: tests/integration/ossba/EVIDENCE_L3_TRUST_ROOT.md).
#
# 링크를 **따라가면 안 된다.** 따라가면 두 뿌리에 각각 쓰는 두 번의 쓰기가 같은
# inode 에 착지해 뒤가 앞을 지우고, 결과는 "여전히 동일" 로 나온다 — 실제로 이
# 측정을 한 번 그렇게 망쳤다. `rm` 은 링크를 따라가지 않으므로 링크 자체가 지워진다.
ID_CERT="$KEYSTORE/public/identity_ca.cert.pem"
ID_KEY="$KEYSTORE/private/identity_ca.key.pem"
PM_CERT="$KEYSTORE/public/permissions_ca.cert.pem"
PM_KEY="$KEYSTORE/private/permissions_ca.key.pem"

sha_of() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }

# issue_root <cert> <key> <cn>
issue_root() {
  local cert="$1" key="$2" cn="$3"
  rm -f "$cert" "$key"
  mkdir -p "$(dirname "$cert")" "$(dirname "$key")"
  openssl ecparam -name prime256v1 -genkey -noout -out "$key"
  openssl req -new -x509 -key "$key" -subj "/CN=$cn" -days 3650 -sha256 -out "$cert" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  chmod 600 "$key"
  echo "trust root issued: ${cert#"$CONFIG_DIR/"} (CN=$cn)"
}

roots_collapsed() {
  if [ -L "$ID_CERT" ] || [ -L "$PM_CERT" ] || [ -L "$ID_KEY" ] || [ -L "$PM_KEY" ]; then
    return 0
  fi
  if [ ! -f "$ID_CERT" ] || [ ! -f "$PM_CERT" ] || [ ! -f "$ID_KEY" ] || [ ! -f "$PM_KEY" ]; then
    return 0
  fi
  [ "$(sha_of "$ID_CERT")" = "$(sha_of "$PM_CERT")" ]
}

if roots_collapsed; then
  # 이미 발급된 enclave 인증서가 있는데 뿌리를 갈아 끼우면 그 인증서들이 조용히
  # 무효가 되고, 실패는 프로비저닝이 아니라 몇 시간 뒤 기동에서 나타난다.
  # 조용히 이어 가지 않는다 — 붕괴한 keystore 는 사람이 처분한다.
  if compgen -G "$KEYSTORE/enclaves/*/cert.pem" > /dev/null; then
    echo "ERROR: existing enclave certificates use collapsed trust roots (identity_ca == permissions_ca)" >&2
    echo "  Splitting these roots would invalidate existing certificates; do not silently reuse them." >&2
    echo "  fix: preserve the existing deployment and provision a new configuration directory with fresh certificates and registry." >&2
    exit 1
  fi
  issue_root "$ID_CERT" "$ID_KEY" sros2IdentityCA
  issue_root "$PM_CERT" "$PM_KEY" sros2PermissionsCA
  # `create_keystore` 가 만든 governance.p7s 는 **옛** permissions CA 로 서명돼
  # 있다. 새 뿌리로 다시 서명하지 않으면 참가자가 governance 를 못 읽고, 그
  # 실패도 프로비저닝이 아니라 기동에서 나타난다.
  if [ -f "$KEYSTORE/enclaves/governance.xml" ]; then
    openssl smime -sign -text -in "$KEYSTORE/enclaves/governance.xml" \
      -signer "$PM_CERT" -inkey "$PM_KEY" -out "$KEYSTORE/enclaves/governance.p7s"
    echo "governance re-signed by the new permissions CA"
  fi
  # 링크가 가리키던 단일 CA 는 이제 아무도 신뢰하지 않는다. 남겨 두면 개인키를
  # 가진 **넷째 뿌리**가 되고, 다음 사람이 링크를 되살리는 자리가 된다.
  rm -f "$KEYSTORE/public/ca.cert.pem" "$KEYSTORE/private/ca.key.pem"
else
  echo "trust roots already separated, keeping: identity_ca ≠ permissions_ca"
fi

for e in "${ENCLAVES[@]}"; do
  ros2 security create_enclave "$KEYSTORE" "/$e"
  ros2 security create_permission "$KEYSTORE" "/$e" "$POLICY"
  echo "enclave /$e provisioned"
done

# --- 2) gRPC mTLS — **세 번째 뿌리** (기준선 `L3`) ----------------------------
#
# 옛 절차는 SROS2 CA 를 `grpc_certs/ca.crt` 로 **복사하고** 그 CA 로 리프를
# 서명했다. 제어 평면과 DDS 가 같은 뿌리에 매달리므로, 한 뿌리가 무너지면 둘이
# 함께 무너진다. 여기서는 gRPC 가 자기 뿌리를 갖는다 — 복사하지 않는다.
CA_CERT="$GRPC_DIR/ca.crt"
CA_KEY="$GRPC_DIR/ca.key"

mkdir -p "$GRPC_DIR"
if [ -L "$CA_CERT" ] || [ -L "$CA_KEY" ]; then
  echo "ERROR: CA material in $GRPC_DIR is a symlink; linked roots are not independent" >&2
  exit 1
fi
if [ -f "$CA_CERT" ]; then
  for r in "$ID_CERT" "$PM_CERT"; do
    if [ "$(sha_of "$CA_CERT")" = "$(sha_of "$r")" ]; then
      echo "ERROR: grpc_certs/ca.crt equals an SROS2 root; the control-plane CA must be independent" >&2
      echo "  fix: preserve existing configuration and provision a new directory; regenerate the matching registry." >&2
      exit 1
    fi
  done
else
  issue_root "$CA_CERT" "$CA_KEY" pail-grpc-CA
fi
if [ ! -f "$CA_KEY" ]; then
  echo "ERROR: $CA_KEY is missing; cannot issue leaves without the CA signing key" >&2
  exit 1
fi

# issue_leaf <dir> <basename> <cn> <eku> <san>
#
# EKU 를 역할별로 가른다 — 옛 발급은 server/client 양쪽에
# serverAuth,clientAuth 를 함께 줘서 클라이언트 인증서가 유효한 서버
# 인증서였다(crypto360 S4 실측). 신원 재료를 나누면서 역할도 나눈다.
issue_leaf() {
  local dir="$1" base="$2" cn="$3" eku="$4" san="$5"
  if [ -f "$dir/$base.crt" ] && [ -f "$dir/$base.key" ]; then
    echo "grpc cert exists, keeping: $dir/$base.crt"
    return 0
  fi
  mkdir -p "$dir"
  openssl ecparam -name prime256v1 -genkey -noout -out "$dir/$base.key"
  openssl req -new -key "$dir/$base.key" -subj "/CN=$cn" -out "$dir/$base.csr"
  openssl x509 -req -in "$dir/$base.csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -set_serial "0x$(openssl rand -hex 8)" \
    -days 3650 -sha256 -out "$dir/$base.crt" \
    -extfile <(printf '%bkeyUsage=digitalSignature\nextendedKeyUsage=%s\n' "$san" "$eku")
  rm -f "$dir/$base.csr"
  chmod 600 "$dir/$base.key"
  echo "grpc cert issued: $dir/$base.crt (CN=$cn, EKU=$eku, signed by the gRPC CA)"
}

# TB3 실기(B4): 클라우드가 다른 호스트에 있으면 SAN 이 그 주소를 이름해야
# 한다 — 단일호스트 기본값만 있으면 원격 dial 이 호스트명 검증에서 죽는다.
issue_leaf "$GRPC_DIR" server pail-server serverAuth \
  "subjectAltName=${PAIL_SERVER_SAN:-DNS:localhost,IP:127.0.0.1}\n"

# --- 3) 로봇별 client 인증서 + 레지스트리 동시 산출 (§2.2 ①·②) --------------
#
# 발급과 등록이 분리되면 등록을 잊은 인증서가 unbound 로 거부되고, 운영자는
# 원인을 인증서가 아니라 인터셉터에서 찾는다(R-C1). 그래서 등록은 별도 절차가
# 아니라 발급의 일부다. 이미 등록된 지문(재실행·기존 인증서)은 건너뛴다 —
# 같은 robot_id 의 새 지문은 새 행으로 쌓인다(회전 공존, §2.3 DC-3 1:N).
if [ ! -f "$REGISTRY" ]; then
  {
    echo "# generated by scripts/sros2_provision.sh — fingerprint = sha256(leaf DER), 64 hex characters"
    echo "version: 1"
    echo "robots:"
  } > "$REGISTRY"
fi
for rid in "${ROBOTS[@]}"; do
  issue_leaf "$GRPC_DIR/$rid" client "pail-robot-$rid" clientAuth ''
  fp="$(openssl x509 -in "$GRPC_DIR/$rid/client.crt" -outform DER | openssl dgst -sha256 | awk '{print $NF}')"
  if grep -q "\"$fp\"" "$REGISTRY"; then
    echo "registry: $rid fingerprint already registered"
  else
    {
      echo "  - robot_id: $rid"
      echo "    role: robot"
      echo "    fingerprints:"
      echo "      - \"$fp\""
    } >> "$REGISTRY"
    echo "registry: $rid registered fp=${fp:0:16}…"
  fi
done

# --- 4) 개인키 퍼미션 (implementation contract `F-KEY-07`) --------------------------
#
# 위 `chmod 600` 은 자기가 방금 만든 gRPC 키만 본다. `ros2 security` 가
# 만드는 CA 개인키와 enclave `key.pem` 은 umask 대로 떨어지고 아무도 좁히지
# 않았다 — §1.3 이 `0644` 로 실측한 자리다. 생성기가 좁히지 않으면 배포
# 스크립트가 매번 넓은 원본에서 복사하게 된다.
KEYMODE_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_keymode.sh"
# shellcheck source=scripts/_keymode.sh
. "$KEYMODE_LIB"
pail_narrow_private_keys "$KEYSTORE" "$GRPC_DIR"
pail_assert_private_key_modes "$CONFIG_DIR/" "$KEYSTORE" "$GRPC_DIR"

# --- 5) 분리 단언 (기준선 `L3`) ----------------------------------------------
#
# 위 절차가 분리를 **만들려고 했다**는 것과 이 트리가 지금 분리돼 **있다**는 것은
# 다르다. 절차 쪽만 읽으면 절차가 조용히 건너뛰어진 경우가 통과로 보인다. 그래서
# 결과에서 다시 잰다 — 그리고 뿌리마다 따로 잰다(`H-B9`): 셋을 한 줄로 재면 어느
# 쌍이 붙었는지가 사라지고, 사라진 자리는 "확인했고 정상" 과 같은 침묵이 된다.
ROOT_BAD=0
ID_FP="$(sha_of "$ID_CERT")"
PM_FP="$(sha_of "$PM_CERT")"
GR_FP="$(sha_of "$CA_CERT")"
echo "trust roots:"
echo "  identity_ca    ${ID_FP:0:16}…  ${ID_CERT#"$CONFIG_DIR/"}"
echo "  permissions_ca ${PM_FP:0:16}…  ${PM_CERT#"$CONFIG_DIR/"}"
echo "  grpc_ca        ${GR_FP:0:16}…  ${CA_CERT#"$CONFIG_DIR/"}"
if [ "$ID_FP" = "$PM_FP" ]; then
  echo "FATAL: identity_ca == permissions_ca; identity and authorization roots must be distinct" >&2
  ROOT_BAD=1
fi
if [ "$ID_FP" = "$GR_FP" ]; then
  echo "FATAL: identity_ca == grpc_ca; DDS identity and control-plane roots must be distinct" >&2
  ROOT_BAD=1
fi
if [ "$PM_FP" = "$GR_FP" ]; then
  echo "FATAL: permissions_ca == grpc_ca; authorization and control-plane roots must be distinct" >&2
  ROOT_BAD=1
fi
# 뿌리를 갈았는데 옛 뿌리로 서명된 리프가 남아 있으면, 실패는 여기가 아니라 첫
# 핸드셰이크에서 나타난다. 발급 절차는 기존 리프를 보존하므로 이 자리가 필요하다.
LEAVES=("$GRPC_DIR/server.crt")
for rid in "${ROBOTS[@]}"; do LEAVES+=("$GRPC_DIR/$rid/client.crt"); done
for leaf in "${LEAVES[@]}"; do
  if ! openssl verify -CAfile "$CA_CERT" "$leaf" > /dev/null 2>&1; then
    echo "FATAL: ${leaf#"$CONFIG_DIR/"} does not verify under the gRPC CA; certificate and root do not match" >&2
    ROOT_BAD=1
  fi
done
if [ "$ROOT_BAD" -ne 0 ]; then
  echo "  fix: preserve existing configuration and provision a new configuration directory." >&2
  exit 1
fi

echo "OK: keystore=$KEYSTORE grpc_certs=$GRPC_DIR registry=$REGISTRY robots=${ROBOTS[*]}"
