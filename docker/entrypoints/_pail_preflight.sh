# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd

# shellcheck shell=bash
# BG 배치 보안 게이트 (PAIL-BG-LLD-v1 §3). ROS 엔트리포인트가 exec 직전에 source 한다.
# 검사: S0(프로파일) S1(보안 on) S2(Enforce) S3(keystore enclave).
# production(기본값)에서 위반 = exit 78(EX_CONFIG). dev = 배너 출력 후 진행.
#
# 이것은 암호학적 보증이 아니라 운영 규율이다. 프로세스 환경을 바꿀 수 있는
# 공격자는 이미 호스트를 장악했다. 목적은 "보안 끄고 디버깅하다 그대로 출하"가
# 로봇까지 조용히 도달하는 것을 막는 것이다.

PAIL_PREFLIGHT_EXIT_CONFIG=78

pail_preflight() {
  local enclave="${1:?pail_preflight: enclave name required}"
  local profile="${PAIL_PROFILE:-production}"
  local -a bad=() ids=()

  case "$profile" in
  production | dev) ;;
  *)
    echo "PAIL PREFLIGHT FAIL: S0 PAIL_PROFILE=${profile} (want production|dev)" >&2
    exit "$PAIL_PREFLIGHT_EXIT_CONFIG"
    ;;
  esac

  if [ "${ROS_SECURITY_ENABLE:-}" != "true" ]; then
    ids+=("S1")
    bad+=("S1 ROS_SECURITY_ENABLE=${ROS_SECURITY_ENABLE:-<unset>} (want true) — DDS participant auth and topic access control are OFF; any process on the domain can publish the drive topic")
  else
    if [ "${ROS_SECURITY_STRATEGY:-}" != "Enforce" ]; then
      ids+=("S2")
      bad+=("S2 ROS_SECURITY_STRATEGY=${ROS_SECURITY_STRATEGY:-<unset>} (want Enforce) — unsecured participants would be silently permitted")
    fi
    if [ -z "${ROS_SECURITY_KEYSTORE:-}" ]; then
      ids+=("S3")
      bad+=("S3 ROS_SECURITY_KEYSTORE unset")
    elif [ ! -d "${ROS_SECURITY_KEYSTORE}/enclaves/${enclave}" ]; then
      ids+=("S3")
      bad+=("S3 enclave not provisioned: ${ROS_SECURITY_KEYSTORE}/enclaves/${enclave} (run scripts/sros2_provision.sh)")
    fi
  fi

  if [ "${#bad[@]}" -eq 0 ]; then
    echo "PAIL PREFLIGHT: profile=${profile} OK (S1,S2,S3) enclave=/${enclave}"
    return 0
  fi

  local joined
  joined=$(
    IFS=,
    echo "${ids[*]}"
  )
  if [ "$profile" = "dev" ]; then
    echo "PAIL PREFLIGHT: profile=dev INSECURE(${joined}) enclave=/${enclave} — NOT FOR PRODUCTION" >&2
    printf 'PAIL PREFLIGHT:   %s\n' "${bad[@]}" >&2
    return 0
  fi
  # printf는 형식을 인자에 순환 적용한다. 형식 지정자를 두 개 쓰면 bad[] 원소와
  # enclave가 뒤섞이므로, 접미사는 형식 문자열에 미리 박아 넣는다.
  printf "PAIL PREFLIGHT FAIL: %s [profile=production enclave=/${enclave}]\\n" "${bad[@]}" >&2
  echo "PAIL PREFLIGHT FAIL: refusing to start. Set PAIL_PROFILE=dev to run without these protections (DEV ONLY)." >&2
  exit "$PAIL_PREFLIGHT_EXIT_CONFIG"
}

# S19 . 개인키 재료가 소유자 밖에서 읽히면 거부한다.
#
# **프로파일 면제가 없다.** 위의 `pail_preflight` 는 dev 에서 배너로 내려가지만
# S15~S20 은 §3.7 이 면제 대상에서 빼 놓았다. 이유는 이 규칙이 재는 것이 "보호를
# 꺼 두고 개발 중"이 아니라 "설정이 구조적으로 깨졌다"이고, 키가 만들어지는 곳이
# 바로 dev 이기 때문이다 — dev 에서 넓게 태어난 키가 그대로 배포로 간다.
#
# 술어는 `scripts/_keymode.sh` 한 벌이고 이미지에 `/usr/local/bin/_keymode.sh`
# 로 실린다. 여기에 다시 쓰지 않는 이유는, 두 벌이면 한쪽만 고쳐졌을 때 어긋남이
# **통과로** 나타나기 때문이다(생성 시점은 좁혔는데 실행 시점은 옛 술어로 본다).
#
# 술어가 없으면 통과가 아니라 거부다. 없는 검사와 통과한 검사가 같은 침묵을
# 내면 안 된다(`H-B2`).
pail_preflight_key_modes() {
  local lib=/usr/local/bin/_keymode.sh
  local profile="${PAIL_PROFILE:-production}"

  if [ ! -r "$lib" ]; then
    echo "PAIL PREFLIGHT FAIL: S19d key-mode predicate missing: ${lib} — the check did not run, and a check that did not run is not a check that passed [profile=${profile}]" >&2
    exit "$PAIL_PREFLIGHT_EXIT_CONFIG"
  fi
  # shellcheck source=/dev/null
  . "$lib"

  # 볼 곳이 없으면 볼 것도 없다. keystore 미설정은 S3 의 소관이고, 여기서 같은
  # 사실을 다른 말로 또 내면 운영자가 결함 두 개를 찾으러 간다.
  local -a roots=()
  [ -n "${ROS_SECURITY_KEYSTORE:-}" ] && [ -d "${ROS_SECURITY_KEYSTORE}" ] &&
    roots+=("${ROS_SECURITY_KEYSTORE}")
  [ -d /etc/pail/grpc_certs ] && roots+=(/etc/pail/grpc_certs)
  [ -d /etc/pail/keys ] && roots+=(/etc/pail/keys)
  if [ "${#roots[@]}" -eq 0 ]; then
    echo "PAIL PREFLIGHT: profile=${profile} OK (S19) no private key material mounted"
    return 0
  fi

  if pail_assert_private_key_modes "" "${roots[@]}"; then
    echo "PAIL PREFLIGHT: profile=${profile} OK (S19) ${#roots[@]} root(s)"
    return 0
  fi
  echo "PAIL PREFLIGHT FAIL: S19 private key material readable beyond its owner (see above) [profile=${profile}]" >&2
  echo "PAIL PREFLIGHT FAIL: refusing to start. PAIL_PROFILE=dev does NOT waive this — a key that is too wide in dev is the key that ships." >&2
  exit "$PAIL_PREFLIGHT_EXIT_CONFIG"
}

# SD1 (see spec/ARCHITECTURE.md). S7: 인가 검증을 건너뛰는 토큰
# 공급자 모드를 production에서 거부한다. 노드 안에도 같은 진리표가 있고 그쪽이
# 정본이다(파라미터 경로까지 봄). 이 함수는 ROS 기동 전에 빠른 오류를 준다.
pail_preflight_token_mode() {
  local mode="${1:-notoken}"
  local profile="${PAIL_PROFILE:-production}"
  local detail=""
  local deny=""

  case "$mode" in
  grpc)
    echo "PAIL PREFLIGHT: profile=${profile} OK (S7) token_provider_mode=grpc"
    return 0
    ;;
  static)
    deny=1
    detail="S7 token_provider_mode=static fabricates an unsigned token and skips signature, time window, single-use and action-type verification"
    ;;
  notoken)
    echo "PAIL PREFLIGHT WARN: S7 token_provider_mode=notoken: no token is ever issued, so every motion is blocked (ERR_NO_TOKEN) [profile=${profile}]" >&2
    return 0
    ;;
  *)
    deny=1
    detail="S7 unknown token_provider_mode '${mode}' (expected grpc|static|notoken)"
    ;;
  esac

  if [ -n "$deny" ] && [ "$profile" = "dev" ]; then
    echo "PAIL PREFLIGHT: profile=dev INSECURE(S7) — NOT FOR PRODUCTION" >&2
    echo "PAIL PREFLIGHT:   ${detail}" >&2
    return 0
  fi
  echo "PAIL PREFLIGHT FAIL: ${detail} [profile=${profile}]" >&2
  echo "PAIL PREFLIGHT FAIL: refusing to start. Set PAIL_PROFILE=dev to run without authorization verification (DEV ONLY)." >&2
  exit "$PAIL_PREFLIGHT_EXIT_CONFIG"
}

# SD2 (PAIL-SD2-LLD-v1 §4). S10: 검사를 무력화하는 임계값을 거부한다. 상한만
# 보고 더 엄격한 값은 전부 통과시킨다 — 현장 수치는 운영자의 몫이고, 배포자는
# "이것이 아직 검사인가"의 경계만 정한다(쉬운설명 §8.1).
#
# 노드가 정본이다. launch·파라미터 파일 경로는 shell 이 보지 못한다. 이 함수는
# 엔트리포인트가 -p 로 넘길 바로 그 값을 ROS 기동 전에 걸러 준다.
# 상한은 thresholds.hpp 와 같아야 하며, test/threshold_matrix.tsv 가 양쪽을 대조한다.
#
# 단계 6  이후 신선도 창 둘은 env 가 아니라 정책 파일에서
# 온다. 여섯 인자 중 window·stale 은 아래 `pail_preflight_policy_freshness` 가
# 정책에서 읽어 넘긴다 — 이 함수의 판정 두 줄을 지우지 않은 이유가 그것이다.
# 지웠다면 S10 의 창 검사가 shell 층에서 사라지고, `threshold_matrix.tsv` 가
# 대조하는 두 구현 중 한쪽만 남는다.
PAIL_S10_MAX_EVIDENCE_WINDOW_MS=60000
PAIL_S10_MAX_SAFETY_STALE_MS=60000
PAIL_S10_MAX_CLOCK_SKEW_MS=30000
PAIL_S10_MAX_PERMIT_HOLD_MS=5000

pail_preflight_thresholds() {
  local conf="$1" window="$2" stale="$3" skew="$4" grace="$5" recheck="$6"
  local profile="${PAIL_PROFILE:-production}"
  local -a bad=()
  local finding

  while IFS= read -r finding; do
    [ -n "$finding" ] && bad+=("$finding")
  done < <(awk -v conf="$conf" -v window="$window" -v stale="$stale" -v skew="$skew" \
    -v grace="$grace" -v recheck="$recheck" \
    -v maxw="$PAIL_S10_MAX_EVIDENCE_WINDOW_MS" -v maxs="$PAIL_S10_MAX_SAFETY_STALE_MS" \
    -v maxk="$PAIL_S10_MAX_CLOCK_SKEW_MS" -v maxh="$PAIL_S10_MAX_PERMIT_HOLD_MS" '
    BEGIN {
      if (conf <= 0) print "S10 evidence_conf_threshold=" conf " — any perception result passes, whatever its confidence";
      else if (conf > 1) print "S10 evidence_conf_threshold=" conf " — confidence is 0..1, so no evidence can ever satisfy this";
      if (window < 0) print "S10 evidence_window_ms=" window " — negative";
      else if (window > maxw) print "S10 evidence_window_ms=" window " > " maxw " — the robot would keep moving on a perception result a minute old";
      if (stale < 0) print "S10 safety_stale_ms=" stale " — negative";
      else if (stale > maxs) print "S10 safety_stale_ms=" stale " > " maxs " — permits would still be granted a minute after the safety signal stopped, which is no freshness check";
      if (skew < 0) print "S10 clock_skew_ms=" skew " — negative";
      else if (skew >= maxk) print "S10 clock_skew_ms=" skew " >= " maxk " — the tolerance cancels the whole token validity window, so expired tokens are accepted";
      if (grace < 0) print "S10 permit_grace_n=" grace " — negative";
      else if (recheck > 0 && grace > int(maxh / recheck)) print "S10 permit_grace_n x permit_recheck_ms = " grace " x " recheck " = " (grace * recheck) "ms > " maxh "ms — that is how long the robot may drive on with the issuer unreachable";
    }')

  if [ "${#bad[@]}" -eq 0 ]; then
    echo "PAIL PREFLIGHT: profile=${profile} OK (S10)"
    return 0
  fi
  if [ "$profile" = "dev" ]; then
    echo "PAIL PREFLIGHT: profile=dev INSECURE(S10) — NOT FOR PRODUCTION" >&2
    printf 'PAIL PREFLIGHT:   %s\n' "${bad[@]}" >&2
    return 0
  fi
  printf "PAIL PREFLIGHT FAIL: %s [profile=production component=pep_gate_entrypoint]\\n" "${bad[@]}" >&2
  echo "PAIL PREFLIGHT FAIL: refusing to start. Set PAIL_PROFILE=dev to run without these protections (DEV ONLY)." >&2
  exit "$PAIL_PREFLIGHT_EXIT_CONFIG"
}

# ── 단계 6 (implementation contract 이월분): 신선도 창 둘의 출처 ────────────────────
#
# 이전에는 `PAIL_EVIDENCE_WINDOW_MS`·`PAIL_SAFETY_STALE_MS` 가 `-p` 로 노드에
# 들어갔고, 정책의 `preconditions[].freshness_ms` 는 파싱되고 버려졌다. 두 출처의
# 기본값이 **우연히 같아서**(2000·1000) 그 사실이 몇 달 동안 보이지 않았다(P-19).
# 이제 출처는 정책 하나다. 그러면 S10 도 그 값을 봐야 한다 — env 를 계속 보면
# 아무도 쓰지 않는 수를 검사하는 장식이 된다.
#
# 값을 못 읽으면 **거부한다.** "확인 못 했다"를 "확인했고 정상"과 같은 바이트로
# 적지 않는다(`H-B2`). 노드도 같은 파일을 못 읽으면 기동을 거부하므로(D-L2) 이
# 거부는 그 거부를 더 이른 자리에서, 이유를 붙여 내는 것뿐이다.
#
# `exit` 를 이 함수 안에서 부르지 않는다. 호출자가 `$(...)` 로 감싸면 죽는 것은
# 서브셸뿐이고 부르는 쪽은 빈 문자열을 받아 계속 간다 — 그 빈 값이 기본값으로
# 채워지면 그것이 곧 "깨끗함"이 된다(S19 실측). 판정은 호출자가 한다.
PAIL_POLICY_SAFETY_STALE_MS=""
PAIL_POLICY_EVIDENCE_WINDOW_MS=""

pail_preflight_policy_freshness() {
  local file="$1" out
  # 한 번만 읽는다. 두 번 부르면 그 사이의 변경이 두 값을 서로 다른 파일에서
  # 온 것으로 만들고, 그 불일치에는 관측점이 없다.
  if ! out="$(python3 - "$file" <<'PYEOF' 2>/dev/null
import sys

try:
    import yaml
except Exception:
    sys.exit(1)

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
except Exception:
    sys.exit(1)

if not isinstance(doc, dict):
    sys.exit(1)
entries = doc.get("preconditions")
if not isinstance(entries, list):
    sys.exit(1)

found = {"safety_feed": None, "evidence_claim": None}
for entry in entries:
    if not isinstance(entry, dict):
        continue
    name = entry.get("id")
    if name not in found:
        continue
    value = entry.get("freshness_ms")
    # bool 은 int 의 하위형이다. `freshness_ms: true` 를 1 로 읽으면 오타가
    # 1ms 창이 되어 전량 차단으로 조용히 착지한다.
    if isinstance(value, bool) or not isinstance(value, int):
        sys.exit(1)
    found[name] = value

if found["safety_feed"] is None or found["evidence_claim"] is None:
    sys.exit(1)
print(found["safety_feed"], found["evidence_claim"])
PYEOF
  )"; then
    return 1
  fi
  case "$out" in
    *' '*) ;;
    *) return 1 ;;
  esac
  PAIL_POLICY_SAFETY_STALE_MS="${out%% *}"
  PAIL_POLICY_EVIDENCE_WINDOW_MS="${out##* }"
  return 0
}

# 죽은 env 가 조용히 무시되지 않게 한다. `-p` 로 넘기던 자리를 지우기만 하면
# 운영자가 창을 조이려고 `PAIL_SAFETY_STALE_MS` 를 설정해도 **아무 일도 일어나지
# 않고 로그도 남지 않는다** — 값을 잘못 넣은 배치와 값을 넣지 않은 배치가 같은
# 바이트로 뜬다. 소리 내어 거부하고 옮겨 갈 자리를 이름으로 알려 준다.
pail_preflight_dead_threshold_env() {
  local profile="${PAIL_PROFILE:-production}" name clause found=0
  for name in PAIL_EVIDENCE_WINDOW_MS PAIL_SAFETY_STALE_MS; do
    if [ -z "$(printenv "$name" 2>/dev/null || true)" ]; then continue; fi
    if [ "$name" = "PAIL_SAFETY_STALE_MS" ]; then
      clause="preconditions[id=safety_feed].freshness_ms"
    else
      clause="preconditions[id=evidence_claim].freshness_ms"
    fi
    echo "PAIL PREFLIGHT FAIL: S10 ${name} is set but no longer reaches the gate — the freshness window moved to ${clause} in the policy file (implementation contract D-L1). Leaving it set means the value you chose is silently not in force [profile=${profile} component=pep_gate_entrypoint]" >&2
    found=1
  done
  [ "$found" -eq 0 ] && return 0
  # dev 로도 내려가지 않는다. 이것은 임계값 판단이 아니라 **설정이 도착하지
  # 않는다**는 사실이고, dev 배치라고 해서 도착하는 것은 아니다.
  exit "$PAIL_PREFLIGHT_EXIT_CONFIG"
}

# EC-2 (EUC D2). S26: 설치 SW 식별 문자열. 게이트가 Attest 로 보내는
# `attest_build_info` 는 ATTESTATION·CONFIG_SEALED 에 글자 그대로 남는다. 비어
# 있으면 체인은 「누구인지 모르는 게이트」를 적고, 그것은 부속서 III 1.1.9 ④
# (설치 SW 식별)의 부재다 — production 은 거부한다. 형식은 일곱 토막
# `pail-build:v1:<component>:<version>:<git_sha>:<image_digest>:<sbom_sha256>`,
# 모르는 값은 `-`(빈 토막 금지 — 「모른다」와 「깨졌다」가 같은 바이트가 된다).
# 이 함수가 조립 자리(엔트리포인트) 옆에 있는 이유: 조립과 거부가 한 스크립트에
# 있어야 한쪽만 되돌렸을 때 다른 쪽이 그것을 본다.
pail_preflight_build_info() {
  local bi="${1:-}"
  local profile="${PAIL_PROFILE:-production}"
  # 규칙 id 는 따옴표 리터럴로 둔다 — TRUST_BOUNDARY 게이트 표 생성기가 그 형태를
  # 「구현됨」의 근거로 읽는다(코드에 없는 번호는 표에서 미구현이 된다).
  local rule="S26"
  local re='^pail-build:v1:(pep_gate|issuer|robot_agent|telemetryd|permit_mirror):[^:]+:[^:]+:[^:]+:[^:]+$'
  local detail=""
  if [ -z "$bi" ]; then
    detail="${rule} attest_build_info is empty — the chain would record a gate nobody can identify"
  elif ! [[ "$bi" =~ $re ]]; then
    detail="${rule} attest_build_info '${bi}' is not pail-build:v1:<component>:<version>:<git_sha>:<image_digest>:<sbom_sha256> (7 tokens, unknown = -)"
  fi
  if [ -z "$detail" ]; then
    echo "PAIL PREFLIGHT: profile=${profile} OK (${rule}) attest_build_info=${bi}"
    return 0
  fi
  if [ "$profile" = "dev" ]; then
    echo "PAIL PREFLIGHT WARN: ${detail} [profile=dev]" >&2
    return 0
  fi
  echo "PAIL PREFLIGHT FAIL: ${detail} [profile=${profile} component=pep_gate_entrypoint]" >&2
  echo "PAIL PREFLIGHT FAIL: refusing to start. Set PAIL_PROFILE=dev to run without software identification (DEV ONLY)." >&2
  exit "$PAIL_PREFLIGHT_EXIT_CONFIG"
}
