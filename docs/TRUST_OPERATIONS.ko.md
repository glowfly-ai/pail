# 신뢰 운영: 번들 만료, 번들 적용, 키 등록

이 문서는 PAIL 배치를 운영하는 주체를 위한 것입니다. 소프트웨어가 스스로 답하지 않는
세 가지 — 신뢰 번들이 만료되면 각 구성요소가 무엇을 하는지, 갱신한 번들을 어떻게 적용하고
적용됐음을 어떻게 아는지, 키를 누가 정하는지 — 를 답합니다. 이 릴리스에 실린 소프트웨어를
그대로 기술하며, 코드에 대한 문장은 모두 릴리스의 계약 시험이 묶고 있어 코드가 바뀌면 이
문서를 고치기 전까지 릴리스 검사가 붉습니다.

하지 않는 것: 키를 교체하거나 운영자 대신 결정하는 관리 도구를 싣지 않습니다. 게이트는 옆에 놓인
번들을 스스로 적용합니다. 번들을 놓는 일, 그리고 키의 등록과 교체는 운영자가 내리는 결정입니다.
소프트웨어는 그 결과를 집행하고 나머지를 거부합니다.

## 1. 신뢰가 있는 곳

- **루트 키.** 오프라인 서명자(`pail-keyring-sign`)에만 있습니다. 어느 PAIL 프로세스도 읽지
  않고, 여기 있는 어떤 것도 대체 루트를 만들지 않습니다.
- **서명 번들.** 루트가 서명한 payload(`bundle_version`, `issued_at_unix`, `expires_at_unix`,
  역할이 붙은 키, 폐기 목록). 경로는 `PAIL_KEYRING_BUNDLE`(기본
  `/etc/pail/keys/keyring_bundle.json`), 루트 공개키는 `PAIL_ROOT_PUBKEY_FILE`.
- **발급자 keyring.** `pail_cloud` / `pail_services`는 기동 때 번들을 적재하고 `expires_at`
  으로 *신선도 게이트*를 둡니다.
- **게이트(어댑터) keyring.** `libpail_gate`는 기동 때 번들을 적재하고, 실행 중에 같은 경로에 놓인
  더 새 번들을 적용하며, `expires_at`이 지난 번들로는 검증을 멈춥니다.
- **로봇 에이전트 풀러.** 선택 사항으로 발급자에게서 새 번들을 받아 배치하고, 게이트가 그것으로
  판정하는지를 게이트의 상태 파일에서 확인합니다. 운영자가 설정한 재기동 명령은 그 확인이 오지 않을
  때의 대체 수단입니다.
- `PAIL_KEYRING_MODE=unsigned-dev`는 번들 없는 개발용 신뢰입니다: 서명도, 만료도, 버전
  바닥도 없습니다. "만료 없는 번들"이 아니며, production 기동은 이를 거부합니다(`S5`).

## 2. 만료되면 구성요소별로 무엇이 일어나는가

| 구성요소 | 검사 시점 | 만료 시 | 증거 줄 |
|---|---|---|---|
| 발급자(`pail_cloud`, `pail_services`) | 기동 때(`InstallTrustFreshness`; 게이트가 없으면 `S20f` 거부) 그리고 **요청마다**: 계획 판정의 첫 문장이 `s.Trust.Check()`입니다. 감시자가 5분마다 다시 검사하지만 로그를 남기기 위해서일 뿐입니다. | `expires_at` 뒤에 제출된 계획은 `ERR_BUNDLE_EXPIRED`(`S20d`)로 거부됩니다. 이미 발급된 것을 회수하지 않고, 새로 발급하지 않습니다. 만료된 번들로는 기동도 거부됩니다. | 기동 시 `trust freshness: expires_at=<RFC3339> (in <duration>)`; 감시자가 한 번 `WARNING: … expired … issuance is refused from here on`. |
| 게이트(`libpail_gate`, ROS 2 어댑터) | 적재 때, 그리고 **실행 중 판정마다**. 적재는 루트 서명, 형식(정의되지 않은 멤버, 역할 없는 항목, 두 번 나온 `key_id`는 번들 전체를 거부), 버전 바닥(작은 버전 거부, 같은 버전은 재적재), `now < expires_at`, `expires_at − now ≤ PAIL_KEYRING_MAX_LIFETIME_SEC`를 검사합니다. 실행 중에는 자기가 읽는 벽시계를 적재한 번들의 `expires_at`과 비교하고, 번들 파일을 봅니다: 같은 검사를 통과한 더 높은 버전은 재기동 없이 적용됩니다(ROS 2 게이트는 초당 네 번, C ABI 어댑터는 `pail_gate_tick`마다 봅니다). | 이미 만료된 번들은 적재되지 않습니다(`ERR_BUNDLE_EXPIRED`, 키 없음). 실행 중인 게이트는 자기 번들의 `expires_at`부터 모든 명령을 거부합니다(`BLOCK ERR_BUNDLE_EXPIRED`). 토큰 자체가 아직 유효해도 그렇고, 유지하던 허가도 거기서 끝납니다. 유효한 더 높은 버전이 적용되면 다시 검증합니다. 검사에 실패한 후보는 아무것도 바꾸지 않고 만료를 늘리지도 않습니다. | 게이트가 적재 때 만들어 상태 스냅숏으로 내보내는 적재 신뢰 기록(robot-ops 상태 소켓의 `trust_snapshot_json` 필드; 콘솔의 준비 상태 화면이 읽습니다): `{"schema_version":1,"loaded_mode":"bundle","load_verdict":"LOADED", … "bundle_version":N,"expires_at_unix":T,"loaded_at_unix":t,"max_remaining_seconds":M,"role_fingerprints":[…]}`. 적용과 함께 바뀝니다. ROS 2 게이트는 변화마다 한 줄도 남깁니다: `PAIL_GATE_TRUST loaded|applied|refused|expired … bundle_version=N expires_at_unix=T`. |
| 로봇 에이전트(`pail_robot_agent`) | `PAIL_ROOT_PUBKEY_FILE`이 있을 때만 당깁니다. `PAIL_KEYRING_POLL_SEC` 미설정 → 기동 거부 `S20c`; `0` → 의도적으로 끔. `PAIL_GATE_RESTART_CMD`는 선택 사항입니다. | 에이전트는 만료를 판정하지 않습니다. 받은 번들을 루트와 놓여 있는 버전에 대조해 배치한 뒤, 게이트의 상태 파일(`PAIL_KEYRING_STATE`)을 최대 5초 읽습니다. 바닥값이 놓은 버전에 닿았으면 게이트가 적용했다는 게이트 자신의 진술입니다. 그 진술이 없으면 에이전트가 이름으로 알리고, 재기동 명령이 설정돼 있으면 실행합니다. | `keyring pull: enabled (interval=… dest=… apply=gate-self[, fallback=restart-cmd])`, `keyring pull: placed bundle v<N> at <path> (was v<M>)`, `keyring pull: gate applied v<N>`, 또는 `keyring pull: KEYRING_APPLY_NOT_CONFIRMED placed=v<N> gate=…`와 (명령이 있으면) `keyring pull: gate restart triggered ("…")`. |
| 운영자 도구(`examples/common/trust_admin.py`) | `inspect`, `plan-renewal`, `stage-renewal`은 프로파일과 소비자 관측을 상대로 오프라인에서 돕니다. | `apply-renewal`은 **거부**됩니다(`MANAGEMENT_EXECUTION_WINDOW_NOT_INSTALLED; candidate remains staged`): 관리 재기동 틀은 2026-10-29에 공개 트리에서 철회됐습니다. 적용은 아래 5단계이며 운영자가 수행합니다. | 운영 상태 옆의 스테이징된 후보 파일; `operation-status`. |

표는 행마다 읽습니다. 발급자와 각 게이트는 자기가 적재한 번들의 만료를 자기 시계로 판정합니다:
"만료가 발급을 멈춘다"는 발급자의 행이고 "만료가 게이트를 멈춘다"는 게이트의 행입니다. 닿을 수 없는
로봇 — 갱신도 폐기도 받지 못하는 로봇 — 은 늦어도 자기 번들의 `expires_at`에 멈춥니다. 그래서
`PAIL_KEYRING_MAX_LIFETIME_SEC`가 폐기가 그 로봇에 닿는 데 걸릴 수 있는 가장 긴 시간입니다.

## 3. 데모가 싣는 것

- TB3 데모(`examples/tb3/demo.py`)는 `bundle` 모드로 돌며 8시간 유효한 초기 번들을 만들고,
  TB3 시험 도구(`examples/tb3/run.py`)는 1시간짜리를 만듭니다. 이는 두 진입 경로의 *초기*
  번들 수명이지 모든 실행이 따라야 할 갱신 주기가 아닙니다. TB3 compose 파일은
  `PAIL_KEYRING_MAX_LIFETIME_SEC: "86400"`(남은 수명이 24시간을 넘는 번들은 적재 거부)과
  `PAIL_KEYRING_POLL_SEC: "0"`(자동 당김 없음)을 둡니다. 초기 번들의 수명을 넘겨 켜 둔 데모는
  허가를 멈춥니다(`ERR_BUNDLE_EXPIRED`). 새 상태로 다시 시작하십시오.
- Microduck 예제는 `unsigned-dev` 모드입니다: 번들 없음, 만료 없음, 서명 신뢰 아님.

## 4. 갱신한 번들 적용하기

절차는 여섯 단계입니다. 단계마다 입력·출력·증거가 있고, 어느 것도 다른 단계가 대신하지
않습니다. 번들을 만드는 데도, 게이트에 적용하는 데도 아무것도 멈출 필요가 없습니다. 발급자에
적용하는 데는 필요합니다.

1~3단계는 Core 루트에서 실행하며, 아래 명령 줄은 적힌 그대로 따라 할 수 있습니다. 값 세 개를 씁니다.

```sh
OPS=/absolute/operator
ISSUED=1795000000
EXPIRES=1795086400
```

`OPS`는 경로 어디에도 심링크가 없는 운영자 소유 디렉터리입니다(macOS에서는 `/tmp/…`가 아니라
`/private/tmp/…`). 프로파일, 소비자 관측, 그리고 각 단계가 쓰는 파일이 여기에 놓입니다. `ISSUED`와
`EXPIRES`는 요청하는 유효기간입니다. `ISSUED`는 관측의 가장 이른 `now_min_unix`보다 늦지 않아야 하고,
`EXPIRES`는 모든 `now_max_unix`보다 늦으면서 모든 소비자의 `max_remaining_seconds` 안이어야 합니다. 위 값은
예시 관측 파일에 맞는 값입니다.

**1단계 전에 서명기를 빌드합니다.** 서명기는 Core에 소스로 들어 있습니다(`cloud/tools/pail-keyring-sign`).
운영 호스트에서 `cloud/go.mod`가 정한 Go 버전으로 한 번 빌드합니다. 마지막 줄이 SHA-256을 출력합니다.

```sh
mkdir -p "$OPS/bin"
(cd cloud && go build -o "$OPS/bin/pail-keyring-sign" ./tools/pail-keyring-sign)
python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$OPS/bin/pail-keyring-sign"
```

그 실행 파일의 경로가 프로파일의 `helper_path`, 출력된 digest가 `helper_sha256`입니다. 실행 파일이 바뀌거나
옮겨지면 거부되므로(`HELPER_CHANGED`), 다시 빌드할 때는 의도적으로 다시 고정합니다.

프로파일은 신뢰하는 루트도 지문으로 적습니다.

```sh
python3 -c 'import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(open(sys.argv[1]).read().strip())).hexdigest())' "$OPS/root_pub.b64"
```

출력이 프로파일의 `root_fingerprint_sha256`입니다. `$OPS/root_pub.b64`는 프로파일의 `root_public_path`가
가리키는 파일을 나타냅니다.

### 1단계 — plan (계획)

`trust_admin.py plan-renewal`이 기준(현재 번들의 `base_sha256`, 루트 지문, 바뀌면 안 되는
키·역할·폐기), 소비자가 관측한 `max_bundle_version`과 수명 상한, 그리고 정확한 새
payload(`bundle_version`, `issued_at_unix`, `expires_at_unix`)를 고정합니다. 갱신에서는 버전과
유효기간만 바뀔 수 있습니다. 키 재료의 변경은 갱신이 아니라 키 변경 절차(§5)입니다. 출력:
계획과 그 digest; 운영 ID를 기록합니다.

`plan-renewal`이 읽는 것:

- **프로파일**(`--profile`). `examples/common/trust_observation.manifest.example.json`에서 시작합니다. 번들, 루트
  공개키, 서명기(`helper_path`, `helper_sha256`으로 고정; 만드는 방법은 2단계)를 선언합니다.
- **소비자 관측**(`--consumers`). 번들의 소비자(발급자와 모든 게이트)마다 객체 하나를 담은 JSON 배열입니다.
  모양은 `examples/common/trust_renewal_consumers.example.json`에 있고, 모든 필드가 필수입니다.

| 필드 | 뜻 | 값의 출처 |
|---|---|---|
| `id` | 소비자에게 붙인 이름. 파일 안에서 유일하고 128자 이하입니다. | 운영자가 정합니다. |
| `observed` | 이 행이 실제 관측에서 왔다는 표시. `false`면 계획이 거부됩니다. | 관측한 행에만 `true`. |
| `loaded_generation` | 소비자가 적재한 것에 대해 스스로 보고하는 세대값. 갱신을 적용할 때 다시 대조됩니다. | 소비자의 상태 응답. |
| `root_fingerprint_sha256` | 소비자가 **적재한** 루트. 기준 번들의 루트와 다르면 계획이 거부됩니다. | 소비자 상태 응답의 `trust_snapshot_json`. |
| `material_digest_sha256` | 소비자가 적재한 키 재료(활성·폐기 키, ID, 역할, 순서). | `trust_snapshot_json`. |
| `max_bundle_version` | 소비자가 받아들일 수 있는 가장 큰 버전. `0`이면 계획이 거부됩니다. | `trust_snapshot_json`의 `max_bundle_version_decimal`을 JSON 수로 적습니다. |
| `rollback_floor` | 소비자의 버전 바닥값. 계획한 버전은 모든 소비자의 바닥값보다 큽니다. | 소비자 상태 파일(`PAIL_KEYRING_STATE`)의 `last_version`. |
| `now_min_unix`, `now_max_unix` | 관측하는 동안 소비자 시계의 하한과 상한. `issued_at_unix` ≤ `now_min_unix`, `expires_at_unix` > `now_max_unix`여야 합니다. | 관측을 시작할 때와 끝낼 때의 소비자 시계. |
| `max_remaining_seconds` | 소비자의 수명 상한. `expires_at_unix` − `now_min_unix`가 이 값을 넘을 수 없습니다. | `trust_snapshot_json`의 `max_remaining_seconds`. |

  적재 값은 **실행 중인 소비자**에게서 옵니다. `pail-keyring-sign inspect-json`은 같은 이름의 값을 번들
  *파일*에서 계산합니다. 그 값을 이 파일에 옮겨 적으면 디코더는 통과하지만, 파일에서 베낀 값은 실행 중 확인이
  아닙니다 — 파일에 무엇이 들었는지를 말할 뿐, 소비자가 무엇을 적재했는지를 말하지 않습니다. 소비자의 상태
  응답을 읽는 것은 배치의 관리 통합이 하는 일이며, 평가 번들에는 이 파일을 만들어 주는 도구가 없습니다.
- **경로.** 프로파일, 그 안의 세 경로, 그리고 `--state`·`--consumers`·`--candidate`는 모두 해석된 절대경로여야
  합니다. 상대경로나 심링크가 낀 경로는 거부되고, 거부는 경로가 아니라 항목 이름(`field`)을 말합니다.
  macOS의 `/tmp`는 `/private/tmp`의 심링크이므로 `/private/tmp/…`로 적습니다.

```sh
python3 examples/common/trust_admin.py plan-renewal \
  --profile "$OPS/profile.json" --state "$OPS/operations" --operation-id renewal-1 \
  --consumers "$OPS/observations.json" --issued-at "$ISSUED" --expires-at "$EXPIRES" \
  --payload-out "$OPS/payload.json" > "$OPS/plan.json"
PLAN_DIGEST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["plan_digest"])' "$OPS/plan.json")
```

`--payload-out`은 계획된 payload — 2단계에서 루트가 서명하는 바로 그 내용 — 를 새 파일로 씁니다. 이미 있는
파일은 덮어쓰지 않습니다. `plan.json`에는 계획과 그 digest가 들어 있습니다. 승인하기 전에 계획을 읽으십시오.
`PLAN_DIGEST`는 3단계가 승인으로 받는 값입니다. 서명기가 요청을 거부하면 응답의 `cause`가 서명기의 사유를
말합니다(예: `CONSUMER_LIFETIME_REJECTED` — 유효기간이 소비자의 시계 구간이나 상한에 맞지 않음).

### 2단계 — sign (서명)

계획된 payload를 오프라인 서명자의 **기존** 루트로 서명합니다. 새 루트는 갱신이 아니라 신뢰
교체이며, 모든 소비자를 §5 절차로 다시 가리켜야 합니다. 출력: 후보 번들 파일.

```sh
"$OPS/bin/pail-keyring-sign" sign --root "$OPS/root_ed25519.json" --payload "$OPS/payload.json" --out "$OPS/candidate.json"
```

루트 개인키는 오프라인 서명자에 그대로 둡니다. `$OPS/root_ed25519.json`은 그것이 보관된 자리를 나타냅니다.

### 3단계 — stage (스테이징)

`trust_admin.py stage-renewal --candidate … --approved-plan-digest …`가 정확한 후보 바이트를
계획과 대조합니다(같은 루트 지문, 같은 재료, 소비자 바닥보다 높은 버전, 상한 안의 수명).
스테이징은 아무것도 설치하지 않고 바닥을 옮기지 않습니다. 출력: 후보의 SHA-256과
`STAGED_NOT_APPLIED`.

```sh
python3 examples/common/trust_admin.py stage-renewal \
  --profile "$OPS/profile.json" --state "$OPS/operations" --operation-id renewal-1 \
  --consumers "$OPS/observations.json" --candidate "$OPS/candidate.json" \
  --approved-plan-digest "$PLAN_DIGEST"
```

계획과 다른 후보는 거부되고, 서명기의 사유가 `cause`로 나옵니다(키·역할·폐기·버전이 다르면
`RENEWAL_IMMUTABLE_OR_VERSION_CHANGED`). 운영은 `PLANNED` 상태로 남습니다.

### 4단계 — place (배치)

스테이징된 후보를 **각** 소비자(발급자 호스트, 모든 게이트 호스트)의 `PAIL_KEYRING_BUNDLE`
— 프로세스가 기동 때 읽는 파일 — 로 복사합니다. 당김이 켜져 있으면 로봇 에이전트가 자기
게이트 몫을 하고 `keyring pull: placed bundle v<N> at <path> (was v<M>)`를 남깁니다. 그 줄을
확인하십시오. 실행 중인 게이트는 배치에 반응합니다: 적재 검사를 통과한 더 높은 버전을 1초 안에
적용합니다. 실행 중인 발급자는 배치로 아무것도 바뀌지 않습니다.

### 5단계 — apply (적용)

게이트는 놓인 번들을 스스로 적용하고 계속 돕니다: 갱신은 주행을 끊지 않고, 폐기는 폐기된 키로
유지되던 허가를 게이트의 다음 검사에서 끝냅니다. 발급자는 자기 번들을 기동 때만 적재합니다. 발급자의
번들이 바뀌었으면 발급자를 재기동하고 그 창을 계획하십시오 — 내려가 있는 동안 발급을 거부합니다.
게이트 재기동(하드웨어 리그의 `start_demo_rig.sh restart-gate`, 데모의 `docker compose … restart robot`,
또는 설정한 `PAIL_GATE_RESTART_CMD`)은 종전대로 놓여 있는 것을 적재합니다. 이것은 적용하지 못한
게이트를 위한 대체 수단이지 번들을 적용하는 방법이 아닙니다. 갱신을 피하려고 수명 상한을 올리지
않습니다.

### 6단계 — confirm (적재 확인)

적용이 끝났다고 말하기 전에 증거를 읽어 계획과 대조합니다: 게이트의 로그 줄
`PAIL_GATE_TRUST applied bundle_version=<N> …`(또는 `"load_verdict":"LOADED"`를 말하는 상태 스냅숏
`trust_snapshot_json`)이 계획한 `bundle_version`·`expires_at_unix`, 기대한 `role_fingerprints`를
보여야 하고, 당김이 켜져 있으면 에이전트의 `keyring pull: gate applied v<N>`이 게이트의 상태 파일에서
같은 것을 말하며, 발급자의 기동 줄 `trust freshness: expires_at=…`이
계획한 만료를 보여야 합니다. 이 기록들 없이 놓인 파일은 6단계가 아니라 4단계입니다.

**운전 재개는 별개의 결정입니다.** 적재 확인은 신뢰가 적재됐다는 뜻이고, 로봇·안전 피드·
운영자가 다시 움직일 준비가 됐는지는 말하지 않습니다. 그 결정은 그것대로의 증거로 내리고
기록하십시오.

**당김이 꺼진 구성**(TB3 compose 파일: `PAIL_KEYRING_POLL_SEC: "0"`)에서는 아무도 당기지
않습니다. 실행 중인 번들의 `expires_at` 전에, 모든 소비자에 대해, 운영자가 4~6단계를 직접
적용합니다. **당김이 켜진 구성**에서는 에이전트가 폴링 주기마다 자기 게이트의 4단계를 하고, 게이트가
5단계를 하며, 에이전트는 확인한 것을 보고합니다. 6단계는 여전히 운영자의 몫이고, 발급자는
에이전트가 재기동하지 않습니다.

## 5. 키 등록·교체·보존

PAIL은 신뢰하는 발급자의 서명과 건네받은 토큰의 범위를 검사합니다. 어느 키가 그 신뢰를
받을지는 소프트웨어 밖에서 정합니다(`TRUST_BOUNDARY`: G-DEL-L01 보관과 신원 심사,
G-DEL-L02 배포·폐기·회전). 소프트웨어의 검사가 뜻을 가지려면 그 결정이 따라야 할 규칙은
다음과 같습니다.

- **최초 신뢰는 승인 결정입니다.** 첫 번들이 생기기 전에 관리 주체가 발급자 신원, 키마다의
  역할, 신뢰근, 번들이 적용될 배치를 확정합니다. 소프트웨어는 그 결정을 **집행만** 합니다.
  키를 만들 수 있다는 사실(`gen_dev_keys.py`, 평가 예제)은 그 키에 발급 권한을 줄 근거가
  아닙니다.
- **키 보관은 폐기 가능한 실행 환경과 분리합니다.** 루트는 오프라인 서명자에 두고, 배치된
  개인키와 번들은 컨테이너·상태 디렉터리·VM보다 오래 사는 위치에 둡니다. **같은** 운영
  정체성의 재시작이나 재설치는 **기존 키를 재사용**합니다. 새 키는 새 정체성이며 위 승인을
  거쳐야 합니다.
- **상태는 지문으로 보이고 키 값은 절대 보이지 않습니다.** 상태 화면이나 보고서는 역할,
  식별자, 공개키 **지문**(`root_fingerprint_sha256`, 게이트 LOADED 줄의 `role_fingerprints`),
  승인 근거, 배포 상태를 적습니다. 개인 재료는 담지 않으며, 적재된 keyring이나 일치하는
  파일 해시는 승인의 증거가 아닙니다.
- **교체는 기존 루트 아래에서 합니다.** 교체는 서비스 변경과 별개의 작업입니다: 새 키의
  역할, 유효기간, 옛 키의 폐기, 번들 버전, 승인 근거를 번들을 배포하기 전에 검증합니다
  (재료가 바뀐 1~3단계는 `stage-renewal`이 갱신으로 받지 않습니다 — 키 변경 경로를
  쓰십시오). 새 루트는 모든 소비자에 대한 신뢰 교체이지 회전이 아닙니다.
- **교체할 때 이전 이슈어 키의 공개 절반을 남깁니다.** 이슈어는 기동할 때 저널의 모든
  체크포인트를 keyring의 이슈어 키로 검증합니다. 저널에 그 키가 서명한 체크포인트가 남아
  있는 동안 이전 키를 `keys`나 `revoked_keys`에 두십시오. 둘 다에 없는 키가 서명한
  체크포인트는 위조와 구별되지 않아 이슈어가 기동을 거부합니다.
- **이슈어 키 폐기는 두 단계이고, 둘째 단계가 게이트에 닿습니다.** 운영자 명령 `RevokeIssuerKey`는
  이슈어를 영구 LOCKDOWN으로 만들 뿐 게이트가 읽는 것을 아무것도 바꾸지 않습니다. 이 명령은 그
  기록이 저널에 들어갔을 때만 "수락"이라고 답합니다(아니면 `JOURNAL_APPEND_FAILED` — 그 잠금은
  재시작을 넘기지 못합니다). 이어서 루트가 그 키를 폐기하는 번들에 서명합니다:
  `pail-keyring-sign prepare-revoke --bundle <현재 번들> --root-pub <root_pub.b64> --key-id <id> --out payload.json`
  이 payload를 쓰고(그 키 하나를 `revoked_keys`로, 버전 + 1, 만료 불변. `--allow-no-issuer` 없이는
  활성 이슈어 키가 하나도 남지 않는 결과를 거부), `sign`이 서명하며, 결과를 이슈어가 내주는 자리에
  놓습니다. 닿을 수 있는 게이트는 에이전트의 폴링 주기에 게이트가 적용하는 몇 초를 더한 시간 안에
  그 키의 토큰을 거부합니다(`ERR_REVOKED_KEY_ID`). 닿을 수 없는 게이트는 갖고 있는 번들의 만료에
  멈춥니다. **루트가 서명하기 전까지는 모든 게이트가 그 키를 여전히 신뢰합니다** — 루트 절차를 그
  창에 맞게 짧게 유지하십시오. 키를 옮겨 두면 잠금 이전으로 잘라 낸 저널로 이슈어가 그 키를 들고 다시
  뜨는 것도 막힙니다. 이슈어는 활성 이슈어 키가 아닌 서명 키로는 기동하지 않습니다.
- **첫 설치는 버전 바닥을 씁니다.** production 프로파일에서 상태 파일(`PAIL_KEYRING_STATE`)이 없는
  소비자는 번들 적재를 거부합니다(게이트는 `ERR_BUNDLE_STATE:missing`, Go는 `bundle state: missing …`).
  없는 바닥을 첫 적재로 읽지 않습니다. 그렇게 읽으면 상태 디렉터리를 잃었을 때 폐기 이전의 번들이
  되살아납니다. 한 번 쓰십시오:
  `pail-keyring-sign init-floor --bundle <놓인 번들> --root-pub <root_pub.b64> --state <상태 파일>`.
  이 명령은 상태 파일을 덮어쓰지 않으며, `dev` 프로파일은 첫 적재 동작을 그대로 둡니다.
- **하지 말 것.** 불일치를 없애려고 새 keyring이나 새 신뢰근을 만들지 말고,
  `ERR_BUNDLE_EXPIRED`를 잠재우려고 소비자의 번들을 **덮어쓰지** 마십시오 — 갱신하십시오(§4).
  실행 환경(상태 디렉터리, 컨테이너, VM)을 지우는 것은 **신뢰 결정이 아닙니다**: 사본
  하나를 없앨 뿐 아무것도 폐기하지 않으며, 그것이 갖고 있던 키는 번들이 달리 말하기 전까지
  여전히 신뢰됩니다.

## 6. 남겨야 할 증거

운영마다: 계획 JSON과 digest, 서명된 후보와 그 SHA-256, 스테이징 결과, 배치 로그 줄(또는
직접 복사한 기록과 해시), 게이트의 `PAIL_GATE_TRUST applied` 줄(재기동했다면 LOADED 기록),
에이전트의 확인 줄, 발급자의 신선도 줄, 그리고
운전 재개 결정의 별도 기록. 운영 ID와 함께 보관하십시오. 저널은 토큰을 기록하지 번들
절차를 기록하지 않습니다.
