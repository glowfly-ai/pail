# 어댑터 계약 v1

PAIL 은 요청자와 로봇 사이에 판정 하나를 둔다 — *이 명령은, 지금, 이슈어가
서명한 토큰이 인가하고, 정책이 요구하는 안전·증거 아래에 있는가?* 판정
자체는 함수 하나(`gate_core::decide()`, `libpail_gate` 로 실린다)다. 명령을 그
함수까지 **나르고**, 판정을 로봇 자신의 제어 경로로 **되돌리는** 것은 전송마다
다르다 — ROS 2 토픽, Unix 소켓, gRPC 스트림 — 그 전송별 절반을 **어댑터**라
부른다.

이 문서는 어댑터가 지켜야 할 계약이다. ROS 가 아닌 로봇의 제조사나
통합사가 PAIL 내부를 읽지 않고 자기 언어로 어댑터를 쓸 수 있도록, 그리고
「PAIL 지원」이 주장이 아니라 검사되는 것이 되도록 썼다.

> 정본은 영문 [`ADAPTER_CONTRACT.md`](ADAPTER_CONTRACT.md) 이다. 두 판이
> 어긋나면 영문이 우선한다.

### PAIL 의 거부가 무엇이고 무엇이 아닌가

PAIL 이 보류하는 것은 **인가**다. 로봇의 안전 기능을 구현하지도, 대체하지도, 인증하지도
않는다. 비상정지·보호정지·속도와 이격 감시·힘 제한은 로봇 제조사와 통합자의 것이고, 이미
그것을 규율하는 표준(IEC 61800-5-2, ISO 10218-1/-2, ISO 3691-4, ISO 13482) 아래 있다.
명령을 막은 게이트는 인가를 거둔 것이지 제동을 건 것이 아니다.

통합자가 붙들어야 할 귀결 둘. 보호 수단이 PAIL 뿐인 배치는 **안전 기능이 없는 배치**다 —
토큰에 실린 이름표(`spec/GUARDRAILS.tsv`)는 *이슈어가 인가한 한도*이고, 한도는 기계가 실제로
한 일의 측정이 아니다. 그리고 곁에서 도는 벤더 안전 제어기를 이름 대지 못하는 게이트는 그
사실을 말한다 — 설정 봉인이 침묵 대신 `degraded=S36` 을 싣는다. 「여기 안전 기능이 있다」는
가정이 아니라 기록된 주장이 된다(SK-5).

## 1. 두 절반

| 절반 | 제공자 | 하는 일 |
|---|---|---|
| **SDK**(공통) | PAIL | `libpail_gate`(판정, 엄격한 토큰 검증, permit/스텝/단일사용 상태기계, 정책 적재 — C ABI 하나, `include/pail_gate/pail_gate.h`); **로봇 에이전트**(gRPC `TokenService`: `GetActiveToken`, `ReportDecision`, `Attest`, `SealConfig`); 설정 봉인과 빌드 식별 |
| **어댑터**(전송별) | 통합사 | ① 의도 유입 ② 판정 유출 ③ 안전·증거 유입 ④ permit 데드맨 집행 + 요청자 신원 + 우회 없는 배치 |

어댑터는 **판정하지 않는다**. 들어온 명령을 `CommandInput`(행동 클래스·선형/각
norm)으로 사상해 라이브러리에 묻고 `Outcome` 에 따른다 — **원 바이트**를
넘기거나 버린다. 자기 캐시도, 부재한 피드의 기본값도, 자기 모드 스위치도,
시계를 읽는 것 이상의 시간 판단도 없다.

## 2. 라이브러리 ABI

`libpail_gate` 는 로봇 하나에 핸들 하나다. 모든 버퍼는
`abi/pail_gate_abi.proto`(헤더 옆에 실린다)의 메시지를 protobuf **바이너리**로
담은 것이다 — protobuf 가 있는 언어는 그 파일 하나에서 바인딩을 만든다.

| 함수 | 입력 → 출력 | 어댑터가 부르는 때 |
|---|---|---|
| `pail_gate_abi_version()` | → `uint32` | 기동 시; 메이저가 다르면 거부 |
| `pail_gate_new(Config)` | → 핸들 또는 NULL + 사유 | 기동 시; 거부 사유는 게이트 프리플라이트 어휘(`POLICY_ABSENT`, `POLICY_INCOMPLETE`, …) |
| `pail_gate_set_token(TokenInput)` | | `permit_recheck_ms` 마다 최신 `GetActiveTokenResponse` — 에이전트가 답하지 않으면 `reachable=false` |
| `pail_gate_observe_safety(SafetyInput)` | → `Outcome` | 안전 피드가 올 때마다; `ESTOP` 결과는 정지다 |
| `pail_gate_observe_evidence(EvidenceInput)` | | 증거 소스가 올 때마다 |
| `pail_gate_command(CommandInput)` | → `Outcome` | 명령마다; `Outcome.forward` 가 답의 전부 |
| `pail_gate_tick(TickInput)` | → `TickOutcome` | `set_token` 뒤 `permit_recheck_ms` 마다; 재확인 경로와 스텝 타이머. 실행 중인 게이트 옆에 놓인 서명 키링 번들도 여기서 적용된다: 적재 검사를 통과한 더 높은 버전이 tick 의 판정 전에 사용 중인 키를 바꾼다(`pail_gate_info` 의 `keys` / `revoked_keys` 가 따라 바뀐다). tick 을 받지 않는 게이트는 아무것도 적용하지 않는다. 사용 중인 번들의 만료부터는 모든 결과가 `BLOCK ERR_BUNDLE_EXPIRED` 이고, 적용된 번들이 폐기한 키로 유지되던 허가는 `ERR_REVOKED_KEY_ID` 로 끝난다 |
| `pail_gate_info()` | → `Info` | 기동 시·상태 |
| `pail_gate_free()` / `pail_gate_free_buf()` | | |

핸들은 스레드 안전하지 않다 — 어댑터가 호출을 직렬화한다.

`Outcome.detail` 은 사유 코드가 말하지 않는 것을 말한다: 어느 이름, 어느 값, 어느 한도.
기록하고 이 ABI 로 실어 나르되 동등 비교는 하지 않는다(그건 사유 문자열의 몫). 지금의
형태: 봉투 거부 `sls.linear_mps=0.3 outside [-,0.2]`; 측정 안 된 이름 `unmeasured:<name>`
(`ERR_BAD_TOKEN`); 스텝 초과 `step.max_duration_s: clock=<elapsed|wall> now=<ms> deadline=<ms> overrun_ms=<ms>`
(`ERR_CONSTRAINT`, 기한을 찍은 것과 같은 스텝 시계); 슬롯·스킬 불일치는 말로.

## 3. 불변조건

| # | 불변조건 | 검사 |
|---|---|---|
| I-1 | 요청자 주체는 어댑터 뒤의 원 제어 유입에 닿을 수 없다 | CB-1 프로브(전송별) + 어댑터 자기 점검(`S27`, 3값: verified / unverified / failed — production 에서 `failed` 는 기동 거부) |
| I-2 | 어댑터는 판정하지 않는다 — 통과는 `Outcome.forward` 만 따른다 | CA-01·04·05·06 |
| I-3 | 허가된 명령은 **바이트 그대로** 넘긴다 | CA-07 |
| I-4 | permit 이 끝나면 `permit_deadline_ms` 안에 통과가 멈춘다 | CA-08·09 |
| I-5 | 모든 판정은 보고된다(PERMIT 포함); 보고 실패는 게이트를 닫는다(issuer-first) | CA-09 |
| I-6 | 안전·증거 부재는 부재로 들어간다 — 어댑터가 「OK」를 만들지 않는다 | CA-10 |
| I-7 | 게이트 모드는 봉인 정책에서만 온다; `observe` 에서는 통과하고 would-BLOCK 을 기록한다 | CA-11 |
| I-8 | 어댑터는 자기 빌드로 증명한다(`Attest`, component `pep_gate`, `pail-build:v1:` 형식) | CA-12 |

I-1 뒤의 배치 규칙: **폴백 경로는 없다.** 어댑터가 죽으면 로봇에 아무것도
닿지 않는다 — 자기 데드맨이 있는 로봇은 서 있는다. 「원 소켓으로 fail-open」
하는 어댑터는 적합하지 않다.

## 4. 적합성 케이스

케이스 하나는 PVS 어휘(`version: 2.0`, `north_cmd`·`inject_evidence`·
`inject_cmd_vel`·`expect_gate`·`expect_bridge`·`expect_drive_never`·`fault`
같은 단계)의 시나리오 하나이고, ROS 2 게이트 노드를 판정하는 **같은 오케스트레이터**로
실행된다. 전송별 백엔드가 단계를 그 전송의 동작으로 바꾸고 결과를 어댑터의
**반대편**(로봇에 실제로 닿은 것)에서 읽는다 — 어댑터 자신의 주장에서 읽지
않는다. 기계 판독형 표는 `pvs-public/scenarios/adapter/CA_MAP.yaml`.

| 케이스 | 기대 | 시나리오 |
|---|---|---|
| CA-01 | 토큰 없음 → BLOCK `ERR_NO_TOKEN`, 아무것도 안 넘어감 | `functional/fn03_no_token` |
| CA-02 | 위조 서명 → BLOCK `ERR_TAMPERED` | `adapter/ca02_forged_signature`(= PVS `token/ti03`) |
| CA-03 | 만료 토큰 → BLOCK `ERR_EXPIRED` | `adapter/ca03_expired_token`(= PVS `token/ti05`, nightly 게이트 없이) |
| CA-04 | 토큰이 품지 않은 행동 클래스 → BLOCK `ERR_ACTION_MISMATCH` | `adapter/ca04_action_class_mismatch`(= PVS `token/ti02`) |
| CA-05 | 증거가 다른 대상을 가리킴 → BLOCK `ERR_TARGET_MISMATCH` | `adapter/ca05_target_mismatch` |
| CA-06 | 토큰 한도보다 빠른 명령 → BLOCK `ERR_CONSTRAINT`(클램프 아님) | `adapter/ca06_speed_over_limit` |
| CA-07 | 허가된 줄이 반대편에 바이트 동일하게 도달 | 전송 도구(소켓: `tools/ca07_bytes.sh`); ROS 2: `functional/fn01` — `/safe_cmd_vel` 메시지 필드 동일, DDS 바이트는 미들웨어의 것 |
| CA-08 | 어댑터 사망 → 통과 중단, 로봇 자체 데드맨이 세움 | `deadman/dm01_pep_kill_bridge_hold` |
| CA-09 | permit 보유 중 에이전트 도달 불가 → grace 사다리 안에 BLOCK `ERR_ISSUER_UNREACHABLE`, 낡은 토큰으로는 아무것도 안 넘어감 | `adapter/ca09_issuer_unreachable`; ROS 2: `…_ros`, 게이트가 부르는 이슈어 컨테이너를 죽인다 |
| CA-10 | 안전 피드 낡음/부재 → 새 permit 없음 | `safety/sf02_safety_stale_no_permit` |
| CA-11 | `gate_mode: observe` → 통과 + `effective_mode=observe` 로 would-BLOCK 기록 | `adapter/ca11_observe_passthrough` |
| CA-12 | 이슈어 체인에 component `pep_gate` 의 `ATTESTATION` 레코드(어댑터 `build_info`) 존재 | `adapter/ca12_attestation_in_chain`(`expect_audit … contains`); ROS 2: `…_ros`, `pail-build:v1:pep_gate:` 접두어 |
| CA-13 | 이름 있는 스킬의 선언 봉투(로봇 자신이 그 스킬에 대해 말한 수)가 토큰 한도를 넘음 → BLOCK `ERR_CONSTRAINT`, 절대 clamp 안 함(SK-2: 게이트는 `GUARDRAILS.tsv` 이름으로 대조) | `adapter/ca13_skill_envelope_over_limit`(소켓: 리그가 1.5 m/s 로 바꾼 스킬의 `robot.do`); ROS 2: `NO_SKILL_INGRESS` |
| CA-14 | **미할당.** 이 id 를 가진 케이스는 없고 있었던 적도 없다; 기록된 적합성 보고서의 id 가 흔들리지 않도록 빈 자리를 그대로 둔다 | — |
| CA-15 | 어댑터 스킬 이름표가 로봇이 답하지 않는 스킬을 적음 → 로봇의 답이 built-in 을 열거할 때 기동 거부(S33); `built_in: []` 인 답은 `unverifiable`(배너, 거부 없음 — 열거 안 됨은 없음이 아니다) | `tools/ca15_s33_table_not_on_robot.sh`(소켓, built-in 을 열거하는 데몬에서; 가짜는 안 함 → `NEEDS_UPSTREAM_BUILTIN_LIST`); ROS 2: `NO_SKILL_INGRESS`(그쪽 S33 은 등재부 대 measures, 노드 배터리) |
| CA-16 | API44 조회 바이트 보존·note 기록·무토큰 명령 거부 | `tools/ca16_new_methods.py`; Microduck only; ROS 2: `MICRODUCK_SOCKET_ONLY` |
| CA-17 | 들어올림 차단·입력 해제 뒤 옛 권한 부활 금지·새 인가 계획으로 복구 | `tools/ca17_pickup.py`; Microduck only; ROS 2: `MICRODUCK_SOCKET_ONLY` |
| CA-18 | 제외한 head IMU 스트림을 포함한 실제 상류와 어댑터 지원 경계 대조 | `tools/ca18_upstream_boundary.py`; Microduck only; ROS 2: `MICRODUCK_SOCKET_ONLY` |
| CB-1 | 요청자 주체가 원 유입에서 거부됨 | `enforcement/enf01_rogue_safe_cmd_vel`(ROS 2) · `tools/cb1_raw_socket_probe.py`(소켓) |

케이스 하나는 규칙 하나만 어긴다. 자기 전송에서 수행할 수 없는 케이스는
**따로 쥘 것이 있어야 관측되는 케이스.** 두 케이스는 로봇을 움직일 권한이 허가 심박
자체가 아니라 **어댑터가 쥐는 무엇**(리스·세션·E-stop 등록)인 전송에서만 관측된다.
`CA_MAP.yaml` 의 행이 아니다 — 그 맵은 소켓·ROS 2 백엔드의 실행 맵이다. gRPC 어댑터는
이 id 로 보고하고, 정의는 여기가 정본이다:

- **CA-19** — 허가가 스텝 기한으로 끝난다: 어댑터가 쥔 것을 놓고 안전 상태를 실행한다.
  (gRPC 인터포저: 상류 세션을 끊고 `Stop`. 소켓·ROS 2: `NO_HOLD_INGRESS` — 그쪽의 쥠은
  허가 심박 **자체**라 따로 놓을 것이 없다.)
- **CB-2** — 요청자가 로봇 자신의 쥠을 가져갈 수 없다: 어댑터가 쥐고, 요청자의 시도는
  로컬에서 답하며 상류로 전달되지 않는다(G-ADP-17). (gRPC 인터포저:
  `StartSession`·`SendSessionHeartbeat`. 소켓·ROS 2: `NO_HOLD_INGRESS`.)

**안정된 사유 토큰과 함께 SKIP** 으로 보고한다(`NEEDS_ROGUE_SEAM`,
`NEEDS_FAULT_INJECTION`, `NEEDS_POLICY_VARIANT`, `NEEDS_EXPECT_AUDIT`,
`NEEDS_SROS2_KEYSTORE`, `NO_SKILL_INGRESS`, `NEEDS_UPSTREAM_BUILTIN_LIST`,
`NO_HOLD_INGRESS`, `NEEDS_TARGET_EVIDENCE`, `NEEDS_ROBOT_SIDE_PROBE`,
`NEEDS_ISSUER_SEAM`); SKIP 은 PASS 가 아니고, 아무것도 실행되지 않은 실행은
실행이 아니다. 케이스는 같고 리그만 다를 때 — 「에이전트」가 어느 컨테이너인지,
그 어댑터의 증명 빌드 문자열이 어떤 꼴인지 — 백엔드는 행의 기본 대신 전송 전용
시나리오 파일을 실행할 수 있다(맵의 `run: <scenario>`). 레퍼런스 어댑터인 ROS 2
게이트 노드도 다른 어댑터와 같은 맵·같은 실행기로 돌고 아무것도 인용하지 않는다. 부정 토큰 케이스는
어댑터와 에이전트 사이의 **토큰 심**(`pvs-public/runner/adapters/token_seam_server.py`)이
낸다 — 어댑터는 계속 「자기 이슈어」와 말하고, 바뀌는 것은 어댑터가 *듣는* 것뿐이며
보고는 전부 실제 이슈어에 닿는다. 리그가 지켜야 할 결과 둘: 어댑터가 보고한 보안
거부는 이슈어를 **운영자 해제**까지 SAFE_STOP 에 두고(리셋이 운영자처럼 해제한다),
「에이전트 도달 불가」(CA-09)는 어댑터가 실제로 부르는 엔드포인트를 죽인다. 하네스는
반대 방향으로도 자기를 증명한다 — 같은 리그 앞에 집행하지 않는 어댑터를 세우면
CA-01 과 CA-05 가 붉어야 한다(2026-09-06 실측). 케이스 id 는 어댑터를 가로질러 한 가지만 뜻한다 — 같은 id 를 다른 기대에 재사용한 리포트는 약한 어댑터를 그리는 것이 아니라 **리포트끼리 비교 불가능하게** 만든다. 적합성 id 가 존재하는 이유가 그것뿐이다.

## 5. 배치 요구

| 전송 | 원 유입 | 요청자를 떼어 놓는 수단 | `S27` 이 읽는 것 |
|---|---|---|---|
| ROS 2 | 모션 브리지의 `/cmd_vel` 구독 | SROS2 권한: 요청자 enclave 는 `/cmd_vel` 발행 불가, 브리지만 `/safe_cmd_vel` 소비 | 자기 enclave 의 permissions(keystore 없으면 unverified) |
| Unix 소켓(Microduck) | `/run/robotd/raw.sock` | 원 소켓과 디렉터리가 어댑터 그룹 소유(`0660` / `0750`); 클라이언트는 공개 소켓 그룹 회원일 뿐 | 원 소켓·디렉터리의 mode 와 gid |
| 범용 TCP/gRPC | 로봇 제어 포트 | 어댑터만 닿는 네트워크 네임스페이스/방화벽 규칙 | 바인드 주소·규칙 |

`S27` 값: `verified`(확인했고 닫혀 있음) · `unverified`(확인 불가 — 보고되지만
통과 아님) · `failed`(남에게 열려 있음 — production 기동 거부). CB-1 프로브는
하네스의 것이다 — 어댑터는 시험 삼아 자기 우회를 열지 않는다.

### 5a. Microduck 호환 UDS/CLI 프로필 (Microduck-compatible UDS/CLI profile)

공개 적합성 리그(`evaluation.py test-adapter --adapter-binary FILE`,
`pvs-public/conformance/rig_microduck.sh`)가 실제로 구동하는 구체적 형상이다. 이 형상을
지키는 대체 어댑터는 리그를 고치지 않고 시험할 수 있다. 참조 구현은 `adapters/microduck/`
(`pail-duckd`)이며, 아래는 그 구현과 리그가 생성하는 compose 파일에서 읽은 사실이고 그
이상을 약속하지 않는다. 영문판이 정본이다.

**실행 파일과 런타임.** Linux ARM64 ELF 실행 파일. 리그는 공급한 파일을 복사해 Core 런타임
이미지의 컨테이너 셋에 `/usr/local/bin/pail-duckd` 로 읽기 전용 마운트한다. 집행 어댑터와
관측 어댑터는 uid 10001·모든 capability 제거로 돌고, 하네스 컨테이너(아래 도구 케이스에서
바이너리를 직접 띄우는 쪽)는 Docker 와 장애 심을 조작하므로 root·capability 유지로 돈다.
이미지는 Debian 13(trixie), 게이트 라이브러리는 `/opt/pail/lib/libpail_gate.so`(§2 의 C ABI;
메이저가 다르면 기동 거부). 바이너리가 필요로 하는 의존성은 그 이미지에 있거나 정적으로
링크돼 있어야 한다. 기동 거부는 종료코드 78 과 게이트 preflight 어휘의 사유로 끝난다. 두
케이스는 하네스가 바이너리를 직접 띄운다: CA-07 은 `PAIL_PROFILE=dev` 아래 `pail-duckd --gate
none --public … --raw …`(비집행 배관 경로, 탭 대 탭으로 바이트를 비교), CA-15 는 로봇에 없는
스킬을 적은 스킬표로 띄워 **종료코드 78 과 로그의 `S33` 줄**을 기대한다. `--gate none` 이 없거나
그 거부가 없는 바이너리는 그 행에서 실패한다.

**명령줄.** 긴 옵션이며 표시한 것은 환경변수로도 준다. 리그는 집행 어댑터를

```
pail-duckd --public /run/duck/pail.sock --public-gid 10002 --raw /run/duck/raw/state-seam.sock \
  --agent http://token-seam:50052 --robot-id robot-1 --policy /etc/pail/policy.yaml \
  --keyring /etc/pail/keys/keyring.json --skills /etc/pail/duck_skills.yaml \
  --evidence /run/duck/evidence.sock --gate-log /run/duck/gate.ndjson
```

로 띄우고, 관측 어댑터는 관측용 fake 를 상대하는 두 번째 인스턴스로 `--public
/run/duck/pail_observe.sock --raw /run/duck/raw/observe-robotd.sock --agent
http://observe-agent:50051 --policy /etc/pail/policy.observe.yaml --gate-log
/run/duck/gate_observe.ndjson`, `--evidence` 없이, 환경 `PAIL_PROFILE=production`,
`PAIL_KEYRING_MODE=unsigned-dev`, `PAIL_BUILD_INFO` 로 띄운다. 두 인스턴스 모두
`PAIL_KEYRING_MODE` 를 환경에서 읽는다: 비어 있으면 서명된 키링 번들을 요구하므로 리그의
서명 없는 개발 키링은 키 0개로 읽히고 모든 토큰이 `ERR_UNKNOWN_KEY_ID` 가 된다.

| 옵션 | 환경 | 뜻 |
|---|---|---|
| `--public PATH` | | 어댑터가 **서비스하는** Unix 스트림 소켓(robotd 가 듣던 자리). 기동 시 `--public-mode`(기본 `0660`)와 `--public-gid N` / `--public-group NAME`(`PAIL_DUCK_PUBLIC_GROUP`; 둘 중 정확히 하나)으로 만든다. 클라이언트는 그 그룹 회원일 뿐이다. |
| `--raw PATH` | | 어댑터가 클라이언트로 **접속하는** robotd 자신의 소켓. 허가된 바이트를 여기로 넘긴다. 이 소켓과 디렉터리의 mode/gid 가 `S27` 자기 점검(`0660`/`0750`, 남에게 닫힘). |
| `--agent URL` | `PAIL_AGENT_ADDR` | 로봇 에이전트 `TokenService`: `unix:/run/pail/agent.sock` 또는 `http://host:port`(dev). 없으면 에이전트 없음(dev 전용: 토큰 뷰·보고·어테스테이션 없음). |
| `--robot-id ID` | `PAIL_ROBOT_ID` | 모든 `GetActiveToken` / `ReportDecision` / `Attest` 의 신원. |
| `--policy FILE`, `--keyring FILE`, `--skills FILE` | `PAIL_POLICY`, `PAIL_KEYRING`, `PAIL_DUCK_SKILLS` | `pail_gate_new` 의 봉인 입력: 정책(없거나 불완전하면 거부), 키링(신뢰 모드는 `PAIL_KEYRING_MODE`), 스킬 이름표 `name → MOVE\|MANIPULATE\|NONE`(production 은 없으면 기동 거부; 표에 없는 스킬은 판정에서 거부). |
| `--evidence PATH` | `PAIL_EVIDENCE_SOCK` | 어댑터가 서비스하는 NDJSON 증거 유입 소켓. 없으면 증거 유입 없음. 한 줄에 객체 하나: `{"source": "NFC", "object_id": "box-12", "confidence": 0.99, "t": <ms>}` → `pail_gate_observe_evidence`. |
| `--gate-log FILE` | `PAIL_GATE_LOG` | 추가 전용 NDJSON 판정 로그(아래). 없으면 로그 없음. 리그는 필수로 요구한다. |
| `--profile NAME` | `PAIL_PROFILE` | `production`(기본; 비집행 게이트나 `S27` 실패를 거부) 또는 `dev`. |
| `--gate libpail\|none` | `PAIL_GATE` | 링크할 게이트. `none` 은 개발 배관 경로이며 결코 적합하지 않다. `--features libgate` 빌드의 기본은 `libpail`. |
| `--safe-state NAME` | `PAIL_SAFE_STATE` | 허가 회수 시 실행하는 안전 상태(기본 `stop_zero_twist`; 실행 가능해야 함, §6). |
| `--permit-recheck-ms N`(100), `--attest-interval-s N`(300), `--attest-component NAME`(`pep_gate`), `--build-info STR`(`PAIL_BUILD_INFO`, `pail-build:v1:…`), `--safety-hz N`(20), `--battery-floor PCT`(15), `--health-poll-s N`(5), `--permit-grace-n N`(3), `--clock-skew-ms N`(500) | | 타이밍·어테스테이션 손잡이. 기본값이 리그가 측정한 값이다. |

**두 소켓의 와이어.** 줄 단위 JSON-RPC 2.0, `adapters/microduck/Cargo.toml` 이 고정한 Microduck
robotd 프로토콜(`duck-ipc-proto`, rev `bc41fb5c`). 클라이언트의 첫 요청은 `hello` 이고
`params` 에 `"api_version": 44` 을 싣는다. 응답은 robotd 의 것(`{"api_version": 44,
"daemon_version": …}`)을 그대로 넘긴다. 메서드는 다섯 갈래다(`adapters/microduck/src/classify.rs`):
**통과** — 로봇 상태를 바꾸지 않는 핸드셰이크·질의·구독(`hello`, `robot.health`, `robot.modelApi`,
`robot.mode`, `robot.policies`, `robot.safeToRestart`, `robot.remoteSessionActive`,
`robot.subscribe`, `robot.skills`, `pad.bindings`, `chorale.subscribe`), 판정 없이 전달;
**정지** — `robot.stop`, 안전한 방향이지만 기록에 남는 판정; **MOVE 판정** — `robot.move {vx, vy,
vyaw}`, 선속도 노름 `hypot(vx, vy)`·각속도 노름 `|vyaw|`; **클래스 NONE 판정** — 자세·표현
(`robot.head`, `robot.look`, `robot.pose`, `robot.mouth`, `robot.sound`, `robot.theremin`,
`robot.chorale`), 다른 명령처럼 토큰에 대해 판정하되 운동 클래스는 없음; **ACTUATE 판정** —
전원·자세 상태·정책·스킬·패드 결속 변경(`robot.enable`, `robot.init`, `robot.relax`,
`robot.setMode`, `robot.loadPolicy`, `robot.reloadPolicies`, `robot.shutdown`, `robot.setSkill`,
`robot.removeSkill`, `pad.bind`); **스킬표 판정** — `robot.do {skill}`. 그 밖에 robotd 와이어에는
있지만 로봇 소켓이 서비스하지 않는 것(업데이터·정책 저장소·계정·네트워크·시스템·패드 페어링)은
로컬에서 JSON-RPC `METHOD_NOT_FOUND` 로 답하고 전달하지 않는다. 원 소켓의 `robot.state` 알림은
공개 소켓 구독자에게 중계한다 — 하네스는 어댑터의 말이 아니라 **그 건너편**을 읽는다. 게이트가 막은 명령은 **넘기지 않고 응답도
없다**. 허가된 명령은 바이트 그대로 넘긴다(I-3). 안전 피드는 어댑터 자신이 원 소켓에
`--safety-hz` 로 거는 `robot.subscribe`(`safety.fallen` / `safety.limp` → 수준), 배터리는
`robot.health` 폴링이다. 클라이언트↔원 소켓 한 쌍의 한쪽이 끝나면 다른 쪽을 즉시 닫는다(이미
사라진 상류를 상대로 클라이언트를 판정하지 않는다).

**게이트 로그 줄.** 모든 판정과 모든 정지 요청을 한 줄에 JSON 객체 하나로:

```
{"t_ms": <ms>, "kind": "outcome", "path": "command|recheck|step|safety", "state": "PERMIT|BLOCK|ESTOP|",
 "reason": "OK|ERR_…|NOGATE", "detail": "…", "forward": bool, "report": bool,
 "permit_active": bool, "step_active": bool, "estop_active": bool, "step_complete": bool, "fatal": bool,
 "mode": "enforce|observe|none", "enforcing": bool, "conn": <n>, "uid": <peer uid 또는 null>,
 "chain_id": "…", "token_id": "…"}
{"t_ms": <ms>, "kind": "stop", "path": "…", "state": "…", "reason": "…"}
```

(`adapters/microduck/src/state.rs`; `path` 는 클라이언트 요청이면 `command`, 주기적 토큰 재확인이면
`recheck`, 스텝 타이머면 `step`, 안전 피드면 `safety`.) 적합성 백엔드는 이 파일을 tail 하며
(`permit_active`, `state`, `reason`, `path`) 건너편과 함께 읽는다
(`pvs-public/runner/adapters/microduck_backend.py`). 사유 어휘는 동결 사전 벡터
`spec/vectors/contract/reason_dict.vec`(원본 `cloud/internal/reason/reason.go`).

**시간.** 게이트는 벽시계와 단조시계를 비교해, 어댑터 기동 이후 그 차이가 `--clock-skew-ms`(500 ms)
를 넘게 움직이면 어댑터가 재시작될 때까지 모든 명령을 `ERR_CLOCK_DRIFT` 로 거부한다 — 설계다.
따라서 어댑터에는 시간을 **slew** 하는 호스트가 필요하며 step 은 안 된다: 시계를 계단식으로
맞추는 VM 게스트 에이전트나 NTP 설정(Lima 의 게스트 에이전트는 약 20 초마다 ~100 ms)은 몇 분이면
한계에 닿는다. 배치 절차에 시간을 어떻게 유지하는지, step 뒤에는 어댑터를 재시작한다는 것을 적는다.
시계 점프가 요구하는 것은 **어댑터(게이트) 프로세스**의 재시작이지 로봇의 재시작이 아니다: 게이트는
기동 때만 시계 기준을 잡는다. 공식 예제의 「로봇 쪽 재시작」은 로봇 쪽 컨테이너 묶음 전체를 다시
띄우는 더 넓은 동작이며, 데모 문서가 그렇게 적는다. 절전에 들어가는 호스트는 깨어날 때 시계가 한
번에 튄다(macOS 용 Docker Desktop: 복귀 때 +1.96 s step 한 번 관측). 따라서 노트북이 절전에서
깨어난 뒤 `ERR_CLOCK_DRIFT` 는 예상되는 상태이고, 게이트 재시작이 복구이며, 그렇다고 임계값을
완화하지 않는다. 배치 절차는 게이트가 도는 곳의 절전을 막거나 「복귀 뒤 게이트 재시작」을 적는다.
게이트가 도는 곳의 시간 소스는 하나만 둔다: 호스트 시계로 맞추는 게스트 에이전트와 NTP 클라이언트가
한 VM 에 같이 돌면 호스트 시계가 NTP 에서 벗어날 때마다 게스트 시계를 서로 되돌린다(약 10 초마다
±2 s 로 실측). 먼저 호스트 시계를 NTP 와 대조한다. 게이트웨이(`pail_robot_agent`)도 시간을 본다:
엣지 리스의 토큰은 그 `not_after`(서명된 바이트에서 읽음)가 게이트웨이 자기 시계보다 뒤에 있지 않은
동안만 내주고, 지나면 창을 놓고 선언하며 다음 읽기는 Issuer 에 묻는다. 이 경계에 게이트의
`clock_skew_ms` 를 **더하지 않는다**: 게이트웨이 시계가 Issuer 보다 빠르면 일찍 놓고 다시 묻고(왕복
한 번, 거부 없음), 느리면 게이트의 `ERR_EXPIRED` 가 잡고 그 보고에 게이트웨이가 놓는다. 유효성은
게이트가 서명된 바이트로 한 번 판정하며, 게이트웨이 시계는 오프라인 창을 최대 skew 만큼 줄일 수
있을 뿐 토큰을 늘리지 못한다.

**새 계획.** 로봇에 대한 계획을 수락하면 그 로봇의 이전 ACTIVE 계획은 끝나고, 게이트웨이는 이전
계획의 창을 — 한 번도 쓰지 않았더라도 — 내려놓는다: Issuer 가 취소 때와 같은 `CHAIN_REVOKED`
비콘을 보내고, 게이트웨이는 창을 버리며, 다음 읽기가 새 계획을 가져오고, 옛 스텝 안에 있던
게이트는 다음 재확인에서 허가를 끝낸다(받은 토큰이 쥐고 있던 토큰이 아니다: `BLOCK ERR_NO_TOKEN`). 그 비콘이 나갈 때 Issuer 와 끊겨 있던 게이트웨이는 오프라인인 동안
창을 유지하고(장애는 진행을 잃을 뿐 정지가 아니다), 다시 연결되면 자기 체인을 선언하고 census 가
`CHAIN_ENDED` 로 답해 창을 버린 뒤 다시 묻는다. 오프라인 창은 네트워크가 돌아올 때가 아니라
게이트웨이가 다시 연결될 때 끝난다: 게이트웨이는 Issuer 연결에 핑을 보내므로(10 s 마다, 응답 5 s),
장애 중에 죽은 연결 — 게이트웨이가 끊겨 있는 동안 Issuer 가 재시작해 그 리셋이 닿지 않은 연결 —
은 네트워크가 돌아온 뒤 약 15 s 안에 새 연결로 바뀐다. 어느 계획이 어느 계획을 대체했는지에 대한 Issuer
의 기억은 Issuer 자신의 재시작 뒤에도 남으므로(저널에서 다시 세움) census 는 여전히 `CHAIN_ENDED` 로 답한다
(이전 사전공개판에서는 1~3분 이상 걸렸고, 그동안 대체된 계획의 창이 계속 쓰였다). 비콘이 닿기 전에 판정된 명령은 이전 계획 기준으로
판정된다 — 새 계획이 수락되기 직전과 같다. `evaluation.py test-supersede` 가 소프트웨어 리그에서
이것을 확인한다(적합성 리그의 케이스 격리로는 보여 줄 수 없는 한 가지). 게이트웨이가 끊긴 동안
Issuer 가 재시작하는 경우와, 실행 중인 스텝 도중에 새 계획이 수락되는 경우도 포함한다. 이전 사전공개판에서는
창이 새 계획보다 오래, 자기 `not_after` 까지 살아 명령이 옛 계획 기준으로 판정됐다.

**다른 전송.** 위 어느 것도 Microduck 이 아닌 로봇에 요구되지 않는다. 그런 어댑터는 자기
백엔드로 적합성 시험을 받는다: 공개 `Backend` 인터페이스(`pvs-public/runner/core/backend.py`:
`setup/teardown/reset_state`, 단계 메서드 `north_cmd`, `inject_evidence`, `inject_cmd_vel`,
`inject_skill`, `inject_safety`, `fault`, 관측 메서드 `gate`, `bridge`, `drive`, `permits`,
`stop_request_asserted`, 그리고 재정의하지 않으면 기본 `False` 라서 Enforcement 축을 PASS 가 아닌
SKIP 으로 보고하는 `enforcement_supported()`)를 구현한 클래스를 `microduck_backend.py` 옆의 모듈로
두고, 지원하지 않는 축은 꾸미지 말고 `unsupported` 로 돌려준다(`example_backend.py` 가 형상을
보여 준다). 리그 이미지는 빌드 당시의 백엔드만 품으므로 이것은 전달된 이미지에 마운트하는 일이
아니라 **작업 사본에서의 온라인 빌드**다: `pail-core` 를 복사해 모듈을 추가하고 `python3
examples/microduck/run.py conformance --build --issuer-image <전달된 Issuer 이미지 ID> --backend
MODULE:CLASS --state DIR` 를 실행하면 그 사본으로 이미지를 빌드하고 소스 신원을 기록하며 당신
클래스를 돌리고, `CA_MAP.yaml` 에 그 전송의 열이 생길 때까지 Microduck 열을 당신 백엔드 이름으로
실행한다(`examples/adapter/README.md` §4a). 그 실행의 두 규칙은 백엔드가 아니라 판정의 것이다:
**SKIP 은 결코 PASS 가 되지 않고**, **리그가 검토하지 않은 SKIP 은 실행을 `BLOCKED` 로 만든다**
(`Unreviewed skip: CA-NN`). 따라서 백엔드가 `unsupported` 로 보고한 케이스는 그 유지보수자가 글로
받아들일 때만 인정된다: `--reviewed-skip "CA-NN:<이유>"`(`run.py conformance`, `test-conformance`,
`test-adapter`)는 행을 SKIP 으로 두고 이유를 보고서와 결과의 `limitations` 에 기록하며, 결과는
`PASS_WITH_LIMITATIONS` 가 된다. FAIL 과 맵이 선언한 skip 은 검토로 지울 수 없다. Microduck 열의
도구 행 둘(CA-07 `--gate none`, CA-15 내장 목록)은 백엔드 이름과 무관하게 Microduck 도구를
실행한다; 그 도구로 구동할 수 없는 전송은 그 행을 `unsupported` 로 보고하고 다른 행처럼 검토한다.
케이스가 낼 수 있는 세 번째 말은 **`INCONCLUSIVE`** 다: 실패한 것은 없지만 관측한 것만으로는 어떤
검사를 판정할 수 없었다 — 게이트 로그는 자랐는데 건너편에서 명령이 흐르는 동안 기록이 하네스에 하나도
닿지 않았거나, 꼬리가 돌고 있지 않았거나, 관측자 자신이 굶주린 상태에서 허가 속도를 쟀거나(백엔드의
`observation_health()` 가 이들을 가른다). 러너는 그런 케이스를 새 리셋에서 한 번 더 돌리고 두 시도를
모두 남기며, 그래도 같으면 실행 결과는 `INCONCLUSIVE`(종료 코드 4)다 — PASS 도 FAIL 도 아니다. 관측된
거부는 FAIL 이다. 어댑터가 구동되는 동안 게이트 로그가 **자라지 않은 것**도 FAIL 이다
(`ADAPTER_GATE_LOG_MISSING` / `ADAPTER_GATE_LOG_STOPPED`): §5a 의 게이트 로그는 판정의 기록이고 기록되지
않은 판정은 검증할 수 없다 — 하네스는 없는 로그를 호스트 탓으로 돌리지 않는다.

## 6. 등재부

`spec/ADAPTERS.tsv` 는 모든 어댑터를 전송·유입/유출·언어·**상태**·그 상태의
근거 결과와 함께 적는다. 적합성 리포트 원본은 유지보수자의 기록이며 이 트리에
싣지 않는다: 등재부는 보고된 결과 — 날짜, 실행·건너뜀 건수, 건너뜀 사유 토큰 — 를
적어 주장을 추적 가능하게 하고, 판정은 파일이 아니라 적합성 리그의 재실행이다.
상태 어휘:

| 상태 | 뜻 |
|---|---|
| `designed` | 설계 존재; 적합성 실행 없음, 또는 SKIP 이 남은 실행 |
| `conformant_fake` | 대역 로봇 위에서 실행 가능한 케이스 전부 PASS; SKIP 은 사유와 함께 열거 |
| `conformant` | 실물 로봇 위에서 전 케이스 PASS |
| `withdrawn` | 더는 유지되지 않음 |

스킬 수준 인가를 위해 열 셋을 더했다(SK-0): `robot_class`(이 어댑터가 서빙하는 `SKILL_VOCAB.tsv` 의 로봇 종류), `measures`(어댑터가 실제로 재어 `decide()` 에 넘기는 `GUARDRAILS.tsv` 이름표, `;` 구분), `safe_state`(철회 시 실행할 수 있는 안전 상태). 스킬 등재부는 어댑터가 `measures` 에 선언한 것만 `envelope[]` 에 둘 수 있다 — 나머지는 유지보수자 쪽 등재부 검사(배포되지 않음)가 거부한다. SK-5: `safe_state` 는 어댑터가 기동 시 자기 자신과 대조하는 선언이고(Microduck `--safe-state`, 실행 불가면 거부; ROS 게이트는 `adapter_safe_state` 밖의 상태를 적은 등재부 행을 거부), 행의 `feeds` 는 게이트가 관측하는 피드(`safety_feed`·`evidence_claim`)여야 한다 — 아무도 안 보는 피드는 게이트와 이슈어 양쪽 기동에서 거부된다.

등재부에 없는 어댑터는 README 가 무어라 하든 PAIL 어댑터가 아니다.

## 7. 이 계약이 다루지 않는 것

토큰 발급, 판정 규칙, 체인 형식, 플릿 매니저의 계획 제출 — 이슈어와 canon 의
계약이다. 로봇 위 어댑터의 갱신·설정은 로봇 제조사의 메커니즘이다. 시간
수치(판정 지연·정지 지연)는 실물에서 재어 배치별로 공개하며 여기서 약속하지
않는다.

### 로컬 스텝 지속시간 시계 (GC-TIME-1)

공통 게이트는 양수 `max_duration_sec`를 절전 시간까지 포함하는 로컬 경과시간으로 잰다.
벽시계 보정·반복 명령은 이 지속시간을 초기화하거나 늘리거나 줄일 수 없다.
명령(발급자 단절 grace 포함)·허가 재검사는 경과시간 기한에 도달하면 거부한다.
종료 타이머가 늦어도 허가가 연장되지 않으며, 타이머는 한 번만 스텝을 소비한다.
시계 측정 실패는 정상 완료가 아니다.

토큰 절대 유효기간·안전/증거 검사·기존 드리프트 허용치는 별도로 유지한다.
지속시간 0은 기존 절대 만료 fallback을 유지한다. C ABI의 `now_ms`는 벽시각이며
게이트의 경과시간 시계를 설정하지 않는다. 거부 detail의 `clock=elapsed`와 `clock=wall`은
서로 다른 시계 영역이다. 공통 게이트와 소비자를 함께 재빌드하며, 발급자·토큰 wire 변경은 없다.

### Supersession is not a mandatory physical stop (TB3 hardware clarification)

A new accepted plan invalidates the previous permit. Subsequent commands are
judged against the new plan: if it permits them, motion may continue without a
physical gap. `BLOCK ERR_NO_TOKEN` describes the Microduck test observation, not
a mandatory ROS log spelling or a stop-before-every-plan contract. The ROS gate
may log `permit recheck failed ... heartbeat stopped` and then grant the next
command under the new token. Application planners must explicitly cancel/stop
when a physical pause is required. Raised-wheel encoder results are not braking
performance. 한국어: 새 계획은 옛 허가를 끝내지만 새 계획이 다음 명령을 허용하면
물리적 공백 없이 이어질 수 있습니다. 새 계획 제출 자체를 정지 명령으로 해석하지 마십시오.
