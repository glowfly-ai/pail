# NVIDIA 플랫폼 준비 도구 — 실험 단계
<!-- ko-structure: abridged -->

> 이 한국어판은 영문판보다 절·표·코드 블록이 적은 요약본이다. 영문판이 정본이며, 두 판이 다르면 영문판이 우선한다.

**NVIDIA/Jetson/Isaac Sim 일반 지원 주장이 아니며** NVIDIA 인증·보증을 뜻하지 않습니다. 측정 범위는 두 가지입니다. ① Jetson Orin Nano Super 네이티브 CPU 참조(v3, 7/7 시나리오·8시간 분할 반복, GPU 없음), ② **Brev L40S VM 1대**(Ubuntu 24.04, 드라이버 580.173, Isaac Sim 6.0.1 파생 이미지, TurtleBot3 Waffle Pi USD)에서의 v4 실제 Isaac Sim endpoint. 지원 행렬과 미해결 사항은 [Isaac Sim 안내](ISAAC.ko.md)를 보십시오. Isaac Sim 이미지는 배포하지 않으며 [`sim/sdk/`](sim/sdk/SDK_IMAGE.md)의 레시피로 직접 파생합니다.

### Jetson 반복시험의 컨테이너 CPU·메모리

Orin Nano Super 8시간 분할 반복시험(exercise/cancel 752회, 결함 주입 22회) 동안 드라이버가
역할 컨테이너 11개의 `docker stats` 를 사이클마다 한 번 표본화했다: 8.4시간에 786표본, 간격
중앙값 35 s. `CPUPerc` 는 `docker stats` 가 찍는 값 그대로 **코어 하나** 기준 백분율이며, SoC
전체 대비 점유율이 아니다.

| 역할 컨테이너 | 중앙값 | p95 | 최대 |
|---|---|---|---|
| 11개 역할 합계 | 32.4 % | 35.1 % | 45.2 % |
| 게이트 + 모션 브리지 + 로봇 에이전트(PAIL 로봇 쪽) | 4.4 % | 5.0 % | 17.2 % |
| monitor(합성 관측자) | 9.7 % | 10.7 % | 11.3 % |
| endpoint(합성 베이스) | 8.9 % | 9.6 % | 10.3 % |
| planner(합성 요청자) | 6.0 % | 6.8 % | 7.3 % |
| gate | 2.2 % | 2.6 % | 15.0 % |
| issuer | 0.8 % | 1.0 % | 1.8 % |

컨테이너 메모리 합계는 248–303 MiB, 호스트 `MemAvailable` 은 4.9–5.2 GiB 안에 머물렀다. 기록하지
않은 것: 호스트 수준 CPU(`tegrastats`), `nvpmodel` 전력 모드, 표본 사이의 값. 따라서 이 수치는
**합성 CPU 참조**의 표본화된 동작점이지 로봇 작업 부하·피크·지연 수치가 아니다. Jetson 위
결정당 지연은 측정하지 않았다.

## 구현 범위

엄격한 JSON 프로필(일반 YAML 미지원), 읽기 전용 doctor, 잠금된 평가 이미지/소스 검증, 동기 실행·상태·중단 요청, 증거 판정기를 구현했습니다. Jetson 후보는 Orin Nano·L4T36·Humble CPU 구성입니다. GPU 권한·실물 driver·새 인가 로직을 추가하지 않았습니다.

별도 mock_endpoint.py는 timeout 계약 시험용 모델입니다. 기존 ROS 참조 sink나 물리 driver에 설치된 watchdog이 아닙니다. 이 차이를 coverage에 남깁니다.

## 실행

Python3.9+, Docker/Compose v2, OpenSSL, 이미지가 이미 load된 평가 꾸러미가 필요합니다. 이 디렉터리에서 다음처럼 실행합니다. 경로는 실제 추출본과 새 상태 디렉터리로 바꿉니다.

```sh
python3 run.py doctor --profile profiles/mock-humble-v1.json
python3 run.py prepare --profile profiles/mock-humble-v1.json --core /path/to/pail-evaluation/pail-core --state /path/to/new-nvidia-run
python3 run.py start --profile profiles/mock-humble-v1.json --state /path/to/new-nvidia-run
python3 run.py status --profile profiles/mock-humble-v1.json --state /path/to/new-nvidia-run
```

상태 디렉터리는 존재하지 않아야 하고 부모는 존재해야 합니다. 소스와 상태는 서로 포함하지 않아야 합니다. 이미지 pull/build는 하지 않습니다. 새 상태를 만들 때마다 증거를 보존하며 실패한 상태를 덮어쓰지 않습니다.

start는 상시 로봇 서비스가 아니라 최대20분의 동기 소프트웨어 시험입니다. 실제 게이트·브리지와 합성 입력을 사용한 뒤 자체 컨테이너를 정리합니다. reference.log로 진행을 봅니다. 실물에 접속하거나 운동 명령을 보내지 않습니다.

다른 터미널에서 동일 프로필·상태로 stop을 요청할 수 있습니다. 살아 있는 래퍼가 자기 자식에게만 중단 신호를 보냅니다. 요청 성공이 정지 완료를 뜻하지 않으며 최종 result.json의 cleanup을 확인해야 합니다. 래퍼 자체가 죽었으면 요청을 처리할 수 없으므로 기록된 자체 project만 수동 확인합니다. 오래된 RUNNING 기록은 실행 중이라는 증거가 아닙니다.

Jetson 후보는 profiles/jetson-orin-humble-v1.json입니다. ARM64 Mac·Raspberry Pi를 Jetson으로 인정하지 않습니다. Jetson에서 실행하더라도 이 단계는 CPU 합성 시험뿐이며 hardware_verified는 false입니다. --require-verified는 검증된 프로필이 없어 rc3으로 거부합니다.

## 결과 해석과 보관

prepare의 NOT_RUN이나 doctor PASS는 실행 시험 통과가 아닙니다. 실제 참조 시험8항목·성공 종료·소스 동일성·자체 컨테이너 정리가 모두 확인돼야 실행 PASS입니다. GPU/Sim/실물 coverage는 false입니다. endpoint_model도 이 래퍼 실행에는 포함되지 않고 별도 계약 시험에서 검증합니다.

reference/ 아래에는 생성된 사설 시험키가 있습니다. 전체 상태 디렉터리를 공개·배포하지 마십시오. prepared.json/result.json과 기존 reference/evidence 경계를 구분합니다. millisecond timeout 모델을 실물 정지 보장으로 해석하지 않습니다.

반환코드: 0=요청 동작 성공(NOT_RUN/status 포함), 2=설정/선행조건 오류, 3=증거 부족/검증 프로필 없음, 4=실행 시험 실패. JSON 상태를 함께 읽습니다.

[영문 상세 안내](README.md)에 종료·제한·남은 작업을 설명했습니다. 실제 Jetson/BSP/부하 검증, 원격 TB3 watchdog·보안, Isaac ROS GPU 패키지, Sim 수명주기 연동은 후속 작업입니다.

## Managed synthetic reference v2

[Optional ROS endpoint, supervision/recovery and MOCK lifecycle](MANAGED.ko.md). Separate from the bounded v1 runner; NVIDIA hardware remains unverified.

## 역할 격리 v3 — 새 작업 권장

[역할 격리 v3 — 새 작업 권장](ISOLATION.ko.md). Legacy v2 remains a shared-key development reference.
