# 설치·실행·시험 결과 확인

정본은 [TRY_IT.md](TRY_IT.md)입니다. 이 릴리스는 공통 PAIL 코어·ROS 2/TB3 참조·Microduck 소프트웨어 프리뷰를 제공합니다.
Core는 Apache-2.0 소스 배포물이며 이슈어 없이 빌드·시험합니다.
동적 발급과 로봇 데모는 별도 이슈어 실행본을 함께 제공하는 **PAIL Evaluation**을 사용합니다.
[`RELEASE.md`](RELEASE.md)의 버전·체크섬을 확인한 뒤 평가 디렉터리에서 실행합니다.

```sh
python3 evaluation.py load
python3 evaluation.py doctor
python3 evaluation.py test-microduck --state /tmp/pail-eval-test-1
python3 evaluation.py microduck --state /tmp/pail-eval-demo-1
```

오프라인 묶음은 이미지 파일을 포함합니다. 시작 묶음만 받았다면 같은 판의 이미지 파일을 별도로
받고 `load --images-dir /path/to/archives`로 불러옵니다. 공개 이미지 저장소가 있다고 가정하지
않으며 온라인 활성화·자료 업로드를 요구하지 않습니다. 실행 상태는 배포물 밖의 새 빈 폴더에
보존합니다. 아래 저수준 명령은 이미지 준비 뒤 `pail-core/`에서 사용하는 경로입니다.

## 오프라인 경로 구분

| 경로 | 이미지 load 후 오프라인? |
|---|---|
| 평가 실행 도구·기본 Microduck/TB3 실행 | 가능, 공급된 이미지 사용 |
| 기본 E2E | 가능, 포트 검사도 공급 이미지 사용 |
| Vault 변형 | 별도 의존성 준비 필요 |
| 명시적 build·Go/C++/Rust 빌드 | 인터넷 또는 도구·의존성 캐시 필요 |

Core 소스 ZIP과 이미지가 포함된 평가 ZIP을 구분합니다. 원본은 보존하고 수정은 작업 사본에서 합니다.
TB3 실물 경로는 동봉 Issuer 실행본과 공개 Core 이미지를 사용합니다. HARDWARE.md와
평가 꾸러미 VALIDATION의 바퀴 띄움 검증 범위를 확인하십시오. 다른 과거 실물 기록은 새 검증이 아닙니다.

## 1. 준비

| 호스트 | 권장 경로와 검증 범위 |
|---|---|
| macOS Apple Silicon | Linux 컨테이너를 사용하는 Docker Desktop. 해당 환경 실행 증거 있음 |
| Linux | Docker Engine + Compose plugin v2 or newer (`docker compose`). 의도된 경로이며 실제 호스트/CPU별 확인 필요 |
| Windows PowerShell/CMD | POSIX 러너이므로 네이티브 지원하지 않음 |
| WSL2 Ubuntu | Docker 통합 후보 경로. 공식 검증된 설치 절차는 아직 아님 |

Python 3.9 이상, Docker/Compose plugin v2 or newer (`docker compose`), OpenSSL 명령이 필요합니다.
macOS의 LibreSSL 3.3.6 기반 `openssl` 명령도 시험했습니다. Docker 메모리는 최소 4GB를 권장합니다.

```sh
python3 --version
docker compose version
docker info
openssl version
```

처음 이미지 다운로드·빌드를 포함하면 10~20분 이상 걸릴 수 있습니다. 캐시가 있으면 수 분으로 줄 수 있습니다.
CPU·네트워크·아키텍처에 따라 다르며 ZIP에는 이미지가 아니라 소스가 들어 있습니다.

### Windows WSL2의 파일시스템

Docker 연동을 켠 WSL Ubuntu 셸에서 Python 3·OpenSSL을 사용합니다. 생성 개인키 상태는 Windows 드라이브
`/mnt/c`, `/mnt/d` 대신 WSL Linux 파일시스템의 `~/pail`, `/tmp/...`에 두세요.
0600 권한을 보장하지 못하는 마운트는 런타임 접근 사전검사가 거부합니다. Mac/Linux/WSL2 모두 같은 ZIP을 사용하며
Windows 네이티브 PowerShell/CMD는 POSIX 실행기의 런타임 지원 경로가 아닙니다.
Docker Desktop 한 버전의 네트워크 관측을 모든 설정으로 일반화하지 않습니다.

Docker 설치 전에도 Python 만으로 도는 검사는 깨끗한 트리에서 바로 실행할 수 있습니다:

```sh
python3 scripts/check_public_content.py
python3 scripts/check_public_links.py
python3 spec/tools/spec_conformance_check.py
```

Windows에서는 설치된 명령이 `python`이면 그 이름을 사용합니다.
규격 진단은 콘솔이 표현할 수 없는 문자를 `\u2014` 같은 형태로 표시하며 검사 데이터는 바꾸지 않습니다.
UTF-8 리디렉션이 필요하면 호출 환경에 `PYTHONIOENCODING=utf-8`을 설정합니다.

## 2. TB3 없이 시작하기

압축을 푼 루트에서 실행합니다.

```sh
python3 examples/tb3/run.py
```

[TB3 안내](examples/tb3/README.md)에 8개 검사의 범위와 별도 하드웨어 연결 조건이 있습니다.
터미널의 `STATE=...`, 각 PASS/FAIL, `RESULT=PASS` 또는 실패 내용을 확인하세요.
`base_forward`는 모의 베이스가 명령을 받았다는 뜻이지 바퀴가 움직였다는 뜻이 아닙니다.

출력된 상태 폴더의 `evidence/FINAL_RESULT.json`, `evidence/results.json`에는 기대값·관측값·시각이 있습니다.
그 옆에 원시 JSONL과 로그가 있습니다. `bridge_deadman`은 플래너가 계속 명령을 내는 중 게이트 단절을 다루며,
물리 비상정지 인증이 아닙니다. duration 완료 검사와 토큰 유효기간 만료 검사도 구별해야 합니다.

### 2a. 같은 스택의 판정을 실시간으로 보기

```sh
python3 examples/tb3/demo.py build --build-window-confirmed   # 소스 체크아웃용(온라인). 평가 배포본은 이 단계를 건너뛴다
python3 examples/tb3/demo.py start
python3 examples/tb3/demo_scenes.py      # 선택, 두 번째 터미널: 모든 장면을 돌리고 판정한다
```

`demo.py`는 같은 이슈어·게이트·모션 브리지를 띄운 채 시뮬레이션 베이스를 붙이고, `forward 1 m`
같은 명령을 치면 판정 하나하나가 보이는 로컬 페이지를 엽니다. 화면과 장면별 설명은
[TB3 데모 따라 하기](examples/tb3/DEMO.ko.md)에 있습니다. 위치는 시뮬레이션이고 태그·안전
입력은 합성이며, 장면 통과는 소프트웨어 결과이지 로봇 측정이 아닙니다. 같은 장면을 실물
TurtleBot3 에서 돌리려면 [`examples/tb3/HARDWARE.ko.md`](examples/tb3/HARDWARE.ko.md)를 따르세요.

## 2b. Microduck 실물·ROS 없이 시험하기

TB3와 **같은 해제 루트**에서 실행합니다. 호스트에 ROS를 설치할 필요는 없습니다.

```sh
python3 examples/microduck/run.py doctor
python3 examples/microduck/run.py demo --state /tmp/pail-duck-first
python3 examples/microduck/run.py conformance --state /tmp/pail-duck-suite
```

시험마다 소스 밖의 **새 상태 폴더**를 사용합니다. demo는 토큰 없음 차단·정상 명령 전달·속도 한도 초과 차단을
공식 upstream fake와 대조합니다. conformance는 장애·권한 검사를 더 수행합니다.
CA-15의 알려진 SKIP는 fake의 스킬 목록 한계이지 실물 시험 통과가 아닙니다.
[Microduck 한국어 안내](examples/microduck/README.ko.md)에 범위와 결과 해석이 있습니다.

같은 스택 위의 브라우저 콘솔과 이 실행의 원장을 읽는 관측 대시보드는 `python3 examples/microduck/demo.py start`
로 띄우고 [Microduck 데모 따라 하기](examples/microduck/DEMO.ko.md)를 봅니다. 소스 체크아웃은 그 전에
`python3 examples/microduck/demo.py build --build-window-confirmed`(온라인)로 빌드하고, **평가 배포본**은 빌드 없이
동봉 이미지로 `python3 evaluation.py microduck --state /tmp/pail-single`(오프라인)을 씁니다.
모의 로봇 두 대를 이슈어 하나·대시보드 하나로 실행하려면 같은 문서의
[공유 이슈어 소프트웨어 fleet](examples/microduck/DEMO.ko.md#공유-이슈어-소프트웨어-fleet) 절을 따릅니다.

출력된 state의 `result.json`, `run.json`, `source-manifest.json`, 로그를 보존하세요.
러너는 종료·실패 시 자기 Compose 서비스만 정리하며 실행별 private 볼륨은 보존합니다. 개인키·private 볼륨 전체를 공유하지 마세요.
처음에는 TB3 → Microduck demo → conformance 순서로 실행하면 됩니다. 최초 다운로드·Docker 디스크 사용량은 ZIP보다 큽니다.
아래 로컬 뷰어는 E2E 상태를 대상으로 하므로 Microduck state를 넣지 않습니다. Microduck 결과는 현재 JSON·로그로 확인합니다.

## 3. 별도 issuer/gate E2E

소스는 변경하지 않습니다. 관리용 설정은 `STATE/provision/config`, 서비스용 설정은 `STATE/runtime/config`로 분리합니다.
개인키는 0600을 유지하며 소스 전체 chown이나 키의 전체 읽기 허용은 하지 않습니다.
같은 소스에서 재실행할 때(실패 후 포함) 새 STATE를 사용합니다. 포트·host networking·ROS domain 0 제약 때문에 순차 실행하세요.


```sh
bash e2e/run_e2e.sh
```

인가 발급·게이트 집행·로컬 원장·파일 앵커·검증을 실행합니다. 매번 새 상태 폴더를 사용하고,
`PAIL_E2E_STATE`로 지정한 폴더도 새 폴더 또는 빈 폴더여야 합니다. 기존 증거는 삭제하지 않습니다.
같은 checkout을 보존한 채 새 STATE로 순차 재실행할 수 있습니다. 병렬 실행은 지원하지 않습니다.

E2E는 Docker의 host networking과 SROS2 domain 0을 사용합니다. Docker Desktop의 host-network 기능이
필요할 수 있으며, 0이 아닌 `ROS_DOMAIN_ID`는 거부합니다. 사용할 수 없으면 격리 네트워크의 TB3 예제를 먼저 실행하세요.

먼저 **서비스 이미지 자체**(동봉 평가 이미지, 또는 소스 체크아웃이 빌드한 이미지)로 Docker 네트워크의 포트를 확인합니다.
별도 프로브 이미지를 받지 않으므로 오프라인에서도 동작합니다. 키 준비 전에 같은 이미지로 다시 검사합니다. 초기 결과는 `evidence/ports-before-build.json`, 재검사는 `evidence/ports.json`에 보존합니다.
이 네트워크는 macOS 호스트의 lsof/netstat 결과와 다를 수 있습니다. 사용 중이거나 확인할 수 없으면 rc=2로 종료하며,
기존 프로세스를 종료하지 않습니다. 사전 확인 뒤에도 경쟁이 있을 수 있어 실제 bind 실패 로그도 확인합니다.

```sh
PAIL_NORTHBOUND_PORT=50151 PAIL_CLOUD_PORT=50161 bash e2e/run_e2e.sh
```

상태 폴더 직접 선택 예시입니다. 이미 사용한 폴더 이름을 재사용하지 마세요.

```sh
PAIL_E2E_STATE=/tmp/my-pail-e2e-first bash e2e/run_e2e.sh
```

| 파일 | 의미 |
|---|---|
| `evidence/run.log` | 판정과 실제 관측 식별자 |
| `evidence/run.done` | rc=0이면 정상 완료. 없으면 완료를 확인할 수 없음 |
| `evidence/services.log`, `observers.log` | 종료 전 수거한 서비스·원시 관측 로그 |
| `evidence/ports.json` | Docker 네트워크의 포트 사전 관측 결과 |
| `blackbox/` | 그 실행의 원본 원장 |
| `anchor/` | 같은 호스트의 파일 앵커. 독립 외부 witness가 아님 |
| `evidence/verification-keyring.json` | 해당 실행의 공개 검증키. 개인 서명키가 아님 |

사전 확인에서 거부되면 evidence 폴더가 아직 없을 수 있습니다. 실패 실행도 보존하고 실행별 원장/인덱스를 합치지 마세요.
전체 상태에는 특히 bundle 모드의 개인 테스트키가 있을 수 있으므로 전체 폴더를 공유하지 마세요.
공유할 것은 검토한 로그·판정·원장·공개 검증 자료이며, 개인키·keystore 전체가 아닙니다.

## 4. 데모와 관측 화면

- **공개 CLI 예제:** E2E와 TB3 명령. 하드웨어 없이 실행 가능.
- **TB3 라이브 데모 콘솔:** `examples/tb3/demo.py`, 포함. 시뮬레이션 베이스가 붙은 로컬 페이지이며
  [따라 하기](examples/tb3/DEMO.ko.md)에 설명. 시연용 요청자이지 운영 대시보드가 아님.
- **Microduck 라이브 데모 콘솔 + 대시보드:** `examples/microduck/demo.py`, 포함. 공식 `robotd --fake`
  위의 같은 꼴 페이지와, 그 실행의 원장 미러를 읽는 관측 대시보드(`pail_telemetryd`) —
  [Microduck 따라 하기](examples/microduck/DEMO.ko.md).
- **오프라인 로봇 운영 예제:** `examples/robotops/`, 포함. 오프라인 선언 검사기 둘과 fixture 생성기를
  빌드해 트리 밖에서 돌리고 일부러 붉혀 본다 — [따라 하기](examples/robotops/README.ko.md).
  로봇에 닿는 것은 없고, PASS 는 무엇을 적용할 권한이 아니다.
- **선택적 관측 UI:** `cloud/cmd/pail_telemetryd`. 영어 기본·한국어 선택. 인가 제어면이 아니며 상용 UI 범위를 확정하지 않음.

Docker 시험 두 경로에는 호스트 Go 컴파일러나 브라우저가 필요하지 않습니다.

### 완료된 E2E 원장을 로컬 관측 UI에서 보기

Mac 또는 Linux/WSL2의 공개 소스 루트에서 실행합니다. 호스트 Go/protoc는 필요하지 않습니다.

```sh
python3 examples/viewer/run.py --state /tmp/my-pail-e2e-first
```

STATE는 완료된 E2E의 정확한 경로입니다(TB3 상태 아님). Docker로 네이티브 뷰어를 빌드하고
내보낸 사본의 해시·reindex·index-check를 확인한 뒤 해당 실행의 로봇 레지스트리를 연결합니다.
`http://127.0.0.1:18090/dashboard/?tab=timeline&preset=6h`를 열고 Ctrl-C로 종료합니다.
포트 충돌은 `--port 18091`, 화면 없이 점검은 `--check-only`, 이미 빌드한 바이너리 재사용은 `--skip-build`입니다.

E2E가 서비스를 멈춘 뒤 `viewer-input/`에 저널 사본을 만들고
`evidence/viewer-input-manifest.json`에 파일 해시를 남깁니다. 사본은 호스트 사용자 소유이며
원본 저널은 서비스 소유로 보존합니다. 개인키·루트 서명키는 복사하지 않습니다.
실시간 원장이 아닌 종료된 실행의 사본입니다. 오래된 실행은 시간창을 조정하세요.
로봇 선택은 `evidence/robot_registry.yaml`을 사용하며 이름 해소와 필터 적용을 확인합니다.

빈 화면이면 E2E 결과 → 사본 내보내기·읽기 권한 → reindex/index-check 결과 → 타임라인 탭 → 시간창 → 로봇 필터 순으로 봅니다.
permission denied와 chain_error는 성공한 빈 입력이 아닙니다. 인덱스 대조는 외부 앵커·물리 동작 인증도 아닙니다.
기본 E2E는 모든 라이브 UDP를 배선하지 않아 원장 타임라인과 빈 현황 표가 함께 있을 수 있습니다.
이 실행기는 loopback 리스너만 엽니다.

**인증 경계:** 정적 HTML은 열리지만 bearer 설정 시 데이터 API는 Authorization 헤더가 필요합니다.
현재 UI에는 bearer 로그인 흐름이 없으므로 이 로컬 실행기는 상속된 `PAIL_TELEMETRY_TOKEN`이 있으면 설명과 함께 거부합니다.
이 절차를 다른 네트워크 인터페이스로 노출하지 마세요. 원격 배포는 별도 인증·TLS 구성이 필요하며 포트 publish만으로 로그인 흐름이 생기지 않습니다.

### 언어 선택과 질의

첫 방문은 영어입니다. 상단 Language / 언어에서 한국어를 선택하면 가능한 경우 브라우저에 기억합니다.
`?lang=en` 또는 `?lang=ko`가 저장된 선택보다 우선합니다. 전환 시 페이지를 다시 불러오며 현재 탭과 적용된 URL 필터는
유지합니다. 아직 적용하지 않은 입력은 전환 전에 마무리하세요.

질의 예: `last 1 hour robot 1 BLOCK` 또는 `최근 1시간 로봇 1 차단`.
한정된 규칙 파서이며 AI 번역기가 아닙니다. 무시된 단어를 표시하고 Apply/적용 전 조건을 검토하게 합니다.
원본 ID·사유 코드·해시·API·원장은 번역하지 않습니다. 임의의 사용자/서버 문구는 추측하지 않고 그대로 표시합니다.

### 이미지 보존·정리

기본값은 재현을 위해 이미지 태그를 보존하고 정확한 정리 명령을 출력하는 것입니다.
`python3 examples/tb3/run.py --remove-images`는 증거 수거 후 **그 실행이 직접 만든 태그만** 제거합니다.
`--skip-build`로 제공한 이미지는 절대 제거하지 않습니다. 공유 레이어·build cache는 남을 수 있으며 전역 prune은 하지 않습니다.
결과는 `evidence/image-cleanup.json`에 따로 남고 정리 실패를 인가 시험 결과와 혼동하지 않습니다.

## 5. 피드백과 검사 결과

ZIP 이름/해시, CPU/OS, Docker/Python 버전, 정확한 명령, STATE, 종료코드, 기대/관측, 검토한 evidence를 함께 보내주세요.
취약점은 [SECURITY.md](SECURITY.md)의 비공개 신고 경로를 따르며 공개 이슈에 올리지 마세요.

파일 링크 검사: `python3 scripts/check_public_links.py`.
규격 검사: `spec/tools/spec_*_check.py`.
마지막 줄은 PASS/FAIL, failures, skipped_groups, unmeasurable_groups, scope를 표시합니다.
SKIP·판정 불가 계수는 관측 그룹 수이며 개별 assertion 수가 아닙니다. PASS는 수행한 범위에서 finding이 없다는 뜻이지
미실행 항목도 실행됐다는 뜻이 아닙니다. 전제 실패는 rc=2, finding은 rc=1, 수행 범위 통과는 rc=0입니다.
`grep -i fail` 대신 종료코드·필드를 사용하세요. 혼동을 주던 legacy FAIL 0 줄은 이번 RC부터 제거했습니다.
검사기 소유 문구는 영어이며 인용 입력은 원래 언어를 유지합니다.


### 공개 Go 시험 범위

cloud 빌더 일부가 아니라 전체 공개 트리를 시험 입력으로 사용합니다. 로봇 지문 TSV와 사이트 모델 예제는
필수 입력이므로 누락·읽기 실패는 SKIP이 아닌 실패입니다. 기본 공개 실행에서 의도적으로 남는 SKIP은 다음입니다.

- `TestEmitRealRecord`: 출력·키 입력을 별도로 지정하는 선택적 레코드 산출.
- `TestCommittedKeyMaterialIsListed`: 이전 소스 이력의 키 파일 감사.
- `TestRenamedKeyStillRejected`: 역사 소스 파일 이름 변경 감사.

공개 실행에서도 TSV/컴파일 지문·제거 표식·등재된 잔존 인증서 부재·새 키 허용·알려진 지문의 이름 변경 거부를 검사합니다.
역사 개인키를 재배포하지 않습니다. 이 시험 SKIP과 규격 검사기의 미실행 관측 그룹 수는 다른 집계입니다.


### 엄격한 umask 확인

TB3는 공유 관측 디렉터리·파일과 개인키의 권한을 구분하고, 서비스 쓰기·호스트 읽기를 기능 시험 전에 확인합니다.
Linux에서 새 상태로 `(umask 077; python3 examples/tb3/run.py)`를 실행해 볼 수 있습니다.
권한·시각 전제조건 실패는 기능 판정과 구분하며, 생성된 경우 `prerequisite-failure.json`을 확인하세요.
실행기가 시스템 시계나 동기화 서비스를 변경하지는 않습니다.
