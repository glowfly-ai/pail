# 로봇 운영 — 공개 통합 안내
<!-- ko-structure: abridged -->

> 이 한국어판은 영문판보다 절·표·코드 블록이 적은 요약본이다. 영문판이 정본이며, 두 판이 다르면 영문판이 우선한다.

[영어 정본](ROBOT_OPERATIONS.md). **pre-1.0 실험적 계약**이며 완성된 플릿 관리 제품이 아닙니다.
통합할 때 릴리스·proto·스키마 판을 확인하고 비호환 변경 시 마이그레이션해야 합니다.

## 1. 공개 범위

- Apache-2.0: Core 오프라인 검사기 `cloud/cmd/pail_robotops_check`, 검사기용 선언 세트 생성기 `cloud/cmd/pail_robotops_fixture`(개인키를 쓰지 않음), `cloud/pkg/robotops`, [운영 proto](../sdk/proto/robot_ops_service.proto), 로봇/수집기 관측 종단.
- Separate evaluation binary license: 이슈어 검사기 `pail_issuer_robotops_check` (evaluation image), 이슈어 hold·정비 잠금 집행.
- **미포함:** 자격 준비·계획·승인 흐름·적용·복구·재개를 조율하는 비공개 상용 오케스트레이터.

[실행 가능한 오프라인 예제](../examples/robotops/README.ko.md)부터 시작하세요.
PASS는 표시한 검사 범위만 통과했다는 뜻입니다. 오프라인에서는 `ready_for_apply=false`,
`runtime_observed=false`입니다. 종료코드 0=범위 통과, 1=관측한 불일치, 2=자료 부족/잘못된 입력.
FAIL과 CANNOT_CHECK가 섞이면 둘 다 보존하고 2로 끝납니다.
대시보드의 robot operations 탭은 외부 생성 projection을 표시할 뿐 적용/재개 권한을 주지 않습니다.
물리 정지·안전 인증·플릿 규모 롤링 업데이트·원격 적용을 보증하지 않습니다.

## 2. 인터페이스와 접근 경계

| 인터페이스 | 연결과 의미 |
|---|---|
| RobotBindingProbe.ProbeBinding | 이슈어 mTLS, 실제 클라이언트 신원/레지스트리 결속과 적재값 조회 |
| RobotAgentSelfProbe.ProbeSelf | agent Unix socket, 메서드가 owner/root UID를 검사, 상류 신원 조회이며 토큰 조회 아님 |
| IssuerOpsAdmin 읽기 | GetCapabilities/GetLoadedStatus/GetHoldStatus, 전용 로컬 Unix socket과 허용 UID |
| IssuerOpsAdmin 변이 | BeginHold/ConfirmQuiesced/ReleaseHold/AdoptHold, 같은 소켓과 계획·실행·대상·역할·신뢰 epoch·시간에 결속된 서명 승인 |
| gate/bridge 상태 | private Unix socket. **gRPC ProbeSelf가 아님**. 64자리 소문자 hex nonce와 줄바꿈 요청, 제한된 JSON 문자열 맵 응답 |
| /v1/telemetry/robotops | 기존 HTTP 인증, ETag/304·revision/member 충돌 409·자료/schema 불가 503·stale 표시 |
| /v1/telemetry/robotops/probe 및 /signals | 같은 인증, nonce 조회. 현재 파싱 registry/검증된 신호 수신 관측이며 과거 기록으로 대체하지 않음 |

관리 변이 RPC는 이슈어 TCP listener에 등록하지 않습니다. 서명만 맞아도 되는 것이 아니며
순수 VerifyApproval 함수 밖의 영속 store가 소비·소유권을 집행합니다. 데이터베이스/볼륨 삭제나
projection 위조로 hold를 해제하지 않습니다. BeginHold는 새 발급을 막지만 모터 정지 증명이
아니고 ConfirmQuiesced도 소프트웨어 관측이며 인증된 물리 정지가 아닙니다.

TB3 kit의 UID/GID는 10001입니다. gate/bridge socket은 0600, agent.sock은 0660입니다.
agent 소켓은 자기 프로브 외에도 Northbound·Token·Operator 서비스를 제공합니다.
파일 권한·상위 디렉터리 통과 권한, 연결 신원, 메서드/로봇별 권한을 구별하세요.
ProbeSelf는 owner/root 외 UID를 거부합니다. 제공 Go 관측 클라이언트는 서버 UID도 검사하므로
root로 실행한 클라이언트가 non-root 서버를 거부할 수 있습니다. 구성요소 소유 UID로 실행하고
권한을 넓히지 마세요.

노드 응답은 nonce·boot/start/instance/clock·적재 지문을 가진 **프로세스 자기 보고**입니다.
실행파일/UID를 고정하고 독립적으로 준비한 기대값과 비교해야 합니다. ZERO는 ROS publish의
반환을 관측했다는 뜻이지 드라이버 수신/물리 정지가 아닙니다. 시작 NONE을 ZERO로 읽지 않습니다.
이 응답만으로 적용/재개를 승인할 수 없습니다.

## 3. 선택적 구성 변수

아래는 모두 한꺼번에 켜라는 목록이 아닙니다. 기존 [기동 보안 조건](../TRUST_BOUNDARY.ko.md)도
적용됩니다. 전체 구성 등재부/스캐너는 유지보수자 도구이며 배포 명령이 아닙니다.

| 변수 | 소비자·미설정/기본값 | 조건과 의미 |
|---|---|---|
| PAIL_OPS_DEPLOYMENT_ID | 이슈어·agent·노드 / 미설정 시 binding probe 비활성 | 같은 배치의 소문자 UUID. hold·노드 상태에는 필수, 권한 부여는 아님 |
| PAIL_OPS_HOLD_DIR | 이슈어 / 미설정 시 hold 기능 없음 | 서비스 소유 0700 영속 디렉터리. deployment ID·trust·admin socket 필요. 서비스 시작 전에 복구하며 읽을 수 없으면 거부. 컨테이너 교체 시 보존 |
| PAIL_OPS_TRUST | 이슈어 / 기본값 없음 | 공개키·역할·scope·trust epoch JSON 경로. 관리 및 정책/사이트 인가에서 요구. 개인 서명키를 넣지 않음. 필수 자료 불가/잘못된 내용은 거부 |
| PAIL_OPS_ADMIN_SOCKET | 이슈어 / 기본값 없음 | hold 사용 시 필수. 로컬 Unix 경로·0600. 서비스가 부모를 통과할 수 있어야 하고 부모를 불필요한 쓰기에서 보호. TCP 아님 |
| PAIL_OPS_ADMIN_UIDS | 이슈어 / 기본은 추가 UID 없음 | uint32 UID 쉼표 목록. 이슈어 UID는 기본 허용. 잘못된 숫자는 거부. UID 허용만으로 서명 승인 대체 불가 |
| PAIL_LOTO_DIR | 이슈어 / 미설정 시 잠금 기능 없음 | 서비스 소유 0700 영속 디렉터리, mTLS 필수. 활성 잠금을 MAINTENANCE로 복구한 뒤 서비스. 삭제로 해제하지 않음 |
| PAIL_LOTO_SUPERVISORS | 이슈어 / 기본은 추가 supervisor 없음 | `{"supervisors":[{"cert_sha256":"<64 hex>","id":"name"}]}` JSON 파일 경로. 사유와 함께 타인 잠금 해제 가능한 인증서 지문. 설정 시 읽기/형식 실패는 거부 |
| PAIL_POLICY_AUTH | 이슈어 / 기본값 없음 | 정확한 정책 바이트의 PolicyAuthorization 경로. 서로 다른 신뢰 주체의 policy_change 승인. production 부재 S40 거부, dev 예외는 insecure 명시 |
| PAIL_SITE_MODEL_AUTH | 이슈어 / 기본값 없음 | 정확한 사이트 바이트와 res:site_model scope 인가. 사이트 설정이 있는 production 부재 S40b 거부, dev 예외 명시 |
| PAIL_ROBOTOPS_STATUS_SOCKET | gate/bridge / 미설정 비활성 | 소유 0700 부모 아래 절대 Unix 경로·0600. 배치 UUID/로봇 신원 필요. gate는 robot_id 파라미터, bridge는 PAIL_ROBOT_ID. 같은 소유자·연결 거부인 잔해만 회수, 살아 있거나 남의 endpoint는 기동 거부 |
| PAIL_GRPC_UDS_PATH | agent / 미설정이면 Unix listener 없음 | 기존 0660 listener 경로. deployment ID가 자기 프로브를 추가. 기존 mTLS 신원 설정을 없애는 옵션 아님 |
| PAIL_ROBOTOPS_PROJECTION | 수집기 / 미설정 404 | 외부에서 생성한 정제 projection JSON 경로. 설정된 파일의 읽기/schema 불가를 정상으로 숨기지 않음. apply 활성화 아님 |
| PAIL_ROBOTOPS_PROJECTION_MAX_AGE_S | 수집기 / 300초 | stale 표시의 양수 임계. 잘못된 값은 경고 후 300. 인가 판정에 쓰지 않음 |
| PAIL_HW_DEPLOYMENT_ID | TB3 kit / 미설정 비활성 | 배치 신원과 로봇 쪽 probe/status를 켜는 wrapper. [실물 안내](../examples/tb3/HARDWARE.ko.md) 참조 |

적재된 trust·정책·사이트·선언 변경은 통제된 배포 작업입니다. 위 변수는 hot reload를
약속하지 않습니다. 재시작 뒤 loaded generation을 확인하세요. 공개 설정도 비신뢰 사용자의
쓰기를 막아야 합니다. 개인키는 공개 fixture와 분리하고 영속 저장소는 정비 전에 백업하되
백업을 승인된 보류/복구 절차 대신 사용하지 않습니다.

## 4. 검증 범위

예제는 선언 파일을 검사하며 실제 로봇의 개인키 소유·DDS 격리·구동을 재지 않습니다.
`cloud/`에서 `go test -tags pail_generated ./...`로 공개 패키지와 이슈어 hold/admission·재열기·UID·동시발급,
projection 관련 시험을 실행할 수 있습니다. 첫 의존성 다운로드에는 네트워크 또는 캐시가 필요합니다.
네트워크 없는 첫 빌드와 실물 검증을 주장하지 않습니다. 관리 hold·에이전트 guard 시험은 Linux 커널
신원(boot id, monotonic clock)을 읽으므로 macOS 등 비Linux 호스트에서는 그 사유로 `SKIP` 을 보고하고
명령은 0 으로 끝납니다. skip 은 통과가 아닙니다 — 그 경로는 Linux 에서 같은 명령으로 재십시오.
추출본 전체가 있어야 합니다(`cloud/` 만 있으면 canon 시험이 `spec/vectors/` 를 찾지 못합니다).

개발 전에 원본 배포를 검증하세요. `go mod tidy`나 소스 수정 뒤의 체크섬 불일치는
배달 원본과 달라졌다는 뜻이지 로봇 인가 실패가 아닙니다.
