# API 표면

PAIL 바깥의 무언가가 말을 걸거나 귀를 기울여야 하는 자리는 넷이다. 호출자가 돌려받는
거부, 센서가 주장하는 증거, 기계 자신의 안전 계층이 발행하는 안전 상태, 그리고 운영자
제어면. 이 문서는 그 넷의 계약이다.

범위는 일부러 좁다. 토큰을 어떻게 발급하는지, 게이트가 어떻게 판단하는지, 무엇을 어떻게
배포하는지는 다루지 않는다 — 다루는 것은 **경계를 넘는 메시지의 형식과 뜻**이다. 플릿 매니저나 리더,
안전 어댑터를 붙이는 제3자가 우리 내부를 읽지 않고도 이 문서만으로 구현할 수 있어야 한다.

> English: [`API_SURFACES.md`](API_SURFACES.md). 영문판이 정본이다. 두 판이 갈라지면
> 영문이 우선한다.

## 1. 네 표면

| 표면 | 전송 | 말하는 쪽 | 듣는 쪽 | 절 |
| --- | --- | --- | --- | --- |
| 거부 | gRPC 응답 필드 | 발급자 | 플릿 매니저·호출자 | §2 |
| 증거 | ROS 2 토픽 `/pail/evidence` | 리더·카메라·운영 UI | 게이트 | §3 |
| 안전 상태 | ROS 2 토픽 `/pail/safety_state` | 기계 안전 계층 | 게이트 | §4 |
| 정지 표명 | ROS 2 토픽 `/pail/stop_request` | 게이트 | 기계 안전 어댑터 | §4.4 |
| 운영자 제어면 | gRPC `OperatorService` | 운영 도구 | 발급자 | §5 |

각 절은 다음 질문의 순서로 읽는다 — 이 표면은 무엇을 위한 것인가, 누가 누구에게 보내는가,
무엇이 들어가고 무엇이 돌아오는가, 호출자는 그것으로 무엇을 해야 하는가, 실린 예제는 어디서
보여 주는가:

| 표면 | 목적 | 보내는 쪽 → 받는 쪽 | 입력 | 응답 | 호출자가 해야 할 일 | 예제 |
| --- | --- | --- | --- | --- | --- | --- |
| 거부 | 계획·토큰 요청이 왜 통과하지 못했고 재시도해도 되는지를 호출자에게 알린다 | 발급자 → 플릿 매니저·호출자 | gRPC 응답의 `Denial` 필드 | `reason_code`, `disposition`, `severity`, `retry_after_ms`, 불리언 둘 | `disposition` 으로 분기하고 `severity` 로 경보하며 `retry_after_ms` 전에는 재시도하지 않는다 | §2.6 |
| 증거 | 센서나 운영자가 대상에 대해 관측한 것을 주장한다 | 리더·카메라·운영 UI → 게이트 | `/pail/evidence` 메시지 | 없음(게이트가 소비하고, 판정은 허가에 나타난다) | 정책의 신선도 주기로 발행하고 `source` 등급을 정직하게 매긴다 | §3.4 |
| 안전 상태 | 기계 자신의 안전 수준을 발행한다 | 기계 안전 계층 → 게이트 | `/pail/safety_state` | 없음 | 계속 발행한다; 낡은 상태는 정지다 | §4.2 |
| 정지 표명 | 기계에게 정지를 요청한다 | 게이트 → 기계 안전 어댑터 | `/pail/stop_request` | 어댑터 자신의 확인 경로 | 정지한 뒤 안전 계층이 풀 때까지 래치를 유지한다 | §4.4 |
| 운영자 제어면 | unlock·revoke·컨텍스트 이벤트 읽기 | 운영 도구 → 발급자 | nonce 를 실은 `OperatorService` RPC | RPC 별 응답 | nonce 하한을 지키고 이벤트는 읽기 전용 문맥으로 다룬다 | §5 |

각 절은 실려서 돌아가는 예제를 하나씩 지목한다. 그 예제들이 §8 검사가 대조하는 세 출처
(문서·실린 소스·실린 예제) 중 셋째다 — 문서에는 있는데 실리는 어느 것도 건드리지 않는
표면은, 아무도 시도해 본 적 없는 표면이다.

## 2. 거부 — `Denial`

<!-- source: sdk/proto/pail.proto -->

거부할 수 있는 모든 응답은 구조화된 `Denial` 을 싣는다. `SubmitActionPlanResponse` ·
`SubmitTextCommandResponse` · `GetPlanStatusResponse` 에 있고, 상태가 거부일 때 채워진다.

이 응답들에는 자유 문자열 `rejected_reason` 도 있다. **거기서 분기하지 말 것.** 안정성
보장이 없는 사람용 문자열이다. 기계가 읽는 계약은 `Denial` 뿐이다.

전송 신원 거부는 정상 애플리케이션 응답이 아니라 gRPC `PermissionDenied`와
`ERR_IDENTITY_UNBOUND`로 전달된다. plan_id만 받는 `CancelPlan`·`GetPlanStatus`는
서버가 현재 계획의 소유 로봇을 찾고, 같은 체인 잠금 안에서 호출자의 leaf를
로봇 레지스트리와 대조한 뒤 취소하거나 계획 상태를 반환한다. 명시적으로 등록된
orchestrator의 위임 권한은 유지한다. mTLS 호출인데 레지스트리 검사 문맥이 없으면
거부한다. dev/UDS의 신원은 기존처럼 unchecked이며 로봇별 mTLS 격리의 증거가 아니다.

### 2.1 필드

<!-- vocab: denial -->

| 필드 | 형 | 뜻 |
| --- | --- | --- |
| `reason_code` | `string` | 거부의 안정 식별자. 버스트 어휘와 같은 사전에서 나오므로 로그에서 본 거부와 안전 버스에서 본 거부를 맞대 볼 수 있다. |
| `reason_value` | `uint32` | 같은 사유의 수치형. 버스트 증거와 바이트 수준으로 대조하기 위한 것. |
| `disposition` | `Disposition` | 호출자가 무엇을 *해야* 하는가(§2.2). 분기할 자리는 여기다. |
| `retry_after_ms` | `uint64` | 재시도 전에 기다려야 하는 하한. 재시도 일정이 아니라 최소 대기 시간이다(§2.4). |
| `severity` | `Severity` | 사람을 깨울 일인가(§2.3). `disposition` 과 직교한다. |
| `observed_epoch` | `uint64` | 이 거부가 판정된 세계 상태의 판번호. |
| `detail` | `string` | 사람용. 기계 파싱 대상이 아니고 안정적이지도 않다. |
| `origin_reason_code` | `string` | 거부 자체가 속도 제한일 때, 원래 원인이 된 사유. |
| `retry_forbidden` | `bool` | `true` 는 재시도 금지가 **사실**이라는 주장이다(§2.5). |
| `epoch_ephemeral` | `bool` | `true` 는 세계 판번호가 없다는 것이 **사실**이라는 주장이다(§2.5). |

### 2.2 `disposition` — 무엇을 할 것인가

<!-- vocab: disposition -->

| 값 | 번호 | 뜻 |
| --- | --- | --- |
| `DISPOSITION_UNSPECIFIED` | 0 | 발신자가 말하지 않았다. "모른다"로 다루고 "재시도해도 된다"로 읽지 말 것. |
| `PERMANENT` | 1 | 이 계획으로는 영원히 통과하지 못한다. 계획을 바꾸거나 상신한다. 재시도는 부하일 뿐이다. |
| `CONDITIONAL` | 2 | 세계나 계획이 먼저 바뀌어야 한다. 시간만으로는 해소되지 않는다. |
| `TRANSIENT` | 3 | 시간만 지나면 해소될 수 있다. 하한 뒤에 재시도한다. |

### 2.3 `severity` — 경보할 것인가

<!-- vocab: severity -->

| 값 | 번호 | 뜻 |
| --- | --- | --- |
| `SEVERITY_UNSPECIFIED` | 0 | 발신자가 말하지 않았다. |
| `NORMAL_DEFENSE` | 1 | 설계대로 거부한 것. 경보 대상이 아니다. |
| `ANOMALY` | 2 | 건강한 시스템이라면 일어나지 않는다. 조사할 값이 있다. |
| `SUSPECTED_TAMPER` | 3 | 무결성 위반 의심. 즉시 조사. |

`severity` 와 `disposition` 은 독립된 두 축이고, 호출자 쪽에서도 그대로 두어야 한다.
`PERMANENT` 거부는 대개 `NORMAL_DEFENSE` — 시스템이 제대로 동작한 것이다. 경보를
`severity` 가 아니라 `disposition` 으로 라우팅하면 평범한 거부마다 호출이 울리고,
늘 울리는 채널은 아무도 읽지 않는 채널이 된다.

### 2.4 `retry_after_ms` 는 최소 대기 시간이다

이 필드가 말하는 것은 *그 전에는 안 된다*이지 *그때 하라*가 아니다. 올바른 대기는
`max(자기 백오프, retry_after_ms)` 다. 재시도 일정으로 읽으면 모든 클라이언트가 같은 순간에
한꺼번에 재시도하는 무리가 된다.

### 2.5 불리언 둘이 있는 이유

<!-- pin: sdk/proto/pail.proto -->
```proto
  bool        retry_forbidden = 9;   // true = 재시도 금지가 **사실**이다
  bool        epoch_ephemeral = 10;  // true = 세계 버전이 없다는 것이 **사실**이다
```

proto3 는 스칼라 영값을 직렬화하지 않는다. 수신자에게 `retry_after_ms = 0` 과 "그 필드가
오지 않았다"는 같은 바이트다. 그 하나의 영값이 세 뜻을 함께 지고 있었다 — 재시도 금지,
하한을 모름, 하한이 아직 계산되지 않음.

그래서 두 주장을 영값에서 꺼내 자기 필드로 세웠다. 3값 열거가 아니라 별도 bool 인 이유는
구판 호환이다. 옛 발신자의 메시지는 두 bool 이 `false` 로 디코드되어 "말하지 않았다"로
읽힌다 — 침묵이 "금지"나 "ephemeral" 로 굳지 않는다.

호출자의 규칙은 따라서 하나다. **영값이 아니라 불리언을 읽어라.** `retry_after_ms == 0`
그 자체는 아무 뜻도 없다.

### 2.6 동작 예제

<!-- example: cloud/cmd/fms_denial_example/main.go -->

`cloud/cmd/fms_denial_example` 은 `disposition` 으로 분기하고, 하한을 하한으로 적용하며,
경보를 `severity` 로 라우팅하는 플릿 매니저 쪽 처리기다.

<!-- example: sdk/grpc_client_go/cmd/submit_plan/main.go -->

`sdk/grpc_client_go/cmd/submit_plan` 은 더 작은 쪽이다. 호출 한 번에, 자유 문자열이 아니라
구조화된 거부를 읽고, 영값에서 추론하는 대신 `retry_forbidden` 을 읽는다.

## 3. 증거 — `/pail/evidence`

<!-- source: robot/pail_msgs/msg/Evidence.msg -->

증거 메시지는 식별 가능한 무언가가 거기 있다는 주장이다. RFID 리더·바코드 스캐너·비전
파이프라인이 발행하는 것이고, 게이트가 표적에 대한 동작을 허용하기 전에 참조하는 것이다.

### 3.1 필드

<!-- vocab: evidence -->

| 필드 | 형 | 뜻 |
| --- | --- | --- |
| `stamp` | `builtin_interfaces/Time` | 주장이 이루어진 시각. 신선도로 판정된다(§3.3) — 발행한 시각이 **아니라** 관측한 시각이다. |
| `source` | `string` | 어느 모달리티가 주장했는가(§3.2). 등급이 매겨진다. 등급 없는 철자는 약한 주장이 아니라 쓸 수 없는 주장이다. |
| `object_id` | `string` | 주장되는 대상. |
| `confidence` | `float32` | 0.0–1.0. 정책 임계값과 대조된다. |
| `frame_id` | `string` | `pose` 의 프레임(선택). |
| `pose` | `geometry_msgs/PoseStamped` | 선택. 대상이 어디 있는가. |

<!-- pin: robot/pail_msgs/msg/Evidence.msg -->
```
builtin_interfaces/Time stamp
string source  # BARCODE|NFC|RFID|VISION|MANUAL
string object_id
float32 confidence
string frame_id
geometry_msgs/PoseStamped pose
```

### 3.2 `source` 와 그 등급

<!-- source: config/policy.yaml -->

source 는 자유 문자열이 아니다. 허용되는 모든 철자는 현장 정책 파일에서 정확히 한 번
등급이 매겨져 세 신뢰 등급 중 하나에 든다.

<!-- vocab: evidence_source -->

| source | 신뢰 등급 | 무엇인가 |
| --- | --- | --- |
| `BARCODE` | `identity_bearing` | 태그 자체가 식별자를 지닌다. |
| `NFC` | `identity_bearing` | 태그 자체가 식별자를 지닌다. |
| `RFID` | `identity_bearing` | 태그 자체가 식별자를 지닌다. |
| `VISION` | `inferential` | 식별자를 지닌 것이 아니라 외형에서 추론한 것이다. |
| `MANUAL` | `asserted` | 사람이 그렇다고 말한 것이다. |

<!-- vocab: trust_class -->

| 등급 | 랭크 | 뜻 |
| --- | --- | --- |
| `identity_bearing` | 3 | 주장의 식별자가 대상에서 왔다. |
| `inferential` | 2 | 주장의 식별자를 모델이 유도했다. |
| `asserted` | 1 | 주장의 식별자를 사람이 입력했다. |

<!-- pin: config/policy.yaml -->
```yaml
trust_classes:
  - id: identity_bearing
    rank: 3
    sources: [RFID, NFC, BARCODE]
  - id: inferential
    rank: 2
    sources: [VISION]
  - id: asserted
    rank: 1
    sources: [MANUAL]
```

기본 정책은 `min_trust_class: identity_bearing` 도 함께 둔다. 통합하는 쪽이 가장 자주
걸리는 자리가 여기다 — **기본 설정에서 `VISION` 주장은 confidence 와 무관하게 거부된다.**
`confidence` 를 1.0 으로 올려도 달라지지 않는다. 등급은 판독값의 성질이 아니라 모달리티의
성질이기 때문이다.

그 거부가 어디서 일어나는지도 함께 보아 두는 게 좋다. 발급자는 이 최소치를 집행하지
않는다 — 설정된 이름이 `trust_classes` 에서 풀리지 않을 때 기동을 거부할 뿐이다. 낮은
등급의 주장을 거부하는 것은 게이트다.

### 3.3 신선도

<!-- pin: config/policy.yaml -->
```yaml
preconditions:
  - id: safety_feed
    class: must_check_live
    freshness_ms: 1000
```

증거와 안전 상태는 둘 다 *판정 시점에 살아 있어야 하는* 사실이다. 최근일 때만 쓸 수 있다.
증거 창이 안전 창보다 긴 것은, 표적 식별이 안전 조건보다 오래 참으로 남기 때문이다.

여기에는 사람의 반나절을 잡아먹는 결과가 하나 딸려 있다. `stamp` 를 0 으로 둔 채 발행하는
쪽은 1970년에 세계를 관측했다고 주장하는 것이고, 게이트는 그 주장을 정확히 낡은 것으로
판정해 막는다. 증상은 — 게이트가 표적을 거부하는 것으로 — 날짜를 적지 않은 메시지가 아니라
정책이 거절한 것처럼 보인다. 명령줄 발행 도구는 대개 stamp 를 0 으로 둔다. 관측 시각을
찍어서 보내야 한다.

### 3.4 동작 예제

<!-- example: e2e/feeders.py -->

`e2e/feeders.py` 는 두 피드를 현재 시각으로 찍어 일정 주기로 발행한다. 소박한 명령줄
발행이 위의 영-스탬프 함정에 정확히 걸리기 때문에 존재하는 노드다.

## 4. 안전 상태 — `/pail/safety_state`

<!-- source: robot/pail_msgs/msg/SafetyState.msg -->

기계 자신의 안전 계층이 PAIL 에게 말하는 자리다. PAIL 은 안전을 평가하지 않는다. 판정을
소비하고, 그 판정이 양호가 아닌 모든 경우에 동작 허용을 거부한다.

### 4.1 필드

<!-- vocab: safety_state -->

| 필드 | 형 | 뜻 |
| --- | --- | --- |
| `stamp` | `builtin_interfaces/Time` | 관측 시각. 더 짧은 창으로 신선도 판정된다(§3.3). |
| `level` | `string` | 판정(§4.2). 인식되는 철자는 정확히 셋이다. |
| `source` | `string` | 어느 안전 계층이 말하는가. 예: 안전 PLC, 존 스캐너. |
| `detail` | `string` | 사람용. 파싱하지 않는다. |

### 4.2 `level` 과 각각이 하는 일

<!-- source: libpail_gate/include/pail_gate/safety_level.hpp -->

<!-- vocab: safety_level -->

| `level` | 파싱 결과 | E-STOP 동작 |
| --- | --- | --- |
| `OK` | `kOk` | `kRelease` |
| `WARN` | `kWarn` | `kHold` |
| `UNSAFE` | `kUnsafe` | `kTrigger` |
| `*` | `kUnknown` | `kHold` |

`*` 는 그 밖의 모든 문자열이다. 빈 문자열, 오타, 당신 안전 계층의 미래 버전이 낼 레벨 —
전부 `kUnknown` 에 떨어진다.

<!-- pin: libpail_gate/include/pail_gate/safety_level.hpp -->
```cpp
inline SafetyLevel ParseSafetyLevel(const std::string &s) {
  if (s == "OK") return SafetyLevel::kOk;
  if (s == "WARN") return SafetyLevel::kWarn;
  if (s == "UNSAFE") return SafetyLevel::kUnsafe;
  return SafetyLevel::kUnknown;  // 빈 문자열·오타·미래 레벨 전부 여기 (§4.1)
}
```

`kUnknown` 은 `kUnsafe` 와 똑같이 새 허용을 막지만 별칭이 아니라 별도 값이다. 저널이
*피드가 침묵했다*와 *피드가 우리가 모르는 레벨을 말하기 시작했다*를 구분할 수 있어야 하기
때문이다. 둘은 다른 수리를 요구하고, 한 값으로 접으면 두 번째가 보이지 않게 된다.

이 표면에서 가장 중요한 한 가지. **양호 레벨의 철자는 `OK` 다.** `SAFE` 를 발행하는 것은
안전하다는 뜻이 아니다 — 인식되지 않는 문자열이므로 E-STOP 래치를 유지하고 새 허용을
막는다.

### 4.3 E-STOP 래치

<!-- vocab: estop_action -->

| 동작 | 뜻 |
| --- | --- |
| `kTrigger` | 정지를 건다. |
| `kRelease` | 래치를 푼다. |
| `kHold` | 래치를 그대로 둔다 — 걸지도 풀지도 않는다. |

<!-- pin: libpail_gate/include/pail_gate/safety_level.hpp -->
```cpp
inline EstopAction EstopActionFor(SafetyLevel l) {
  switch (l) {
    case SafetyLevel::kUnsafe:  return EstopAction::kTrigger;
    case SafetyLevel::kOk:      return EstopAction::kRelease;
    case SafetyLevel::kWarn:    return EstopAction::kHold;
    case SafetyLevel::kUnknown: return EstopAction::kHold;
  }
```

`kOk` 만이 유일한 해제 경로이고, 이 대응은 `default` 라벨이 없는 전건 스위치다. 둘 다
의도한 것이다. 이전 모양은 `UNSAFE` 가 아닌 모든 값에서 래치를 풀었고, 그것은 발행자가
문자열 하나만 바꿔도 비상정지가 해제된다는 뜻이었다. 그리고 `default` 라벨이 있으면 미래의
새 안전 레벨이 기존 분기에 조용히 흡수될 수 있다 — 라벨이 없다는 것은 새 값이 흡수되는
대신 빌드를 실패시킨다는 뜻이다.

### 4.4 정지 표명 — `/pail/stop_request`

<!-- source: robot/pail_msgs/msg/StopRequest.msg -->

<!-- vocab: stop_request -->

| 필드 | 형 | 뜻 |
| --- | --- | --- |
| `stamp` | `builtin_interfaces/Time` | 정지를 표명한 시각. |
| `reason` | `string` | 이유. 사람용. |

<!-- pin: robot/pail_msgs/msg/StopRequest.msg -->
```
builtin_interfaces/Time stamp
string reason
```

이 토픽의 방향을 잘 읽어야 한다. PAIL 이 발행하고, 소비하지 않는다. PAIL 의 책임은 이
메시지까지다. 이것을 실제 인증된 안전 입력 — GPIO 선, 안전 PLC 입력 — 으로 바꾸는 것은
통합하는 쪽의 몫이고, ROS 토픽은 그 자체로 안전 기능이 아니다.

## 5. 운영자 제어면 — `OperatorService`

<!-- source: sdk/proto/operator_service.proto -->

RPC 셋, 전부 발급자 쪽이다. 로봇과 게이트는 이 중 어느 것도 보지 않는다.

### 5.1 컨텍스트 이벤트

발급자는 세계 모델에 대해 인가한다. `IngestContextEvent` 는 그 세계가 바뀌는 통로다 —
사람이 존에 들어오고, 물체가 옮겨지고, 로봇이 정비에 들어간다. 변경은 발급과 직렬화되므로
모든 토큰은 일관된 세계 단면에 대해 서명된다.

<!-- vocab: context_event_kind -->

| 종류 | 번호 | `node_id` / `arg` |
| --- | --- | --- |
| `CONTEXT_EVENT_KIND_UNSPECIFIED` | 0 | 거부된다. 이름 없는 변경은 적용되지 않는다. |
| `HUMAN_ENTER` | 1 | 존 id / 사람 id |
| `HUMAN_LEAVE` | 2 | 존 id / 사람 id |
| `OBJECT_MOVE` | 3 | 물체 id / 목적지 존 id |
| `MAINTENANCE_ON` | 4 | 로봇 id |
| `MAINTENANCE_OFF` | 5 | 로봇 id |
| `CORDON_ON` | 6 | 로봇 id |
| `CORDON_OFF` | 7 | 로봇 id |
| `CUSTOM` | 8 | 대응된 종류를 따른다; `custom_kind` = 사이트 모델의 `custom_events` 에 선언된 `<namespace>.<name>` |

<!-- pin: sdk/proto/operator_service.proto -->
```proto
enum ContextEventKind {
  CONTEXT_EVENT_KIND_UNSPECIFIED = 0; // rejected (fail-closed)
  HUMAN_ENTER = 1;   // node_id = zone id; arg = human local id
  HUMAN_LEAVE = 2;   // node_id = zone id; arg = human local id
  OBJECT_MOVE = 3;   // node_id = object id; arg = destination zone id
  MAINTENANCE_ON = 4;  // node_id = robot id (LOTO)
  MAINTENANCE_OFF = 5; // node_id = robot id
  CORDON_ON = 6;       // node_id = robot id (isolation)
  CORDON_OFF = 7;      // node_id = robot id
  // AG-8: a customer-defined world event. custom_kind names it
  // ("<namespace>.<name>", lowercase [a-z0-9_] on both sides) and the site
  // model's `custom_events` maps that name to one of the built-in kinds
  // above, whose node_id/arg conventions then apply. An undeclared name, an
  // empty custom_kind, or custom_kind on a non-CUSTOM kind is rejected
  // (fail-closed); nothing is mapped implicitly.
  CUSTOM = 8;
}
```

고객 정의 이벤트(AG-8)는 변경 어휘를 늘리지 않고 이름을 붙인다. 사이트 모델이

```yaml
custom_events:
  - id: acme.gas_alarm      # <namespace>.<name>
    effect: CORDON_ON       # a built-in kind; node_id/arg follow its convention
```

를 선언하면 `ContextEvent{kind: CUSTOM, custom_kind: "acme.gas_alarm", node_id:
"robot:robot-01"}` 은 `CORDON_ON` 과 정확히 같게 적용된다. 저널은 둘 다 남긴다:
`GRAPH_MUTATION.mutation_kind` 는 효과(그래서 재생은 그대로)이고 `custom_kind` 는
선언된 이벤트 이름이며, 출처 기록의 종류는 `CUSTOM:acme.gas_alarm` 이다. 사이트
모델이 선언하지 않은 이름은 거부되고, 추측으로 대응되지 않는다.

ack 는 변경 적용 후의 그래프 판번호를 돌려준다. 그 수는 `Denial.observed_epoch` 에 나타나는
것과 같은 수다. 즉 거부를 그것이 판정된 정확한 세계 판본에 묶을 수 있다.

<!-- example: cloud/cmd/cge1_evidence/main.go -->

`cloud/cmd/cge1_evidence` 가 이 이벤트들을 걸고 ack 를 찍는다.

### 5.2 Unlock 과 Revoke

둘 다 서명된 운영자 명령이다. `Unlock` 은 로봇을 안전정지 상태에서 되돌리고,
`RevokeIssuerKey` 는 발급자를 프로세스 수명 동안 지속되는 락다운에 넣는다.

<!-- vocab: unlock -->

| 필드 | 형 | 뜻 |
| --- | --- | --- |
| `robot_id` | `string` | 정상으로 되돌릴 로봇. |
| `unix_ms` | `int64` | 명령 시각. 서버 창 안에 들어야 한다. |
| `nonce` | `bytes` | 예측 불가능한 값, 최소 16바이트(§5.3). |
| `operator_sig` | `bytes` | canon 문자열에 대한 Ed25519 서명. |
| `operator_key_id` | `string` | 어느 운영자 키가 서명했는가. |

<!-- vocab: revoke -->

| 필드 | 형 | 뜻 |
| --- | --- | --- |
| `issuer_key_id` | `string` | 폐기할 발급자 키. |
| `unix_ms` | `int64` | 명령 시각. 서버 창 안에 들어야 한다. |
| `nonce` | `bytes` | 예측 불가능한 값, 최소 16바이트(§5.3). |
| `operator_sig` | `bytes` | canon 문자열에 대한 Ed25519 서명. |
| `operator_key_id` | `string` | 어느 운영자 키가 서명했는가. |

서명은 재직렬화한 protobuf 가 아니라 연결로 조립한 canon 문자열에 대해 이루어진다. 같은
메시지에 대해 인코더 둘이 다른 바이트를 낼 수 있고, 인코더에 의존하는 서명은 서명이 아니기
때문이다. 두 명령의 정확한 canon 은 실린 `.proto` 의 서비스 주석에 적혀 있다.

### 5.3 nonce 하한

<!-- source: cloud/internal/operator/operator.go -->

<!-- pin: cloud/internal/operator/operator.go -->
```go
const MinNonceBytes = 16
```

이보다 짧은 nonce 는 서명을 검사하기도 전에 거부된다. 이 하한이 권고가 아니라 계약인 이유는,
호출자가 서버의 재생 창이나 수용률을 볼 수 없어 스스로는 무엇이 안전한지 계산할 수 없기
때문이다.

16 이 무엇을 사고 무엇을 사지 않는지는 정확히 적어 두는 편이 좋다. 이 수는 암호학적 유도처럼
보이지만 그렇지 않다. 여기서의 재생 방지는 최근에 본 nonce 집합이고 짧은 타이머로 만료되므로,
nonce 는 그 창 안에서만 유일하면 된다 — 그리고 운영자 명령은 사람이 내는 것이지 초당 수천 건이
아니다. 이 하한이 실제로 막는 것은 한 바이트 같은 *예측 가능한* nonce 다. 그런 값은 길이와
무관하게 공격자가 재생 창을 미리 채우게 한다. 16바이트는 관례이고, 계산된 필요조건이 아니라
정직한 안전 여유다.

<!-- example: cloud/cmd/operator_cli/main.go -->

`cloud/cmd/operator_cli` 가 canon 문자열을 만들고 서명하며 규격에 맞는 nonce 를 생성한다.

## 6. 선택적 운영·관리 인터페이스 (실험적)

<!-- source: sdk/proto/robot_ops_service.proto -->

rc20 부터 트리에는 `sdk/proto/robot_ops_service.proto`(패키지 `pail.robotops.v1`,
Apache-2.0)와 gRPC 서비스 셋이 더 실린다. 이것은 §1 의 의미에서 다섯째 표면이 아니다 —
플릿 매니저·리더·안전 어댑터를 붙이는 데 어느 것도 필요하지 않고, 전부
[`ROBOT_OPERATIONS.md`](ROBOT_OPERATIONS.ko.md) §3 의 설정을 주지 않으면 비활성이다. 한
이슈어 아래 여러 로봇을 운영하기 위한 것이며, 이것을 구동하는 도구 — 계획·승인·적용·복구
오케스트레이터 — 는 Glowfly 가 별도로 제공한다. 여기 실리는 것은 계약, 검증
라이브러리, 종단이다.

**안정성.** 이것은 실험적 pre-1.0 계약이다. `.proto` 를 Apache-2.0 으로 공개한 것은
라이선스이지 호환성 약속이 아니다. 비호환 변경은 그것을 만든 릴리스 식별자 아래
`CHANGELOG.md` 에 기록되고 당신 쪽의 마이그레이션을 요구하며, §2–§5 처럼 외부 소비자를
위해 버전이 매겨지는 것이 아니다. 통합한 릴리스 식별자를 고정해 둔다.

| 서비스 | 리스너 | 누가 부르는가 | 무엇을 하는가 |
| --- | --- | --- | --- |
| `RobotBindingProbe.ProbeBinding` | 이슈어의 기존 mTLS 리스너. 조회 전용 | 로봇 클라이언트 인증서 보유자 | 호출자의 TLS leaf 가 요청한 로봇에 결속돼 있는지, 그리고 이슈어가 실제로 적재한 레지스트리·사이트·요청자·정책 digest 를 보고한다. lease 없음, 회전 없음 |
| `RobotAgentSelfProbe.ProbeSelf` | 에이전트의 Unix 소켓(`PAIL_GRPC_UDS_PATH`). 메서드는 에이전트 소유자 UID 나 root 만 받는다 | 로봇 위의 로컬 관측자 | 에이전트가 실제로 적재한 TLS 신원, 상류 결속, 런타임 가드 요약 |
| `IssuerOpsAdmin` | 전용 로컬 Unix 소켓(`PAIL_OPS_ADMIN_SOCKET`, mode 0600). TCP 에는 절대 없음. 매 호출마다 커널 peer UID 검사 | 허용된 UID 로 도는 운영 실행기 또는 로컬 운영 도구 | 읽기 `GetCapabilities`·`GetLoadedStatus`·`GetHoldStatus`. 변이 `BeginHold`·`ConfirmQuiesced`·`ReleaseHold`·`AdoptHold` 는 추가로 배치·행동·정규 계획 digest·대상 집합·실행 id 에 결속된 서명 승인을 요구한다 |

서비스 선언은 실린 파일에 핀돼 있다:

<!-- pin: sdk/proto/robot_ops_service.proto -->
```proto
service RobotBindingProbe { rpc ProbeBinding(ProbeBindingRequest) returns (ProbeBindingResponse); }
service RobotAgentSelfProbe { rpc ProbeSelf(ProbeSelfRequest) returns (ProbeSelfResponse); }
```

<!-- pin: sdk/proto/robot_ops_service.proto -->
```proto
service IssuerOpsAdmin {
 rpc GetCapabilities(GetCapabilitiesRequest) returns (GetCapabilitiesResponse);
 rpc GetLoadedStatus(GetLoadedStatusRequest) returns (GetLoadedStatusResponse);
 rpc GetHoldStatus(GetHoldStatusRequest) returns (GetHoldStatusResponse);
 rpc BeginHold(BeginHoldRequest) returns (ManagementResponse);
 rpc ConfirmQuiesced(ConfirmQuiescedRequest) returns (ManagementResponse);
 rpc ReleaseHold(ReleaseHoldRequest) returns (ManagementResponse);
 rpc AdoptHold(AdoptHoldRequest) returns (ManagementResponse);
}
```

유효한 서명만으로 변이의 권한이 되지 않고, hold 는 모터가 멈췄다는 증명이 아니며,
`ConfirmQuiesced` 는 인증된 물리 정지가 아니라 소프트웨어 관측을 기록한다. 이 소켓에
무엇이든 향하게 하기 전에 [`ROBOT_OPERATIONS.md`](ROBOT_OPERATIONS.ko.md) §2 에서 리스너마다
겹쳐 있는 층 — 파일 모드, peer 신원, 메서드별 검사 — 을 읽는다.

<!-- example: cloud/cmd/pail_robotops_fixture/main.go -->

이 절의 실려서 돌아가는 예제는 오프라인이다.
[`examples/robotops/`](../examples/robotops/README.ko.md) 는 선언 검사기 둘과
`cloud/cmd/pail_robotops_fixture` 를 빌드해 생성된 선언 세트에 대고 돌리고, 검사마다 일부러
붉혀 본다. 돌아가는 이슈어나 에이전트에 대고 위 서비스 셋을 부르지는 않는다 — 그것은
안내서의 선택 활성화 설정이 있어야 한다.

## 7. 표면이 아닌 것

계약의 일부처럼 보이지만 아닌 것이 넷 있다.

submit 응답의 `rejected_reason` 은 안정성 보장이 없는 사람용 문자열이다. 구조화된 거부보다
먼저 있었고, 옛 로그가 계속 읽히도록 남아 있을 뿐이다. 여기서 분기하면 깨진다.

`Denial.detail` 도 같다 — 파서를 위한 필드가 아니라 사람을 위한 문장이다. 두 거부를 구분해야
한다면 `reason_code` 를 쓴다.

위 넷 밖의 내부 gRPC 서비스와 토픽은 공개 경계가 아니다. 외부 소비자를 위해 버전이 매겨지지
않으며 예고 없이 바뀔 수 있다. `sdk/proto/` 아래의 나머지 `.proto` 둘이 이 종류다 —
`token_service.proto` 는 게이트와 에이전트 사이의 와이어, `agent_relay.proto` 는 에이전트와
이슈어 사이의 비컨 릴레이다. 게이트와 에이전트가 이 트리에서 빌드되기 때문에 실리는 것이지,
제3자가 그것을 말하리라 기대해서가 아니다.

§6 의 서비스 셋은 넷째 경우다 — 공개되고 문서화되지만, 위 네 표면의 하나가 아니라 실험적
pre-1.0 계약으로서다.

## 8. 이 문서를 정직하게 유지하는 방법

위의 모든 것은 주장이 아니라 측정이다. `spec/tools/spec_api_surfaces_check.py` 가 실린
`.proto`·`.msg`·`.hpp`·`policy.yaml` 을 읽어 각 어휘를 유도하고 셋을 대조한다.

```
이 문서  ==  실린 소스  ==  실린 예제
```

둘만 재면 모자란다. 문서와 예제만 재면 소스가 선언한 적 없는 철자를 둘이 합의할 수 있고,
문서와 소스만 재면 예제가 조용히 낡아 독자가 처음 돌려보는 것이 깨진다. 인용 블록은 전부 그
파일의 바이트 부분문자열인지 확인되고, 이 문서가 가리키는 파일은 전부 실제로 실리는지
확인되며, 한국어판이 같은 이름을 가르치는지도 확인된다 — 재지 않는 번역본은 낡는 것이 아니라
**낡은 채로 통과한다**.

한계 하나는 감추지 말고 적어 둔다. 실린 `.proto`·`.msg`·`.hpp` 파일은 인라인 주석을 한국어로
달고 있다. 그래서 위 인용 블록에는 한국어가 들어 있고, 영문판은 그 파일들이 선언하는 계약의
영어 표현이다. 검사기가 대조하는 것은 언어와 무관한 이름과 구조이며, 주석을 번역하지는 않는다.

[Core communication contract](CORE_COMM.md)
