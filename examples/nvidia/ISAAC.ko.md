# 실제 SDK·ROS 연결 v4 — Brev L40S 1대에서 측정됨
<!-- ko-structure: abridged -->

> 이 한국어판은 영문판보다 절·표·코드 블록이 적은 요약본이다. 영문판이 정본이며, 두 판이 다르면 영문판이 우선한다.

기존 인가 gate/bridge를 유지하고 endpoint만 Isaac SDK로 교체하는 **headless rclpy 연결**이다. NVIDIA OmniGraph bridge 전체 지원을 의미하지 않는다. SDK 없이 mock으로 fallback하지 않는다. v3 CPU 합성 리그는 그대로 유지된다.

## 측정된 지원 범위 (전체 행렬 2026-11-03, 0.2.0 모듈·0.2.0 amd64 이미지)

| 항목 | 값 |
|---|---|
| 검증 조합 | Nebius/Brev L40S 1 GPU, Ubuntu 24.04.5, NVIDIA 580.173.02, Docker 29.9.2, Isaac Sim 6.0.1 security-candidate 파생 이미지(`sim/sdk/` 레시피, 0.2.0 amd64 gate 기준), TurtleBot3 Waffle Pi USD(`sim/assets/` 레시피, 트리 해시 `3d46465d…`) |
| 행렬 | `check_isaac_matrix.py` BS-01~12·BP-01~12, 케이스마다 새 상태(캐시 시드, `READY_LOCKED` 37~41 s), 새 상태 반복 2회 |
| 결과 | 14 케이스 전부 릴리스 실행의 새 상태 반복 2회 PASS(BP-11 양성 대조는 모두 DETECTED), 28/28 완료, suite 판정 PASS, 무허가 이동 샘플 0; 같은 이미지의 이전 시험판의 실행 1회는 INCONCLUSIVE 1건(`deadline`, 반복 2, 정지 후 판독 지터)을 기록했고 PASS 로 세지 않았으며 release 페이지에 공개했다. 정지는 physics step 당 위치 변화로 판정한다(snapshot schema 3). 급정지 뒤 joint·본체가 움직이지 않는데도 튀는 SDK 보고 velocity 는 모든 기록에 증거로 남는다 |
| 렌더링 | 시험 장면에 DistantLight 를 두고 viewport 캡처(비검정 픽셀 비율 0.979, 2026-10-19 캡처). 조명 없는 첫 캡처는 검은 프레임이었다 |
| 미검증 | 실물 로봇, RTX 5080, 다른 OS/Sim 버전, 공식 OmniGraph ROS 2 bridge, 스트리밍/viewer, 50 Hz 최악 지연, 장시간 단일 프로세스 |

알려진 한계: 60 Hz endpoint 기록은 분당 약 5 MB, 공식 SDK 이미지의 HEALTHCHECK 는 portable root 이동으로 항상 unhealthy 로 보임(컨트롤러 준비 판정과 무관).

## 전제

- native Linux amd64, 충분한 GPU/CPU/RAM, 이미 로드된 immutable SDK 이미지와 matching amd64 평가 Core/Issuer 이미지.
- 해당6.0.0 또는6.0.1 SDK의 실제 API/내부 Humble 라이브러리·SROS2 동작을 실측해야 한다. 이 코드는6.0.1 소스에서 확인한 legacy WheeledRobot/World API 후보를 사용한다.
- 검토한 차동구동 USD asset 트리(개인키/다른 프로젝트가 없는 별도 디렉터리), 두 wheel joint 이름·반경·간격. asset은 자동 다운로드하지 않고 파일별 해시를 잠근다. 외부 참조·추가 extension/controller writer는 별도로 검토한다.
- SDK EULA를 읽고 동의한 경우에만 profile 생성의 `--accept-sdk-eula`를 사용한다. 개인정보 수집 opt-in은 자동 설정하지 않는다.

## 준비

`make_isaac_profile.py --help`에서 인자를 확인한다. `--image`에는 tag가 아니라 local Docker inspect의 sha256 ID를 주고, 실제 joint 이름·미터를 마이크로미터로 환산한 크기를 사용한다. 예:0.0325m는32500um. 임의 geometry를 다른 로봇에 복사하지 않는다.

생성된 profile과 새로운 persistent state로 실행한다:

```sh
python3 session.py doctor --profile /persistent/isaac-profile.json --state /persistent/isaac-run1
python3 session.py prepare --profile /persistent/isaac-profile.json --core /path/pail-evaluation/pail-core --state /persistent/isaac-run1
python3 session.py serve --state /persistent/isaac-run1
```

다른 터미널에서 `status`로 READY_LOCKED를 확인하고:

```sh
python3 check_isaac.py --state /persistent/isaac-run1
python3 session.py stop --state /persistent/isaac-run1
python3 session.py export --state /persistent/isaac-run1 --dest /persistent/isaac-export1
```

normal/cancel 검사는 실제 수평 pose 변화·속도와 관절/차체 정지를 요구한다. target 숫자나 ROS 발행 성공만으로 PASS하지 않는다. 전체 우회/수명주기 시험은 아직 이 검사에 포함되지 않는다. 기존 `check_managed.py`는 v4를 명시적으로 거부한다.

## 경계

- endpoint는 자기 `/nv_endpoint` SROS2 키만 가진다. `Enforce`, FastDDS, Humble이 아니면 시작을 거부한다. 원시 `/cmd_vel`이 아니라 허가 경로의 `/drive_cmd_vel`만 구독한다.
- coordinator가 실제 mTLS 발급 응답과 agent의 active token ID/bytes hash를 비교한 뒤 read-only control에 grant를 전달한다. control은 공개 ROS 권한 API가 아니며 planner에 쓰기 mount를 주지 않는다.
- 한 실행 상태당 exercise1회다. idle/timeout/pause/reset/clock fault 이후에는 stop하고 **새 state**로 전체 경로를 재생성한다. 자동 재개하지 않는다.
- 적용 wheel target과 실제 physics pose/velocity를 별도로 기록한다. 외부 ROS monitor는 다른 프로세스지만 physics read는 신뢰된 SDK 프로세스 안이므로 SDK 관리자 침해에 독립적인 관측이라고 주장하지 않는다.
- 정지·움직임 판정은 SDK가 보고하는 velocity가 아니라 한 physics step의 위치 변화(`wheel_velocity_from_angle`, `speed_from_pose`, `yaw_rate_from_pose`; snapshot schema 3)로 한다. 급정지 뒤 solver가 한쪽 wheel을 최대 0.3 rad/s, yaw rate를 0.03 rad/s로 보고한 샘플에서 joint 각도는 1e-5 rad 안에 머물고 본체는 14 µm만 밀렸다. 보고된 velocity는 모든 기록에 증거로 남고, 임계값(0.05 rad/s, 0.005 m/s, 0.005 rad/s)은 바뀌지 않는다.
- 첫 profile은 embedded OmniGraph와 nonzero initial drive targets를 거부한다. 이 검사가 임의 SDK 확장/관리자 Python 코드의 모든 우회를 증명하는 것은 아니다.
- 보안 namespace를 유지하기 위해 public streaming을 열지 않는다. 화면 viewer가 필요한 경우 별도 네트워크 설계/검증을 한다. root/privileged로 자동 전환하지 않는다.
- SDK endpoint만8CPU/24GiB/단일 GPU 요청/cache mount를 추가한다. 다른 역할의 키·namespace·mount 경계는 유지한다.

운영 참고: ① 새 상태의 콜드 스타트는 셰이더 컴파일 때문에 L40S 에서 **약 9~10분**이 걸리고, 같은 이미지·드라이버에서 컴파일한 캐시를 `--cache-seed <…/kit/cache>`(행렬) 또는 `<state>/sim-cache/kit/cache` 에 미리 복사하면 40~60 s 다. ② 정상 취소 뒤 컨트롤러 상태는 `EXERCISE_COMPLETE` 이고 `stop` 은 요약 파일이 기록된 뒤 돌아오므로 바로 `export` 해도 된다. ③ SDK 이미지는 [`sim/sdk/SDK_IMAGE.md`](sim/sdk/SDK_IMAGE.md)(고정 digest·NGC 로그인 포함), 자산은 [`sim/assets/ASSETS.md`](sim/assets/ASSETS.md)(importer 실행 스크립트·시험용 구동 덧씌우기·기대 해시) 로 재현한다. ④ 이미지 ID 는 저장소 방식(containerd vs overlay2)에 따라 다르게 보이므로 눈으로 비교하지 말고 `load`/lock 검사로 비교한다. 영문판: [ISAAC.md](ISAAC.md).

위 측정 조합 밖의 GPU/asset/ROS/SROS2 compatibility 는 **NOT_RUN** 이다. 준비/실행 오류를 `hardware_verified=true` 로 바꾸거나 root·Permissive fallback 으로 우회하지 않는다. 결과를 회수한 뒤 Brev VM Stop 도 별도로 수행해야 비용이 끝난다. 전체 행렬은 `check_isaac_matrix.py --with-fixture` 로 돌리고 `suite.json` 의 verdict 를 읽는다. fixture 실행(`prepare --fixture`)은 Sim 전용 대조군이며 지원 주장에 합산하지 않는다.

## 정지 후 관측 한계

`body_reading_jitter`는 기존 판정기의 관측 분류명이며 **입증된 원인이 아닙니다**. INCONCLUSIVE 실행의 원시 기록에는 SDK 각속도·바퀴각 변화와 함께 지속되는 자세의 미세 계단이 있습니다. 접촉·마찰·솔버 원인은 미확정이며 원래 INCONCLUSIVE를 유지합니다. 잠금 뒤 2.817초의 추가 기준 초과는 고정 2초 판정 창 밖에 있습니다. 이 창은 잠금 이후 전체 구간에 대한 보장이 아닙니다. 이후 3회 PASS로 최초 사건을 지우지 않습니다. 수치 기준과 인가 검사는 변경하지 않았습니다.
