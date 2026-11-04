# Brev 준비 도구
<!-- ko-structure: abridged -->

> 이 한국어판은 영문판보다 절·표·코드 블록이 적은 요약본이다. 영문판이 정본이며, 두 판이 다르면 영문판이 우선한다.

GPU VM을 생성하거나 과금하는 도구가 아니다. 기존 mock/Jetson 프로필과 역할 격리는 유지한다. 실제 Sim 연결의 측정 범위와 결과는 [ISAAC.ko.md](ISAAC.ko.md) 의 지원 행렬이 정본이며, 이 문서의 "미검증" 표현은 그 표 밖의 조합에만 해당한다. VM 을 Stop 해도 저장공간 과금은 남고, Delete 는 데이터가 복구되지 않는다.

## 현재 구현

- 배포 준비 파이프라인은 target 아키텍처를 명시하고 image inspect로 확인한다. 빌드·수출·잠금·포장은 receipt의 같은 target을 사용한다. 기존 arm64 기본값·이름은 유지한다. 수령자는 자신의 서버 아키텍처에 맞게 제공된 평가 꾸러미를 사용하며, 비공개 Issuer를 직접 빌드할 필요가 없다.
- amd64 평가는 별도의 `linux-amd64` ZIP/TAR를 만든다. native helper는 Linux amd64와 Mac arm64를 별개로 준비한다. 배포 가능한 실제 제품 이미지 빌드/native 회귀 통과 여부는 별도 결과를 확인한다.
- 아래 사전 진단은 읽기 전용이며 새 output 파일을 요구한다. 비용·포트 접근·렌더러·ROS·지원 인증을 자동 판정하지 않는다.

```sh
python3 brev_preflight.py --state-parent /home/ubuntu/workspace --output /home/ubuntu/workspace/preflight.json
```

`preflight=PASS`라도 `support_status=UNVERIFIED`다. L40S 후보1개, Linux amd64, 최소8vCPU/32GiB RAM/200GiB free를 확인하며 권장은16vCPU/64GiB/500GiB다. 실제 제공되는 RAM/SSD의 단위 및 OS 오버헤드를 확인한다. 다른 GPU를 임의로 지원된 것으로 바꾸지 않는다.

## 실제 SDK smoke 후보

고정한 Isaac Sim 이미지 안에서 해당 배포의 `python.sh`로 실행한다. SDK 없는 일반 Python에서는 실패해야 정상이다.

```sh
docker run --rm --gpus all --network none -e ACCEPT_EULA=Y -e PRIVACY_CONSENT=N \
  --entrypoint /isaac-sim/python.sh -v "$PWD:/pail:ro" -v /persistent/smoke:/out \
  pail/isaac-sim:6.0.1-security-candidate /pail/sim/isaac_smoke.py --output /out/sdk-smoke.json
```

smoke 는 결과를 Kit 종료 **전에** 기록하고 로컬 바닥 평면을 쓰므로 네트워크가 필요 없다(preview.14 평가에서 원격 바닥 자산 때문에 결과 없이 rc 0 으로 끝난 문제를 고쳤다). 영문판: [BREV.md](BREV.md).

6.0.1 upstream의 legacy core API 경로를 근거로 작성했으며 GPU에서 아직 미검증이다. PASS의 범위는 실제 pose 변화 및 렌더 step 요청뿐이다. 화면 픽셀, 스트리밍, PAIL 인가, ROS, SROS2, 물리 정지를 증명하지 않는다. smoke 실행은 실제 PAIL 통합 구현을 대신하지 않는다.

## 연결 계약

`sim/resume_barrier.py`는 신뢰된 orchestration 코드용 준비 계약이다. 외부 입력을 직접 전달할 권한 API가 아니다. stop_inputs/clear_targets/play/apply 포트, 인증된 계획·로봇 준비 확인, 신선한 zero 관측을 실제 구현과 연결해야 한다. mock 기반 단위시험을 실제 Sim 포트 검증으로 표시하지 않는다. 기존 `sim/lifecycle.py`의 MOCK-only 제약은 바꾸지 않았다.

남은 실제 통합: Sim timeline/physics callback·큐와 target 제거·독립 관측·ROS 신원/QoS·pause 중 watchdog·실제 SDK 버전 고정·native amd64 런타임. 이 항목이 검증되기 전에는 실제 Sim 지원 프로필이나 자동 실행 서비스를 제공하지 않는다.

Brev 상태/증거는 `/home/ubuntu/workspace` 같은 보존 경로에 두고 `/tmp` 보존을 기대하지 않는다. 전체 key 상태를 배포하지 않는다. 화면 연결이 끝나도 VM 과금은 계속되며 Stop/Delete는 별도다.
