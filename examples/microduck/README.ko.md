# Microduck 소프트웨어 프리뷰
<!-- ko-structure: abridged -->

> 이 한국어판은 영문판보다 절·표·코드 블록이 적은 요약본이다. 영문판이 정본이며, 두 판이 다르면 영문판이 우선한다.

> **0.2 평가 묶음:** 먼저 평가 디렉터리에서 `python3 evaluation.py load`를 실행합니다.
> 이슈어 소스는 포함하지 않습니다. 아래의 저수준 명령은 그 뒤 `pail-core/`에서 사용합니다.
> 처음에는 `evaluation.py` 실행 도구를 권합니다.


**실험적 기능이며 실제 Microduck에서는 아직 검증하지 않았습니다.** Pollen Robotics나
Hugging Face의 공식 통합·인증을 의미하지 않습니다. 정확한 절차는 [영문 안내](README.md)를 따릅니다.

ROS2 경로와 같은 PAIL Core를 사용하지만 Microduck 예제를 실행하기 위해 ROS2를 설치할
필요는 없습니다. 로봇·Anchor SaaS 계정·유료 AI 서비스 없이 공식 robotd fake로 시험합니다.

공개 소스 루트에서 Python 3.9 이상과 Linux 컨테이너용 Docker/Compose를 준비하고:

```sh
python3 examples/microduck/run.py doctor
python3 examples/microduck/run.py demo --state /tmp/pail-duck-demo-1
```

소스 트리 밖의 새 상태 디렉터리를 사용합니다. 첫 빌드는 의존성을 내려받고 컴파일합니다.
토큰 없음→거부, 정상 허가→전달, 속도 초과→거부를 확인하며 실제 모터의 움직임을 시험하는
것은 아닙니다. 결과와 로그는 상태 디렉터리에 남고 종료 시 해당 실행의 서비스만 정지합니다.
생성 키와 원본 저널은 실행별 Linux Docker private 볼륨에 보관합니다. 호스트의 private 폴더는 마운트 지점이며 키 저장소가 아닙니다. 해당 볼륨은 외부로 보내지 마십시오.

전체 소프트웨어 적합성 시험은 `demo` 대신 `conformance`를 사용합니다. 지정된 CA-15의
SKIP는 fake의 built-in 스킬 목록 미제공을 뜻하며 통과로 세지 않습니다. 물리 환경·NFC·
출하 펌웨어·실물 설치는 별도 시험 대상입니다. 지원 표에 실측된 환경만 검증 완료입니다.

이 예제는 격리된 개발용 통신과 로컬 키를 사용합니다. 어댑터의 production 기동 검사가
전체 서비스의 운영 보안 검증을 대신하지 않습니다. 권한 문제가 나면 로그를 확인하고,
키나 전체 디렉터리를 world-readable로 바꾸지 마십시오.


## 인가 경계

상류 `robotd`는 일반 명령 분기표에 들어가기 전에 `head_imu.stream`도 처리합니다.
어댑터 v2는 이 센서 스트림을 **명시적으로 지원하지 않습니다**. 이 거부는 PAIL의
지원 범위이며, 상류도 거부한다는 뜻이 아닙니다.

PAIL은 클라이언트가 로봇 소켓으로 보내는 명령을 판정합니다. 로봇 데몬이 스스로
시작하는 동작 — 들어올림 시 일시정지 자세(`picked_up`으로 보고되어 PAIL은 UNSAFE로
처리), 유휴 머리·몸 동작, 정책 시작 전 자세 점검(보고되지 않음) — 은 이 인가 경계
밖입니다. PAIL이 이 동작을 정지시키지는 않으며, `picked_up` 이외에는 관측할 수도
없습니다. 원장에는 그 구간의 클라이언트 명령에 대한 판정이 기록되며, 로봇의 자율
동작 자체가 기록되는 것은 아닙니다.

`picked_up` 해제는 안전 입력만 회복합니다. 철회된 계획은 복구되지 않으며 새로
인가된 계획이 필요합니다. `robot.rest`·`robot.rebootMotors`에는 ACTUATE 인가가 필요하고,
`robot.flashlight`는 표현 명령입니다. `robot.vetbookNote`의 기록은 어댑터 로컬 감사이며,
PAIL 블랙박스 영속 저장을 증명하는 영수증이 아닙니다.


## 라이브 데모 콘솔과 대시보드

```sh
python3 examples/microduck/demo.py build --build-window-confirmed
python3 examples/microduck/demo.py start
python3 examples/microduck/demo_scenes.py      # 선택, 두 번째 터미널: 모든 장면을 돌리고 판정한다
```

같은 스택에 데모 액터를 더하고, TurtleBot3 와 같은 꼴의 브라우저 콘솔과 이 실행의 원장 미러를
읽는 관측 대시보드를 띄웁니다. 화면 캡처와 장면별 설명이 있는 따라 하기: [`DEMO.ko.md`](DEMO.ko.md)
(영어 원문 [`DEMO.md`](DEMO.md)). 위치는 fake 가 적용했다고 보고한 속도의 적분이고, 태그 피드와
안전 피드 심은 합성이며, 이 로봇 클래스에는 실시간 판정 피드가 없습니다.

## 빌드 진행 확인

출력된 STATE의 `build.log`에서 진행을 확인할 수 있습니다(예: `tail -f /tmp/pail-duck-demo-1/build.log`).
이미지 layer·Rust crate 다운로드가 네트워크를 기다릴 수 있으므로 정지한 진행 숫자만으로 실패를 판정하지 않습니다.
로그와 최종 종료코드를 보존하며 소스를 지우거나 개인키 권한을 완화하지 마세요.
Native artifact·OS/SONAME 조건은 [보드 설치 안내](../../adapters/microduck/deploy/INSTALL.ko.md)에 있습니다.
