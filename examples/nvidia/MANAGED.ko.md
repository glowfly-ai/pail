# 관리형 소프트웨어 참조 리그 v2
<!-- ko-structure: abridged -->

> 이 한국어판은 영문판보다 절·표·코드 블록이 적은 요약본이다. 영문판이 정본이며, 두 판이 다르면 영문판이 우선한다.

**Jetson·GPU·실제 Isaac Sim·물리 로봇 지원 완료가 아닙니다.** 실제 PAIL ROS 게이트/브리지에 합성 endpoint와 독립 관측기를 연결하고, 자체 리그의 시작·중지·고아 자원 복구 및 Sim 모의 상태기계를 제공합니다.

기존 run.py start는 단발 시험 그대로이고 v2는 session.py로 분리했습니다. 이미지가 load된 평가 꾸러미, Python3.9+, Docker/Compose v2, OpenSSL이 필요합니다. 묵시적 pull/build·privileged·host network·장치 접근·부팅 서비스 설치는 없습니다.

```sh
python3 session.py doctor --state /tmp/nv-run --profile profiles/mock-humble-v2.json
python3 session.py prepare --state /tmp/nv-run --profile profiles/mock-humble-v2.json --core /path/to/pail-evaluation/pail-core
python3 session.py serve --state /tmp/nv-run
```

serve는 foreground입니다. 다른 터미널에서 아래 명령을 사용합니다. 상태 경로는 짧고 새 경로여야 하며 소스와 분리합니다.

```sh
python3 session.py status --state /tmp/nv-run
python3 session.py exercise --state /tmp/nv-run
python3 session.py idle --state /tmp/nv-run
python3 session.py stop --state /tmp/nv-run
```

exercise만 실제 평가 Issuer에 인증된 시험 계획을 제출하고 합성 입력을 최대8초 켭니다. gate의 실제 인가는 별도이며 더 일찍 끝날 수 있습니다. 합성 endpoint는 실제 구동 토픽으로 재발행하지 않습니다. serve만 켜서는 계획이 자동 제출되지 않습니다. stop 응답은 요청 수락이고 완료는 최종 summary/cleanup을 확인해야 합니다.

controller가 죽으면 파일의 ACTIVE를 살아 있는 것으로 믿지 않습니다. 전용 socket challenge와 실행별 ID로 확인합니다. recover 기본은 조사만 하며 --cleanup은 정확한 자체 컨테이너/이미지/label이 일치할 때만 정리합니다. 자동 운동 재개는 없고 새 상태·새 명시적 요청이 필요합니다.

```sh
python3 session.py recover --state /tmp/nv-run
python3 session.py recover --state /tmp/nv-run --cleanup
```

ROS endpoint는 CLOCK_BOOTTIME과 별도 timer로 만료를 판단합니다. 관측기 사망을 zero 확인으로 바꾸지 않습니다. 250ms endpoint/500ms heartbeat는 합성 시험 설정이지 실물 정지 보장이 아닙니다. host/daemon/runtime 진단을 분리하고 모르는 값을 PASS로 바꾸지 않습니다.

장애 시험은 별도 합성 리그에서만 실행합니다. 권한 없는 발행, 노드 사망, supervisor 강제 종료, permit 중복을 의도적으로 주입합니다. Sim 상태기계는 MOCK 입력과 가짜 actuator로만 검사합니다.

```sh
python3 check_managed.py --core /path/to/pail-evaluation/pail-core --root /tmp/nv-suite --case all --repeat 3
```

전체 state에는 사설키와 인증 자료가 있습니다. 전체를 압축하지 말고 allowlist export만 사용합니다.

```sh
python3 session.py export --state /tmp/nv-run --dest /tmp/nv-public-export
```

[영문 상세 계약](MANAGED.md)에 소유권·실패·관측·coverage·한계를 설명했습니다. 기존 [v1 도구](README.ko.md)와 현재 배포 ZIP은 그대로 유지합니다.

## 개발 리그의 신뢰 경계

합성 actor는 개발 컨테이너·서비스 UID와 시험 키 저장소를 공유합니다. 음성 시험은 지정된 신원의 DDS 권한을 확인한 것이며, 같은 신뢰 컨테이너 안의 악성 코드가 다른 키를 탈취하는 공격까지 차단했음을 뜻하지 않습니다. 제품 배치의 역할별 키 격리·실제 driver 안전은 별도입니다. READY는 노드 생성뿐 아니라 독립 관측기의 실제 zero 수신을 요구합니다. 전체 예정 장면이 끝나지 않은 suite는 INCONCLUSIVE입니다.

## 역할 격리 v3

[역할 격리 v3](ISOLATION.ko.md). Legacy v2 remains a shared-key development reference.
