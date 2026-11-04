# 역할별 키·프로세스 격리 참조 v3
<!-- ko-structure: abridged -->

> 이 한국어판은 영문판보다 절·표·코드 블록이 적은 요약본이다. 영문판이 정본이며, 두 판이 다르면 영문판이 우선한다.

새 작업의 권장 준비 프로필입니다. v1/v2는 기존 재현을 위해 유지하며, v2의 공유 키 한계가 사라진 것으로 표시하지 않습니다. **실제 NVIDIA 하드웨어·Sim·물리 로봇 검증 완료가 아닙니다.**

10개 역할을 별도 컨테이너·비root UID·PID/IPC namespace로 분리했습니다. 각 역할은 자기 credential view만 읽고 자기 로그/상태만 씁니다. rootfs는 read-only, capability는 전부 제거, no-new-privileges를 사용합니다. loopback network namespace는 공유하므로 네트워크 DoS나 커널/Docker 탈출까지 막았다고 주장하지 않습니다.

Issuer·agent·requester·gate의 TLS/서명 키를 분리하고, ROS 역할에는 자기 enclave 키와 서명된 권한만 제공합니다. CA 개인키·keyring root·operator unlock 키는 준비 영역에 남기며 런타임에 마운트하지 않습니다. 요청 클라이언트는 cloud로 계획을 제출하고 gate는 agent에 접속합니다. 기존 gRPC robot binding/요청자 정책을 재사용하며 새 메서드별 권한 체계를 만들지는 않습니다.

```sh
python3 session.py prepare --profile profiles/mock-humble-v3.json --core /path/to/pail-evaluation/pail-core --state /tmp/iso-run
python3 session.py serve --state /tmp/iso-run
```

다른 터미널에서 status/exercise/idle/stop을 사용합니다. exercise는 명시적인 합성 시험 요청이며 모터를 움직이지 않습니다. 새 상태 디렉터리를 사용하고, 실패 시 전체 config로 fallback하지 않습니다. 준비 단계의 일회용 root 컨테이너만 인증서 생성·chown을 수행하며 runtime은 비root입니다. 개인키 내용은 출력하지 않습니다.

```sh
python3 check_isolation.py --core /path/to/pail-evaluation/pail-core --root /tmp/iso-matrix --repeat 3
python3 check_managed.py --profile profiles/mock-humble-v3.json --core /path/to/pail-evaluation/pail-core --root /tmp/iso-faults --case all --repeat 3
```

자기 키 사용·타 역할 키 부재, CA/root/operator 미제공, UID/PID/IPC·마운트, 파일 변경, 다른 enclave 사칭, 자기 신원의 권한 밖 발행을 정상 양성 대조와 함께 검사합니다. 같은 client.key 파일명이라도 역할마다 다른 키인지 재료 해시로 구분하며 값은 출력하지 않습니다.

v3의 all은 정상/bridge stall/endpoint loss/monitor loss/orphan 5개 장면입니다. 기존 v2의 trusted permit fixture는 v3에 넣지 않았고 명시적으로 거부합니다. 시험을 위해 planner에 gate키를 다시 주지 않습니다. 로그 손상은 별도 --case log_corruption으로 검사합니다.

키를 포함한 전체 상태를 압축하지 마십시오. session.py export는 공개 요약 allowlist만 내보냅니다. 호스트/Docker 관리자·준비 helper는 계속 신뢰 대상이고, 각 역할의 본래 권한 악용이나 센서 거짓말까지 해결한 것은 아닙니다. 개발 인증서/짧은 trust bundle은 production 키 회전 기능이 아닙니다.

[영문 세부 계약](ISOLATION.md) · [관리 명령](MANAGED.ko.md)
