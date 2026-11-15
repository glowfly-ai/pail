# 실제 TurtleBot3 에서 PAIL 을 시험하기

## 분할 평가본의 현재 실행 경로 (먼저 읽기)

이 꾸러미의 게이트·브리지·pail_msgs 는 함께 빌드된 것입니다. 이 ROS 노드와 다른 배포의
메시지를 혼합하지 마십시오. 바닥 제동·안전 인증은 주장하지 않습니다.

- 평가 디렉터리에서 `evaluation.py load` → `evaluation.py tb3 --state /tmp/hw-state`.
  준비되면 다른 터미널에서 `evaluation.py stop-tb3 --state /tmp/hw-state`로 정지합니다
  (각 명령 앞에 `python3`). 설정은 `/tmp/hw-state/runtime/config`에 있습니다.
- 아래 명령은 `pail-core`의 쓰기 가능한 작업 사본에서 실행합니다. Issuer 소스는 필요 없습니다.
- 운영 PC는 `pail/issuer-eval:0.2.2`, 로봇 agent는 공개
  `pail/core-microduck:0.2.2`, 게이트 기준 이미지는
  `pail/core-tb3-gate:0.2.2`입니다. 이는 이번 배포의 태그입니다(Linux amd64 꾸러미의 태그에는 `-amd64` 접미사가 붙습니다).
  잠금 이미지 ID를 확인하고 이 게이트 기준 이미지에 vendor 드라이버를 추가합니다.
- Mac/Linux 호스트에서 공개 네이티브 도구를 빌드합니다(Go 1.27.2+와 의존성 캐시 또는
  인터넷이 필요합니다; 임시 패키지는 자동 제거됩니다):

```sh
bash examples/tb3/hardware/build_native_tools.sh /tmp/pail-hw-tools
```

- Mac은 `--probe-bin /tmp/pail-hw-tools/tb3-probe --verify-bin /tmp/pail-hw-tools/blackbox_verify`
  경로를 사용합니다. Docker Desktop 컨테이너에서 PC LAN 주소로 접속 실패한 경로를
  기본값으로 쓰지 않습니다. 콘솔은 로봇에 쓰기 전에 실제 도구로 mTLS 조회를 확인합니다.
- `PAIL_HW_DEPLOYMENT_ID`는 선택이며, 비어 있으면 게이트/브리지 상태 소켓은 꺼집니다.
  지정한다면 UUID여야 합니다. `RIG_UP`은 S33 한 줄이 아니라 생성자 완료와 브리지
  기동을 확인한 뒤 표시합니다. 실패 시 모터 드라이버를 띄우지 않고 로그를 보존합니다.

바퀴를 띄운 시험은 바닥 주행·제동 성능 인증이 아닙니다. 아래 과거 시험 기록의
버전·날짜는 새 수정본의 검증 결과로 바꾸지 않습니다.



<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Glowfly Identity Systems Co.,Ltd -->

English (canonical): [`HARDWARE.md`](HARDWARE.md)

관리자가 [라이브 데모](DEMO.ko.md)를 실물 TurtleBot3 에서 돌릴 때 쓰는 절차다: 같은 콘솔, 같은
장면, 같은 판정기에, 시뮬레이션 베이스 대신 로봇 OpenCR 위의 벤더 베이스 드라이버를 쓰고 위치는
바퀴 엔코더에서 읽는다. 필요한 것은 전부 [`hardware/`](hardware/) 에 있다. 두 단계가 있다:

| 단계 | 배치 진술 | 보여 주는 것 | 누가 해도 되는가 |
|---|---|---|---|
| **바퀴 띄움** | `raised` | 모든 데모 장면; 거리는 바퀴가 돈 양 | TurtleBot3 와 아래 준비물이 있는 누구나 |
| **바닥** | `clear-floor` | 1.5 m 바닥에서 직진·회전·주행 중 정지·주행 중 UNSAFE | 로봇 옆에 서서 즉시 세울 수단이 있는 운영자 |

신원(태그)과 안전(레벨) 입력은 합성으로 남는다: 리더나 안전 PLC 가 아니라 콘솔에서 온다. 여기의
어떤 결과도 제동 성능 수치·기능안전 인증·로봇 자체 비상정지에 대한 진술이 아니며, 비상정지는
별도 책임으로 남는다. 관리자가 실측한 값은 8절에 있다.

## 1. 준비물

- OpenCR 에 벤더 펌웨어가 올라간 TurtleBot3(`burger`, `waffle`, `waffle_pi`)와 Ubuntu 22.04
  (arm64 또는 amd64) + Docker Engine 이 도는 온보드 컴퓨터(Raspberry Pi 등). 로봇 사용자는
  `docker` 를 실행할 수 있어야 하고, 한 번은 `sudo -n install`(게이트의 사설 상태 디렉터리)이
  되어야 한다. Raspberry Pi 3 로 충분하나 SROS2 디스커버리가 느리다(9절).
- 운영자 PC(Linux 또는 macOS): Docker, Python 3.9+, OpenSSL, 그리고 비밀번호 없이 로봇에
  붙는 `ssh`(`BatchMode`). 이슈어·콘솔·판정기가 여기서 돈다.
- 둘이 한 네트워크에. 네트워크를 건너는 것은 mTLS gRPC(로봇 에이전트 → 이슈어)뿐이다. ROS 2
  트래픽은 소프트웨어 데모처럼 로봇의 격리된 Docker 네트워크 네임스페이스 안에 머문다.
- 운영자 PC 에서 위 `evaluation.py tb3` 준비·정지 경로 을 한 번 완료한 것(그 뒤 Ctrl-C). 그 상태
  디렉터리에 키·인증서·SROS2 키스토어·정책·요청자 등록이 들어 있고, 그때 빌드한 이미지 둘을
  다시 쓴다(`evidence/console.json` 에 이름이 있다).
- 벤더 드라이버 이미지: 운영자 PC 에서 그 게이트 이미지 위에 빌드해 로봇에 싣는다:

```sh
docker build --build-arg PAIL_TB3_GATE_IMAGE=pail/core-tb3-gate:0.2.2 \
  -t pail/tb3-hardware:<tag> -f examples/tb3/hardware/Dockerfile examples/tb3/hardware
docker save pail/tb3-hardware:<tag> pail/core-microduck:0.2.2 | gzip -1 | ssh <user>@<robot> 'gunzip | docker load'
```

Dockerfile 은 공개 게이트 이미지에 `ros-humble-turtlebot3-node` 와 `ros-humble-turtlebot3-bringup`
둘만 더하고 그 버전을 `/opt/tb3-package-versions.txt` 에 남긴다. Raspberry Pi 용은 arm64 기계에서
(또는 `--platform` 으로) 빌드한다. 펌웨어·라이다·팔 패키지는 없다.

## 2. 무엇이 어디서 도는가

| 운영자 PC | 로봇 |
|---|---|
| `pail_cloud` — 이슈어, 별도 Issuer 평가 이미지, mTLS `<pc-ip>:50064`(`hardware/issuer_host.sh`) | `pail_robot_agent` — 이슈어에서 토큰을 받아 `127.0.0.1:50051` 로 게이트에 준다 |
| `hardware/console_hw.py` — 데모 콘솔(같은 페이지, 같은 HTTP API) | `pep_gate` — 게이트, SROS2 Enforce, `/pep_gate` enclave, 스킬 등재부 `diff_drive_amr` |
| `tb3-probe`, `blackbox_verify` — cloud 이미지에서 실행(`--tool-image`) 또는 네이티브 바이너리 | `motion_bridge` — 허가된 `/cmd_vel` 을 `/drive_cmd_vel` 로 |
| `examples/tb3/demo_scenes.py` — 판정기, 무수정 | `hardware/demo_hw_io.py` 참가자 다섯: 플래너(`/oem_planner`), 엔코더 관측자(`/robot_state_publisher`), 구동 관측자(`/driver`), 안전 피드(`/safety_adapter`), 신원 피드(`/perception`) |
| `hardware/floor_run.py` — 바닥 장면(7절) | `turtlebot3_ros` — 벤더 베이스 드라이버, `/driver` enclave, `/cmd_vel`→`/drive_cmd_vel` 리맵, OpenCR 장치를 받는 유일한 컨테이너 |

콘솔은 플래너의 지시를 ssh 로 로봇의 `control/demo.json` 에 쓰고, 참가자들의 `docker logs -f` 를
자기 상태 디렉터리로 미러링한다. 그래서 페이지와 판정기는 소프트웨어 데모가 내는 것과 똑같은
이벤트를 보고, 거기에 `source: encoders` 인 `pose` 행이 더해진다.

## 3. 로봇의 설정

데모는 올인원 개발 설정을 만든다. **그것을 로봇에 복사하지 말 것.** `issuer_host.sh robot-config`
가 로봇에 필요한 부분집합을 새 디렉터리에 쓴다:

```sh
export PAIL_HW_STATE=/path/to/demo/state PAIL_HW_ROBOT_ID=robot-01
examples/tb3/hardware/issuer_host.sh robot-config /tmp/robot-config
```

| 로봇에 주는 것 | 운영자 PC 에 남기는 것 |
|---|---|
| `policy.yaml`, `skills.diff_drive_amr.yaml`, `sros2_policy.xml`(참조), `robot_registry.yaml` | `requesters.yaml`, `site_model.yaml` |
| `keys/keyring_bundle.json`, `keys/root_pub.b64`(신뢰 재료), `keys/agent_ed25519.json`(에이전트 자신의 키) | `keys/issuer_*.json`, `keys/operator_ed25519.json`, `keys/mirror_ed25519.json`, `keys/payload.json` |
| `grpc_certs/ca.crt`, `grpc_certs/<robot>/client.crt`·`client.key`, 그리고 새로 발급된 `grpc_certs/<robot>/server.crt`·`server.key` | `grpc_certs/ca.key`, 이슈어 자신의 `server.crt`·`server.key` |
| `sros2_keystore/enclaves/*`, `sros2_keystore/public/*` | `sros2_keystore/private/*`(identity·permissions CA 키) |

로봇에 복사하고 컨테이너 사용자에게 준다(게이트·브리지·에이전트·드라이버는 컨테이너 안에서 모두
uid 10001 로 돈다):

```sh
scp -r /tmp/robot-config <user>@<robot>:/home/<user>/pail-robot-config
ssh <user>@<robot> 'sudo chown -R 10001:10001 pail-robot-config && sudo chmod 700 pail-robot-config'
```

배포되는 `sros2_policy.xml` 은 이미 `/driver` 에 벤더 드라이버의 토픽(`/joint_states`, `/odom`,
`/tf`, …)을, `/robot_state_publisher` 에 엔코더 관측자가 필요한 구독을 허용하므로 데모의 키스토어를
그대로 쓴다. 정책을 바꾸면 데모가 하듯 `scripts/sros2_provision.sh` 로 키스토어를 다시 만들고
enclave 를 다시 복사한다. 데모가 서명하는 키링 번들은 8시간 유효하다; 그보다 오래 가는 로봇 세션은
`evaluation.py tb3` 을 다시 돌리거나 새 번들을 서명해 `keys/keyring_bundle.json` 을 다시 복사해야 한다.

2026-09-19 까지 관리자 자신의 실행은 따로 프로비저닝한 로봇 쪽 설정을 썼고, 이 부분집합은 운영자
쪽에서만 확인돼 있었다. 실물 TurtleBot3 에서 돌리자 기동하지 못했다 — 에이전트가 `robot_registry.yaml`
부재(RG-4)로, 이어서 서버 인증서 부재로 거부했다. 두 파일은 이제 부분집합에 들어 있고, 위 실행은
**손으로 보탠 파일 없이** 이 부분집합만으로 로봇에서 다시 수행했다.

## 4. 로봇 쪽

파일 넷과 배치 진술을 로봇의 한 디렉터리, 예컨대 `/home/<user>/pail-hw` 에 둔다:

```sh
scp examples/tb3/hardware/start_demo_rig.sh examples/tb3/hardware/demo_hw_io.py \
    examples/tb3/tb3_base_driver.launch.py examples/tb3/fastdds_loopback.xml <user>@<robot>:pail-hw/
ssh <user>@<robot> 'mkdir -p pail-hw/control && echo "{\"seq\": 0, \"instruction\": 0, \"mode\": \"idle\", \"steps\": [], \"tag\": \"sample-box\", \"safety\": \"OK\"}" > pail-hw/control/demo.json'
```

그다음 **로봇에서**, 바퀴를 띄운 채(또는 바닥을 비운 채, 7절):

```sh
echo raised > pail-hw/control/hardware_confirmed          # 운영자의 진술, 운영자가 쓴다
export PAIL_HW_CONFIG=/home/<user>/pail-robot-config \
       PAIL_HW_CLOUD_ADDR=<pc-ip>:50064 \
       PAIL_HW_SERVICES_IMAGE=pail/core-microduck:0.2.2 \
       PAIL_HW_GATE_IMAGE=pail/tb3-hardware:<tag>
pail-hw/start_demo_rig.sh up        # Raspberry Pi 3 에서 1–3분 뒤 RIG_UP
pail-hw/start_demo_rig.sh status
```

`up` 은 배치 진술이 없으면(종료 78), OpenCR 장치가 없으면, 이 리그의 컨테이너가 이미 있으면
거부한다. 에이전트, 참가자 다섯, 브리지, 게이트, 마지막으로 베이스 드라이버를 띄우며 전부 격리된
네트워크 네임스페이스 하나를 `--cap-drop ALL` 로 공유한다. 선택 변수: `PAIL_HW_ROBOT_ID`
(`robot-01`), `PAIL_HW_MODEL`(`waffle_pi`; 벤더 파라미터 파일 선택), `PAIL_HW_USB_PORT`
(`/dev/ttyACM0`), `PAIL_HW_TARGET`(`sample-box`), `PAIL_HW_MAX_STEP_S`(`30`, 플래너가 절대 넘지 않는
정책의 스텝 한도), `PAIL_HW_PROFILE`(`production`), `PAIL_HW_KEYRING_MAX_LIFETIME_SEC`(`86400`). `PAIL_HW_DEPLOYMENT_ID`(기본 미설정)를 주면 게이트·브리지가 `state/gate_status.sock`·`state/bridge_status.sock`(mode 0600)에서 로컬 상태 질의에 답하고 에이전트가 `state/agent.sock`(mode 0660)에 gRPC 자기 프로브를 연다(모두 uid/gid 10001 소유). 파일 모드는 첫 층일 뿐이다 — 에이전트 리스너는 Northbound·Token·Operator 서비스도 나르고, `ProbeSelf` 자체는 커널 peer UID 가 에이전트 소유자거나 root 인 호출자에게만 답한다. 어느 리스너가 어느 서비스를 나르고 각 메서드가 무엇을 검사하는지는 [`spec/ROBOT_OPERATIONS.md`](../../spec/ROBOT_OPERATIONS.ko.md) §2 에 있다. 소멸자 없이 죽은 노드(`docker rm -f`, SIGKILL)는 소켓 파일을 남기는데, 다음 기동은 같은 uid 소유의 소켓이면서 아무도 듣지 않을 때만 인수하고(로그 `RO_STATUS: stale endpoint reclaimed`) 살아 있거나 남의 것이면 78로 거부한다. `start_demo_rig.sh down`은 리그의 소켓 파일을 지운다.

첫 명령 전에 로그 셋을 읽는다:

```sh
docker logs pailhw-gate 2>&1 | grep 'S33 OK'           # 게이트가 스킬 등재부를 읽었다
docker logs pailhw-base 2>&1 | grep 'Run!'             # 벤더 드라이버가 OpenCR 위에서 돈다
docker logs pailhw-agent 2>&1 | tail -3                # burst CHECKPOINT 줄: 이슈어 링크가 살아 있다
```

`down` 은 이 리그의 컨테이너만 지운다; `restart-gate` 는 콘솔의 `로봇 쪽 재시작` 버튼이 부르는
것이고, `restart-agent` 는 이슈어 주소가 바뀌었을 때 쓴다. `up` 은 자기 매개변수를 `rig.env`
(경로와 이미지 이름, 비밀 없음)에 남겨 두므로 콘솔이 ssh 로 부르는 재시작이 `up` 과 똑같이 뜬다.

## 5. 운영자 쪽

```sh
export PAIL_HW_STATE=/path/to/demo/state \
       PAIL_HW_CLOUD_IMAGE=pail/issuer-eval:0.2.2 \
       PAIL_HW_ISSUER_IP=<pc-ip>
examples/tb3/hardware/issuer_host.sh up            # ISSUER_UP <pc-ip>:50064 …
```

데모는 서버 인증서를 `localhost` 앞으로 발급했다; `up` 은 `<pc-ip>` 를 더해 데모 CA 로 다시
서명하고(이전 파일은 옆에 보존) 데모의 Compose 파일과 같은 설정으로 cloud 이미지에서 `pail_cloud`
를 띄운다. 저널은 상태 디렉터리의 `blackbox/`. 그다음 콘솔을 **새로 비어 있는** 상태 디렉터리로:

```sh
C=$PAIL_HW_STATE/runtime/config
python3 examples/tb3/hardware/console_hw.py --state /tmp/pail-hw-console --port 8765 --placement raised \
  --robot <user>@<robot> --rig-dir /home/<user>/pail-hw --issuer <pc-ip>:50064 \
  --config $C --certs $C/grpc_certs --operator-key $C/keys/operator_ed25519.json \
  --journal $PAIL_HW_STATE/blackbox --issuer-key $C/keys/issuer_ed25519.json \
  --probe-bin /tmp/pail-hw-tools/tb3-probe --verify-bin /tmp/pail-hw-tools/blackbox_verify
```

포트를 먼저 잡고, 로봇에 idle 지시 하나를 쓰고, 참가자 다섯의 미러링을 시작한 뒤
`CONSOLE=http://127.0.0.1:8765/` 를 찍는다. 페이지는 데모 페이지 그대로다. 헤더 배지는 `Position: encoders (raised wheels)`이며 지도는 바퀴 오도메트리다.

콘솔은 `--config`(기본값: `--certs`의 상위 디렉터리)를 `tb3-probe -mode limits`로 읽습니다. 이슈어와 같은 정책·사이트모델·스킬 파서를 사용하며, 로봇 클래스·`twist` 스킬·대상 구역의 상한을 선택합니다. **`issuer_host.sh up`에 제공한 것과 같은 설정 디렉터리**를 지정하세요. 누락·잘못된 설정은 로봇에 지시하기 전에 거부됩니다. 위 공개 네이티브 도구를 빌드해야 하며, 구형 probe를 만났다고 기본 숫자로 대체하지 않습니다.

설정 출처·선택 범위·SHA-256은 `evidence/console.json`, ready 이벤트, `/api/state`에 남습니다. 이것은 **로컬 설정 스냅숏이며 실행 중 이슈어의 원격 증명이 아닙니다.** 이슈어 설정을 바꾸면 콘솔도 다시 시작하세요. 선택적인 `--limits` JSON은 값이 같다는 확인용입니다. 정책과 다르면 거부하며 덮어쓰지 않습니다. 최종 판단은 계속 이슈어가 합니다.

`--target` 과
`--other-tag` 는 사이트 모델의 객체 id 다(데모 사이트 모델은 `sample-box`, `other-box`).
`--probe-bin`·`--verify-bin` 은 `--tool-image` 대신 네이티브 바이너리를 쓴다.

[시간 예산·복구 프로필](TIMING.ko.md)을 읽고 계획기를 포팅하십시오.

## 6. 바퀴 띄움: 장면과 판정기

[장면별 따라 하기](DEMO.ko.md#4-장면별-따라-하기)의 모든 장면이 그대로 적용된다 — 손으로 누르거나,
무수정 판정기로:

```sh
PAIL_RESULTS_DIR=$(mktemp -d /tmp/pail-tb3-raised.XXXXXX)
python3 examples/tb3/demo_scenes.py --url http://127.0.0.1:8765 --out "$PAIL_RESULTS_DIR/hw-raised-scenes.json"   # 포트는 콘솔의 --port; 콘솔이 이 JUDGE 줄을 찍는다
```

실행할 때마다 소스 트리 밖에 새 결과 디렉터리를 만듭니다. 결과 JSON과 옆의
`.events.jsonl`을 함께 보관하세요. JSON에는 사건 수와 SHA-256이 기록됩니다.
기존 `--out` 파일은 덮어쓰지 않고 거부합니다. 결과를 소스 트리 안에 쓰면
`verify_release.py`가 추가 파일을 보고하며, 이는 로봇이나 인가 동작의 실패가 아닙니다.

판정기는 콘솔에서 `position_source` 를 읽어 결과에 `scope: real robot side, positions from
encoders (raised wheels)` 를 적는다. 시뮬레이션과 다른 점:

- **거리·각도는 바퀴 오도메트리다.** `forward 1 m` 는 약 1.00 m 로 읽힌다 — 엔코더는 바퀴가 한 일을
  재기 때문이고, 바닥에서는 같은 명령에 미끄러짐이 섞인다. `left 90 deg` 는 88–92°: 벤더 드라이버의
  램프와 플래너의 0.1 s 조기 정지.
- **장면 R 은 게이트만 재시작한다.** 베이스 드라이버는 그대로 살아 있고, 판정기는 베이스의 `ready`
  를 기다리지 않는다. Raspberry Pi 3 에서 게이트 재시작은 15–45 s(SROS2 디스커버리); 콘솔은 게이트의
  `S33 OK` 를 기다린 뒤 30 s 더 있다가 `robot_restarted` 를 보고한다.
- **정지는 침묵이 아니라 명령이다.** 플래너는 정지나 완료 뒤 0.5 s 동안 0 속도를 보낸다; 그냥
  조용해지는 플래너는 OpenCR 을 마지막 속도에 남겨 둔다. 정지 장면(S)은 로봇 쪽이 정지를 확인한 뒤
  드라이버가 본 구동 명령 수를 기록하고 0 을 요구한다.
- **첫 `ERR_ISSUER_UNREACHABLE` 또는 `NO_TOKEN` 한 줄**이 기동 뒤 맨 첫 계획에서 에이전트의 첫
  토큰 호출이 끝나는 동안 보일 수 있다; 다음 허가는 1초 안에 따라온다. 계획의 거부가 아니며 판정기는
  세지 않는다.

## 7. 바닥: `floor_run.py`

`control/hardware_confirmed` 에 `clear-floor` 가 있을 때만 — 로봇 앞 1.5 m·뒤 0.5 m 가 비어 있고,
옆에 서 있으며, 즉시 세울 수 있음(전원 스위치나 들어올리기)을 운영자가 확인한 뒤 쓴다. 콘솔을
`--placement floor` 로 띄우고:

```sh
PAIL_RESULTS_DIR=$(mktemp -d /tmp/pail-tb3-floor.XXXXXX)
python3 examples/tb3/hardware/floor_run.py --out "$PAIL_RESULTS_DIR/hw-floor.json"      # --only F2,F6 로 단계 선택
```

시작 방향의 직진과 제자리 회전만 보내며, 매 명령 전에 그 방향의 위치를 투영한다; `[-0.45 m, +1.45 m]`
를 벗어날 명령은 보내지 않고 실행을 중단한다. 단계: F0 정지 상태 · F1 허가 없이 구동 · F2 앞으로 1 m
뒤 뒤로 1 m · F3 앞으로 5 m 거부, 0.3 m 대조 · F4 0.3 m/s 로 1 m 거부, 대조 · F5 플래너가 허가를
넘김 · F6 좌 90°, 우 90° · F7 다른 태그 · F8 주행 중 UNSAFE(정지 거리, 자동 재개 없음, 운영자 해제) ·
F8b 주행 중 정지(이슈어에서 취소, 다음 계획은 자기 토큰) · F9 원장 검증. 매 단계 뒤 출발선으로
돌아간다. 거리는 여전히 바퀴 오도메트리이며 이제 미끄러짐이 포함된다.

## 8. 이 하드웨어에서 측정된 것

모든 실행: TurtleBot3 `waffle_pi`, Raspberry Pi 3(arm64, Ubuntu 22.04, Docker 29), OpenCR 위의
공식 ROS 2 Humble 드라이버, 양쪽 엔코더 살아 있음, 같은 Wi-Fi 의 노트북 이슈어, 합성 신원·안전 입력,
SROS2 Enforce, mTLS on, 이 꾸러미의 게이트 이미지 위에 `hardware/Dockerfile` 로 만든 vendor 이미지.
어느 실행에서도 게이트 임계값·서명·시계를 완화하지 않았다.

### 분할 배포 실물 측정

각 측정 행에 실제 근거 빌드를 적는다:

<!-- hw-measurements:begin defs -->
- **발행자** — 그 꾸러미의 콘솔·판정기·hardware/fault_inject.py 로 발행자가 직접 실행한 것; 에이전트 사유 레지스트리와 이미지가 다시 빌드되기 전; 빌드 0.2.0-preview.19, 2026-10-18.
- **독립** — 발행자의 트리를 공유하지 않는 수령자가 그 꾸러미의 이미지로 실행한 것; 빌드 0.2.0-preview.22, 2026-10-20. 둘이 다른 곳에서는 더 나중 빌드의 값이 현재 값이다.
- **독립(0.2.0-preview.40 꾸러미)** — 같은 바퀴 들림 TurtleBot3 에서 평가자가 preview.40 ARM64 꾸러미로 실행한 것(PAIL-EVALUATION-0.2.0-preview.40-single-contract-20261029); 소요 시간은 기록되지 않아 횟수와 결함 주입의 일시정지 값만 싣는다; 빌드 0.2.0-preview.40, 2026-10-29.
- **독립(0.2.0-preview.44 꾸러미)** — 최종 ARM64 꾸러미의 바퀴 공중 TB3: 전체 판정 3회, 재시작 10회, permit 단절·시계 스텝 검사; 재시작 1회 시간 초과; 빌드 0.2.0-preview.44, 2026-10-31.
- **독립(0.2.0-preview.45 꾸러미)** — 최종 preview.45 ARM64 꾸러미의 바퀴 들림 실물: 전체 판정 3회, 재시작 10회, permit 12초와 원격 에이전트 종료. 시계 스텝은 이번 범위 제외.; 빌드 0.2.0-preview.45, 2026-10-31.
- **독립(0.2.0-preview.45 꾸러미)** — preview.46 평가: 소스 동일 preview.45 ARM64 실물 런타임의 유효 재시작 29회 및 별도 117회 조사. preview.47 실물 수락 아님.; 빌드 0.2.0-preview.45, 2026-11-01.
<!-- hw-measurements:end defs -->

둘 다 인증이 아니다. 엔코더 거리는 바닥 주행·제동 거리가 아니고, 바퀴 띄운 판정은 바닥 주행이 아니다.

| 확인 | 확립된 것 | 출처 |
|---|---|---|
|<!-- hw-measurements:begin table --> 전체 판정기(13 장면, 6절) | 독립 실행 3회 모두 13/13; 소요 시간 미기록 | 독립(0.2.0-preview.45 꾸러미): 13/13 x3 |
| 장면 8 단독(안전 `UNSAFE` → `ESTOP` → `OK`; 중단된 계획은 재개되지 않음) | 5/5 | 독립(0.2.0-preview.22 꾸러미): 5/5; 발행자(0.2.0-preview.19 빌드): 5/5 |
| 살아 있는 허가로 이동 중 E-STOP 을 가로지르는 Issuer 단절 — `fault_inject.py --mode permit`, Issuer 를 12 s·30 s 일시정지, 그 사이 `UNSAFE` → `OK` | E-STOP 중 Issuer 12 s 정지: PASS, OK 뒤 구동 0. 이번 평가에서 30 s 경우는 재실행하지 않음. | 독립(0.2.0-preview.45 꾸러미): 12 s PASS; OK 뒤 구동 0 |
| 허가가 없는 상태의 E-STOP — `fault_inject.py --mode outage`: 게이트가 이미 `BLOCK ERR_ISSUER_UNREACHABLE` 이 될 때까지 Issuer 를 일시정지한 뒤 `UNSAFE`, `OK` 0.5 s 뒤 Issuer 재개 | 2회 모두 `OK` 뒤 구동 명령 0; 스텝이 끊긴 체인은 거부되고 다음 계획은 자기 토큰으로 실행 | 소프트웨어 데모(0.2.0-preview.23 빌드): `--wait-block 4` 로 2/2; 독립(0.2.0-preview.22 꾸러미): 실물의 무허가 outage 전제는 아직 달성하지 못했다. 다중 스텝·긴 대기만으로 보장되지 않는다. 이미 위임된 창은 Issuer 정지 중에도 다음 스텝을 허가할 수 있다. PRECONDITION_NOT_MET는 안전 PASS가 아니다. |
| 스텝 중 로봇 시스템 시계 ±0.6 s 스텝(`date -s`), 4 s 뒤 되돌림 | ±0.6 s 4회 모두 clock abort; 시계 복귀 뒤 전달 0, 새 계획 정상 | 독립(0.2.0-preview.44 꾸러미): 4/4; 양방향 |
| 정상 이동 중 스텝 기한 초과 거부 | 위 모든 판정기·결함 주입에서 0건 | 독립(0.2.0-preview.22 꾸러미): 0건; 발행자(0.2.0-preview.19 빌드): 0건 |
| 1 m 지시, 엔코더 거리 | 3회 0.998~1.005 m(바퀴 공중 엔코더) | 독립(0.2.0-preview.44 꾸러미): 0.998~1.005 m x3 |
| 게이트 재시작부터 준비까지(장면 R, SROS2 디스커버리) | DDS 인증 정체 미해결: 29회 중 1회; 별도 117회 중 1회 및 별개 이동 미달 1회. 고정 실패율·라이브러리 수정 완료 주장 없음. | 독립(0.2.0-preview.45 꾸러미): 늦은 Final/인증 비대칭 관측; 보고된 수동 복구 5/5, 자동 복구 아님 |
| 바닥 1.5 m(7절 장면 F0–F9) | F2 0.952 m / −0.996 m; F6 +88.4° / −89.2°; F5 플래너가 0.3 m/s 를 요구하는 동안 게이트가 드라이버를 ≤ 0.1 m/s 로 유지; F8 `UNSAFE` → 게이트 `ESTOP` 0.164 s, 입력 뒤 이동 0.045 m, 그 뒤 드라이버 명령 없음, `OK` 뒤에도 운영자가 행동할 때까지 이동 없음 | 발행자(0.2.0-preview.19 빌드): 같은 게이트 계열의 이전 빌드; 바닥 장면은 그 뒤 다시 돌리지 않았다 <!-- hw-measurements:end table -->|

판정기·`hardware/fault_inject.py`·콘솔은 이 꾸러미에 든 것이며, 위 수치는 게이트 창이나 임계값을
늘릴 근거가 아니다. `fault_inject.py` 의 `--issuer` 는 운영자 PC 의 Issuer 컨테이너 이름이다 — 이
리그에서는 `pailhw-issuer`, 소프트웨어 데모에서는 실행마다 달라지는 이름을
`docker ps --format '{{.Names}}' | grep issuer` 로 찾는다. 직접 실행한 회차는 실패를 포함해 자기
증거와 함께 기록한다.

### 시계 오류로 중단된 지시

실물 참조 계획기는 `ERR_CLOCK_DRIFT`를 받으면 지시 전체를 끝낸다. 시계 복귀,
피드 변경·속도 변경이나 같은 토큰의 새 지시 번호로는 재개하지 않는다. 원인을
확인한 뒤 새 계획을 제출하고 그 새 토큰의 실제 게이트 허가를 기다린다. 토큰 ID만
바꿔서는 풀리지 않으며 콘솔의 지시 번호는 재사용될 수 있어 계획 신원이 아니다. 기존 로봇 런타임 상태 디렉터리의 작은 시계 중단
기록은 계획기 재시작에도 남는다. 우회하려고 삭제하지 않는다. 읽기·쓰기 오류는
참조 계획기의 동작을 막으므로 저장소를 복구해야 한다. 이는 예제 실행 상태이지
Issuer의 권한 취소가 아니다. 정상 stop/cancel로 옛 권한을 정리하고, 실패한 저장기의
재시작만으로 복구됐다고 판단하지 않는다. 게이트 규칙·로그 건수 의미는
[TIMING.ko.md](TIMING.ko.md)를 참고한다.

## 9. 이상해 보일 때

| 증상 | 뜻 | 할 일 |
|---|---|---|
| `up` 이 `REFUSED` 를 찍고 78 로 끝남 | 배치 진술 없음 | 확인한 뒤 `raised` 또는 `clear-floor` 를 직접 쓴다 |
| `RIG_UP` 인데 콘솔에 `pose` 행이 없음 | 드라이버나 엔코더 관측자가 아직 안 떴거나 `/joint_states` 가 발행되지 않음 | `docker logs pailhw-base`, `docker logs pailhw-robot`; 관측자는 1 s 무데이터 뒤 `encoders_stale` 을 찍는다 |
| 첫 명령이 `ERR_NO_TOKEN` 거부 뒤 허가됨 | 로컬 agent RPC(이 구성은 50ms), 캐시 또는 상류 상태가 준비되지 않음 | 없음; 기록될 뿐 계획의 결함이 아니다 |
| 모든 명령이 `ERR_CLOCK_DRIFT` 거부 | 게이트가 시계를 고정한 뒤 로봇 벽시계가 뛰었다(NTP) | `로봇 쪽 재시작`(게이트 재시작); 임계값은 절대 넓히지 않는다 |
| 게이트 로그 `attest UNKNOWN_MEASUREMENT` | 이슈어가 attestation off 로 돈다(데모 설정); 정보성 | 없음 |
| 기동 시 `keyring bundle` 거부 | 데모의 8시간 번들이 만료됐거나 남은 유효기간이 `PAIL_HW_KEYRING_MAX_LIFETIME_SEC`를 넘는다 | `evaluation.py tb3` 을 다시 돌려 새 번들을 만들고 `keys/keyring_bundle.json` 복사 |
| 콘솔 `gate did not report preflight within 120 s` | 느린 로봇의 SROS2 디스커버리 | `docker logs pailhw-gate`; `로봇 쪽 재시작` 을 다시 |
| `로봇 쪽 재시작` 이 `control write failed` 로 실패 | 로봇으로의 ssh 가 끊김 | `ssh <user>@<robot>` 확인; 콘솔은 마지막 지시를 유지한다 |
| `stop` 뒤에도 로봇이 계속 움직임 | 플래너가 0 을 보내지 않거나(옛 `demo_hw_io.py`) 드라이버가 구독을 잃음 | 먼저 물리적으로 세운다; 그다음 로봇의 `demo_hw_io.py` 를 이 트리와 비교 |

## 10. 경계

- 바퀴 띄움 수치는 바퀴 회전을 거리로 환산한 것이고, 바닥 수치는 미끄러짐을 포함한다. 어느 쪽도
  정지 거리·제동·기능안전 수치가 아니다.
- 태그와 안전 레벨은 합성 콘솔 입력이지 리더나 안전 PLC 가 아니다.
콘솔은 `--config`(기본값: `--certs`의 상위 디렉터리)를 `tb3-probe -mode limits`로 읽습니다. 이슈어와 같은 정책·사이트모델·스킬 파서를 사용하며, 로봇 클래스·`twist` 스킬·대상 구역의 상한을 선택합니다. **`issuer_host.sh up`에 제공한 것과 같은 설정 디렉터리**를 지정하세요. 누락·잘못된 설정은 로봇에 지시하기 전에 거부됩니다. 위 공개 네이티브 도구를 빌드해야 하며, 구형 probe를 만났다고 기본 숫자로 대체하지 않습니다.

설정 출처·선택 범위·SHA-256은 `evidence/console.json`, ready 이벤트, `/api/state`에 남습니다. 이것은 **로컬 설정 스냅숏이며 실행 중 이슈어의 원격 증명이 아닙니다.** 이슈어 설정을 바꾸면 콘솔도 다시 시작하세요. 선택적인 `--limits` JSON은 값이 같다는 확인용입니다. 정책과 다르면 거부하며 덮어쓰지 않습니다. 최종 판단은 계속 이슈어가 합니다.
- 벤더 펌웨어·드라이버·파라미터 파일은 설치된 그대로 쓴다; 여기서는 아무것도 그것을 바꾸거나
  라이다·팔을 띄우거나 로봇 자체 비상정지를 대신하지 않는다.
- 관리자의 기록된 실행은 관리자 자신이 프로비저닝한 로봇 설정과 네트워크에서 한 것이다; 당신의
  로봇에서 이 키트로 한 실행은 당신의 측정이지 관리자의 것이 아니다.

## Hardware feedback follow-up: observation clocks and diagnostics

The hardware console queries the robot's monotonic clock **after receiving each
batch** and charges the entire SSH round trip plus processing delay to the age
upper bound. The existing two-second freshness limit is unchanged. Unknown,
replayed, pre-start, future-monotonic and different-boot samples are not current.
`evidence/remote-clock-brackets.jsonl` records the measurement; source wall times
are preserved, not rewritten. A small PC/robot wall-clock offset no longer drops
all completion events. If SSH is too slow, the sample remains unmeasured/stale;
we do not label receipt time alone as current robot state.

The ROS `GateState` now includes diagnostic `detail`; rebuild all participating
`pail_msgs` consumers together. The gate's clock refusal identifies the measured
drift and limit. The bridge deadman and age log use suspend-inclusive elapsed
time, and the forwarding callback also checks permit age before publishing.
Only startup TLS connection preparation gets a bounded five-second wait; the
normal command/recheck RPC deadline is unchanged. This is not a first-command
latency guarantee under arbitrary CPU/network load.

한국어: 실물 콘솔은 로봇 단조시계를 표본 수신 뒤 조회하여 왕복 지연까지 포함한
나이 상한으로 판단합니다. 2초 한도는 그대로이며 PC와 로봇의 벽시각 일치를
가정하지 않습니다. ROS 메시지 `detail` 추가로 관련 노드는 함께 재빌드해야 합니다.
브리지의 허가 경과시간은 절전 포함 시계로 계산합니다. 기동 시 TLS 연결 준비는
일반 RPC의 50ms 판정 한도를 늘리지 않습니다. 부하와 무관한 최초 응답 보장은 아닙니다.

## 실물 수락 상태

게이트 재시작 뒤 DDS 인증 정체는 **알려진 미해결 결함**입니다. preview.45/preview.46 동일 소스 ARM64 런타임의 독립 평가에서 유효 재시작 29회 중 DDS 실패 1회, 별도 117회 조사에서 DDS 실패 1회와 별개 이동 미달 1회가 보고됐습니다. 늦은 Final/인증 비대칭이 관측됐지만 Fast DDS 소스 수준 원인과 수정은 아직 미검증입니다. 집단별 측정은 고정 실패율이 아닙니다. 수동 복구 5/5는 자동 복구 보장이 아닙니다. `RIG_FAILED: gate IO readiness timeout` 발생 시 정지를 유지하고 정상 cancel/stop으로 현재 계획을 취소한 뒤 로그를 보존하고 수동 재시도하며, 준비 확인 후 새 계획으로 검사합니다. 근본 원인 조사 책임은 유지보수자에게 남습니다. `PAIL_GATE_READY`는 생성 완료이지 DDS 준비 완료가 아닙니다. 재시작은 현재 `PAIL_GATE_IO serving=1`(명령 발행자 매칭, 신선한 evidence/safety 수신, safe 명령·permit 구독자 매칭)을 기다립니다. 유휴 플래너는 명령을 내지 않을 수 있으므로 계획 전 명령 샘플을 요구하지 않습니다. 이는 연결·입력 준비이며 **실제 구동의 증거가 아닙니다**. `PAIL_BRIDGE_IO`는 매칭·입출력 계수를 기록하며 발행 계수는 드라이버 수신 증명이 아닙니다. 지속되는 SROS2 연결 실패는 원인 진단 대상이며, 대기 시간 증가나 자동 권한 해제로 우회하지 않습니다.

재시작·종료 전 gate/bridge/planner/drive/agent 로그와 inspect를 로봇 리그의 `restart-logs/`(이 스크립트 옆, 운영자 소유)에 보존한다. `state/`는 게이트(uid 10001, mode 700) 전용이며 운영자가 읽지 않는다. 각 보존본은 이전 보존 이후의 로그만 담고(`restart-logs/.last`의 시각 이후 `--since`; 첫 보존은 전체) 정상 보존본만 최근 10회로 회전한다. 준비 실패 보존본(수집 중 실패한 부분 기록 포함)은 `restart-logs/failed/`에 별도 저장하고 자동 회전하지 않는다. 수동 정리 전 외부에 복사하고 디스크 여유를 관리해야 하며, 실패 보존본에는 자동 용량 상한이 없다. gate·bridge·planner·drive·base·agent·safety·robot-state helper가 존재하면 해당 진단 자료를 수집한다. 이는 증거 보존 개선이며 DDS 인증 수정이나 자동 재시도를 의미하지 않는다.

**실물의 C1 cohort.** 통신 계약은 하나이고 고르는 설정이 없다. `issuer_host.sh up`과 `start_demo_rig.sh up`은 `PAIL_CORE_COMM_CONTRACT`가 어떤 값이든 설정돼 있으면 이름을 대고 기동을 거부한다(`CORE_COMM_CONTRACT_SETTING_REMOVED`, 코드 78). 비워 둔다. Issuer를 먼저 띄운다. 로봇 에이전트는 첫 census에서 Issuer의 계약을 읽고, 불일치면 `PAIL STARTUP REFUSED: CORE_COMM_COHORT_MISMATCH …`(코드 78)로 종료하며 `up`은 `RIG_FAILED: agent exited`로 끝난다. 운용 중 Issuer가 교체·롤백되면 에이전트는 새 권한을 보류하고(로봇이 허가를 더 받지 못함; `GetActiveToken`은 `CORE_COMM_COHORT_MISMATCH`), readiness 프로브는 `report_storage_state=COHORT_MISMATCH`를 보고하며, 보유 보고 수와 함께 30 s마다 불일치를 기록하고 5 s~60 s 백오프로 census를 다시 선언한다. Issuer가 다시 `v1`로 답하면 그 census에서 보류가 풀린다 — 에이전트 로그의 `CORE_COMM_COHORT_RESTORED`, 백오프 한 간격 안, **에이전트 재시작 없이** — 그리고 보존된 보고가 전달된다(끝난 체인은 거부 `TERMINAL_REJECTED`로 기록). 풀리는 것은 cohort 보류만이다. 저장소 fault(`CORE_REPORT_STORAGE_UNHEALTHY`)는 재시작까지 유지되며 복구 로그 줄이 남아 있는 보류를 이름으로 적는다. 이 릴리스의 Microduck 봉인 전 실행에서 측정했고, TurtleBot3 운용 중 Issuer 교체는 아직 미측정이다. C1 보고를 C0 와이어로 낮춰 보내지 않으므로 혼합 구간의 결정 증거는 원장에 남지 않고, 그 구간이 있었다는 사실은 에이전트 상태가 말한다. 로그를 보존하지 못한 재시작은 `RIG_LOGS_NOT_SAVED`를 출력하고 그대로 재시작한다(`GATE_RESTARTED logs=unsaved`). 로그를 보존하지 못한 `down`은 `RIG_DOWN_INCOMPLETE`를 출력하고 종료 코드 3으로 정지된 컨테이너를 남긴다. `start_demo_rig.sh down --discard-logs`는 보존 없이 컨테이너를 지우며, 그 뒤 `up`이 다시 받아들여진다. planner의 `step_done`·`plan_done`은 명령 시간 예산 종료를 뜻하며 `physical_execution=NOT_VERIFIED`로 표시한다. 실제 실행은 독립 drive·encoder 관측으로 확인한다.

원격 agent 결함 주입은 `--robot-ssh ubuntu@tb3.local --agent pailhw-agent`를 추가한다. gate도 죽이려는 경우에만 `--robot pailhw-gate`를 추가한다. Issuer 정지·재개·원장 조회는 운영 PC에서 수행한다. 실물 outage의 무허가 전제를 만드는 검증된 절차는 아직 없고, 선발급 위임 스텝은 계속 허가될 수 있다. 전제 미달성을 PASS로 기록하지 않는다.
