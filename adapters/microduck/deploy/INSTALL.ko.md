> **실험적 기능: 실물 보드 검증은 미완료입니다.** 먼저 공개 루트의 `examples/microduck/`에서 로봇 없는 프리뷰를 사용하세요.

# Microduck 보드에 pail-duckd 설치하기

`pail-duckd` 는 Microduck 용 PAIL 어댑터다. 모든 클라이언트가 부르는 제어 소켓(`/run/robotd.sock`)을
대신 열고, 의도마다 PAIL 판정 라이브러리에 「이슈어가 서명한 토큰이 이 명령을 인가하는가」를 물어
PERMIT 일 때만 원래 바이트를 그대로 넘긴다. 로봇의 데몬은 손대지 않는다 — 드롭인 하나가 `robotd`
의 소켓을 어댑터 뒤로 옮길 뿐이다. 이 문서는 설치 절차이며 실물 검증 완료를 뜻하지 않는다.

> 영문판 [`INSTALL.md`](INSTALL.md) 이 정본이다. 두 문서가 다르면 영문이 우선한다.

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


## 1. 준비물

| 항목 | 출처 |
|---|---|
| `pail-duckd`(aarch64, `--features libgate` 빌드) | 공개 `examples/microduck/Dockerfile` 또는 호환성이 확인된 artifact |
| `libpail_gate.so`(aarch64) | PAIL 판정 라이브러리, **ROS 없이** 빌드: `cmake -S libpail_gate -B build && cmake --build build`(또는 `libpail_gate/Dockerfile.ci`) — ABI 는 `libpail_gate/abi/pail_gate_abi.proto` |
| 상류 데몬이 설치된 보드(microduck 리포의 `scripts/install.sh`) | `/opt/robot/daemon/current` 아래 robotd·updaterd·padd·btd … |
| 봉인된 PAIL 설정 | `/etc/pail/policy.yaml`, `/etc/pail/keys/keyring.json`(또는 서명 번들) — 이슈어 쪽에서 프로비저닝, **이 설치기는 쓰지 않는다** |
| 보드에서 닿는 PAIL 로봇 에이전트 | `unix:/run/pail/agent.sock`(같은 보드) 또는 개발 벤치 주소 |

### 1a. 소스가 연결된 개발용 artifact 추출

**압축을 푼 공개 루트**에서 Docker·Python 3.9 이상을 사용합니다. 새 state를 사용하면 현재 소스로 빌드한 정확한 image ID가 기록됩니다.

```sh
python3 examples/microduck/run.py demo --state /tmp/pail-duck-export-run
PAIL_EXPORT_IMAGE=$(python3 -c 'import json; print(json.load(open("/tmp/pail-duck-export-run/run.json"))["image_id"])')
PAIL_EXPORT_DIR=$(mktemp -d /tmp/pail-duck-artifacts.XXXXXX)
PAIL_EXPORT_CONTAINER=$(docker create "$PAIL_EXPORT_IMAGE")
docker cp "$PAIL_EXPORT_CONTAINER:/usr/local/bin/pail-duckd" "$PAIL_EXPORT_DIR/pail-duckd"
docker cp "$PAIL_EXPORT_CONTAINER:/opt/pail/lib/." "$PAIL_EXPORT_DIR/lib"
docker cp "$PAIL_EXPORT_CONTAINER:/opt/pail/upstream/updater.toml" "$PAIL_EXPORT_DIR/updater.toml"
docker rm "$PAIL_EXPORT_CONTAINER"
cp /tmp/pail-duck-export-run/run.json "$PAIL_EXPORT_DIR/origin-run.json"
docker run --rm --network none --entrypoint cat "$PAIL_EXPORT_IMAGE" /etc/os-release > "$PAIL_EXPORT_DIR/build-os.txt"
docker run --rm --network none --entrypoint ldd "$PAIL_EXPORT_IMAGE" /usr/local/bin/pail-duckd > "$PAIL_EXPORT_DIR/build-loader.txt"
printf '%s\n' "$PAIL_EXPORT_DIR"
```

`docker create`는 daemon을 실행하지 않습니다. updater.toml은 같은 pinned upstream에서 온 참조이지 실제 보드 설정을 새로 만든 것이 아닙니다.
origin-run.json·소스/image 해시·build-os.txt·loader 출력을 함께 보존하세요. lib 디렉터리는 linker/SONAME 이름을 포함하지만 배포판의 모든 라이브러리를 묶은 것은 아닙니다.
다른 컴퓨터로 옮기면 artifact 폴더를 복사하고 `PAIL_EXPORT_DIR`를 그 컴퓨터의 실제 절대경로로 다시 지정합니다. 셸 변수는 파일과 함께 이전되지 않습니다.

### 1b. 목표 OS·라이브러리 호환성

| 환경 | 의미 |
|---|---|
| 프리뷰 빌드/runtime | Debian 12 bookworm 컨테이너. Mac에서 꺼내도 binary는 Linux ELF |
| bookworm native 실행 | 호환 glibc/libstdc++ 및 `libprotobuf32`, `libsodium23`, `libyaml-cpp0.7` 등이 필요. 실제 ELF 의존성을 확인 |
| Ubuntu 24.04 ARM64 | 일반적으로 yaml-cpp SONAME 0.8이므로 bookworm의 0.7과 다름. 해당 OS용 Core를 빌드한 뒤 검사 |
| 실제 Microduck 보드 OS | 아직 인증한 지원 OS가 아님. vendor image, `/etc/os-release`, CPU와 runtime 패키지 버전을 먼저 확인 |

**ARM64가 같다는 사실만으로 배포판 ABI까지 같지는 않습니다.** 자신이 빌드/확인한 artifact를 목표 Linux에서 점검합니다.

```sh
file "$PAIL_EXPORT_DIR/pail-duckd"
readelf -d "$PAIL_EXPORT_DIR/lib/libpail_gate.so" | grep -E 'NEEDED|SONAME'
LD_LIBRARY_PATH="$PAIL_EXPORT_DIR/lib" ldd "$PAIL_EXPORT_DIR/pail-duckd"
```

`not found`, version 오류, 다른 아키텍처는 설치 전에 해결해야 합니다. 서로 다른 major SONAME을 강제 symlink로 연결하지 않습니다.
이미지 안의 loader 성공은 목표 host의 성공이 아닙니다. **Ubuntu 24.04 native Core**가 필요하면 같은 공개 소스 루트에서:

```sh
sudo apt-get install build-essential cmake pkg-config libprotobuf-dev protobuf-compiler \
  libsodium-dev libyaml-cpp-dev python3 systemd file binutils
cmake -S libpail_gate -B "$PAIL_EXPORT_DIR/native-core" -DBUILD_TESTING=OFF
cmake --build "$PAIL_EXPORT_DIR/native-core" -j2
```

해당 host의 `--lib`에는 `$PAIL_EXPORT_DIR/native-core/libpail_gate.so`를 사용합니다. 이는 Core의 runtime ABI를 맞추는 것이며,
임의의 외부 adapter binary까지 항상 호환시키는 방법은 아닙니다. adapter 자체가 다른 glibc/libstdc++를 요구하면 목표 OS용으로 빌드해야 합니다.

## 2. 설치

공개 루트에서 adapter 디렉터리로 이동합니다. 다음 명령은 호환 artifact·상류 daemon·별도 인가 설정이 준비된 **실제 보드**에 적용할 때만 실행합니다.

```sh
cd adapters/microduck
sudo sh deploy/install.sh --binary /absolute/artifacts/pail-duckd \
    --lib /absolute/compatible-core/libpail_gate.so
```

멱등이며 다음을 놓는다.

| 경로 | 역할 |
|---|---|
| `/opt/pail/bin/pail-duckd`, `/opt/pail/lib/libpail_gate.so` | 어댑터와 판정 라이브러리 |
| `/etc/systemd/system/pail-duckd.service` | 어댑터 유닛 — `/run/robotd.sock` 을 서비스하고 `robot` 그룹에 **이름으로** 넘긴다 |
| `/etc/systemd/system/robotd.service.d/pail.conf` | 드롭인: `robotd` 가 `/run/robotd/raw.sock`(root:pail 0660, `/run/robotd` 0750)에서 듣는다 |
| `/usr/lib/sysusers.d/pail.conf` | `pail` 그룹 — 원 소켓을 열 수 있는 유일한 주체 |
| `/etc/pail/pail-duckd.env` | 프로파일·에이전트 주소·로봇 id(있으면 보존) |
| `/etc/pail/duck_skills.yaml` | 스킬 이름표 `이름 → MOVE\|MANIPULATE\|NONE`(있으면 보존) — §3 |
| `/etc/robot/updater.toml` | `robot_socket` 한 값만 원 소켓으로(§4) |

그다음 systemd 가 돌고 있으면 `systemd-sysusers` · `daemon-reload` · `enable pail-duckd` ·
`restart robotd`(소켓이 옮겨진다) · `start pail-duckd`. 확인:

```sh
systemctl status pail-duckd
journalctl -u pail-duckd | grep -E 'S27|S28|S29|skill table|serving'
```

`S27 verified: raw socket closed to others` · `skill table loaded` · `serving` 이 보여야 한다.
`PAIL_PROFILE=production`(기본)에서 유닛은 다음에 **기동을 거부**한다.

| 배너 | 뜻 | 조치 |
|---|---|---|
| `S27 raw ingress reachable by others` | 원 소켓 또는 `/run/robotd` 가 others 에 열려 있다 — 드롭인이 적용되지 않았다 | `systemctl daemon-reload && systemctl restart robotd`, `ls -la /run/robotd` 확인 |
| `S28 no enforcing gate linked` | `--features libgate` 없이 빌드됐거나 `libpail_gate.so` 를 못 읽었다 | 재빌드; `LD_LIBRARY_PATH=/opt/pail/lib` 확인 |
| `S29 skill name table missing` | `/etc/pail/duck_skills.yaml` 부재·빈 표·모르는 클래스 낱말 | 표를 쓴다(§3) |
| `--public-group names no group` | `robot` 그룹이 없다 | `systemd-sysusers`(상류 `robot.conf`) |

## 3. 스킬 이름표

상류는 스킬을 문자열로 부르고(`robot.do {skill}`) 목록은 런타임에 온다(`robot.skills`). 어댑터는
이름마다 게이트가 판정할 클래스를 준다. 표에 없는 이름은 판정에서 **거부**된다
(`ERR_ACTION_UNMAPPED`) — 기본 클래스는 없다.

기동 때 어댑터가 로봇에 스킬 목록을 묻고 표에 없는 것을 인쇄한다.

```
WARN skills the robot answers to that the table does not map — each will be refused (ERR_ACTION_UNMAPPED) unmapped=["roulade", "kick_left", "kick_right"]
```

그 이름들을 결정한 클래스와 함께 `/etc/pail/duck_skills.yaml` 에 적고 유닛을 재시작하면
`skill table covers every skill the robot answers to` 가 나온다. 이 파일은 봉인 설정이다.
빈 표와 모르는 클래스 낱말은 모든 프로파일에서 거부된다.

## 4. 상류 업데이트를 넘어 무엇이 살아남는가 (R1)

상류 업데이터는 `robotd.service` 를 **릴리스 아티팩트마다 설치**하고(`updater/src/config.rs` 가
아티팩트에 `<unit>/systemd/<unit>.service` 를 요구) 재시작한다. 그래서 이 패키지는 그 파일을 절대
고치지 않는다. 드롭인 `robotd.service.d/pail.conf` 는 별개 파일이고 systemd 가 릴리스가 설치한
유닛 위에 겹친다. 업데이터의 고아 검사는 `*.service` 파일만 읽지(`updater/src/orphan.rs`)
`.d/` 디렉터리는 보지 않는다. 고정된 상류(`942e58e`) 코드 정독으로 확인했고, 보드 위 실측은
아직이다(MD-4).

상류 릴리스마다 다시 볼 것 둘:

- 드롭인의 `ExecStart=` 재지정은 상류 명령에 `--socket /run/robotd/raw.sock` 만 더한 것이다.
  릴리스가 robotd 의 경로나 플래그를 바꾸면 이 줄이 따라가야 한다. 아래 검사가 그 줄을 인쇄한다.
- `updater.toml` 은 업데이트가 다시 쓰지 않으므로(상류 규칙 「업데이트는 /etc 를 건드리지
  않는다」) `robot_socket` 패치는 남는다. `updaterd` 는 root 로 돌고 의도를 보내지 않으므로
  robotd 와 직접 — 원 소켓으로 — 말한다. 패치가 필요한 이유가 그것이다: `/run/robotd.sock` 에
  남은 업데이터는 robotd 의 건강을 *어댑터*에게 묻게 된다.

## 5. 보드 없이 패키지 검사

Python 3와 systemd 패키지가 있는 호환 Linux host의 **adapter 디렉터리**에서 실행합니다.

```sh
sh deploy/check.sh --binary "$PAIL_EXPORT_DIR/pail-duckd" \
    --lib "$PAIL_EXPORT_DIR/native-core/libpail_gate.so" \
    --updater-toml "$PAIL_EXPORT_DIR/updater.toml" \
    --workdir /tmp/pail-duck-stage-first
```

위 예는 §1b에서 만든 Ubuntu native Core를 사용합니다. 호환 bookworm host라면 `--lib`에 `$PAIL_EXPORT_DIR/lib/libpail_gate.so`를 사용하세요.
소스 밖의 **새 workdir**를 사용합니다. 생략하면 private 임시 폴더를 만듭니다. root 권한·실행 중인 systemd가 필요하지 않으며 실제 서비스를 기동하지 않습니다.

- C1~C4: 배치 경로·unit/drop-in·그룹/소켓·updater patch의 멱등성/변경 범위를 확인합니다. upstream robotd 실행 파일은 보드 전제조건입니다.
- C5: staged library를 우선하고 기존 loader 경로의 비어 있지 않은 항목을 병합합니다. staged unit의 flag를 읽어 staged ELF `--help`와 대조합니다.
  호환 host의 라이브러리/권한/flag 오류는 FAIL, 실행할 수 없는 host/아키텍처는 NOT_RUN입니다. 실제 stderr·종료코드·ELF/host 값은 `C5.json`, `C5.log`에 남습니다.
- C6: host 배포판이 제공하는 실제 `.target`/`.slice` 파일을 검증 root에 준비하고 해시를 남깁니다. **변경하지 않은 adapter unit**에
  `systemd-analyze verify --man=no`를 적용합니다. 가짜 target이나 의존성 완화는 하지 않습니다. host의 enablement 링크·generator·관계없는 서비스는 복사하지 않습니다.
  도구/배포판 정의가 없으면 NOT_RUN, 실제 unit/검증 오류는 FAIL입니다.
- **upstream robotd unit, 실제 보드의 활성화된 서비스 그래프·drop-in 적용·재시작·업데이트 생존은 C6 범위가 아닙니다.** `C6.json`과 최종 결과가 이 미검증 범위를 명시합니다.

`STAGE=...`, `MD3_RESULT=...`를 출력하며 stage·`result.json`·C5/C6 JSON/로그·install.log를 **실패 때도 보존**합니다.
`PASS_WITH_LIMITATIONS`/NOT_RUN은 전부 통과가 아닙니다. 실제 updater 설정에 운영자 정보가 있으면 stage 전체가 아니라 검토한 보고서만 공유하세요.
개인키 권한을 전체 읽기로 완화하지 않습니다.

## 6. 제거

```sh
sudo systemctl disable --now pail-duckd
sudo rm /etc/systemd/system/pail-duckd.service /etc/systemd/system/robotd.service.d/pail.conf /usr/lib/sysusers.d/pail.conf
sudo sed -i 's|robot_socket = "/run/robotd/raw.sock"|robot_socket = "/run/robotd.sock"|' /etc/robot/updater.toml
sudo systemctl daemon-reload && sudo systemctl restart robotd
```

일부러 스크립트로 만들지 않았다. 어댑터를 빼는 것은 원 제어 경로를 모든 클라이언트 앞에 되돌리는
일이고, 그것은 손으로 칠 결정이다.


## 백업·설치 근거

덮어쓰는 기존 파일은 `/var/lib/pail/install-backups/` 아래에 보존합니다. 복원 전 현재 운영자 변경을 확인하세요.
설치기는 `libpail_gate.so`와 SONAME 이름 `libpail_gate.so.1`을 함께 배치합니다. 실제 서비스·실물 확인은 별도입니다.
