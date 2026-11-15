# 내 어댑터를 평가 이슈어에 연결하기
<!-- ko-structure: abridged -->

> 이 한국어판은 영문판보다 절·표·코드 블록이 적은 요약본이다. 영문판이 정본이며, 두 판이 다르면 영문판이 우선한다.

이슈어 소스 없이 **실제 이슈어 실행본 + 공개 게이트웨이**를 띄우는 소프트웨어 시험 경로입니다.
평가 묶음에서 이미지를 불러온 뒤 실행합니다.

```sh
python3 evaluation.py issuer --state /tmp/my-adapter-rig
```

아래 모든 명령은 **두 번째 터미널**에서 실행합니다. 압축을 푼 `pail-evaluation/` 에서 열고 그 위치를
기록해 두십시오 — 이후 모든 블록은 거기서 시작해 거기로 돌아옵니다.

```sh
EVAL=$PWD      # the extracted pail-evaluation directory (contains evaluation.py and images.lock.json)
```

발급 요청은 `127.0.0.1:50061`, 게이트웨이는 `127.0.0.1:50051`입니다. 두 엔드포인트가 이
호스트에서 HTTP/2 preface 에 응답하면 `ENDPOINT_CHECK: PASS` 를 출력한 뒤 넘겨줍니다. 다른 포트는
`--issuer-port 50161 --agent-port 50151`로 지정합니다. 터미널은 계속 점유하며 Ctrl-C로
정지합니다. 다른 터미널의 `stop-microduck --state /tmp/my-adapter-rig`도 사용할 수 있습니다.
이 예는 루프백에 한정한 **개발용 평문 통신**이며 실물·생산 배치 지침이 아닙니다.

상태의 `compose.json`에 이미지·환경변수·마운트가 모두 보입니다. `config/`에는 실행마다
생성한 키·정책·사이트·로봇 등록부·스킬 파일, `journal/`에는 원장이 있습니다. 개인키는
외부로 보내지 않습니다. 키 생성 도구는 공개 `scripts/gen_dev_keys.py`입니다.

새 종류는 `--robot-id robot-17 --robot-class my_amr --skills /absolute/skills.my_amr.yaml`로
지정합니다. 정책·사이트도 `--policy`, `--site`로 공급할 수 있습니다. 스킬 파일의 종류와
사이트의 로봇 선언은 일치해야 합니다. 새 이름이 새 제어 기능을 구현하지는 않습니다.

`minimal.py`는 ctypes로 실제 C ABI를 호출하는 작은 예입니다. 토큰·입력·명령·tick·보고·STOP을
연결하지만 출력은 JSON일 뿐, 모터를 구동하지 않습니다. `--synthetic-inputs`는 합성 안전·증거임을
명시합니다. 실제 포트는 센서·정지·우회 차단 등을 어댑터 계약에 따라 구현해야 합니다.
어댑터를 유지한 채 `ready` 확인 뒤 계획을 제출합니다. 정확한 실행 명령은 [영문 안내](README.md)의 3절을 따릅니다. 기동 시 stderr 에 `{"startup": …}`
한 줄로 게이트가 불러온 키링 모드와 키 수를 알리고, 게이트웨이가 응답했지만 토큰 요청을 거부한
경우(리그가 묶지 않은 robot id)는 `GATEWAY_REFUSED_TOKEN_REQUEST` 로 알립니다. 게이트웨이가
묶는 것은 robot **id** 이며, 로봇 클래스는 스킬 파일과 정책이 강제합니다.

## 대체 바이너리 시험 (영문 §4)

`test-adapter`가 구동하는 형상은 하나, [어댑터 계약 §5a](../../spec/ADAPTER_CONTRACT.ko.md)에
적은 **Microduck 호환 UDS/CLI 프로필**(소켓, 명령줄, `hello`/`api_version`, 게이트 로그 줄,
런타임 이미지와 `libpail_gate` ABI)입니다. 그 형상을 지킨 자체 Linux 실행 파일(아키텍처는 `images.lock.json`)은
다음으로 직접 시험합니다.

```sh
python3 evaluation.py test-adapter --adapter-binary /absolute/my-pail-duckd \
  --state /tmp/my-adapter-conformance
```

실제 파일을 세 시험 역할에 읽기 전용으로 연결하고 SHA-256을 기록합니다. 공급된 어댑터로
몰래 대체하지 않습니다. CA-15는 이 백엔드에서 미지원이므로 SKIP로 남깁니다. 없는 경로나
그 아키텍처 Linux ELF가 아닌 파일은 이름을 대며 거부하고(`CUSTOM_ADAPTER_NOT_FOUND`,
`CUSTOM_ADAPTER_PLATFORM`), 공개 소켓을 열지 않는 ELF는 어댑터 준비 시한에서 `BLOCKED`가 됩니다.

증거가 되는 세 단계. 여기부터 모든 블록은 `$EVAL`(§1)에서 시작하는 서브셸이라 첫 오류에서 멈추고
셸을 원래 자리에 둡니다. 그래서 **이 순서대로 한 셸에 붙여 넣어** 실행할 수 있고, 유지보수자도 꾸러미를
포장하기 전에 정확히 그렇게 — 하나의 스크립트로 — 실행합니다. 단계마다 작업 디렉터리가 다르며, 이미
있는 디렉터리는 재사용하지 않고 거부합니다. 블록은 들여쓰지 않았으므로 원문 `README.md` 에서 복사해도
렌더링된 화면에서 복사한 것과 똑같이 실행됩니다.

결과가 PASS·FAIL 외에 낼 수 있는 말 하나: **`INCONCLUSIVE`**. 리그가 관측한 것만으로는 케이스를 판정할
수 없었다는 뜻입니다 — 건너편에서는 명령이 흐르는데 게이트 기록이 하네스에 하나도 닿지 않았거나, 관측자
자신이 굶주린 상태에서 허가 속도를 쟀거나. 러너는 그런 케이스를 새 리셋에서 한 번 더 돌리고, 그래도
같으면 `RESULT=INCONCLUSIVE`(종료 코드 4)와 이유를 `limitations` 에 남깁니다. 그때 할 일은 조용한
호스트에서 새 `--state` 로 다시 돌리는 것입니다. 어댑터에 대한 판정이 아니며, 정상 어댑터도 바쁜
호스트에서는 받을 수 있습니다. 실제로 *관측된* 거부는 FAIL 이고 FAIL 로 남습니다.

**1단계 — 이미지에서 참조 바이너리를 꺼내** 먼저 시험합니다.

```sh
( set -e; cd "$EVAL"
  IMG=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["images"]["microduck"]["id"])' images.lock.json)
  C=$(docker create "$IMG"); docker cp "$C:/usr/local/bin/pail-duckd" /tmp/reference-pail-duckd; docker rm "$C" >/dev/null
  python3 evaluation.py test-adapter --adapter-binary /tmp/reference-pail-duckd --state /tmp/ad-reference )
# PASS_WITH_LIMITATIONS 17 pass / 0 fail / 1 skip; run.json custom_adapter.sha256 == sha256sum of the file
```

**2단계 — 작업 사본에서 직접 빌드**합니다(온라인; 배포 트리는 그대로 둠). 준비물(Ubuntu 24.04):
apt `cmake protobuf-compiler libsodium-dev libyaml-cpp-dev pkg-config build-essential git python3-venv`
(`python3-venv` 는 §5 용), 그리고 **rustup 의 Rust ≥ 1.89**(`Cargo.toml` 이 요구; apt 의 rustc 1.75 는
너무 낮음). 첫 `cargo build` 는 고정된 upstream IPC crate 를 git 에서 받습니다. rustup 은 **새 셸에서만** `cargo` 를
`PATH` 에 올립니다. 아래 블록은 `cargo` 가 없으면 `$HOME/.cargo/env` 를 읽으므로, rustup 을 방금 설치한 그
셸에서도 그대로 돕니다.

```sh
( set -e; cd "$EVAL"
  test ! -e /tmp/pail-adapter-work || { echo "/tmp/pail-adapter-work exists: remove it first"; exit 1; }
  cp -R pail-core /tmp/pail-adapter-work
  cmake -S /tmp/pail-adapter-work/libpail_gate -B /tmp/gate-build -DBUILD_TESTING=ON && cmake --build /tmp/gate-build -j
  command -v cargo >/dev/null || . "$HOME/.cargo/env"   # rustup puts cargo on PATH only for NEW shells
  cd /tmp/pail-adapter-work/adapters/microduck && PAIL_GATE_LIB_DIR=/tmp/gate-build cargo build --locked --features libgate
  python3 "$EVAL"/evaluation.py test-adapter --adapter-binary /tmp/pail-adapter-work/adapters/microduck/target/debug/pail-duckd --state /tmp/ad-built )
# PASS_WITH_LIMITATIONS 17 pass / 0 fail / 1 skip for a healthy build; INCONCLUSIVE (see above) is the host, not your code
```

Ubuntu 24.04 에서 빌드한 디버그 바이너리(glibc 2.39, 최대 `GLIBC_2.34` 요구)가 bookworm 이미지에서
돌았지만 이는 관찰이지 호환 약속이 아닙니다 — 이미지에 대해 `ldd` 로 확인하십시오.

**3단계 — 결함을 심어 리그가 잡는지 봅니다**(리그가 *내* 바이트를 시험한다는 음성 대조). 블록은
`adapters/microduck/src/relay.rs` MOVE 분기의 `if !shared.judge(...) { continue; }` 를 결과를 버리는
호출로 바꿔 빌드하고, **결함 바이너리를 작업 사본 밖으로 복사**한 뒤 소스를 복원해 다시 빌드합니다.
그래서 작업 사본은 정상으로 끝나고 `/tmp/defective-pail-duckd` 만 결함 파일입니다. 기대값:
`RESULT=FAIL`(그래서 블록의 종료 코드는 1), **정확히 다음 9건** 실패(CA-01~06, 09, 10 — MOVE 의 BLOCK 이
바이트를 막아야 하는 케이스들 — 와 토큰 없는 명령이 거부되어야 하는 CA-16). CA-13 은 초록으로 남습니다: 스킬 호출(`robot.do`)이고 결함은 MOVE 분기의
BLOCK 만 무시하기 때문입니다(이전 판들이 CA-13 을 붉은 목록에 넣은 것은 직전 케이스의 미사용 리스가 새어
들어온 탓이었고, 이제 케이스마다 격리됩니다). CA-08(데드맨 타이밍)은 바쁜 호스트에서 결함과 무관하게 붉거나
`INCONCLUSIVE` 가 될 수 있으며 정상 바이너리에서는 PASS 입니다. 두 run.json의 `custom_adapter.sha256`이 다릅니다.

```sh
( set -e; cd /tmp/pail-adapter-work/adapters/microduck
  command -v cargo >/dev/null || . "$HOME/.cargo/env"   # rustup puts cargo on PATH only for NEW shells
  cp src/relay.rs /tmp/relay.rs.orig
  python3 - <<'EOF'
import pathlib
p = pathlib.Path("src/relay.rs"); s = p.read_text()
old = """                if !shared.judge(conn, &peer, &req.method, Some(class), None, lin, ang) {
                    reply_blocked(&c_wr,req.id.clone()).await;
                    continue;
                }"""
assert old in s, "MOVE arm not found"
p.write_text(s.replace(old, "                let _ = shared.judge(conn, &peer, &req.method, Some(class), None, lin, ang); // DELIBERATE DEFECT: ignore BLOCK", 1))
EOF
  PAIL_GATE_LIB_DIR=/tmp/gate-build cargo build --locked --features libgate
  cp target/debug/pail-duckd /tmp/defective-pail-duckd      # the defective binary lives OUTSIDE the working copy
  cp /tmp/relay.rs.orig src/relay.rs                          # the source is restored ...
  PAIL_GATE_LIB_DIR=/tmp/gate-build cargo build --locked --features libgate   # ... and so is target/debug/pail-duckd
  python3 "$EVAL"/evaluation.py test-adapter --adapter-binary /tmp/defective-pail-duckd --state /tmp/ad-defective )
```

### Microduck 이 아닌 로봇: 자체 conformance 백엔드 (영문 §4a)

다른 컨트롤러 프로토콜은 `pvs-public/runner/core/backend.py` 의 `Backend` 를 구현한 클래스를
`pvs-public/runner/adapters/` 아래 모듈로 둡니다(`setup/teardown/reset_state`, 단계 메서드
`north_cmd`·`inject_evidence`·`inject_cmd_vel`·`inject_skill`·`inject_safety`·`fault`, 건너편 관측
`gate`·`bridge`·`drive`·`permits`·`stop_request_asserted`; `enforcement_supported()` 는 재정의하지
않으면 `False` 이고 그러면 Enforcement 축은 PASS 가 아니라 SKIP). 지원하지 않는 축은 꾸미지 않고
`unsupported` 로 돌려줍니다. `example_backend.py` 가 형상을 보여 주지만 Microduck 전송을
재사용하므로 당신 로봇에 대해서는 아무것도 증명하지 않습니다.

하네스는 이미지에 구워진 트리를 실행하므로 새 백엔드는 **작업 사본 빌드**(온라인)와 전달된
Issuer 이미지가 필요합니다.

```sh
ISSUER=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["images"]["issuer"]["id"])' "$EVAL"/images.lock.json)
( set -e; cd "$EVAL"
  test ! -e /tmp/pail-backend-work || { echo "/tmp/pail-backend-work exists: remove it first"; exit 1; }
  cp -R pail-core /tmp/pail-backend-work && cd /tmp/pail-backend-work
  cp pvs-public/runner/adapters/example_backend.py pvs-public/runner/adapters/my_backend.py
  sed -i 's/class ExampleBackend/class MyBackend/; s/example_backend:ExampleBackend/my_backend:MyBackend/' pvs-public/runner/adapters/my_backend.py
  python3 examples/microduck/run.py conformance --build --issuer-image "$ISSUER" --backend my_backend:MyBackend --state /tmp/my-backend-ca )
```

`--build` 는 이 사본으로 Core 이미지를 빌드하고 소스 신원을 기록하며, `--issuer-image` 는
`images.lock.json` 이 없는 트리 옆에 전달된 Issuer 이미지를 지정하고, `--backend MODULE:CLASS` 가
당신 클래스를 고릅니다. 행은 전송별 열이 생길 때까지 `CA_MAP.yaml` 의 Microduck 열을 쓰며, 그 열의
도구 행 둘(CA-07, CA-15)은 백엔드 이름과 무관하게 Microduck 도구를 실행합니다.

**심(seam)이 없는 로봇.** 실제 로봇 대부분은 모든 축을 구동하지 못합니다. 정직한 백엔드는 그 자리에서
`Unsupported` 를 올립니다(`example_backend.ExampleBackendWithoutSafetyFeed` 가 안전 피드 CA-10 에
대해 그렇게 합니다). 리그는 그 행을 PASS 가 아니라 SKIP 으로 보고하고, 그것만으로는 실행이 **`BLOCKED`**
입니다(`Unreviewed skip: CA-10`) — 그 공백이 받아들일 만한지는 리그가 대신 정하지 않습니다. 당신이
글로 받아들입니다: `--reviewed-skip "CA-NN:<이유>"`. 행은 SKIP 으로 남고 이유는 보고서와 결과의
`limitations` 에 기록되며 결과는 `PASS_WITH_LIMITATIONS` 입니다. FAIL 과 맵이 선언한 skip 은 검토로
지울 수 없습니다.

```sh
( set -e; cd /tmp/pail-backend-work
  python3 examples/microduck/run.py conformance --build --issuer-image "$ISSUER" \
    --backend example_backend:ExampleBackendWithoutSafetyFeed \
    --reviewed-skip "CA-10:this robot exposes no safety-feed seam; the stale-feed refusal is covered by its own bench procedure" \
    --state /tmp/my-honest-ca )
# PASS_WITH_LIMITATIONS 13 pass / 0 fail / 2 skip; limitations name CA-10 and the reason. Without --reviewed-skip: RESULT=BLOCKED
```

## 호스트에서 실행하기 (영문 §5)

`evaluation.py issuer` 는 두 엔드포인트가 **호스트에서** 응답한 뒤에야(`ENDPOINT_CHECK: PASS`)
넘겨줍니다. 호스트에서 `minimal.py` 를 돌리려면 2단계의 `libpail_gate.so`, proto 로 생성한 Python
메시지, grpcio/protobuf(apt `python3-venv`), 그리고 **키링 신뢰 모드**가 필요합니다. 블록은 새 어댑터의 실행 확인이 끝난 뒤 자기 계획을 제출합니다. 이전 프로세스의 위임 권한을 재사용하지 않습니다.

```sh
( set -e; cd "$EVAL"
  python3 -m venv /tmp/v && /tmp/v/bin/pip install grpcio grpcio-tools protobuf   # measured with grpcio 1.84 / protobuf 7.36
  mkdir -p /tmp/py && /tmp/v/bin/python -m grpc_tools.protoc -I pail-core/sdk/proto -I pail-core/libpail_gate/abi \
    --python_out=/tmp/py --grpc_python_out=/tmp/py pail-core/sdk/proto/*.proto pail-core/libpail_gate/abi/pail_gate_abi.proto
  RIG=/tmp/my-adapter-rig
  PROJECT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["project"])' $RIG/run.json)
  CMD_DIR=$(mktemp -d)
  mkfifo "$CMD_DIR/in"
  exec 3<>"$CMD_DIR/in"
  PAIL_KEYRING_MODE=unsigned-dev PYTHONPATH=/tmp/py /tmp/v/bin/python pail-core/examples/adapter/minimal.py --library /tmp/gate-build/libpail_gate.so --gateway 127.0.0.1:50051 --policy "$RIG/config/policy.yaml" --keyring "$RIG/config/keys/keyring.json" --skills "$RIG/config/skills.microduck.yaml" --robot-id robot-1 --robot-class microduck --synthetic-inputs <"$CMD_DIR/in" 3>&- >"$CMD_DIR/out" 2>"$CMD_DIR/errors" &
  ADAPTER_PID=$!
  trap 'exec 3>&-; kill "$ADAPTER_PID" 2>/dev/null || true' EXIT
  for i in $(seq 1 60); do grep -q '"ready": true' "$CMD_DIR/out" && break; sleep 0.5; done
  grep -q '"ready": true' "$CMD_DIR/out" || { cat "$CMD_DIR/errors"; exit 1; }
  docker exec "$PROJECT-issuer-1" python /opt/pail/example/demo_probe.py submit --target box-12 --steps '[{"linear":0.1,"angular":0,"duration":5}]'
  printf '%s\n' '{"linear":0.1,"angular":0,"duration":1,"skill":"twist"}' >&3
  sleep 2
  exec 3>&-
  wait "$ADAPTER_PID"
  trap - EXIT
  cat "$CMD_DIR/out"
  echo "Adapter evidence: $CMD_DIR" )
```

핵심은 `PAIL_KEYRING_MODE=unsigned-dev` 입니다. 이것이 없으면 게이트 라이브러리는 서명된 번들을
요구해 키를 0개 불러오고, Issuer 가 발급한 토큰도 `BLOCK ERR_UNKNOWN_KEY_ID` 로 거부합니다. 기동
시 stderr 의 `{"startup": …}` 줄에 불러온 모드와 키 수가 보입니다. 이 모드는 개발 전용이며 배치는
서명된 키링 번들을 씁니다. 컨테이너 안에서는 compose 파일이 같은 변수를 설정하므로 3절에는
추가 설정이 없었습니다.

## 실행 재시작 경계

게이트웨이·Issuer·집행 클라이언트는 같은 꾸러미의 버전을 함께 배치합니다. 클라이언트는 프로세스마다 새 UUID를 만들고 모든 GetActiveToken 요청에 `pail-execution-instance` 메타데이터를 보냅니다. 응답에서 같은 값이 정확히 한 번 확인되지 않으면 토큰을 사용하지 않습니다. 게이트웨이 또는 집행 프로세스가 재시작되면 이미 위임됐던 활성 계획은 종료되며 새 계획 제출이 필요합니다. 위임되지 않은 대기 계획은 유지됩니다. 로봇당 집행 프로세스 하나를 운영하며 이 기능은 중복 게이트 조정 기능이 아닙니다.

시험용 `--interactive-inputs`는 NDJSON 명령의 `synthetic_inputs` 불리언으로 합성 피드 갱신을 제어합니다. 피드를 끄면 기존 관측은 원래 기한에 따라 낡아집니다. `request_id`가 있으면 해당 명령 응답에 그대로 돌려주며 tick 응답과 구별할 수 있습니다.
