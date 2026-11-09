# 오프라인 로봇 운영 검사 — 실행 가능한 예제

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Glowfly Identity Systems Co.,Ltd -->

[영어 정본](README.md). 계약과 구성 변수 참조: [`spec/ROBOT_OPERATIONS.md`](../../spec/ROBOT_OPERATIONS.ko.md).

이 예제는 배포물에 실린 오프라인 검사기 둘을, 작은 Go 프로그램이 만들어 주는 **완결된
선언 세트**에 대고 돌린다. 로봇·이슈어·네트워크에는 아무것도 닿지 않는다. 모든 산출물은
**소스 트리 밖**에 쓰므로, 끝난 뒤에도 `scripts/verify_release.py` 는 추출본을 원본 그대로라고
판정한다.

한 번의 실행이 증명하는 것과 증명하지 않는 것:

- **증명한다:** 선언된 로봇 신원·자격 경로·사이트 배치·스킬·격리 그룹이 서로, 그리고 그것들이
  가리키는 레지스트리·사이트 모델·정책·스킬 등재부와 일관된다.
- **증명하지 않는다:** 어떤 로봇이 자기 인증서의 개인키를 가졌는지, DDS 격리가 실제인지,
  프로세스가 돌고 있는지, 무엇이든 적용해도 되는지. 보고서가 스스로 그렇게 말한다 —
  오프라인에서 `ready_for_apply` 는 항상 `false`, `runtime_observed` 는 `false`, 그리고 PASS
  마다 **보지 않은 것**을 적는다(`private-key possession NOT observed`,
  `actual DDS isolation NOT observed`).

요구 사항: Go 1.27.2 또는 문서화된 지원 툴체인, 첫 의존성 내려받기를 위한 모듈 캐시나 네트워크.
추출본의 `cloud/` 에서 실행한다.

## 1. 프로그램 셋 빌드

```sh
cd cloud
go build -o /tmp/pail-ro/fixture ./cmd/pail_robotops_fixture
go build -o /tmp/pail-ro/check   ./cmd/pail_robotops_check
# Select the pinned Issuer evaluation executable:
ISSUER_IMAGE="$(python3 ../examples/common/evaluation_runtime.py --root .. --role issuer)"
```

`pail_robotops_check` 와 `pail_robotops_fixture` 는 PAIL-Core(Apache-2.0)다.
`pail_issuer_robotops_check` 는 PAIL Issuer(별도 평가 실행본)라 Core 단독 아카이브에는 없다. 아래의 Core
검사는 그것 없이도 돈다.

## 2. 트리 밖에 선언 세트 쓰기

```sh
/tmp/pail-ro/fixture --out /tmp/pail-ro/two --config ../config --robots 2
```

디렉터리에는 새 CA, 로봇 클라이언트 인증서 둘(`client0.crt`, `client1.crt`),
`robot_registry.yaml`, `requesters.yaml`, `site_model.yaml`, 공개 참조 `policy.yaml` 과
`skills.diff_drive_amr.yaml` 의 사본, 그리고 검사기가 읽는 문서 둘 — `resources.json`(무엇이
어디에 있는가)과 `inventory.json`(어느 로봇이 그 자원 중 무엇에 결속되는가) — 이 생긴다.
인증서 유효기간은 12시간이다. **개인키는 절대 파일로 쓰이지 않는다.** 이 세트는 검사기용
개발 데이터이지 등록이 아니며, 로봇 자격으로 바꿀 수 없다.

로봇 하나면 `--robots 1`. 이미 있는 `--out` 디렉터리, 모르는 로봇 수, 남는 인자는 거부한다.

## 3. 검사 실행

```sh
/tmp/pail-ro/check --inventory /tmp/pail-ro/two/inventory.json \
  --resources /tmp/pail-ro/two/resources.json --root /tmp/pail-ro/two \
  > /tmp/pail-ro/two-core.json; echo rc=$?
```

기대: `rc=0`, 보고서의 `summary` 는 검사 id 여덟 개(`RO-C01`, `RO-C02`, `RO-C03.static`,
`RO-C04`, `RO-C05`, `RO-C07.declared`, `RO-C08.declared`, `RO-C11.declared`; 로봇별 검사는 두
로봇을 모두 필수 대상으로 든다) 전부에서 `PASS`. `ready_for_apply` 와 `runtime_observed` 는 `false`. 이슈어 쪽 요청자 검사는 같은 입력을 읽는다:

```sh
docker run --rm --network none -v /tmp/pail-ro:/tmp/pail-ro:ro \
  --entrypoint pail_issuer_robotops_check "$ISSUER_IMAGE" --inventory /tmp/pail-ro/two/inventory.json \
  --resources /tmp/pail-ro/two/resources.json --root /tmp/pail-ro/two \
  > /tmp/pail-ro/two-issuer.json; echo rc=$?
```

기대: `rc=0`, scope `b_requester_offline/v1`, 두 로봇 모두 `RO-C06` PASS.

계약은 문장이 아니라 종료코드다. `0` 범위 안의 검사 전부 통과 · `1` 관측된 불일치 하나 이상 ·
`2` 사용법 오류, 읽을 수 없거나 잘못된 입력, 또는 재지 못한 검사(`CANNOT_CHECK`). FAIL 과
CANNOT_CHECK 가 섞인 보고서는 둘 다 보존하고 `2` 로 끝난다. 실패하거나 재지 못한 검사를 통과로
바꾸는 플래그는 없다.

## 4. `describe`: 계획 단계 인벤토리 초안이지 승인이 아니다

```sh
/tmp/pail-ro/check describe --resources /tmp/pail-ro/two/resources.json \
  --root /tmp/pail-ro/two > /tmp/pail-ro/two-described.json; echo rc=$?
```

`describe` 는 자원 맵과 공식 레지스트리·사이트 파서로부터 인벤토리를 유도한다. 내놓는 로봇은
모두 `lifecycle: "planned"` 다 — 로봇을 관측한 것이 그 로봇을 활성화할 권한은 아니다. fixture
세트에서는 이 초안이 생성된 `inventory.json` 과 바이트 단위로 같다. 모호하면 추측하지 않고
거부한다: 레지스트리가 둘이거나 두 agent 가 같은 로봇을 주장하면 `RO_IMPORT_AMBIGUOUS` 로 `2`.
입력을 고치면 보게 될 거부 코드: `RO_SCHEMA: resource map schema_version must be 1`,
`… deployment_id must be a lowercase UUID`, `… resources must not be empty`,
`… resources exceeds 10000 entries`, `… file resource needs a relative path`(경로는 `--root`
기준 상대경로), `RO_CAPABILITY: unsupported resource kind`.

## 5. 일부러 붉히기

한 번도 붉어 본 적 없는 검사기는 아무것도 증명하지 않는다. 아래 세 편집은 각각 정확히 한 가지만
바꾸고, 각각 다른 검사를 건드린다.

**두 로봇에 같은 격리 그룹**(`resources.json` 에서 로봇 2 의 agent·gate·bridge·transport 에
로봇 1 의 그룹을 준다):

```sh
cp -R /tmp/pail-ro/two /tmp/pail-ro/samegroup
python3 - <<'EOF'
import json
p='/tmp/pail-ro/samegroup/resources.json'; d=json.load(open(p))
for r in d['resources']:
    if r['id'] in ('cmp:a1','cmp:g1','cmp:b1','res:n1'): r['group']='net0'
json.dump(d,open(p,'w'),indent=2)
EOF
/tmp/pail-ro/check --inventory /tmp/pail-ro/samegroup/inventory.json \
  --resources /tmp/pail-ro/samegroup/resources.json --root /tmp/pail-ro/samegroup \
  > /tmp/pail-ro/samegroup.json; echo rc=$?
```

기대: `rc=1`; `robot-added-02` 에 `FAIL RO-C08.declared` 하나, 사유
`two robots share a declared isolation group`; 나머지는 PASS.

**로봇 2 를 로봇 1 의 인증서에 결속**(`inventory.json` 편집):

```sh
cp -R /tmp/pail-ro/two /tmp/pail-ro/wrongcert
python3 - <<'EOF'
import json
p='/tmp/pail-ro/wrongcert/inventory.json'; d=json.load(open(p))
d['robots'][1]['client_credential_ref']='cred:c0'
json.dump(d,open(p,'w'),indent=2)
EOF
/tmp/pail-ro/check --inventory /tmp/pail-ro/wrongcert/inventory.json \
  --resources /tmp/pail-ro/wrongcert/resources.json --root /tmp/pail-ro/wrongcert \
  > /tmp/pail-ro/wrongcert.json; echo rc=$?
```

기대: `rc=1`; `robot-added-02` 에 `FAIL RO-C03.static`, 사유 `leaf not bound to this robot`.

**참조된 파일이 없음**(CA 제거):

```sh
cp -R /tmp/pail-ro/two /tmp/pail-ro/missing && rm /tmp/pail-ro/missing/ca.crt
/tmp/pail-ro/check --inventory /tmp/pail-ro/missing/inventory.json \
  --resources /tmp/pail-ro/missing/resources.json --root /tmp/pail-ro/missing \
  > /tmp/pail-ro/missing.json; echo rc=$?
```

기대: `rc=2`; 두 로봇 모두 `CANNOT_CHECK RO-C03.static`(`CA ref unavailable`), 그리고 자격 경로를
더는 풀 수 없으므로 두 로봇 모두 `FAIL RO-C07.declared`. 요약은 `CANNOT_CHECK` — 재지 못한 검사는
재지 못했다고 보고되지, 통과로 접히지 않는다.

## 6. 정리

```sh
rm -rf /tmp/pail-ro
```

추출본에는 아무것도 쓰지 않았다. 트리 안에서 빌드하거나 결과를 트리 안에 쓰면
`scripts/verify_release.py` 가 추가 파일을 보고한다. 그것은 무결성 검사가 동작한 것이지 로봇이나
인가의 실패가 아니다.
