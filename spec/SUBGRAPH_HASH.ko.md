# 서브그래프 스냅숏 해시 — 토큰이 발급된 세계 조각

모든 행동 토큰은 서명되는 바이트 안에 32바이트 값 `subgraph_snapshot_hash`를
싣는다. 이 값은 발급자가 발급 시점에 인가 근거로 삼은 세계 모델의 **조각**에
토큰을 묶는다. 이 문서는 그 값을 완전히 정의한다 — 어느 조각을 고르는지, 그
조각을 어떻게 바이트로 적는지, 어떤 해시를 취하는지 — 그래서 이 글만 보고 만든
구현이 발급자와 같은 32바이트를 내고, 검증자가 그 수를 믿는 대신 **다시 계산**할
수 있게 한다.

> 영문판 [`SUBGRAPH_HASH.md`](SUBGRAPH_HASH.md)가 정본이다. 두 판이 어긋나면
> 영문이 우선한다.

**정본은 이 문서가 아니라 벡터다** — [`spec/subgraph-vectors/`](subgraph-vectors/).
아래 인용된 값은 전부 그 동결 파일의 사본이고, `tools/spec_subgraph_check.py`는
여기 적힌 규칙만으로 자기 인코더·자기 선택기·자기 컴파일러를 써서 전 케이스를
재유도한다. 문서가 모자라면 그 검사기가 가장 먼저 안다.

---

## 1. 이 수는 무엇이고 어디로 다니는가

<!-- vocab: format -->

| name | value |
| --- | --- |
| `magic` | `PAILSG` |
| `format_version` | `1` |
| `hash` | `sha256` |
| `token_field` | `61` |
| `response_field` | `5` |

- **토큰 안.** `ActionToken.subgraph_snapshot_hash`는 `sdk/proto/pail.proto`의
  필드 `61`이다. `schema_version >= 3`에서 존재하고, 서명이 직렬화된 토큰
  바이트 전체 위에서 계산되므로 서명에 덮인다. `policy_hash`(정적 규칙)와
  다르다 — 이 값은 **세계 상태**를 묶는다.
- **서빙 응답 안.** `GetActiveTokenResponse.current_subgraph_hash`는
  `sdk/proto/token_service.proto`의 필드 `5`다. 발급자는 서빙하는 스텝의 해시를
  **현재** 세계에서 발급 시점 에폭을 고정한 채(§6.4) 다시 유도해 토큰 옆에
  실어 보낸다. `graph_epoch`(필드 6)는 진단용이며 대조하지 않는다.
- **게이트에서.** 게이트는 소비 질문을 묻기 전에 토큰의 값과 서빙된 값을
  대조하고, 허가를 쥔 동안의 주기 재확인마다 다시 대조한다. 결과는 둘이
  아니라 셋이다:

<!-- vocab: gate_reason -->

| reason | code |
| --- | --- |
| `ERR_WORLD_CHANGED` | `0x14` |
| `ERR_WORLD_INDETERMINATE` | `0x19` |

  같으면 → 세계 질문이 답해진 것. 둘 다 있는데 다르면 → `ERR_WORLD_CHANGED`,
  체인을 철회하는 치명 거부. **어느 한쪽이 비어 있으면** →
  `ERR_WORLD_INDETERMINATE`, 치명이 *아닌* 거부: 빈 해시는 인프라 신호(사이트
  모델 미적재, 실패한 재유도)이지 세계가 바뀌었다는 증거가 아니며, 치명으로
  다루면 발급자 결함이 스스로 만든 서비스 거부가 된다. 「대조하지 못했다」는
  절대 「대조했고 같다」로 보고되지 않는다. 코드는
  `spec/vectors/contract/reason_dict.vec`에 등재된 것이다.
- **원장 안.** 발급 레코드(`TOKEN_ISSUED`)는 `subgraph_snapshot_hash_hex`,
  체인이 발급된 `graph_epoch`, 그리고 `node_refs` — 선택된 노드 id와 버전
  (`id@version`) — 를 싣는다. 수락된 컨텍스트 이벤트 하나하나는
  `GRAPH_MUTATION` 레코드로 `mutation_kind`, 수신된 이벤트 그대로의
  (`event_node_id`, `arg`), 변이된 `node_id`, `old_version`, `new_version`,
  결과 `epoch`을 싣는다(§6.2).

---

## 2. 자료 모델

세계는 **그래프**다: 전역 변이 카운터(`epoch`), id로 찾는 **노드** 집합, 방향
있는 **에지** 목록. **서브그래프**는 그 조각이다: 잘라낸 시점의 에폭, 노드
일부(깊은 복사라 나중 변이가 스냅숏을 바꾸지 못한다), 에지 일부.

노드는 `id`(`kind:local` 관례, 예 `zone:z7`), `kind`, `state`, 노드별
`version`(부호 없는 64비트, 그 노드의 변이마다 1 증가), 그리고 타입 있는
속성 맵을 가진다.

<!-- vocab: kind -->

| kind | value |
| --- | --- |
| `agent` | `1` |
| `executor` | `2` |
| `object` | `3` |
| `zone` | `4` |
| `human` | `5` |
| `constraint` | `6` |

kind `0`(미지정)은 인코딩할 수 없다. 그것을 가진 노드는 서브그래프 전체를
인코딩 불가로 만든다(§3.5).

<!-- vocab: state -->

| state | value |
| --- | --- |
| `active` | `0` |
| `maintenance` | `1` |
| `cordoned` | `2` |

에지는 노드 id 위의 `(from, rel, to)`다.

<!-- vocab: rel -->

| rel | value |
| --- | --- |
| `located_in` | `1` |
| `targets` | `2` |
| `constrains` | `3` |
| `operates` | `4` |
| `occupies` | `5` |

속성 값에는 태그가 붙는다. 태그가 있어야 맵을 정규 인코딩할 수 있다 — 문자열·
수·불리언 사이의 강제 변환이 없다.

<!-- vocab: tag -->

| tag | value |
| --- | --- |
| `string` | `0x01` |
| `int64` | `0x02` |
| `double` | `0x03` |
| `bool` | `0x04` |

---

## 3. 정규 인코딩

<!-- source: cloud/internal/graph/encode.go -->

인코딩은 결정적이다: 같은 논리 서브그래프는 노드·에지·속성을 어떤 순서로
넣었든 같은 바이트가 된다. Protocol Buffers 직렬화는 정규가 아니므로 이
목적에는 쓰지 않는다.

### 3.1 원시

```
u32(v)   4바이트, 빅엔디언
u64(v)   8바이트, 빅엔디언
i64(v)   8바이트, 빅엔디언 2의 보수
f64(v)   8바이트, 빅엔디언 IEEE 754 binary64; -0.0 은 +0.0 으로 적는다
LP(s)    u32(len(NFC(s))) ‖ NFC(s)        — 유니코드 NFC 정규화 뒤의 UTF-8
```

`LP`는 canon 규격의 다른 곳에서 쓰는 길이 접두 프레이밍과 같다. NFC는 **모든**
문자열에 적용된다: 노드 id, 속성 키, 문자열 값. 한 id의 두 철자(조합된 `é`와
`e` 뒤에 결합 악센트)는 같은 id다. 벡터는 두 철자를 모두 싣고 둘은 같은
바이트가 된다(`SG-04a`, `SG-04b`) — 그리고 둘을 한 서브그래프에 함께 넣으면
중복 id다(`SG-95`).

### 3.2 노드

```
node(n) = LP(id) ‖ u8(kind) ‖ u8(state) ‖ u64(version) ‖ attrs(n.attrs)

attrs(m) = u32(count) ‖ NFC(key) 바이트 오름차순의 각 키에 대해:
             LP(key) ‖ u8(tag) ‖ value

value: string → LP(s)      int64 → i64(i)
       double → f64(f)     bool   → u8(1) 또는 u8(0)
```

속성 맵이 없는 것과 비어 있는 것은 둘 다 `u32(0)`으로 인코딩된다(`SG-10`).

### 3.3 에지

```
edge(e) = LP(from) ‖ u8(rel) ‖ LP(to)
```

인코더는 id를 해석하지 않는다: 에지는 서브그래프의 노드가 아닌 id를 가리켜도
되고(`SG-09`), 완전히 같은 에지 둘은 둘 다 남는다(`SG-06`).

### 3.4 서브그래프

```
subgraph = "PAILSG" ‖ u8(1) ‖ u64(epoch)
         ‖ u32(node_count) ‖ node(n) 바이트 오름차순으로 정렬한 노드들
         ‖ u32(edge_count) ‖ edge(e) 바이트 오름차순으로 정렬한 에지들
```

정렬 키는 **인코딩된 바이트**이고 모든 인코딩은 길이 접두 id로 시작한다.
따라서 순서는 길이 우선이다: `zone:b`(6바이트)가 `zone:aa`(7바이트)보다 앞에
온다, `a` < `b`인데도(`SG-05`). id 문자열로 정렬하는 구현은 정확히 이런
입력에서 다른 해시를 낸다.

그래프 전체는 `PAILSG` 대신 `PAILCG` 매직으로 같은 방식으로 인코딩된다. 그
값은 세계 벡터의 그래프 해시(§7)에 쓰이며 토큰이 싣는 값이 아니다.

### 3.5 인코딩할 수 없는 것

인코더는 추측하지 않고 거부한다. 거부는 **바이트도 해시도 없음**이다.
발급자는 인코딩할 수 없는 세계에 대해 토큰을 서명하지 않는다.

<!-- vocab: reject -->

| reason | cases |
| --- | --- |
| `kind_unspecified` | `1` |
| `non_finite_double` | `3` |
| `duplicate_node_id` | `2` |
| `unknown_attr_tag` | `1` |

- `kind_unspecified` — kind `0`인 노드.
- `non_finite_double` — NaN, +Inf, −Inf인 double 속성.
- `duplicate_node_id` — **NFC 뒤** id가 같은 노드 둘.
- `unknown_attr_tag` — §2 밖의 속성 태그.

벡터는 이것들 각각을 `expect: reject` 케이스로 사유와 함께 싣는다. 두 번째
구현은 같은 입력을 받아들이는지뿐 아니라 같은 입력을 **거부하는지**도 잴 수
있다.

---

## 4. 해시

```
subgraph_snapshot_hash = SHA-256(subgraph)
```

32바이트. 원장과 이 문서에서는 소문자 16진 64자로 적는다. 기준 케이스는
옛 골든 서브그래프 `SG-01`이다: 노드 셋, 에지 둘, 각 타입 속성 하나씩.

<!-- sample: encoding -->

```json
{"id": "SG-01", "sha256": "58b631c03edf4600000aec54715c022b0c5505d29b1639af021abf79d1474aa1"}
```

그 정규 바이트를 동결 파일에서 인용하면:

<!-- pin: spec/subgraph-vectors/cases.json -->

```
5041494c534701000000000000000700000003000000077a6f6e653a7a3704000000000000000001000000020000000e61646a6163656e745f636f756e7402000000000000000200000004747970650100000009776f726b5f6172656100000009726f626f743a746231010000000000000000030000000000000013636f6e73747261696e743a7370656564407a37060000000000000000010000000200000004686172640401000000146d61785f6c696e6561725f73706565645f6d7073033fe00000000000000000000200000009726f626f743a74623101000000077a6f6e653a7a3700000013636f6e73747261696e743a7370656564407a3703000000077a6f6e653a7a37
```

왼쪽부터 읽으면 `5041494c5347`은 `PAILSG`, `01`은 형식 판, `0000000000000007`은
에폭, `00000003`은 노드 셋. 첫 노드는 인코딩이 가장 짧은 `zone:z7`(7바이트),
그다음 `robot:tb1`, 그다음 `constraint:speed@z7`. 그다음 `00000002`는 에지 둘.

---

## 5. 요청이 고르는 조각

<!-- source: cloud/internal/graph/build.go -->

요청은 행동하는 로봇(`robot_id`, 접두어 없는 지역 id)과 선택적으로 표적
객체(`target_object_id`)를 지정한다. 선택되는 서브그래프는 세계로부터 다음
순서로 만든다. 「노드 추가」는 세계에 그 노드가 있으면 복사하고, 없으면
아무것도 하지 않는다는 뜻이다. 에지는 양 끝의 존재와 무관하게 덧붙인다.

1. 에이전트 노드 `robot:<robot_id>`를 추가한다.
2. 에이전트에서 나가는 모든 세계 에지에 대해: `located_in` → 구역과 에지를
   추가; `operates` → 실행체와 에지를 추가. 여기서 추가된 구역들을
   **에이전트 구역**이라 부른다.
3. 표적이 에이전트이거나 에이전트 구역 중 하나인 모든 `constrains` 에지에
   대해: 제약 노드와 에지를 추가.
4. 에이전트 구역으로 들어가는 모든 `located_in` 에지 중 출발이 `human`
   노드인 것에 대해: 사람과 에지를 추가.
5. 표적 객체가 지정됐으면: `object:<target_object_id>`를 추가하고, **합성**
   에지 `(agent, targets, object)`를 덧붙이며 — 객체가 세계에 없어도
   낸다(`SEL-05`) — 객체에서 나가는 모든 `located_in` 에지에 대해 그 구역과
   에지를 추가. 객체 구역의 사람은 선택되지 **않는다**: 4단계는 에이전트
   구역만 훑었다(`SEL-02`).
6. 서브그래프의 에폭은 세계의 에폭이다.

선택은 아무것도 결정하지 않는다. 발급자는 그다음 조각을 평가하고 —
`maintenance`나 `cordoned` 상태의 에이전트, 에이전트 구역 안의 사람은 발급을
거부한다(`SEL-03`은 `HUMAN_IN_ZONE`을 싣는다) — 그 뒤에야 해시한다. 그래도
해시는 조각의 전함수다. 벡터는 거부된 선택과 심지어 빈 선택(`SEL-04`, 세계가
모르는 에이전트)의 해시도 싣는다. 검증자가 어느 것이든 재계산할 수 있어야
하기 때문이다.

<!-- sample: selection -->

```json
{"id": "SEL-02", "node_ids": ["constraint:human_excl@z7", "constraint:payload@tb1", "executor:tb1", "object:box1", "robot:tb1", "zone:z7", "zone:z8"], "sha256": "933fcc152c1fc10e892e36d98fa3971323d339dd960097b42d9efc4a0c76a0ae"}
```

---

## 6. 세계 절단면

해시는 세계의 조각을 묶는다. 재계산하려면 검증자는 발급 에폭 시점의 세계가
필요하다. 이 절은 그 세계가 어떻게 생기고 어떻게 바뀌는지를 적어, 원장
레코드만으로 그것을 다시 세울 수 있게 한다.

### 6.1 사이트 선언 컴파일

<!-- source: cloud/internal/graph/compile.go -->

[`SITE_MODEL.md`](SITE_MODEL.md)가 운영자의 파일을 설명한다. 컴파일된
그래프는 YAML 문법이 아니라 **선언** 위에서 정의된다 — 같은 선언을 내는 JSON
이나 API 프런트엔드는 같은 그래프를 낸다. 그래서 세계 벡터는 선언을 YAML
텍스트와 평문 JSON 둘 다로 싣는다. 컴파일된 그래프는 에폭 `0`이고 모든 노드는
버전 `0`, 상태 `active`다:

- 구역 `z` → 노드 `zone:z`, kind `zone`; 선언됐으면 속성 `type`(string);
  인접이 선언됐으면 속성 `adjacent`(string) = 선언된 인접 id를 정렬해 `,`로
  이은 것.
- 객체 `o` → 노드 `object:o`, kind `object`; `at: z`가 선언됐으면 에지
  `(object:o, located_in, zone:z)`.
- 로봇 `r` → 노드 `robot:r`, kind `agent`; 선언됐으면 속성
  `capabilities`(string) = 정렬한 id를 `,`로 이은 것; 선언됐으면 속성
  `schema`(string); 선언됐으면 속성 `robot_class`(string). 항상 노드
  `executor:r`(kind `executor`)과 에지 `(robot:r, operates, executor:r)`.
  `home: z`가 선언됐으면 에지 `(robot:r, located_in, zone:z)`.
- 제약 `human_exclusion`, `zone: z` → 노드 `constraint:human_excl@z`, kind
  `constraint`, 속성 `ctype` = `human_exclusion`, 에지
  `(constraint:human_excl@z, constrains, zone:z)`. `zone: "*"`는 선언된 모든
  구역으로 id 오름차순 전개.
- 제약 `exclusive`, `object: o` → `object:o`에 속성 `exclusive`(bool `true`).
  `"*"`는 선언된 모든 객체로 전개.
- `actions`와 `policy`는 발급자가 집행하는 선언이지 세계 상태가 아니다.
  노드를 만들지 않는다.

컴파일은 거부하고, 그러면 발급자는 모든 발급을 거부한다: 미지의 최상위 키,
미지의 제약 타입(`WLD-91`), 선언되지 않은 구역이나 객체 참조(`WLD-92`), 중복
id, 빈 `site`, 그리고 `speed_limit` 제약(`WLD-90`) — 구역별 한도는 게이트
정책에 살고 토큰 봉투에 실린다. 사이트 모델은 그것을 집행한 적이 없다.

### 6.2 세계 변이

<!-- source: cloud/internal/graph/mutate.go -->

수락된 컨텍스트 이벤트 하나는 표적 노드의 버전과 전역 에폭을 정확히 1씩
올리고, 수신된 이벤트 그대로 — `mutation_kind`, `event_node_id`(이벤트의
`node_id`: `HUMAN_*`는 구역, `OBJECT_MOVE`는 객체, 상태 이벤트는 그 노드),
`arg` — 와 변이된 `node_id`, 아래 버전 값들을 가진 `GRAPH_MUTATION` 레코드로
저널된다. 컴파일된 그래프 위에 레코드를 재생하면 어느 에폭의 세계든 다시
선다. 벡터도 이벤트마다 같은 세 입력 필드를 쓴다. `event_node_id`와 `arg`가
추가되기(2026-09-18) 전에 쓰인 레코드는 변이된 노드만 싣는다. 그 레코드로는
`HUMAN_ENTER`, `HUMAN_LEAVE`, `OBJECT_MOVE`를 원장만으로 재생할 수 없고
운영자 자신의 이벤트 기록이 필요하다.

<!-- vocab: event -->

| kind | cases |
| --- | --- |
| `HUMAN_ENTER` | `2` |
| `HUMAN_LEAVE` | `1` |
| `OBJECT_MOVE` | `1` |
| `MAINTENANCE_ON` | `1` |
| `MAINTENANCE_OFF` | `0` |
| `CORDON_ON` | `1` |
| `CORDON_OFF` | `1` |

- `MAINTENANCE_ON` / `MAINTENANCE_OFF` / `CORDON_ON` / `CORDON_OFF`, `node_id`
  대상: 상태를 `maintenance` / `active` / `cordoned` / `active`로;
  `old_version` = 이전 버전, `new_version` = `old_version + 1`.
- `HUMAN_ENTER`, `node_id = zone:z`, `arg = h`: `human:h`가 없으면 만든다
  (kind `human`, 버전 `0`) — 그 레코드는 `old_version 0, new_version 0`을
  보인다; 있으면 버전을 올린다. 에지 `(human:h, located_in, zone:z)`가 없으면
  추가한다.
- `HUMAN_LEAVE`, `zone:z`, `arg = h`: 에지 `(human:h, located_in, zone:z)`를
  제거한다. 사람이 아직 다른 구역에 `located_in`이면 버전을 올린다; 아니면
  **노드를 삭제**하고, 레코드는 더는 없는 노드에 대해 `new_version =
  old_version + 1`을 보고한다.
- `OBJECT_MOVE`, `node_id = object:o`, `arg = z`: 객체에서 나가는 모든
  `located_in` 에지를 제거하고 `(object:o, located_in, zone:z)`를 추가하며
  객체 버전을 올린다.

미지의 노드·구역·사람을 지정한 이벤트는 거부되고 아무것도 저널하지 않는다.
에폭은 움직이지 않는다.

### 6.3 임시 세계

<!-- source: cloud/internal/graph/ephemeral.go -->

사이트 모델이 적재되지 않았으면 발급자에게 상주 세계가 없다. 발급자는 아는
것으로 에폭 `0`의 요청별 세계를 만들어 그것에 대해 인가한다:

- `robot:<robot_id>`, kind `agent`, 버전 `1`;
- 토큰 한도 `max_linear_speed_mps`, `max_angular_speed_rps`,
  `max_duration_sec` 중 하나라도 양수면: 노드
  `constraint:speed@<robot_id>`, kind `constraint`, 버전 `1`, **양수 한도만**
  double 속성으로 실은 것, 그리고 에지
  `(constraint:speed@<robot_id>, constrains, robot:<robot_id>)`;
- 표적이 지정됐으면 `object:<target_object_id>`, kind `object`, 버전 `1`.

그 세계 위에서 선택(§5)이 돈다(`SEL-EPH-01` … `SEL-EPH-03`). 이 모드에서
발급자는 `current_subgraph_hash`를 서빙하지 **않으므로** 게이트는 대조를
미확정으로 읽고 동작을 거부한다(§1): 토큰은 유효하고, 세계 질문은 답할 수
없으며, 집행하려는 배치는 사이트 모델을 적재해야 한다.

### 6.4 에폭 고정

에폭은 해시되는 바이트 안에 있다(§3.4). 발급자가 스텝의 해시를 현재 세계에서
다시 유도할 때 — `current_subgraph_hash`를 서빙하거나, 변이 뒤 어느 체인을
철회할지 정할 때 — **현재** 세계에서 조각을 고르되 해시하기 전에 에폭을
체인의 **발급** 에폭으로 고정한다. 고정하지 않으면 어디서든 변이가 일어날
때마다 모든 체인의 해시가 바뀌고, 고정하면 이 체인 자신의 노드나 에지가
바뀌었을 때에만 해시가 달라진다. 토큰 값을 재계산하는 검증자도 같이 해야
한다: 발급 에폭 시점의 세계로, 아니면 현재 세계에 발급 에폭을 헤더에 써서.

---

## 7. 파일과 필드

<!-- vocab: file -->

| file | array key | rows |
| --- | --- | --- |
| `cases.json` | `cases` | `18` |
| `selection.json` | `cases` | `9` |
| `world.json` | `cases` | `5` |

셋 다 UTF-8 JSON, 두 칸 들여쓰기, 끝에 개행. 해시는 소문자 16진 64자.
`cases.json`은 추가로 최상위 문자열 `format`과 `format_version`을 싣는다.

JSON의 서브그래프나 세계는 `{epoch, nodes, edges}`; 노드는
`{id, kind, state, version, attrs}`에 §2의 숫자 값; 속성은 `{t, v}`이고 `t`는
`string`, `int64`, `double`, `bool` 중 하나 — **double 값은 JSON 문자열**이다
(`"0.5"`, `"-0"`, `"1e+308"`, `"5e-324"`), 음의 0과 비유한 거부 입력이 JSON을
살아 넘도록 — 미지 태그 거부 케이스는 `{t: "unknown", tag}`. 에지는
`{from, rel, to}`.

- `cases.json` — 수락 케이스는 `{id, title, expect, subgraph, canonical_hex,
  sha256}`; 거부 케이스는 `{id, title, expect, reason, subgraph}`.
- `selection.json` — `{id, title, mode, world, request, selected, evaluate,
  canonical_hex, sha256}`; `mode`는 `site` 또는 `ephemeral`이고, 임시
  케이스는 세계를 만든 입력 `ephemeral`(`robot_id`, `target_object_id`, 한도
  셋)도 싣는다. `selected`는 `{node_ids, edges}`로 id는 정렬, 에지는
  `(from, rel, to)`로 정렬; `evaluate`는 `{violated, reason}`.
- `world.json` — `{id, title, expect, site_yaml, site, events, graph,
  graph_sha256, requests}`; `events`는 적용 순서대로이며 저널되는 `epoch`,
  `old_version`, `new_version`을 싣는다; `graph_sha256`은 최종 세계의
  `PAILCG` 해시; 각 요청은 선택된 `node_ids`와 그 조각의 `sha256`을 싣는다.
  거부 케이스는 `reason`을 싣고 그래프는 없다.

<!-- sample: world -->

```json
{"id": "WLD-01", "epoch": 7, "graph_sha256": "104448dfd7810f059dc27366aab64cc7573e85385725326e657b287dd98708fc"}
```

---

## 8. 이 세트가 실제로 닿는 것

아래 수는 전부 검사기가 동결 바이트에서 재유도한다.

<!-- vocab: coverage -->

| name | count |
| --- | --- |
| `accept_cases` | `11` |
| `reject_cases` | `7` |
| `selection_site` | `6` |
| `selection_ephemeral` | `3` |
| `world_accept` | `2` |
| `world_reject` | `3` |
| `nfc_pairs` | `1` |
| `length_major_cases` | `4` |
| `duplicate_edge_cases` | `1` |
| `empty_subgraph_cases` | `1` |
| `evaluate_violations` | `1` |

- `nfc_pairs` — 입력이 유니코드 조합에서만 다르고 정규 바이트가 같은 수락
  케이스 쌍.
- `length_major_cases` — 노드를 id 문자열로 정렬하면 인코딩 바이트로 정렬한
  것과 순서가 달라지는 수락 케이스.
- `duplicate_edge_cases` — 같은 에지 둘을 싣는 수락 케이스.
- `empty_subgraph_cases` — 노드도 에지도 없는 수락 케이스.
- `evaluate_violations` — 발급자가 그 조각을 거부할 선택 케이스.

---

## 9. 매니페스트와 세트 해시

`spec/subgraph-vectors/MANIFEST.sha256`은 파일별 SHA-256을 나열한 뒤 세트 전체의
`set_sha256` 줄을 둔다. 세트 해시는 `"<hex>  <name>\n"` 줄들만을 파일명
오름차순으로 늘어놓고 계산한다. 주석 줄과 `set_sha256` 줄 자체는 입력이
아니다.

<!-- vocab: claim -->

| name | value |
| --- | --- |
| `subgraph_set_sha256` | `2ab87f04885b82dcf22a67d5b565d0fed057abb3e9a4d95ea9f613bd80e4c752` |
| `canon_set_sha256` | `bbddff16fb5997faeff47bf6913e64d9675178d2ddffd5828aa898a235688701` |
| `golden_g1_sha256` | `58b631c03edf4600000aec54715c022b0c5505d29b1639af021abf79d1474aa1` |

이 세트는 `spec/vectors/canon/`(문자열을 어떻게 적는가)과도
`spec/merkle-vectors/`(로그 산술)와도 다른 평면이다. 서로 다른 이유로
개정되므로 자기 매니페스트를 따로 가진다. `golden_g1_sha256`은 이 세트 이전에
있던 유일한 서브그래프 벡터다. `SG-01`이 그것을 그대로 실어 연속성을
가정하지 않고 잰다.

[`CONFORMANCE.ko.md`](CONFORMANCE.ko.md)의 적합성 주장은 직렬화 평면
`canon_set_sha256`을 덮는다. 이 세트를 통과하는 것은 아직 그 주장의 일부가
아니다. 바뀐다면 `CONFORMANCE.md`와 그것을 재는 검사기에서 바뀌지, 이 문단에서
바뀌지 않는다.

---

## 10. 세트 사용법

시험 대상 구현에 대해:

1. `cases.json`의 모든 수락 케이스를 §3으로 인코딩하고 먼저 `canonical_hex`,
   그다음 `sha256`을 대조한다. 바이트 불일치는 규칙을 지목하고, 바이트가
   같은데 해시가 다르면 해시 원시가 틀린 것이다.
2. 모든 거부 케이스를 넣는다. 인코더는 같은 `reason`으로 거부해야 한다.
3. `selection.json`의 각 케이스에 대해 `world`에서 §5로 선택하고(`mode`가
   `ephemeral`이면 먼저 §6.3으로 임시 세계를 만든다) `selected`를 대조한 뒤
   해시해 `sha256`을 대조한다.
4. `world.json`의 각 수락 케이스에 대해 `site`를 §6.1로 컴파일하고 `events`를
   §6.2로 적용하며 저널 삼중값을 하나씩 확인하고, 세계를 해시해
   `graph_sha256`을 대조하고, 각 요청에 답한다.
5. 실제 토큰을 검증하려면: 사이트 선언과 `GRAPH_MUTATION` 레코드로 체인의
   발급 에폭 시점 세계를 다시 세우고, 토큰의 로봇과 표적으로 조각을 골라
   해시한 뒤 토큰의 필드 `61`과 원장의 `subgraph_snapshot_hash_hex`에
   대조한다.

실린 도구 `cmd/pail-recompute` 가 다섯 단계를 전부 수행한다(`vectors` 모드가
1~4, `ledger` 모드가 5). 서명된 `action_token_bytes` 에서 필드 `61`·로봇·표적을
읽고, 저널을 따라 발급자의 에폭을 좇으며 — 높은 에폭 뒤에 `epoch` `1` 인 변이가
오면 발급자가 사이트 모델을 다시 적재한 것이다 — 토큰마다 검증됨·불일치·검증
불가(저널된 `site_model_hash_hex` 와 해시가 다른 사이트 파일, 원장으로 닿을 수
없는 에폭, `event_node_id` 없는 이벤트 레코드)를 보고한다.

---

## 11. 이 문서는 어떻게 유지되는가

| 무엇 | 검사 |
| --- | --- |
| 동결 파일이 매니페스트와 맞고 세트 해시가 §9와 맞는가 | `tools/spec_subgraph_check.py` `S1` `S2` |
| §1·§2의 어휘가 벡터가 실제로 쓰는 값인가 | 같은 도구 `S3` |
| §3으로 쓴 인코더가 모든 수락 케이스를 재현하고 모든 거부 케이스를 거부하는가 | 같은 도구 `S4` |
| §4의 인용이 동결 바이트에서 왔고 `SG-01`이 옛 골든인가 | 같은 도구 `S5` |
| §5와 §6.3으로 쓴 선택기가 모든 선택 케이스를 재현하는가 | 같은 도구 `S6` |
| §6.1과 §6.2로 쓴 컴파일러와 재생기가 모든 세계 케이스를 재현하는가 | 같은 도구 `S7` |
| 인용 샘플이 동결 케이스에 있는가 | 같은 도구 `S8` |
| §8의 커버리지 수가 벡터가 닿는 것과 같은가 | 같은 도구 `S9` |
| §1의 게이트 사유가 등재된 코드이고 proto 필드가 실린 것과 같은가 | 같은 도구 `S10` |
| 한국어판이 같은 어휘와 샘플을 가르치는가 | 같은 도구 `S11` |
| 생성기와 인코더의 상수가 §1과 같은가 | 같은 도구 `S12` |

검사기가 자기 전제를 세우지 못하면(벡터 없음, 매니페스트 없음, 어휘 표 없는
문서) `FAIL 0`이 아니라 **rc=2**로 멈춘다. 아무것도 읽지 못한 실행과 위반
없는 실행이 같은 바이트를 내면 안 된다.
