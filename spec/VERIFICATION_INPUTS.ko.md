# 검증 입력 (Verification inputs)

이 문서는 독립 검증자가 PAIL 앵커 로그의 **추가 전용(append-only)** 성질과 특정
기록의 **포함(inclusion)** 을 확인하기 위해 소비하는 세 가지 와이어 형식을
동결한다: 서명된 체크포인트 노트, 포함 증명 응답, 일관성 증명 응답.

> 영문 정본: [`VERIFICATION_INPUTS.md`](VERIFICATION_INPUTS.md). **영문이 정본이며,
> 두 문서가 어긋나면 영문 문면이 지배한다.**

## 1. 하나의 규칙

**루트를 유도하는 것은 루트를 검증하는 것이 아니다.**

이 문서의 모든 RFC 6962 증명 알고리즘은 32바이트 값을 내놓으며 끝난다. 유효한
증명에도 하나를 내놓고, 통째로 다시 쓰인 증명에도 하나를 내놓는다. 그 값은 신뢰하는
키가 보증한 루트와 **대조된 뒤에야** 증거가 된다.

이것은 가정된 실패가 아니다. 이 프로젝트의 투명성 로그 하네스가 실제로 안고 있던
결함이다 — 체크포인트를 개행으로 쪼개 크기와 루트를 그대로 믿었기 때문에, 구조적으로
완벽한 머클 트리를 발행하되 **아무도 서명하지 않은** 체크포인트를 내건 로그가 모든
검사를 통과했다. 산술은 처음부터 끝까지 옳았다. 산술이야말로 공격자가 틀릴 이유가
없는 유일한 부분이다.

이 규칙에서 두 가지 귀결이 나오고, 그것이 이 문서 전체를 관통한다:

1. **체크포인트의 바이트를 읽기 전에 먼저 인증한다** (§2).
2. **두 증명 응답 어느 쪽도 신뢰할 수 있는 루트를 싣지 않는다** (§5). 포함 응답은
   보증할 수 있을 때만 루트를 되울리고, 일관성 응답은 아예 싣지 않는다. 둘 다
   검증자가 **이미 쥐고 있어야 하는 입력**이다.

## 2. 서명된 체크포인트 노트

체크포인트는 `golang.org/x/mod/sumdb/note` 형식의 서명된 노트이며,
`text/plain; charset=utf-8` 로 제공된다.

### 2.1 와이어 형식

<!-- sample: spec/proof-vectors/checkpoint.note -->

```
glowfly-anchor-log\n      <- 0행: origin
4\n                       <- 1행: 트리 크기, 십진
3qvyBdwNhKy/…SkxVU=\n     <- 2행: base64(root), 표준 알파벳, 패딩 포함
\n                        <- 빈 행: 본문의 끝
— glowfly-anchor-log <base64>\n   <- 서명 행 하나 이상
```

서명 행은 하이픈이 아니라 **U+2014 EM DASH** 로 시작한다. `"- "` 로 쪼개는 구현은
서명을 찾지 못해 그 노트를 **서명 없음**으로 보고하는데, 서명 없음을 연성 실패로
다루면 그것은 **애초에 검사하지 않은 노트와 구분되지 않는다**.

`note.Open` 이 성공했을 때 돌려주는 본문은 0~2행과 그 뒤의 개행이다. 서명 블록은
본문에 포함되지 않는다.

<!-- vocab: checkpoint_line -->

| 이름 | 행 |
| --- | --- |
| `origin` | 0 |
| `size` | 1 |
| `root_b64` | 2 |

### 2.2 일부러 갈라 둔 두 관문

노트를 여는 일은 두 개의 검사이며, 둘은 서로 다른 질문에 답한다:

<!-- pin-internal: anchor-checkpoint-implementation -->
```go
	// ErrSignature is gate 1: nobody we trust wrote this.
	ErrSignature = errors.New("checkpoint: signature not from a trusted log key")
	// ErrOrigin is gate 2: a trusted key wrote it, about a different log.
	ErrOrigin = errors.New("checkpoint: note is for another log")
```

서명은 *우리가 신뢰하는 누군가가 이것을 썼다* 고 말한다. origin 은 *그리고 그가 이
로그에 대해 썼다* 고 말한다. 앞의 것만 있으면, 같은 운영자가 돌리는 **형제 로그**의 —
그 자체로는 완벽하게 유효한 — 체크포인트가 내 것으로 받아들여진다.

검증자 키와 기대 origin 은 둘 다 **대역 외(out of band)** 로 검증자에게 도달해야
한다. 지금 검사 중인 노트에서 origin 을 읽거나, 감사 대상 로그에서 키를 받아 오는
검증자는 **피감사자에게 자기 답안지 채점을 맡긴 것**이다.

세 번째 상태가 두 판정만큼이나 중요하다: *신뢰근이 설정되지 않았다* 가 호출자에게
*서명이 확인됐다* 와 같은 값으로 도달해서는 안 된다. 빈 검증자 목록은 **거부**이지,
아무거나 받아들이는 검증자가 아니다.

### 2.3 인증한 뒤의 파싱

인증된 본문만 파싱한다. 두 개의 폭(width) 규칙이 적용된다:

<!-- pin-internal: anchor-checkpoint-implementation -->
```go
	if len(root) != sha256.Size {
		return 0, nil, fmt.Errorf("%w: root is %d bytes, want %d", ErrMalformed, len(root), sha256.Size)
	}
```

루트 폭을 호출 지점이 아니라 파싱 시점에 검사하는 데에는 분명한 이유가 있다. 잘린
노트 — `"origin\nsize\n"` — 는 마지막 칸이 빈 세 개의 필드로 쪼개지고, base64 는 빈
문자열을 아무 불평 없이 디코드한다. 폭 검사가 없으면 호출자는 **길이 0인 루트와 nil
에러**를 받고, *루트 없음* 이 *루트* 로 둔갑해 흘러간다.

### 2.4 서명, 바이트 단위로

§2.3 까지는 노트의 *형태* 를 적은 것이다. 관문 1 이 검사하는 것은 형태가 아니다.
이 문서의 이전 판은 `note.Open` 을 이름으로만 부르고 멈췄고, 그래서 가장
중요하다고 스스로 적은 연산 — *우리가 신뢰하는 키가 서명했는가* — 이 Go 라이브러리
하나로만 규정돼 있었다. 다른 언어로 쓰인 검증자는 §2.1 의 규칙을 전부 재현하고도
서명을 확인할 방법이 없고, 그때 남는 선택지가 바로 §1 이 첫 문장으로 경고한 결함이다:
노트에서 크기와 루트를 읽어 그대로 진행하는 것.

아래 여섯 가지가 `note.Open` 은 알고 이 문서는 말하지 않던 것이다.

<!-- vocab: sig_element -->

| name | value |
| --- | --- |
| `key_encoding` | `name ‖ "+" ‖ hex(hint) ‖ "+" ‖ base64(algid ‖ pubkey)` |
| `key_algid` | `0x01` |
| `hint_input` | `name ‖ 0x0A ‖ algid ‖ pubkey` |
| `hint_width` | `4` |
| `blob_layout` | `hint ‖ signature` |
| `sig_message` | `body` |

`‖` 는 이어붙이기다. `name`·`algid`·`pubkey`·`hint`·`signature`·`body` 는 이 절과
§2.1 이 이름 붙인 값이고, 따옴표로 묶인 조각과 `0x` 리터럴은 그 자신이다.

`key_encoding` 은 키 파일을 **쓰는** 규칙이고, 읽는 것은 그것의 거울상이 아니다.
구분자 `+` 는 base64 자신의 알파벳에 속해 있어서 키 본체가 그것을 품는다 — 본체
44글자 중에 최소 하나가 들어 있을 확률이 넷 중 셋가량이다. 모든 `+` 에서 자르고
세 조각을 요구하는 독자는 그래서 정당한 신뢰근을 대부분 거부한다. 그리고 건네받은
키를 거부하는 검증자는 fail-closed 가 아니라 벽이다. 왼쪽에서 두 번만 자르고
나머지를 통째로 본체로 삼는다.

`hint` 은 `SHA-256(hint_input)` 의 앞 `hint_width` 바이트이고, 키 파일에는 소문자
16진수로, 서명 블롭에는 원시 바이트로 실린다. 어느 키를 시도할지 고르는 값이다.
**검사가 아니다** — 네 바이트는 두 키가 충돌할 수 있고, 충돌을 원하는 공격자라면
가지고 있을 수 있다. 힌트가 하는 일은 후보를 좁히는 것뿐이고, 판정은 ed25519
검증만 한다.

`sig_message` 는 §2.1 의 인증된 본문이다 — 0~2행과 그 뒤의 개행까지, 그 밖은
아니다. 파일 전체가 아니다: 빈 행과 서명 블록은 바깥이다. 이것을 굳이 적는 이유는
두 선택 모두 32바이트 루트를 갖는 파싱 가능한 노트를 만들어 내고, 그중 하나만
검증에 성공하기 때문이다. 서명 구간을 잘못 잡은 검증자는 **정직한 노트를 전부
거부** 하고, 그 거부는 연성 실패 정책 아래에서 *서명 없음* 으로 읽힌다 — §2.1 의
실패 양식에 반대편에서 도달하는 것이다.

§7 의 동결 벡터에 대고 구체적으로:

```
키 파일 : glowfly-anchor-log+7f93d626+AczZJ3Eob4eEopbRhtqoseh3r4Pc1cOdjAWw/Z6jF9X0
힌트    : SHA-256("glowfly-anchor-log" || 0x0A || 0x01 || pubkey)[:4] = 7f93d626
블롭    : 68바이트 = 4(힌트) + 64(ed25519 서명)
메시지  : "glowfly-anchor-log\n4\n3qvyBdwNhKy/…SkxVU=\n"   (66바이트, 본문만)
```

실린 검사기는 각 행을 문자열로 맞춰 보지 않고 **다시 유도한다**: `hint_input` 으로
힌트를 재계산해 키 파일의 16진수와 대조하고, `sig_message` 로 서명을 검증하는
동시에 파일 전체로는 검증이 **실패한다는 것까지** 확인한다. 자기 자신과만 일치하는
행은 아무것도 말하지 않는다.

## 3. 포함 증명 응답

`GET /v1/proof/inclusion/{tenant}?leaf_index=L[&tree_size=T]` →
`application/json`. `tree_size` 를 생략하면 최신 발행 체크포인트의 크기가 쓰인다.

<!-- vocab: inclusion_field -->

| 필드 | 타입 |
| --- | --- |
| `status` | `string` |
| `tenant_id` | `string` |
| `leaf_index` | `uint64` |
| `tree_size` | `uint64` |
| `root_b64` | `string` |
| `leaf_b64` | `string` |
| `proof_b64` | `string[]` |

`leaf_b64` 는 로그가 커밋한 리프 바이트열 그 자체다. 증명 검증에 관한 한 이 값은
**불투명(opaque)** 하다: RFC 6962 리프 해시는 받은 바이트 그대로에 대한
`SHA-256(0x00 || leaf_bytes)` 이고, 그 내부 구조는 계산에 전혀 들어오지 않는다.
구조는 [`CANON.md`](CANON.md) 의 `pail-saas-anchor:v2` 에서 따로 규정하며, 증명된
리프를 **해석**할 때만 필요하고 리프를 **증명**할 때는 결코 필요하지 않다.

`proof_b64` 는 리프에서 루트 방향으로 정렬된다. 빈 배열은 정상이다 — 크기 1인 트리에는
형제가 없다.

<!-- sample: spec/proof-vectors/inclusion_size4_idx0.json -->
<!-- sample: spec/proof-vectors/inclusion_size4_idx3.json -->
<!-- sample: spec/proof-vectors/inclusion_size2_idx0.json -->

## 4. 일관성 증명 응답

`GET /v1/proof/consistency/{tenant}?from=T1&to=T2` → `application/json`.

<!-- vocab: consistency_field -->

| 필드 | 타입 |
| --- | --- |
| `status` | `string` |
| `tenant_id` | `string` |
| `from` | `uint64` |
| `to` | `uint64` |
| `proof_b64` | `string[]` |

<!-- sample: spec/proof-vectors/consistency_2_4.json -->
<!-- sample: spec/proof-vectors/consistency_1_4.json -->

## 5. 응답이 싣지 **않는** 것

이 절은 건너뛰기 가장 쉽고, 조용한 가짜 초록을 만들기 가장 쉬운 절이다.

### 5.1 과거 트리 크기에서 `root_b64` 는 비어 있다

서버는 보증할 수 있는 루트만 되울린다 — 즉 요청된 `tree_size` 가 최신 발행 체크포인트
크기와 같을 때만:

<!-- pin-internal: services/anchor_saas/internal/proofapi/proofapi.go -->
```go
	// Only echo a root the server can vouch for (latest checkpoint).
	echoRoot := ""
	if size == latest {
		echoRoot = b64(root)
	}
```

그보다 앞선 크기에서는 이 필드가 빈 문자열이다.
`spec/proof-vectors/inclusion_size2_idx0.json` 이 바로 그런 응답이며, 이 경우가
가정으로 치부되지 않도록 동결해 두었다.

빈 `root_b64` 는 에러가 아니고 열화된 응답도 아니다. 서명하지 않은 것을 주장하지 않는,
**옳게 사양하는** 서버의 태도다. 검증자는 그 크기에서 자기가 인증한 체크포인트로부터
루트를 **스스로 공급해야** 한다.

### 5.2 일관성 응답에는 루트가 아예 없다

빈 루트가 아니라 — 없다. 일관성 검증에는 루트 두 개가 필요하고, 둘 다 검증자가 따로
인증한 체크포인트에서 온다.

여기에는 더 날카로운 함정이 하나 들어 있다. `from` 크기가 정확한 2의 거듭제곱일 때
`root@from` 은 마지막에 대조하는 값이 아니라 **알고리즘의 입력**이다 — 왼쪽 트리의
루트가 증명에 실려 오지 않기 때문이다. 틀린 값을 넣어도 유도는 끝까지 완주하고
32바이트 값을 내놓는다.

`spec/proof-vectors/consistency_2_4.json`(`from=2`) 과
`consistency_1_4.json`(`from=1`) 은 둘 다 2의 거듭제곱 사례이며, 증명을 자기완결적인
것으로 다루는 구현이 **자기 테스트는 통과하고 여기서 실패하기** 때문에 일부러
동결했다.

### 5.3 같은 개념의 두 철자

증명 해시 배열의 이름이 이 시스템의 두 표면에서 다르게 쓰인다. 어느 쪽도 틀린 것이
아니며, 두 표면을 오가는 구현자는 둘 다 알아야 한다.

<!-- vocab: proof_key -->

| 키 | 표면 |
| --- | --- |
| `proof_b64` | `proof_plane` |
| `proof_base64` | `verdict_bundle` |

## 6. 상태 코드와 사유

에러는 `application/json` 이며 정확히 두 필드를 갖는다 — `status`(항상 `"error"`) 와
`reason`.

아래 `reason` 집합은 방출자(emitter)와 그 앞에 선 미들웨어에서 유도했다.
`disposition` 칸은 "제3자가 이것을 실제로 볼 수 있는가?" 에 대한 **네 값**의 답이며,
정직한 답이 이분법이 아니기 때문에 존재한다:

- `observed` — `spec/proof-vectors/` 의 동결 벡터에 실제로 나타난다.
- `shadowed` — 핸들러는 방출하지만, 배치된 배선이 같은 조건을 더 앞에서 가로채 다르게
  답한다. 제3자는 결코 보지 못한다.
- `auth_only` — 자격증명 집행이 켜진 배치에서만 도달 가능하다. 동결 벡터는 그것이 꺼진
  배치에서 채집했다.
- `state_only` — 동결 벡터가 담고 있지 않은 로그·테넌트 상태에서만 도달 가능하다.

<!-- vocab: reason -->

| 사유 | http | 처분 |
| --- | --- | --- |
| `bad_leaf_index` | 400 | `observed` |
| `bad_range` | 400 | `observed` |
| `bad_tree_size` | 400 | `observed` |
| `method_not_allowed` | 405 | `observed` |
| `not_found` | 404 | `observed` |
| `proof_error` | 422 | `observed` |
| `bad_path` | 404 | `shadowed` |
| `auth_fail` | 401 | `auth_only` |
| `no_credential` | 401 | `auth_only` |
| `revoked` | 403 | `auth_only` |
| `scope_mismatch` | 403 | `auth_only` |
| `tenant_mismatch` | 403 | `auth_only` |
| `tenant_suspended` | 403 | `state_only` |
| `checkpoint_unavailable` | 503 | `state_only` |

클라이언트 구현자가 알아야 할 세 가지:

**`bad_path` 는 가려져 있다(shadowed).** 경로가 정확히 한 개의 테넌트 세그먼트로
풀리지 않을 때 핸들러는 `404 bad_path` 로 답하지만, 모든 증명 라우트 앞에 선
미들웨어가 **동일한 술어**를 먼저 적용해 `404 not_found` 로 답한다. `bad_path` 로
분기하지 말 것 — 받을 일이 없다. 지우지 않고 여기 적어 두는 이유는 그것이 여전히
소스에서 방출되고 있기 때문이며, **코드에는 있는데 규격에는 없는 사유**가 바로 다음
격차가 시작되는 자리다.

**`tenant_mismatch` 에는 두 개의 원인이 있다.** 자격증명의 테넌트가 경로의 테넌트와
다를 때 미들웨어가 방출하고, 요청된 리프가 호출자와 다른 테넌트의 것일 때 핸들러가
방출한다. 응답은 **바이트까지 동일**하다. 클라이언트는 "토큰이 틀렸다" 와 "당신의
리프가 아니다" 를 구분할 수 없으며, 구분할 수 있는 것처럼 재시도해서는 안 된다.

**`proof_error` 는 일부러 성기다.** 트리 끝을 넘은 리프 인덱스, 최신 체크포인트를 넘는
`tree_size`, 거꾸로거나 0인 일관성 구간이 모두 이 하나를 낸다. 뜻은 "로그가 이 증명을
만들지 않겠다" 이지 결코 "로그가 불일치한다" 가 아니다. `422` 를 변조의 증거로 다루는
검증자는 **잘못 만든 질문을 던질 때마다** 사고를 신고하게 된다.

증명 평면에는 레이트리밋 사유가 없다 — 리미터는 수집(ingest)과 검증(verify) 정문을
지키고, 이 읽기 전용 라우트는 지키지 않는다.

## 7. 동결된 벡터

`spec/proof-vectors/` 에는 실제 한 번의 실행을 채집한 스냅숏이 들어 있으며,
`RESPONSES.tsv` 가 각 응답의 HTTP 상태와 content type 을 기록한다. 이것은 **채집한
바이트**이지 손으로 쓴 예제가 아니다 — 손으로 쓴 예제는 **저자가 형식을 그렇게 믿었다는
것**만 증명한다.

실린 검사기는 그 안의 모든 증명을 자기 자신의 RFC 6962 구현으로 다시 유도한다. 이
구현은 벡터를 만들어 낸 Go 라이브러리와 **독립적으로** 작성되었다. 그 라이브러리를
재사용했다면 일치는 증거가 아니라 **항등식**이었을 것이다.

> **`checkpoint.vkey` 는 신뢰근이 아니다.** 한 번의 시험 실행을 위해 만들고 버린
> 일회용 키쌍의 공개 절반이며, 개인 절반은 디스크에 쓰인 적이 없다. 동결된 노트를 열 수
> 있도록 여기 둔 것뿐이다. 이것을 실제 로그의 신뢰근으로 고정하는 것은 **아무도 보유하지
> 않고 아무도 회전시키지 않는 키**를 고정하는 것이다. 이 키는
> `spec/trust-roots.tsv` 에 `not-anchor` 로 등재돼 있고, 실제 로그의 신뢰근을
> 정의·취득·회전하는 문서는 [`spec/TRUST_ROOT.md`](TRUST_ROOT.md) 다. 현재 앵커
> 수가 0 이라는 사실도 그 문서가 적는다.

이 벡터들은 일부러 `spec/vectors/` **아래에 두지 않았다**. 그 디렉터리는 canon 동결
창이 지배하며, 동결 창이 보호하는 것은 그 변경이 버전 사건이 되는 서명·해시의
**입력**이다. 이 파일들은 채집된 **출력**이다. 동결 기계를 빌리려고 그리로 옮기는 것은
규칙을 지키는 것이 아니라 **규칙을 피해 가는 것**이고, 통상적인 재채집을 canon 변경처럼
보이게 만든다.

## 8. 범위 밖: verdict 번들

`POST /v1/verify/{tenant}/{robot}` 은 `verdict`, `log_consistency`,
`log_root_hex`, `log_size`, `inclusion_proofs[]` 를 담은 번들을 돌려준다. 이것은 검증
**입력이 아니라** 서버의 **주장**이다. 거기서 `verdict` 나 `log_consistency` 를 읽어
쓰는 독립 검증자는 §1 의 결함을 한 층 위에서 재생산한 것이다 — 피감사자가 자기 감사에
대해 내놓은 요약을 믿는 것이다.

검증자가 이 번들을 쓴다면, 증명 재료의 **운반체**로만 쓸 수 있다:
`inclusion_proofs[].proof_base64` 와 `sth_tree_size` 를, 각각 §2 에 따라 인증한
체크포인트에 대해 다시 검증하는 방식이다. 여기에는 §5.3 의 두 번째 철자가 적용된다는
점에 유의할 것.

## 9. 무엇이 측정되고, 실린 검사기가 무엇을 보지 못하는가

`spec/tools/spec_verification_inputs_check.py` 는 이 문서를 주장하지 않고
**측정**한다. 모든 검사는 자기 줄을 인쇄한다 — 건너뛴 검사도 그렇다. 조용히 없는
검사는 통과한 검사와 구분되지 않기 때문이다.

공개적으로 측정하는 것은 **문서 대 동결 벡터**다: 필드 표를 벡터 본문과, 사유 표를
`RESPONSES.tsv` 및 동결된 에러 본문과, 노트 파싱 규칙을 `checkpoint.note` 와 대조하고,
동결된 모든 증명을 동결된 루트로부터 다시 유도한다.

측정하지 **못하는** 것은 **문서 대 방출자 소스**다. 앵커 서비스가 공개 스냅숏에 실리지
않기 때문이다. 그 대조 — 응답 구조체, 사유 집합 전체, `disposition` 칸 — 는 내부
트리에서만 돌며, 그 결과는 여러분이 다시 돌릴 수 있는 무언가가 아니라 **이 문서의
내용**으로 도달한다. 확인할 수 있는 곳에서는 확인하라. 위 절들은, 확인할 수 **없는**
부분이 우리 배선을 서술하는 부분이 되고, *여러분* 검증자의 의무를 서술하는 부분은 전부
여러분이 쥔 벡터로 뒷받침되도록 배열되어 있다.
