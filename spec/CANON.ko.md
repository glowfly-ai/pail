# PAIL canon 규격 — 서명·해시 대상 바이트의 정규문

> This is the Korean edition. The canonical document is
> [`CANON.md`](CANON.md) (English).

**이 문서는 두 번째 구현을 위한 것이다.** 여기 적힌 것을 그대로 조립하면
[`vectors/`](vectors/)의 동결 바이트와 같은 값이 나와야 하고, 나오지 않으면
둘 중 하나가 틀린 것이다.

**정본은 이 문서가 아니라 벡터다.** 아래 각 절의 인용 블록은 `vectors/canon/`의
동결 파일에서 **바이트 그대로 옮긴 것**이며, `tools/spec_canon_check.py`가 CI에서
그 인용이 실제로 부분문자열인지 잰다. 문서만 고치는 것은 불가능하다 — 인용이
벡터와 어긋나면 붉어진다.

손으로 쓴 규격이 코드보다 오래 사는 것이 이 문서가 겨냥하는 실패다. 스펙을 읽고
클린룸으로 만든 구현은 우리 코드를 보지 않으므로, 규격이 낡으면 그 구현은 우리가
싣지도 않은 형식을 구현하게 된다.

---

## 1. 적합성 주장의 단위

프로파일 이름 **`PAIL-CORE-2026.1`** 과 세트 해시
`set_sha256  bbddff16fb5997faeff47bf6913e64d9675178d2ddffd5828aa898a235688701`
한 쌍이다. 정본은 [`spec/vectors/canon/MANIFEST.sha256`](vectors/canon/MANIFEST.sha256)에
있고, 그 계산법도 그 파일의 머리말에 적혀 있다.

벡터가 하나라도 바뀌면 세트 해시가 바뀌고, 세트 해시가 바뀌면 **그것은 다른
프로파일이다.** 두 값을 함께 적지 않은 적합성 주장은 무엇에 대한 주장인지 정해지지
않는다 — 규칙은 [`CONFORMANCE.ko.md`](CONFORMANCE.ko.md)에 있다.

---

## 2. 모든 canon에 공통인 조립 규칙

### 2.1 `R-A` — 식별자 필드는 구분자를 담을 수 없다

`:` 로 이어 붙이는 정규문에서 식별자 필드(`tenant`, `robot_id`, `key_id` 등)는
**구분자 `:` 를 포함할 수 없고 비어 있을 수도 없다.** 위반은 **조립 지점에서
거부한다.**

경계(HTTP 핸들러, ingest)에서만 막으면 조립 함수를 직접 부르는 경로가 무방비로
남는다. 벡터의 `expect=reject` 레코드들이 고정하는 것이 바로 이 성질이며, 그
레코드에는 **바이트가 없다** — 거부는 "빈 문자열을 냈다"가 아니라 "아무것도 내지
않았다"이다.

### 2.2 `R-B` — 자유 텍스트는 길이 접두 프레이밍(LP)

사용자·환경에서 오는 자유 텍스트는 `:` 로 잇지 않고 LP로 감싼다.

```
LP(x) = u32BE(len(NFC(x))) ‖ NFC(x)
```

정규화는 NFC다. LP 아래에서는 값에 `:` 가 들어 있어도 안전하며, 그래서 `R-A`가
자유 텍스트 필드에는 적용되지 않는다.

### 2.3 `R-C` — 줄 단위 정규문의 이스케이프

`pail-config-seal:*`만 `:` 이 아니라 줄 단위로 조립한다. 값 안의 문자는
`'\\'→'\\\\'`, LF→`'\\n'`, CR→`'\\r'` 로 이스케이프한다.

### 2.4 hex와 실수

바이너리 값은 **소문자 hex**로 싣는다. 실수는 `x1e6` 정수로 싣는다 — `'%f'`는
로케일을 따라가고, 소수점이 쉼표가 되는 순간 digest가 달라진다.

### 2.5 구판은 폐기가 아니라 동결이다 (`F8`)

`v1` 접두어들은 **생성이 종료됐고 파싱은 영구 유지된다.** 적합한 구현은 `v1`
바이트를 새로 만들어서는 안 되지만, 받은 `v1` 바이트는 계속 검증할 수 있어야
한다. 이미 기록된 저널을 나중에 읽을 수 없게 되는 것은 증빙 계층의 자기 부정이다.

벡터에서 구판은 `expect=parse_only` 레코드로 산다.

---

## 3. 접두어 등록부

**23종이다.** 아래 절의 목록이 곧 등록부이며, `vectors/` 에서 관측되는 접두어
전건에 절이 있어야 한다 — 빠지면 `tools/spec_canon_check.py`가 `B1`으로 붉어진다.
빠뜨림은 언제나 조용하기 때문에 이 방향의 검사가 따로 필요하다.

| 무엇을 서명·해시하는가 | 접두어 |
|---|---|
| 저널 앵커 | `pail-anchor:v1` · `pail-anchor:v2` |
| 투명성 로그 leaf | `pail-saas-anchor:v1` · `pail-saas-anchor:v2` |
| 검증 판정 | `pail-verdict:v1` · `pail-verdict:v2` · `pail-verdict:v3` · `pail-verdict-evidence:v1` |
| 운영 알림 | `pail-alert:v1` · `pail-alert:v2` · `pail-alert-detail:v1` |
| 세그먼트 체크포인트 | `pail-checkpoint:v2` |
| 운영자 명령 | `pail-unlock:v1` · `pail-unlock:v2` · `pail-revoke-issuer:v1` · `pail-revoke-issuer:v2` |
| 단일사용 소비 키 | `pail-tokenkey:v1` |
| 컨텍스트 출처 | `pail-context:v1` · `pail-ctxbody:v1` |
| 배포 설정 봉인 | `pail-config-seal:v1` · `pail-config-seal:v2` · `pail-config-seal:v3` |
| 버스트 체인 상관값 | `pail-burstchain:v1` |
| 재시도 하한 동일성 키 | `pail-planhash:v1` |

**두 종은 동결 벡터가 없다** — `pail-burstchain:v1`과 `pail-planhash:v1`. 그 사실은
숨기지 않고 [`vectors/canon/UNPINNED.tsv`](vectors/canon/UNPINNED.tsv)에 사유·담당·해소
조건과 함께 적혀 있으며, 이 문서에서는 `pin: none`으로 적힌다. 검사기는 그 선언을
등록부와 대조한다(`B5`) — 등록되지 않은 "핀 없음"은 기록이 아니라 면제다.

**동결 벡터가 없다는 것은 적합성 주장의 대상이 아니라는 뜻이다.** §1의 세트 해시는
이 두 종을 덮지 않는다.

---

## 4. 접두어별 정규문

각 절의 인용 블록은 지목된 동결 벡터의 바이트 그대로다. `#` 는 벡터 파일의 주석
표시이며, 인용을 그 형태로 두는 이유는 **부분문자열 대조를 가능하게** 하기
위해서다 — 다듬어 옮기는 순간 그 인용은 반증할 수 없는 문장이 된다.

### `pail-anchor:v2`

로봇이 자기 저널의 머리를 외부 기준점에 고정할 때 서명하는 값. `v1`이 빠뜨린
`tenant`·`robot`이 서명 안으로 들어와 있다 — 그것이 없으면 로봇 A의 앵커 서명이
로봇 B의 앵커로 재사용된다.

<!-- pin: spec/vectors/canon/anchor_v2.vec -->
```
# canon: pail-anchor:v2:<tenant_id>:<robot_id>:<head_hash_hex>:<segment_seq>:<record_count>:<unix_ms>
```

### `pail-anchor:v1`

구판이다. 현재 공개 M9 생산자(`cloud/internal/anchor/anchor.go`)는 여전히 v1을
생성한다. v2 벡터가 있다는 것이 생산자 마이그레이션 완료를 뜻하지 않는다.
기존 기록의 파싱은 유지한다(§2.5). v1 서명에는 배치 범위 식별자가 없다.

<!-- pin: spec/vectors/canon/anchor_v2.vec -->
```
canon	pail-anchor:v1:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:7:42:1700000000000
```

### `pail-saas-anchor:v2`

투명성 로그에 들어가는 leaf 바이트. **서명 대상이 아니라 로그에 실리는 값 자체**라
벡터에 `sig` 칸이 없다.

<!-- pin: spec/vectors/canon/saas_anchor_v2.vec -->
```
# leaf: pail-saas-anchor:v2:<tenant>:<robot>:<key_id>:<server_seq>:<server_recv_ms>
#       :<anchor_sha256>:<segment_seq>:<record_count>:<head_hash_hex>
```

기존 Anchor 서비스 계약에서 `anchor_sha256`은 **수신한 AnchorRecord JSON 원문
바이트**(공백·서명 필드 포함)의 SHA-256 소문자 hex다. 서명 정규문이나 재직렬화한
JSON의 해시가 아니다. proof 검증만으로 원문→leaf 결박까지 검증되지는 않는다.
동결 leaf 벡터는 주어진 해시로 필드 조립을 재는 것이며 완전한 수신 교환 시험이 아니다.
공개 M9 HTTP 클라이언트는 `PUT BaseURL/<name>`를 사용한다. `POST /v1/anchor/{tenant}`만
받는 서버는 별도 어댑터가 필요하며 주소만 바꾸는 업로드 호환을 주장할 수 없다.

### `pail-saas-anchor:v1`

구판. 세그먼트·레코드 수와 head가 leaf 밖에 있었다.

<!-- pin: spec/vectors/canon/saas_anchor_v2.vec -->
```
# v1  : pail-saas-anchor:v1:<tenant>:<robot>:<key_id>:<server_seq>:<server_recv_ms>:<anchor_sha256>
```

### `pail-verdict:v3`

검증 판정의 서명 대상. 두 줄로 이어지며, 둘째 줄의 선두 `:` 는 이어 붙임의
일부이지 새 필드의 시작이 아니다.

<!-- pin: spec/vectors/canon/verdict_v3.vec -->
```
# canon: pail-verdict:v3:<tenant>:<robot>:<generated_ms>:<verdict>:<head_hex>:<segments>:<records>
#        :<anchors_checked>:<anchors_found>:<log_consistency>:<log_root_hex>:<log_size>:<evidence_hash_hex>
```

`log_consistency`는 **문자열 3값**(`ok`·`fail`·`none`)이다. 불리언이 아니다 —
"검사하지 못했다"와 "검사했고 정상이다"가 한 비트에 담기면 미확인이 통과로 읽힌다.

### `pail-verdict:v2`

구판. `log_*` 세 필드와 `evidence_hash_hex`가 서명 밖에 있었다.

<!-- pin: spec/vectors/canon/verdict_v3.vec -->
```
canon	pail-verdict:v2:acme:robot-1:1700000000000:MATCH:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:3:128:5:5:true
```

### `pail-verdict:v1`

구판. `tenant`·`robot`·`generated_ms`가 없어 판정이 언제 누구에 대한 것인지
서명이 말하지 못했다.

<!-- pin: spec/vectors/canon/verdict_v3.vec -->
```
canon	pail-verdict:v1:MATCH:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f:3:128:5:5:true
```

### `pail-verdict-evidence:v1`

`pail-verdict:v3`의 `evidence_hash_hex`를 만드는 **해시 입력** 접두어. 값 문자열에는
나타나지 않는다.

<!-- pin: spec/vectors/canon/verdict_v3.vec -->
```
# evidence_hash = SHA-256("pail-verdict-evidence:v1:" ‖ LP(first_div) ‖ LP(proofs) ‖ LP(errors))
```

목록은 **두 겹으로 감싼다** — `proofs = LP( LP(item₀) ‖ LP(item₁) ‖ … )`, `leaf_index`
오름차순. `errors`도 같은 형태이며 발생 순서다. 목록이 붙는 규칙을 적지 않으면
제3자는 같은 해시를 낼 수 없다.

### `pail-alert:v2`

운영 알림의 서명 대상. 상세 본문이 해시로 서명 안에 들어온다.

<!-- pin: spec/vectors/canon/alert_v2.vec -->
```
# canon: pail-alert:v2:<type>:<tenant>:<robot>:<count>:<ms>:<detail_hash_hex>
```

`type` 값 공간은 `ANCHOR_GAP_ROLLUP` · `FORK` · `REWIND` · `WORM_VIOLATION`.

### `pail-alert:v1`

구판. 상세가 서명 밖이라 본문을 바꿔도 서명이 유지됐다.

<!-- pin: spec/vectors/canon/alert_v2.vec -->
```
# v1   : pail-alert:v1:<type>:<tenant>:<robot>:<count>:<ms>   (상세가 서명 밖)
```

### `pail-alert-detail:v1`

`pail-alert:v2`의 `detail_hash_hex`를 만드는 해시 입력 접두어.

<!-- pin: spec/vectors/canon/alert_v2.vec -->
```
# detail_hash = SHA-256("pail-alert-detail:v1:" ‖ LP(detail))
```

### `pail-checkpoint:v2`

세그먼트 체크포인트의 서명 대상. `:` 로 잇는 문자열이 아니라 **바이너리 연접**이다.

<!-- pin: spec/vectors/canon/checkpoint_v2.vec -->
```
# 서명 대상: "pail-checkpoint:v2:" ‖ head(32B) ‖ record_count(u64BE) ‖ segment_seq(u64BE)
# 레코드 페이로드(112B): head(32) ‖ count(u64BE) ‖ seg_seq(u64BE) ‖ sig(64)  / record_type=31
```

### `pail-unlock:v2`

운영자가 `SAFE_STOP`을 푸는 명령의 서명 대상. **operator 키**로 서명하며 issuer 키가
아니다. `operator_key_id`가 canon 안에 있어야 "누가 눌렀는가"가 서명으로 남는다.

<!-- pin: spec/vectors/canon/unlock_v2.vec -->
```
# canon: pail-unlock:v2:<robot_id>:<unix_ms>:<b64std(nonce)>:<operator_key_id>
```

nonce는 base64 표준 알파벳(패딩 포함)이다.

### `pail-unlock:v1`

구판. `operator_key_id`가 없어 되돌릴 수 있는 명령이나마 책임 주체가 비어 있었다.

<!-- pin: spec/vectors/canon/unlock_v2.vec -->
```
canon	pail-unlock:v1:robot-1:1700000000000:AAECAwQFBgcICQoLDA0ODw==
```

### `pail-revoke-issuer:v2`

발급자 키 폐기 명령의 서명 대상. `unlock`의 형제이며 더 무겁다 — unlock은 되돌릴 수
있지만 폐기는 `LOCKDOWN`으로 가는 영구 명령이다.

<!-- pin: spec/vectors/canon/revoke_issuer_v2.vec -->
```
# canon: pail-revoke-issuer:v2:<issuer_key_id>:<unix_ms>:<b64std(nonce)>:<operator_key_id>
```

**체인 폐기와 다른 사건이다.** 이것은 발급의 신뢰 기점을 내리는 것이고, 특정 체인을
무효화하는 것이 아니다.

### `pail-revoke-issuer:v1`

구판. `operator_key_id` 결손 — `pail-unlock:v1`과 같은 형태의 같은 결손이 두 자리에
따로 있었다.

<!-- pin: spec/vectors/canon/revoke_issuer_v2.vec -->
```
canon	pail-revoke-issuer:v1:dev-key-1:1700000000000:AAECAwQFBgcICQoLDA0ODw==
```

### `pail-tokenkey:v1`

단일사용을 집행하는 소비 키. 입력은 **검증에 사용된 바로 그 원문 바이트**이지
재직렬화한 바이트가 아니다.

<!-- pin: spec/vectors/canon/tokenkey_v1.vec -->
```
# consumption_key = SHA-256("pail-tokenkey:v1:" ‖ action_token_bytes)
```

봉투의 `token_id` 필드를 소비 키로 쓰면 안 된다. 그 필드는 서명 대상 밖이라
공격자가 고칠 수 있고, 그러면 같은 토큰이 두 번 통과한다.

### `pail-context:v1`

컨텍스트 출처 레코드(`record_type=51`)의 페이로드 선두 리터럴.

<!-- pin: spec/vectors/canon/context_v1.vec -->
```
# record_type=51 / payload = "pail-context:v1:" ‖ LP(event_kind) ‖ LP(caller_kind) ‖ LP(caller_id)
#                            ‖ u8(context_verified) ‖ LP(event_body_hash_hex)
```

`context_verified`는 u8 한 바이트다. **이 값이 0이라는 것은 "검증하지 않았다"이지
"검증했고 실패했다"가 아니다** — 둘을 같은 값으로 적으면 미확인이 판정으로 읽힌다.

### `pail-ctxbody:v1`

위 레코드의 `event_body_hash`를 만드는 해시 입력 접두어.

<!-- pin: spec/vectors/canon/context_v1.vec -->
```
# event_body_hash = SHA-256("pail-ctxbody:v1:" ‖ LP(node_id) ‖ LP(kind_name) ‖ LP(arg) ‖ u64BE(claimed_unix_ms))
```

`arg`에 `:` 가 들어 있어도 안전하다 — LP 아래이기 때문이다(§2.2). 벡터의 고정 본문이
일부러 `zone:z7`을 쓰는 것이 그 증거다.

### `pail-config-seal:v3`

배포 설정 봉인의 현행 판(SK-4). **줄 단위**로 조립하며 키 이름과 순서는 동결
— v2 의 31키에 `skills_file_sha256` 이 `policy_file_sha256` 바로 다음에 삽입됐다.
게이트가 읽은 스킬 등재부(`config/skills.<robot_class>.yaml`)의 내용 해시다.
어휘는 정책 해시와 같다: 64 소문자 hex(읽고 해시함) · `unknown`(이름은 됐으나 읽지
못함 — `degraded` 축 S21 을 함께 싣는다) · 빈 값(등재부 미설정). 이슈어는 자기
사본과 대조해 두 해시와 3값 판정(`skills_registry_match`: match / mismatch /
unknown, S38)을 저널에 나란히 남긴다.

<!-- pin: spec/vectors/canon/config_seal_v3.vec -->
```
# canon: "pail-config-seal:v3\n" 다음에 고정 순서 32줄의 `<key>=<escape(value)>\n`.
# 키 순서(동결): component robot_id profile use_sim_time ros_security_enable ros_security_strategy ros_security_keystore enclave_provisioned effective_enclave
#              token_provider_mode use_token_service grpc_built verifies_authorization token_service_addr keyring_mode control_transport control_trust_anchors
#              trusted_key_fingerprints evidence_conf_threshold_x1e6 evidence_window_ms safety_stale_ms clock_skew_ms permit_grace_n permit_recheck_ms
#              permit_rate_hz permit_deadline_ms motion_deadman_ms policy_file policy_file_sha256 skills_file_sha256 human_safety_enabled degraded
```

v2 는 폐기가 아니라 동결이다 — 조립기와 키 표가 그대로 남는다(F8).

### `pail-config-seal:v2`

배포 설정의 봉인. `:` 이 아니라 **줄 단위**로 조립하며, 키의 이름과 순서가 동결돼
있다. digest는 정규문 바이트의 SHA-256이며 서명 대상이 아니라 저널·전송에 실리는
값이다.

<!-- pin: spec/vectors/canon/config_seal_v2.vec -->
```
# canon: "pail-config-seal:v2\n" 다음에 고정 순서 31줄의 `<key>=<escape(value)>\n`.
# 키 순서(동결): component robot_id profile use_sim_time ros_security_enable ros_security_strategy ros_security_keystore enclave_provisioned effective_enclave
#              token_provider_mode use_token_service grpc_built verifies_authorization token_service_addr keyring_mode control_transport control_trust_anchors
#              trusted_key_fingerprints evidence_conf_threshold_x1e6 evidence_window_ms safety_stale_ms clock_skew_ms permit_grace_n permit_recheck_ms
#              permit_rate_hz permit_deadline_ms motion_deadman_ms policy_file policy_file_sha256 human_safety_enabled degraded
```

**v2의 5키는 끝에 붙지 않고 논리 위치에 삽입됐다.** 목록 필드
(`control_trust_anchors`, `trusted_key_fingerprints`, `degraded`)는 정렬·중복 제거 후
`,` 로 잇는다.

### `pail-config-seal:v1`

구판 26키. 폐기가 아니라 동결이며 파서는 영구 유지된다(§2.5).

<!-- pin: spec/vectors/canon/config_seal_v1.vec -->
```
# canon: "pail-config-seal:v1\n" 다음에 고정 순서 26줄의 `<key>=<escape(value)>\n`.
```

### `pail-burstchain:v1`

버스트 패킷의 체인 상관값 유도에 쓰는 해시 입력 접두어. 같은 16바이트 자리가 토큰
해시와 체인 해시를 함께 나르므로 **두 유도식이 서로 달라야** 도메인 분리가 성립한다.

<!-- pin: none -->

**동결 벡터가 없다.** 버스트 v2는 무동결로 판정되어 고정 벡터 자체가 없고, 따라서
§1의 적합성 주장에 실리지 않는다. 사유·해소 조건은
[`vectors/canon/UNPINNED.tsv`](vectors/canon/UNPINNED.tsv)에 있다.

### `pail-planhash:v1`

재시도 하한을 판정할 때 쓰는 동일성 키의 해시 입력 접두어.

<!-- pin: none -->

**동결 벡터가 없다.** 이 값은 서명되지도 유통되지도 않는 내부 값이라 드리프트의 외부
관측자가 없다 — 상호운용 프로파일의 일부가 아니다. 유통되기 시작하면 그때 동결
대상이 된다.

---

### `pail-ctx:v1`

SHA-256 input domain for the original context payload bytes. Embedded requester claims do not replace transport identity.

The existing contract vector is pinned by its own `spec/vectors/contract/MANIFEST.sha256`; it is not an addition to the canon profile set.

<!-- pin: spec/vectors/contract/ledger_v2.vec -->
```
hash	CX2-02	pail-ctx:v1:	{"job":"j1"}	c5b0c87c78e38182140541a19b2ca309088c2c46cf536e5332625fe768648fb6
```

### `pail-constraints:v1`

SHA-256 input domain for the constraints payload bytes. The trailing colon belongs to the hash prefix.

The existing contract vector is pinned by its own `spec/vectors/contract/MANIFEST.sha256`; it is not an addition to the canon profile set.

<!-- pin: spec/vectors/contract/ledger_v2.vec -->
```
hash	CN2-02	pail-constraints:v1:	{"job":"j1"}	a8409ccc71d0cfcfc0d5c7ac7b6f49602f8f15d0c4f62f4687781a7e6be0fa92
```

### `pail-params:v1`

SHA-256 input domain for the original action-parameter bytes; this hash does not itself authorize an action.

The existing contract vector is pinned by its own `spec/vectors/contract/MANIFEST.sha256`; it is not an addition to the canon profile set.

<!-- pin: spec/vectors/contract/ledger_v2.vec -->
```
hash	PM2-02	pail-params:v1:	{"l":2}	e40c68aeb1df6deb1b5344e9762d3d62a31ed7b769a57d411aaedfbca7a2538c
```

## 5. 이 문서가 어떻게 유지되는가

| 무엇 | 검사 |
|---|---|
| 실린 벡터의 접두어 전건에 절이 있는가 | `tools/spec_canon_check.py` `B1` |
| 절이 지어낸 접두어를 담고 있지 않은가 | 동 `B2` |
| 인용이 동결 벡터의 바이트 부분문자열인가 | 동 `B3` |
| 인용 대상이 매니페스트에 등재(동결)돼 있는가 | 동 `B4` |
| `pin: none`이 미고정 등록부에 뒷받침돼 있는가 | 동 `B5` |
| §1의 프로파일·세트 해시가 실린 매니페스트와 같은가 | `tools/spec_conformance_check.py` |

검사기가 자기 전제를 세우지 못하면(벡터 0편, 절 0개, 매니페스트 부재) `FAIL 0`이
아니라 **rc=2**로 죽는다. 아무것도 읽지 못한 실행과 위반이 없는 실행은 같은 바이트를
내기 때문이다.
