# 스킬 등재부 — `config/skills.<robot_class>.yaml`

상태: 집행됨. 행은 선언이 아니라 **이슈어가 인가하는 근거이자 게이트가 판정하는 근거**다.
이슈어가 행을 대조해 봉투를 토큰에 굽고(SK-1), 게이트가 명령을 그 봉투와 **이름으로**
비교하며(SK-2), 행의 `complete.signal` 이 스텝을 무엇이 소비하는지 정한다(SK-3). 정책
`token_schema: 5` 아래에서는 봉투가 스킬 이름과 함께 이름 목록으로 토큰에 실리고(SK-4),
행의 `feeds`·`safe_state` 는 기동에서 검사되며 허가를 결박한다(SK-5).
구조: [ARCHITECTURE.md](ARCHITECTURE.md). 정본은 영문 `SKILLS.md`.

스킬 등재부는 로봇 종류마다 계획이 부를 수 있는 모든 스킬의 이름을 적는다. **등재부에 없는
이름은 인가되지 않는다** — 등재부는 허용 목록이고 `"*"` 행은 없다. 등재는 배치 행위다:
로봇 제조사(또는 PAIL 을 포팅하는 운영자)가 파일을 쓰고, 나머지 로봇 설정과 함께 봉인되며,
이슈어와 게이트가 같은 바이트를 읽는다.

등재부는 행동을 열거하지 않는다. 스킬 API 가 없는 로봇(정책 스트리밍)에서는 행이 *에피소드
종류*(`tidy_episode`)를 이름 붙인다 — 봉투·피드·안전 상태·요청자 허용을 한 이름 아래 묶은
것 — 그리고 물리 한도가 무게를 진다. LLD §14.4.

## 필드

로봇 종류마다 파일 하나: `version: 1`, `robot_class: <SKILL_VOCAB.tsv 의 robot_class>`,
`skills: [...]`. 모르는 키는 거부된다. 스킬 행:

<!-- source: cloud/internal/skills/skills.go -->
<!-- source: libpail_gate/src/skills_load.cpp -->
<!-- example: config/skills.diff_drive_amr.yaml -->
| 필드 | 필수 | 어휘 · 형식 | 뜻 |
|---|---|---|---|
| `name` | 예 | `[a-z][a-z0-9_]{0,63}` | namespace 없는 `ActionSpec.name`, 또는 원시 스킬(`twist`·`pick`·`place`) |
| `classes` | 예 | `SKILL_VOCAB.tsv` 의 `action_class`, 1개 이상 | v4 토큰 마스크로 굽는다; v5 는 이름을 대조(LLD L15) |
| `evidence.when` | 예 | `none` / `before` / `at_complete` | 대상 증거를 언제 요구하나. `none` 은 스텝에 `target_object_id` 가 없다 |
| `evidence.trust` | `when ≠ none` 이면 예 | `policy.yaml` `trust_classes` 의 id | 최저 허용 등급; `evidence.min_trust_class` 보다 낮을 수 없다 |
| `envelope` | 예(빈 배열 허용) | `GUARDRAILS.tsv` 의 이름 | 이 스킬 호출마다 실리는 한도; 각각 서빙 어댑터의 `measures` 안이어야 한다 |
| `feeds` | 예(빈 배열 허용) | `policy.yaml` `preconditions[].id` | 허가를 쥐는 동안 신선해야 하는 상태 피드. SK-5: 게이트가 관측하지 않는 피드(`safety_feed`·`evidence_claim` 밖)는 기동에서 거부; 행에 `evidence_claim` 이 있으면 표적 유무와 무관하게 그 스킬의 모든 v5 허가에 신선한 증거가 조건이 된다; `safety_feed` 는 모든 허가가 이미 가진 바닥이다 |
| `complete.signal` | 예 | `duration` / `robot_report` / `robot_report+evidence` | 무엇이 스텝을 소비하는가(SK-3) |
| `safe_state` | 예 | 서빙 어댑터가 `ADAPTERS.tsv` 에 선언한 상태 | 허가가 철회되면 어댑터가 실행하는 것. SK-5: 어댑터는 기동 시 선언을 자기가 실행할 수 있는 집합과 대조한다(Microduck `--safe-state`, 밖이면 거부); ROS 게이트는 `adapter_safe_state` 밖의 상태를 적은 행을 기동에서 거부한다 |
| `slot` | 아니오 | `[a-z][a-z0-9_]{0,63}`, 기본 `main` | 이 스킬이 차지하는 허가 슬롯(동시 스킬, LLD L16) |
| `params_schema` | 미지원 | 예약된 JSON Schema 필드 | 이 배포판은 이 필드를 선언한 행을 거부한다. JSON Schema 검증을 제공하지 않는다. 일반 `params_json` 형식·크기 검사와 등록된 수치 한도 검사는 별개다. |

## 어휘

- `spec/GUARDRAILS.tsv` — 가드레일 이름표(`name kind unit compare classes standard desc since`).
  `kind` A = 명령 한도, B = 상태 한도(피드); `compare` `le` / `ge` / `range` / `feed`. 이름은
  IEC 61800-5-2 와 ISO 10218/3691-4/13482 에서 빌린 것이지 발명한 것이 아니다 — 뜻을 빌린
  것이지 지위를 빌린 것이 아니다. PAIL 이 토큰에 싣는 한도는 **무엇이 인가됐는가**의 한계이고,
  같은 이름의 인증된 기능과 그 적합성은 기계 쪽에 남는다.
- `spec/SKILL_VOCAB.tsv` — `robot_class` 와 `action_class` 낱말.
- `spec/ADAPTERS.tsv` — 어댑터마다 `robot_class`·`measures`·`safe_state`.

## 검사기

공개 루트에서 `python3 spec/tools/spec_skills_check.py`를 실행한다.
이 문서의 필드, Go/C++ 파서, 동봉 예제를 대조한다. 종료코드는 통과 0, 불일치 1,
전제조건을 확인하지 못함 2다. 다른 검사기나 문서는 필요 없다.

동봉 예제는 `config/skills.diff_drive_amr.yaml`이다. Microduck/Viam 예제는 별도
어댑터 배포 대상이며 TB3 참조의 필수 입력이 아니다.
