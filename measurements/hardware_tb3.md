# Raised-wheel TurtleBot3 measurements (generator input)

This file is the only input of `scripts/gen_hardware_measurements.py`; the hardware rows of
`examples/tb3/HARDWARE.md`, `HARDWARE.ko.md`, both READMEs and the VALIDATION `Real TurtleBot3` row are
generated from the JSON block below. Edit the block, run the generator, never the generated regions.
Every cell names the build it was measured on through its `source`; the English prose of the generated
regions says "this candidate" only when a source build equals the tree's VERSION.

```json
{
  "schema_version": 1,
  "about": "Raised-wheel TurtleBot3 measurements that HARDWARE.md section 8, the README hardware rows and the VALIDATION 'Real TurtleBot3' row are generated from (scripts/gen_hardware_measurements.py). Every number names the build it was measured on through its source; prose never says 'this candidate' unless the source build equals VERSION.",
  "robot": "TurtleBot3 waffle_pi, Raspberry Pi 3 (arm64, Ubuntu 22.04, Docker 29), official ROS 2 Humble driver on the OpenCR, both encoders live, wheels raised",
  "sources": {
    "publisher": {
      "build": "0.2.0-preview.19",
      "date": "2026-10-18",
      "who": "publisher",
      "note_en": "the publisher's own run with the console, judge and hardware/fault_inject.py of that bundle, before the agent's reason registry and the images were rebuilt",
      "note_ko": "그 꾸러미의 콘솔·판정기·hardware/fault_inject.py 로 발행자가 직접 실행한 것; 에이전트 사유 레지스트리와 이미지가 다시 빌드되기 전"
    },
    "independent": {
      "build": "0.2.0-preview.22",
      "date": "2026-10-20",
      "who": "independent recipient (evaluator)",
      "note_en": "a recipient who did not share the publisher's tree, on that bundle's images",
      "note_ko": "발행자의 트리를 공유하지 않는 수령자가 그 꾸러미의 이미지로 실행한 것"
    },
    "software_demo": {
      "build": "0.2.0-preview.23",
      "date": "2026-10-20",
      "who": "publisher, software TurtleBot3 demo (no robot)",
      "note_en": "the software TurtleBot3 demo of that build; not the real base",
      "note_ko": "그 빌드의 소프트웨어 TurtleBot3 데모; 실물 아님"
    },
    "independent_p40": {
      "build": "0.2.0-preview.40",
      "date": "2026-10-29",
      "who": "independent recipient (evaluator)",
      "note_en": "the evaluator's run of the preview.40 ARM64 bundle on the same raised-wheel TurtleBot3 (PAIL-EVALUATION-0.2.0-preview.40-single-contract-20261029); durations were not recorded, so only counts and the fault-injection pauses are carried",
      "note_ko": "같은 바퀴 들림 TurtleBot3 에서 평가자가 preview.40 ARM64 꾸러미로 실행한 것(PAIL-EVALUATION-0.2.0-preview.40-single-contract-20261029); 소요 시간은 기록되지 않아 횟수와 결함 주입의 일시정지 값만 싣는다",
      "validation_summary_en": "judge 13/13 ×3, Issuer paused 12 s / 30 s with 0 drive commands after `OK`, 12/12 console restarts (durations not recorded)"
    },
    "independent_p44": {
      "build": "0.2.0-preview.44",
      "date": "2026-10-31",
      "who": "independent recipient (evaluator)",
      "note_en": "final ARM64 bundle on raised-wheel TB3; full judge three times, ten restart attempts, permit outage and clock-step checks; one restart timed out",
      "note_ko": "최종 ARM64 꾸러미의 바퀴 공중 TB3: 전체 판정 3회, 재시작 10회, permit 단절·시계 스텝 검사; 재시작 1회 시간 초과",
      "validation_summary_en": "final ARM64 bundle: judge 13/13 x3, restart 9/10 with one explicit gate-to-bridge IO matching timeout and successful next retry, permit pause 12 s PASS, remote agent-crash 2/2, clock steps +/-0.6 s 4/4, encoder 0.998–1.005 m over three runs; root cause of the intermittent restart failure remains open"
    },
    "independent_p45": {
      "build": "0.2.0-preview.45",
      "date": "2026-10-31",
      "who": "independent recipient (evaluator)",
      "note_en": "final ARM64 bundle on raised-wheel TB3; full judge three times, ten restarts, 12 s permit pause and remote agent-crash. Clock steps excluded in this evaluation.",
      "note_ko": "최종 preview.45 ARM64 꾸러미의 바퀴 들림 실물: 전체 판정 3회, 재시작 10회, permit 12초와 원격 에이전트 종료. 시계 스텝은 이번 범위 제외.",
      "validation_summary_en": "final ARM64 images: judge 13/13 x3, restart 10/10, permit pause 12 s PASS, remote agent-crash 2/2 with no drive after OK and ESTOP recorded. Evaluator reports one failure in 120 cumulative restarts; root cause remains open, not a guaranteed rate. Clock steps were not repeated."
    },
    "independent_p46_dds": {
      "build": "0.2.0-preview.45",
      "date": "2026-11-01",
      "who": "independent recipient (evaluator)",
      "note_en": "preview.46 evaluation on source-equivalent preview.45 ARM64 hardware runtime: 29 valid restarts, then separate 117-restart investigation; not preview.47 hardware acceptance",
      "note_ko": "preview.46 평가: 소스 동일 preview.45 ARM64 실물 런타임의 유효 재시작 29회 및 별도 117회 조사. preview.47 실물 수락 아님."
    }
  },
  "rows": [
    {
      "id": "full_judge",
      "check_en": "Full judge (13 scenes, §6)",
      "check_ko": "전체 판정기(13 장면, 6절)",
      "established_en": "13/13 in three independent runs; durations not reported",
      "established_ko": "독립 실행 3회 모두13/13; 소요 시간 미기록",
      "cells": [
        {
          "source": "independent_p45",
          "en": "13/13 x3",
          "ko": "13/13 x3"
        }
      ]
    },
    {
      "id": "scene8",
      "check_en": "Scene 8 alone (safety `UNSAFE` → `ESTOP` → `OK`; the interrupted plan never resumes)",
      "check_ko": "장면 8 단독(안전 `UNSAFE` → `ESTOP` → `OK`; 중단된 계획은 재개되지 않음)",
      "established_en": "5/5",
      "established_ko": "5/5",
      "cells": [
        {
          "source": "independent",
          "en": "5/5",
          "ko": "5/5"
        },
        {
          "source": "publisher",
          "en": "5/5",
          "ko": "5/5"
        }
      ]
    },
    {
      "id": "permit_outage",
      "check_en": "Issuer outage across an E-STOP while moving under a live permit — `fault_inject.py --mode permit`, Issuer paused 12 s and 30 s, `UNSAFE` → `OK` during the pause",
      "check_ko": "살아 있는 허가로 이동 중 E-STOP 을 가로지르는 Issuer 단절 — `fault_inject.py --mode permit`, Issuer 를 12 s·30 s 일시정지, 그 사이 `UNSAFE` → `OK`",
      "established_en": "12 s Issuer pause across E-STOP: PASS, no drive after OK. The 30 s case was not rerun in this evaluation.",
      "established_ko": "E-STOP 중 Issuer12 s 정지: PASS, OK 뒤 구동0. 이번 평가에서30 s 경우는 재실행하지 않음.",
      "cells": [
        {
          "source": "independent_p45",
          "en": "12 s PASS; no drive after OK",
          "ko": "12 s PASS; OK 뒤 구동0"
        }
      ]
    },
    {
      "id": "outage_no_permit",
      "check_en": "E-STOP with no live permit — `fault_inject.py --mode outage`: the Issuer is paused until the gate is already `BLOCK ERR_ISSUER_UNREACHABLE`, then `UNSAFE`, Issuer resumed 0.5 s after `OK`",
      "check_ko": "허가가 없는 상태의 E-STOP — `fault_inject.py --mode outage`: 게이트가 이미 `BLOCK ERR_ISSUER_UNREACHABLE` 이 될 때까지 Issuer 를 일시정지한 뒤 `UNSAFE`, `OK` 0.5 s 뒤 Issuer 재개",
      "established_en": "0 drive commands after `OK` in 2 runs; the chain whose step was interrupted is refused and the next plan runs on its own token",
      "established_ko": "2회 모두 `OK` 뒤 구동 명령 0; 스텝이 끊긴 체인은 거부되고 다음 계획은 자기 토큰으로 실행",
      "cells": [
        {
          "source": "software_demo",
          "en": "2/2 with `--wait-block 4`",
          "ko": "`--wait-block 4` 로 2/2"
        },
        {
          "source": "independent",
          "en": "Hardware no-permit outage precondition has not been established. A multi-step instruction and a longer wait do not guarantee it: an already delegated window can authorize the next step while the Issuer is paused. PRECONDITION_NOT_MET is not a safety PASS.",
          "ko": "실물의 무허가 outage 전제는 아직 달성하지 못했다. 다중 스텝·긴 대기만으로 보장되지 않는다. 이미 위임된 창은 Issuer 정지 중에도 다음 스텝을 허가할 수 있다. PRECONDITION_NOT_MET는 안전 PASS가 아니다."
        }
      ]
    },
    {
      "id": "clock_step",
      "check_en": "System-clock steps of ±0.6 s on the robot during a step (`date -s`), stepped back 4 s later",
      "check_ko": "스텝 중 로봇 시스템 시계 ±0.6 s 스텝(`date -s`), 4 s 뒤 되돌림",
      "established_en": "Clock abort in all four +/-0.6 s steps; no forwarding after the clock returned, and a new plan ran",
      "established_ko": "±0.6 s 4회 모두clock abort; 시계 복귀 뒤 전달0, 새 계획 정상",
      "cells": [
        {
          "source": "independent_p44",
          "en": "4/4; both directions",
          "ko": "4/4; 양방향"
        }
      ]
    },
    {
      "id": "step_deadline",
      "check_en": "Step-deadline refusals during normal motion",
      "check_ko": "정상 이동 중 스텝 기한 초과 거부",
      "established_en": "0 in every judge and fault run above",
      "established_ko": "위 모든 판정기·결함 주입에서 0건",
      "cells": [
        {
          "source": "independent",
          "en": "0",
          "ko": "0건"
        },
        {
          "source": "publisher",
          "en": "0",
          "ko": "0건"
        }
      ]
    },
    {
      "id": "one_metre",
      "check_en": "1 m instruction, encoder distance",
      "check_ko": "1 m 지시, 엔코더 거리",
      "established_en": "0.998–1.005 m over three runs (encoders, wheels raised)",
      "established_ko": "3회0.998~1.005 m(바퀴 공중 엔코더)",
      "cells": [
        {
          "source": "independent_p44",
          "en": "0.998–1.005 m x3",
          "ko": "0.998~1.005 m x3"
        }
      ]
    },
    {
      "id": "gate_restart",
      "check_en": "Gate restart to ready (scene R, SROS2 discovery)",
      "check_ko": "게이트 재시작부터 준비까지(장면 R, SROS2 디스커버리)",
      "established_en": "Unresolved DDS authentication stall: 1/29; separately 1/117 plus one unrelated movement shortfall. No guaranteed rate or repaired-library claim.",
      "established_ko": "DDS 인증 정체 미해결: 29회 중 1회; 별도 117회 중 1회 및 별개 이동 미달 1회. 고정 실패율·라이브러리 수정 완료 주장 없음.",
      "cells": [
        {
          "source": "independent_p46_dds",
          "en": "Late Final / asymmetric authentication observed; manual recovery 5/5 in the reported attempts, not automatic recovery",
          "ko": "늦은 Final/인증 비대칭 관측; 보고된 수동 복구 5/5, 자동 복구 아님"
        }
      ]
    },
    {
      "id": "floor",
      "check_en": "Floor, 1.5 m (§7 scenes F0–F9)",
      "check_ko": "바닥 1.5 m(7절 장면 F0–F9)",
      "established_en": "F2 0.952 m / −0.996 m; F6 +88.4° / −89.2°; F5 the gate held the driver at ≤ 0.1 m/s while the planner asked 0.3 m/s; F8 `UNSAFE` → gate `ESTOP` in 0.164 s, 0.045 m travelled after the input, no driver command after it, no motion after `OK` until the operator acted",
      "established_ko": "F2 0.952 m / −0.996 m; F6 +88.4° / −89.2°; F5 플래너가 0.3 m/s 를 요구하는 동안 게이트가 드라이버를 ≤ 0.1 m/s 로 유지; F8 `UNSAFE` → 게이트 `ESTOP` 0.164 s, 입력 뒤 이동 0.045 m, 그 뒤 드라이버 명령 없음, `OK` 뒤에도 운영자가 행동할 때까지 이동 없음",
      "cells": [
        {
          "source": "publisher",
          "en": "an earlier build of the same gate line; the floor scenes were not re-run since",
          "ko": "같은 게이트 계열의 이전 빌드; 바닥 장면은 그 뒤 다시 돌리지 않았다"
        }
      ]
    }
  ],
  "readme": {
    "hardware_row_en": "| TurtleBot3 hardware (wheels raised) | Encoder-based observation and acceptance judge | Latest independent hardware evidence: 13/13 scenes x3 on the final 0.2.0-preview.45 bundle; evidence is scoped to that build and is not a hardware acceptance claim for this release | [examples/tb3/HARDWARE.md](examples/tb3/HARDWARE.md) §8 |",
    "hardware_row_ko": "| TurtleBot3 실물(바퀴 띄움) | 엔코더 관측·수락 판정기 | 최신 독립 실물 근거: 최종 0.2.0-preview.45 꾸러미에서13/13 장면 x3. 해당 빌드의 근거이며 이 릴리스의 실물 수락 주장이 아님 | [examples/tb3/HARDWARE.ko.md](examples/tb3/HARDWARE.ko.md) §8 |",
    "deadline_row_en": "| Step-deadline refusals at the gate during normal motion | TurtleBot3 on a Raspberry Pi 3, wheels raised | 0 in every judge: 3 independent runs {independent_of} and 3 publisher runs {publisher_of} | [HARDWARE.md](examples/tb3/HARDWARE.md) §8 |",
    "deadline_row_ko": "| 정상 이동 중 게이트의 스텝 기한 초과 거부 | Raspberry Pi 3 위 TurtleBot3, 바퀴 띄움 | 모든 판정기에서 0건: {independent_of_ko} 독립 3회와 {publisher_of_ko} 발행자 3회 | [HARDWARE.ko.md](examples/tb3/HARDWARE.ko.md) §8 |",
    "restart_row_en": "| Gate restart IO readiness | TurtleBot3 hardware | Unresolved DDS authentication stall; independent cohorts: 1/29 and separately 1/117, not a guaranteed rate. Manual recovery only | [KNOWN_ISSUES.md](KNOWN_ISSUES.md) |",
    "restart_row_ko": "| 게이트 재시작 입출력 준비 | TurtleBot3 실물 | DDS 인증 정체 미해결; 독립 집단 29회 중 1회 및 별도 117회 중 1회. 고정 실패율 아님, 수동 복구만 지원 | [KNOWN_ISSUES.ko.md](KNOWN_ISSUES.ko.md) |"
  },
  "vocabulary_ko": {
    "this_candidate": "이 후보",
    "this_candidate_of": "이 후보의",
    "publisher": "발행자",
    "independent": "독립",
    "software_demo": "소프트웨어 데모",
    "build": "빌드",
    "bundle": "꾸러미",
    "later_build_current": "둘이 다른 곳에서는 더 나중 빌드의 값이 현재 값이다.",
    "of_suffix": "의",
    "hardware_words": [
      "TurtleBot3",
      "TB3",
      "실물",
      "실제 베이스",
      "실제 로봇",
      "바퀴 띄움"
    ],
    "this_candidate_aliases": [
      "현재 판",
      "이 판",
      "이번 판",
      "현재 후보",
      "이번 후보",
      "현재 빌드",
      "이 빌드"
    ],
    "run_words": [
      "실행",
      "측정",
      "통과",
      "판정",
      "돌렸",
      "돌린",
      "돌려",
      "결과",
      "회"
    ],
    "negations": [
      "않",
      "못 ",
      "미실행",
      "없",
      "안 "
    ]
  }
}
```
