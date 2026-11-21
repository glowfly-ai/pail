# 평가 묶음과 공개 Core의 설정
<!-- ko-structure: abridged -->

> 이 한국어판은 영문판보다 절·표·코드 블록이 적은 요약본이다. 영문판이 정본이며, 두 판이 다르면 영문판이 우선한다.

내부 관리 설정 전체가 아니라 사용자가 실제로 받는 경로의 안내입니다. 각 실행의
`compose.json`·`fleet.compose.json`·`run.json`에서 이미지·마운트·식별자·값을 확인합니다.
기존 설치의 설정을 덮어쓰지 않습니다.

`evaluation.py issuer`는 배포물 밖의 새 상태 폴더에 정책·사이트·로봇 등록부·스킬·새 키를
만듭니다. `journal/`은 원장, `agent-state/`는 게이트웨이 보고 대기열입니다. 개인키는 공유하지 않습니다.
로봇 등록부(`config/robot_registry.yaml`)를 비롯한 이 파일들의 경로는 `--state`로 준 상태 폴더
기준입니다. Core 소스 트리의 `config/` 폴더에는 참조용 입력(`policy.yaml`,
`site_model.example.yaml`, `skills.diff_drive_amr.yaml`, `sros2_policy.xml`)만 있고
`robot_registry.yaml`은 없습니다.

이 개발 리그는 `PAIL_PROFILE=dev`, `PAIL_GRPC_TLS=off`, `PAIL_KEYRING_MODE=unsigned-dev`를
명시하고 루프백 포트만 공개합니다. **실제 등록·인증을 마친 생산 보안 프로파일이 아닙니다.**
발급자는 내부 50061, 게이트웨이는 내부 50051이며 호스트 포트는 실행 인자로 바꿉니다.

[영문 설정 표](CONFIG.md), [스킬](spec/SKILLS.ko.md), [사이트 모델](spec/SITE_MODEL.md),
[어댑터 계약](spec/ADAPTER_CONTRACT.md), [통합 안내](examples/adapter/README.ko.md)를 확인합니다.
스킬 종류가 추가된다고 새로운 모션 제어 기능이 생기지 않습니다. `horizon.max_steps`는
위임 단계 수이고 미러 시간의 배수가 아닙니다. 미지원 `params_schema`는 거부합니다.
