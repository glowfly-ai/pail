// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd

// TB-7 배선 배터리가 공유하는 최소 정책 픽스처 (implementation contract, D-L2).
//
// D-L2 이전에는 이 배터리들이 존재하지 않는 경로를 줘서 "부재 = 결측 = enforce"
// 경로로 기동했다. 이제 부재는 preflight 거부이므로 실재하는 파일이 필요하다.
// 경로는 CMake 가 소스 트리 기준 절대경로로 굳혀 준다 — 상대 경로의 "없다"는
// "확인했고 정상"과 바이트가 같다 (H-B2).
#ifndef PAIL_TB7_POLICY_FIXTURE_HPP
#define PAIL_TB7_POLICY_FIXTURE_HPP

#ifndef PAIL_TB7_POLICY_FIXTURE
#error "PAIL_TB7_POLICY_FIXTURE not defined — CMake must pin the fixture path"
#endif
#ifndef PAIL_TB7_POLICY_OBSERVE_FIXTURE
#error "PAIL_TB7_POLICY_OBSERVE_FIXTURE not defined — CMake must pin the fixture path"
#endif

namespace {

constexpr const char kTb7PolicyFixture[] = PAIL_TB7_POLICY_FIXTURE;
constexpr const char kTb7PolicyFileArg[] = "policy_file:=" PAIL_TB7_POLICY_FIXTURE;

// L-9 S7: gate_mode 한 줄만 다른 사본. 여기에는 sha256 거울을 두지 않는다 —
// 이 파일은 봉인을 재는 배터리(test_gate_profile / test_gate_deadman_seal)의
// 입력이 아니고, 아무도 재지 않는 값을 거울로 두면 다음 사람이 그것을 보증으로
// 읽는다(등재되지 않은 보증은 위반이 아니라 무색이다).
constexpr const char kTb7PolicyObserveFileArg[] =
    "policy_file:=" PAIL_TB7_POLICY_OBSERVE_FIXTURE;

// RQ-7 (DD-4): 봉인은 정책의 *내용*을 안다 — 같은 경로 다른 바이트가 같은
// 봉인을 내면 안 된다. 그래서 거울은 이 값을 리터럴로 박는다. 생산 코드의
// 해시 함수를 불러 계산하면 둘 다 틀려도 초록이 된다(생산기와 검증기를 일부러
// 공유하지 않는다, `E-C3`).
//
// 픽스처 바이트를 고치면 이 상수도 함께 고쳐야 한다:
//   shasum -a 256 pail_ws/src/pail_pep_gate/test/fixtures/policy_min.yaml
// 2026-08-23 (D-L8): 픽스처의 주석이 "게이트는 revocation_classes 를 읽지
// 않는다"고 적고 있었는데 그 문장이 이 단계에서 거짓이 됐다. 주석만 고쳤고 —
// 그것으로 바이트가 바뀌었으므로 이 상수도 함께 움직인다. 이 동반 편집이
// 귀찮은 것이 아니라 **의도된 것**이다: 봉인은 내용을 알고, 픽스처의 주석도
// 내용이다.
constexpr const char kTb7PolicyFixtureSha256[] =
    "d8e8c120a7b546b460e11d5a5eb88c93f80e8e8a3b04c651e1a9522e015fcf9f";

}  // namespace

#endif  // PAIL_TB7_POLICY_FIXTURE_HPP
