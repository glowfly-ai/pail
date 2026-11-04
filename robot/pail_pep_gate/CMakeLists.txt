cmake_minimum_required(VERSION 3.8)
project(pail_pep_gate)

add_compile_options(-Wall -Wextra -Wpedantic)

# Read-only local status uses libsodium SHA-256/randomness, never signing keys.
find_package(PkgConfig REQUIRED)
pkg_check_modules(ROBOTOPS_SODIUM REQUIRED libsodium)
include_directories(${ROBOTOPS_SODIUM_INCLUDE_DIRS})
link_libraries(${ROBOTOPS_SODIUM_LIBRARIES})


find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(geometry_msgs REQUIRED)
find_package(pail_msgs REQUIRED)
find_package(pail_deploy_guard REQUIRED)
find_package(yaml-cpp REQUIRED)  # M8: policy.yaml human_safety wiring

option(PAIL_ENABLE_GRPC "Enable grpc++ TokenService client" OFF)

# The decision library lives outside the ROS workspace (../../../libpail_gate — transport-
# neutral, no ROS; the Microduck adapter links the same library without ROS). The node
# compiles its sources in directly, exactly as before the split (AD-5, 2026-09-06): no
# behaviour change, only the source location. The shared library and its batteries are
# built through add_subdirectory below so `colcon test` still runs them here.
set(PAIL_GATE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../libpail_gate)
if(NOT EXISTS ${PAIL_GATE_DIR}/CMakeLists.txt)
  message(FATAL_ERROR "libpail_gate not found at ${PAIL_GATE_DIR} — the gate node is an adapter of that library")
endif()
set(PEP_SOURCES
  src/pep_gate_node.cpp
  ${PAIL_GATE_DIR}/src/gate_core.cpp
  ${PAIL_GATE_DIR}/src/gate_session.cpp
  src/token_provider_notoken.cpp
  src/token_provider_static.cpp
  ${PAIL_GATE_DIR}/src/strict_verify.cpp
  ${PAIL_GATE_DIR}/src/keyring_bundle.cpp
  ${PAIL_GATE_DIR}/src/skills_load.cpp
)

if(PAIL_ENABLE_GRPC)
  message(STATUS "PAIL_ENABLE_GRPC=ON: building grpc++ TokenService client")
  # SD4: the seal client is listed here, not under the provider, because it is
  # sent in every provider mode — including the ones whose provider never dials.
  list(APPEND PEP_SOURCES
    src/grpc/grpc_channel.cpp
    src/grpc/token_provider_grpc.cpp
    src/grpc/config_seal_client.cpp)
  add_compile_definitions(PAIL_ENABLE_GRPC=1)
else()
  list(APPEND PEP_SOURCES
    src/token_provider_grpc_stub.cpp
    src/config_seal_client_stub.cpp)
  add_compile_definitions(PAIL_ENABLE_GRPC=0)
endif()

add_executable(pep_gate_node ${PEP_SOURCES})

# BEFORE: the library headers are compiled from the source tree (PAIL_GATE_DIR), but
# --merge-install also installs a copy of them into install/include, and the ament
# dependencies put that directory ahead of ours. A stale installed header then shadows the
# source header the build is actually compiling against (AD-4 first build, 2026-09-08:
# "GateSession has no member WantsTokenFetch" while the source header had it).
target_include_directories(pep_gate_node BEFORE PRIVATE include ${PAIL_GATE_DIR}/include)

ament_target_dependencies(pep_gate_node rclcpp geometry_msgs pail_msgs pail_deploy_guard)
target_link_libraries(pep_gate_node yaml-cpp)

# Optional grpc++ client + stub generation (only when enabled)
if(PAIL_ENABLE_GRPC)
  find_package(Protobuf REQUIRED)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(GRPCPP REQUIRED grpc++)
  pkg_check_modules(GRPC REQUIRED grpc)
  pkg_check_modules(SODIUM REQUIRED libsodium)
  find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)

  set(GEN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/grpc/gen)
  file(MAKE_DIRECTORY ${GEN_DIR})

  # Repo layout (dev): PAIL/proto
  # Container layout (Dockerfile.pail_pep_gate): /opt/pail_ws/proto
  set(PROTO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto)
  if(NOT EXISTS ${PROTO_ROOT}/token_service.proto)
    set(PROTO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../proto)
  endif()

  set(PAIL_PROTO_FILE ${PROTO_ROOT}/pail.proto)
  set(TOKEN_PROTO_FILE ${PROTO_ROOT}/token_service.proto)

  # token_service.proto imports pail.proto → both must be generated into the same GEN_DIR.
  add_custom_command(
    OUTPUT ${GEN_DIR}/pail.pb.cc ${GEN_DIR}/pail.pb.h
           ${GEN_DIR}/token_service.pb.cc ${GEN_DIR}/token_service.grpc.pb.cc
           ${GEN_DIR}/token_service.pb.h  ${GEN_DIR}/token_service.grpc.pb.h
    COMMAND protobuf::protoc
    ARGS -I ${PROTO_ROOT}
         --cpp_out=${GEN_DIR}
         --grpc_out=${GEN_DIR}
         --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
         ${PAIL_PROTO_FILE} ${TOKEN_PROTO_FILE}
    DEPENDS ${PAIL_PROTO_FILE} ${TOKEN_PROTO_FILE}
    VERBATIM
  )

  add_custom_target(pail_proto_gen DEPENDS
    ${GEN_DIR}/pail.pb.cc
    ${GEN_DIR}/token_service.pb.cc ${GEN_DIR}/token_service.grpc.pb.cc
  )

  target_sources(pep_gate_node PRIVATE
    ${GEN_DIR}/pail.pb.cc
    ${GEN_DIR}/token_service.pb.cc
    ${GEN_DIR}/token_service.grpc.pb.cc
  )
  add_dependencies(pep_gate_node pail_proto_gen)

  target_include_directories(pep_gate_node PRIVATE ${GEN_DIR} ${GRPCPP_INCLUDE_DIRS} ${GRPC_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
  target_link_directories(pep_gate_node PRIVATE ${GRPCPP_LIBRARY_DIRS} ${GRPC_LIBRARY_DIRS} ${SODIUM_LIBRARY_DIRS})
  target_compile_options(pep_gate_node PRIVATE ${GRPCPP_CFLAGS_OTHER} ${GRPC_CFLAGS_OTHER} ${SODIUM_CFLAGS_OTHER})
  target_link_libraries(pep_gate_node ${GRPCPP_LIBRARIES} ${GRPC_LIBRARIES} ${SODIUM_LIBRARIES} protobuf::libprotobuf)

  # libpail_gate (shared library + its batteries) — one CMake, two front doors. The proto
  # root is the one this package already resolved (repo: ../../../proto; image: ../../proto).
  set(PAIL_PROTO_ROOT ${PROTO_ROOT} CACHE PATH "directory holding pail.proto and token_service.proto" FORCE)
  add_subdirectory(${PAIL_GATE_DIR} pail_gate)
endif()

# KM2-1 (§6.5): signed keyring bundle loader battery. Sodium-only — no
# rclcpp/protobuf — so it only needs the GRPC-mode sodium discovery above.

# TB-2 : token golden-vector reader. The verifier (sodium + pail.pb)
# only exists in the GRPC-ON flavor; the OFF stub returns false without a
# reason (design observation D-F5) and is not the subject here.

# E-W5 : `R-A` 게이트 경계. 동결 벡터(TB-2)에는 `:` 를 품은
# 유효 서명본이 없으므로 이 배터리는 자기 키로 자기 픽스처를 만든다 —
# 동결본은 건드리지 않는다. 벡터 파일을 읽지 않으므로 PAIL_REPO_ROOT 도 없다.

# `C-B16` : 폐기된 key_id 가 값으로 도달한다. 검증기와 적재기를
# 한 배터리에 묶는다 — 나누면 "게이트는 3값인데 적재기가 폐기를 안 읽는다"가
# 두 초록 사이의 틈으로 살 수 있다. 그 틈이 정확히 FAIL-first 에서 관측한 형태다.

# E-W2 : token_id 는 서명이 덮은 바이트에서 온다 — 의미 축.
# TB-7 과 달리 노드 TU 를 끌어오지 않는다: 시험 대상은 provider 하나이고,
# rclcpp/DDS 를 끌어오면 이 배터리의 실패가 게이트 배선 실패와 같은 줄이 된다.
if(PAIL_ENABLE_GRPC AND BUILD_TESTING)
  add_executable(test_token_id_binding
    test/test_token_id_binding.cpp
    src/grpc/token_provider_grpc.cpp
    src/grpc/grpc_channel.cpp
    ${GEN_DIR}/pail.pb.cc
    ${GEN_DIR}/token_service.pb.cc
    ${GEN_DIR}/token_service.grpc.pb.cc)
  add_dependencies(test_token_id_binding pail_proto_gen)
  target_include_directories(test_token_id_binding BEFORE PRIVATE include ${PAIL_GATE_DIR}/include ${GEN_DIR}
    ${GRPCPP_INCLUDE_DIRS} ${GRPC_INCLUDE_DIRS})
  target_link_directories(test_token_id_binding PRIVATE
    ${GRPCPP_LIBRARY_DIRS} ${GRPC_LIBRARY_DIRS})
  target_compile_options(test_token_id_binding PRIVATE
    ${GRPCPP_CFLAGS_OTHER} ${GRPC_CFLAGS_OTHER})
  target_link_libraries(test_token_id_binding
    ${GRPCPP_LIBRARIES} ${GRPC_LIBRARIES} protobuf::libprotobuf)
  add_test(NAME token_id_binding COMMAND test_token_id_binding)
endif()

if(BUILD_TESTING)
  add_executable(test_clock_warning_summary test/test_clock_warning_summary.cpp)
  target_include_directories(test_clock_warning_summary PRIVATE include)
  target_compile_options(test_clock_warning_summary PRIVATE -UNDEBUG)
  add_test(NAME clock_warning_summary COMMAND test_clock_warning_summary)
endif()

# TB-7 : node-wiring batteries. Each test TU #includes
# pep_gate_node.cpp with main() compiled out (PAIL_PEP_GATE_UNDER_TEST), so the
# node source is excluded from the source list. grpc-ON only: the node TU pulls
# sodium/proto headers, and the OFF flavor has no digest to test (G-DEP-04).
if(PAIL_ENABLE_GRPC AND BUILD_TESTING)
  set(TB7_SOURCES ${PEP_SOURCES})
  list(REMOVE_ITEM TB7_SOURCES src/pep_gate_node.cpp)
  # gate_passthrough 는 TB-17(implementation contract IC-1)이지 TB-7 이 아니다. 여기에 얹는
  # 것은 소속이 아니라 배선이 같기 때문 — 노드 TU 를 #include 하고 실 DDS 로
  # 도는 배터리는 전부 같은 소스 집합·같은 정책 픽스처를 필요로 한다. 목록을
  # 갈라 두 벌로 만들면 한쪽이 낡는 자리가 하나 더 생긴다.
  foreach(tb7 gate_evidence gate_profile gate_deadman_seal gate_polclass gate_passthrough
              gate_step_consume gate_lookup_consume recheck_boundary)
    add_executable(test_${tb7}
      test/test_${tb7}.cpp
      ${TB7_SOURCES}
      ${GEN_DIR}/pail.pb.cc
      ${GEN_DIR}/token_service.pb.cc
      ${GEN_DIR}/token_service.grpc.pb.cc)
    add_dependencies(test_${tb7} pail_proto_gen)
    ament_target_dependencies(test_${tb7} rclcpp geometry_msgs pail_msgs pail_deploy_guard)
    target_include_directories(test_${tb7} BEFORE PRIVATE include ${PAIL_GATE_DIR}/include ${GEN_DIR}
      ${GRPCPP_INCLUDE_DIRS} ${GRPC_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
    target_link_directories(test_${tb7} PRIVATE
      ${GRPCPP_LIBRARY_DIRS} ${GRPC_LIBRARY_DIRS} ${SODIUM_LIBRARY_DIRS})
    target_compile_options(test_${tb7} PRIVATE
      ${GRPCPP_CFLAGS_OTHER} ${GRPC_CFLAGS_OTHER} ${SODIUM_CFLAGS_OTHER})
    # implementation contract D-L2: 정책 파일의 부재가 기동 거부가 되면서 배선 배터리도
    # 실재하는 최소 정책이 필요해졌다. 경로는 소스 트리에서 굳힌다 — 테스트가
    # 실행되는 cwd 는 빌드 배치마다 다르고, 상대 경로의 "없다"는 "확인했고
    # 정상"과 바이트가 같다 (H-B2).
    # L-9 S7: observe 판은 gate_mode 한 줄만 다른 사본이다. 같은 자리에서 함께
    # 굳힌다 — 한쪽만 CMake 가 알고 다른 쪽을 테스트가 상대경로로 찾으면 그
    # "없다"가 다시 "확인했고 정상"이 된다.
    target_compile_definitions(test_${tb7} PRIVATE
      PAIL_TB7_POLICY_FIXTURE="${PAIL_GATE_DIR}/test/fixtures/policy_min.yaml"
      PAIL_TB7_POLICY_OBSERVE_FIXTURE="${PAIL_GATE_DIR}/test/fixtures/policy_min_observe.yaml")
    target_link_libraries(test_${tb7} yaml-cpp
      ${GRPCPP_LIBRARIES} ${GRPC_LIBRARIES} ${SODIUM_LIBRARIES} protobuf::libprotobuf)
    add_test(NAME ${tb7} COMMAND test_${tb7})
  endforeach()
  # In-process DDS still crosses process boundaries within a domain; pin each
  # battery to its own domain so parallel ctest/colcon runs cannot cross-talk
  # (the gate publishes /pail/permit, which the deadman battery subscribes to).
  set_tests_properties(gate_evidence PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=42")
  set_tests_properties(gate_profile PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=43")
  set_tests_properties(gate_deadman_seal PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=44")
  set_tests_properties(gate_polclass PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=45")
  set_tests_properties(gate_passthrough PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=46")
  set_tests_properties(gate_step_consume PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=47")
  set_tests_properties(gate_lookup_consume PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=48")
  set_tests_properties(recheck_boundary PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=49")
endif()

# SD1-1 (§4): deploy profile truth table. Header-only subject — no sodium,
# no grpc, no rclcpp — so it runs in every build configuration.
if(BUILD_TESTING)
  add_executable(test_deploy_profile test/test_deploy_profile.cpp)
  target_include_directories(test_deploy_profile BEFORE PRIVATE include ${PAIL_GATE_DIR}/include)
  add_test(NAME deploy_profile COMMAND test_deploy_profile)
endif()

# TB-1/TB-6/TB-11 : decision-core batteries. Deliberately under
# BUILD_TESTING alone — the core depends only on std headers, and running on a
# PAIL_ENABLE_GRPC=0 build is the premise of G-ENF-10. Guarding these with the
# grpc flag would silently skip them (§9.3's failure mode).
if(BUILD_TESTING)


  # implementation contract (X26): unsafe defaults. Same tier as the truth table —
  # the subject is decide() alone.

  add_executable(test_profile_monotonic test/test_profile_monotonic.cpp)
  target_include_directories(test_profile_monotonic BEFORE PRIVATE include ${PAIL_GATE_DIR}/include)
  add_test(NAME profile_monotonic COMMAND test_profile_monotonic)

  # implementation contract C3-C8/C3-C9: std-only on purpose — env parsing and the
  # expiry predicate must stay measurable on a PAIL_ENABLE_GRPC=0 build.
  add_executable(test_env_strict test/test_env_strict.cpp)
  target_include_directories(test_env_strict BEFORE PRIVATE include ${PAIL_GATE_DIR}/include)
  add_test(NAME env_strict COMMAND test_env_strict)

  # C1 contract decision matrix (preview.38 RV11): std-only — contract x provider path x build must stay
  # measurable on a PAIL_ENABLE_GRPC=0 build, where v1 is exactly the value that must be refused.
  add_executable(test_core_contract_matrix test/test_core_contract_matrix.cpp)
  target_include_directories(test_core_contract_matrix BEFORE PRIVATE include ${PAIL_GATE_DIR}/include)
  add_test(NAME core_contract_matrix COMMAND test_core_contract_matrix)

  # implementation contract D4-C2/C3/C4/C7: transport decision, std-only on purpose —
  # the choice among uds/mtls/plaintext must stay measurable (and refusable)
  # on a PAIL_ENABLE_GRPC=0 build, or tolerance hides behind grpc linkage.
  add_executable(test_control_transport test/test_control_transport.cpp)
  target_include_directories(test_control_transport BEFORE PRIVATE include ${PAIL_GATE_DIR}/include)
  add_test(NAME control_transport COMMAND test_control_transport)

  # implementation contract (C-B5): `0 = 무제한` removal — issuance-value truth table
  # (strict_verify.hpp inline) + step-overrun enforcement on the command path
  # (gate_core). std-only: the refusal must not hide behind grpc linkage.
  add_executable(test_constraint_zero
    test/test_constraint_zero.cpp
    ${PAIL_GATE_DIR}/src/gate_core.cpp)
  target_include_directories(test_constraint_zero BEFORE PRIVATE include ${PAIL_GATE_DIR}/include)
  add_test(NAME constraint_zero COMMAND test_constraint_zero)

  # implementation contract (C-B7): safety-level domain — 4값 파싱 · E-STOP kOk-only
  # 해제 · NaN 4지점. std-only: the refusal must not hide behind rclcpp/grpc.
  add_executable(test_safety_level
    test/test_safety_level.cpp
    ${PAIL_GATE_DIR}/src/gate_core.cpp)
  target_include_directories(test_safety_level BEFORE PRIVATE include ${PAIL_GATE_DIR}/include)
  add_test(NAME safety_level COMMAND test_safety_level)

  # P15-H1: fatal reports are retried off the callback thread until the issuer
  # confirms them (fatal_report_worker.hpp). std-only: no rclcpp, no grpc.
  find_package(Threads REQUIRED)
  add_executable(test_attestation_worker test/test_attestation_worker.cpp)
  target_include_directories(test_attestation_worker PRIVATE include)
  target_link_libraries(test_attestation_worker Threads::Threads)
  add_test(NAME attestation_worker COMMAND test_attestation_worker)
  add_executable(test_fatal_report_worker test/test_fatal_report_worker.cpp)
  target_include_directories(test_fatal_report_worker BEFORE PRIVATE include ${PAIL_GATE_DIR}/include)
  target_link_libraries(test_fatal_report_worker Threads::Threads)
  add_test(NAME fatal_report_worker COMMAND test_fatal_report_worker)

  # implementation contract (C-B8): world_match 3-valued predicate + indeterminate
  # verdicts on both gate paths. std-only: the refusal must not hide behind
  # rclcpp/grpc.


  # implementation contract DC-10: drift judgment (core) + baseline helpers
  # (wall_clock.hpp is header-only). Same std-only premise as the tiers above.
endif()

install(TARGETS pep_gate_node
  DESTINATION lib/${PROJECT_NAME})

# DC-8 : the judgment clock is a cross-package contract —
# the bridge's silence watchdog must read the same clock as the gate. Only
# wall_clock.hpp is exported; token/crypto headers stay package-private.
# AD-5: wall_clock.hpp now lives in libpail_gate; it is exported through this package's
# include dir so the bridge keeps finding it (`#include "pail_gate/wall_clock.hpp"`).
install(DIRECTORY ${PAIL_GATE_DIR}/include/ DESTINATION include)
ament_export_include_directories(include)

# AD-1/AD-5: the C ABI header, the shared library and the ABI .proto install from
# libpail_gate's own CMake (add_subdirectory above, GRPC=ON) — nothing else about the
# library is public.

ament_package()

# core-comm-v1: pin the immutable event digest against independent language vectors.
if(BUILD_TESTING AND PAIL_ENABLE_GRPC)
  add_executable(test_core_report_wire test/test_core_report_wire.cpp
    ${GEN_DIR}/pail.pb.cc ${GEN_DIR}/token_service.pb.cc)
  target_include_directories(test_core_report_wire PRIVATE ${GEN_DIR})
  target_link_libraries(test_core_report_wire protobuf::libprotobuf sodium)
  add_test(NAME core_report_wire COMMAND test_core_report_wire)
endif()
