# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Glowfly Identity Systems Co.,Ltd
#
# libpail_gate — the PAIL decision library. Transport-neutral: no ROS, no gRPC. What it
# needs is protobuf (the token and ABI messages), libsodium (Ed25519 verification) and
# yaml-cpp (the sealed policy). One C ABI (include/pail_gate/pail_gate.h, protobuf-binary
# buffers of abi/pail_gate_abi.proto) and the C++ classes behind it.
#
# Standalone:
#   cmake -S libpail_gate -B build -DBUILD_TESTING=ON && cmake --build build && ctest --test-dir build
# Inside the ROS 2 workspace the gate node's package add_subdirectory()s this file, so the
# same sources and the same tests are built there too (pail_ws/src/pail_pep_gate). The
# ROS 2 node is one adapter of this library; it is not where the library lives.
cmake_minimum_required(VERSION 3.16)
project(pail_gate VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra -Wpedantic)
# strict_verify.cpp and keyring_bundle.cpp guard their libsodium/protobuf paths with
# `#if PAIL_ENABLE_GRPC` — the ROS package's build option, kept as the macro name so the
# sources stay byte-identical across the split (AD-5). The library always has protobuf and
# libsodium, so the guard is always on here; without it the crypto paths compile to stubs
# that answer ERR_GRPC_DISABLED (measured 2026-09-06: 5 of 11 batteries red on plain Debian).
add_compile_definitions(PAIL_ENABLE_GRPC=1)

find_package(Protobuf REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(yaml-cpp REQUIRED)

# The token and plan messages are the issuer's contract (../proto); the ABI schema is ours.
# PAIL_PROTO_ROOT may be pointed elsewhere by a consumer that vendors the .proto files.
# Repository layout: ../proto. Gate image layout (docker/Dockerfile.pail_pep_gate copies the
# workspace to /opt/pail_ws and this directory to /opt/libpail_gate): ../pail_ws/proto.
if(NOT DEFINED PAIL_PROTO_ROOT)
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../proto/token_service.proto)
    set(PAIL_PROTO_ROOT_DEFAULT ${CMAKE_CURRENT_SOURCE_DIR}/../proto)
  elseif(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../sdk/proto/token_service.proto)
    set(PAIL_PROTO_ROOT_DEFAULT ${CMAKE_CURRENT_SOURCE_DIR}/../sdk/proto)
  else()
    set(PAIL_PROTO_ROOT_DEFAULT ${CMAKE_CURRENT_SOURCE_DIR}/../pail_ws/proto)
  endif()
  set(PAIL_PROTO_ROOT "${PAIL_PROTO_ROOT_DEFAULT}" CACHE PATH "directory holding pail.proto and token_service.proto")
endif()
set(PAIL_PROTO_FILE ${PAIL_PROTO_ROOT}/pail.proto)
set(TOKEN_PROTO_FILE ${PAIL_PROTO_ROOT}/token_service.proto)
set(ABI_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/abi)
set(ABI_PROTO_FILE ${ABI_PROTO_DIR}/pail_gate_abi.proto)
if(NOT EXISTS ${TOKEN_PROTO_FILE})
  message(FATAL_ERROR "token_service.proto not found under PAIL_PROTO_ROOT=${PAIL_PROTO_ROOT}")
endif()

set(PAIL_GATE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen)
file(MAKE_DIRECTORY ${PAIL_GATE_GEN_DIR})
add_custom_command(
  OUTPUT ${PAIL_GATE_GEN_DIR}/pail.pb.cc ${PAIL_GATE_GEN_DIR}/pail.pb.h
         ${PAIL_GATE_GEN_DIR}/token_service.pb.cc ${PAIL_GATE_GEN_DIR}/token_service.pb.h
         ${PAIL_GATE_GEN_DIR}/pail_gate_abi.pb.cc ${PAIL_GATE_GEN_DIR}/pail_gate_abi.pb.h
  COMMAND protobuf::protoc
  ARGS -I ${PAIL_PROTO_ROOT} -I ${ABI_PROTO_DIR}
       --cpp_out=${PAIL_GATE_GEN_DIR}
       ${PAIL_PROTO_FILE} ${TOKEN_PROTO_FILE} ${ABI_PROTO_FILE}
  DEPENDS ${PAIL_PROTO_FILE} ${TOKEN_PROTO_FILE} ${ABI_PROTO_FILE}
  VERBATIM)
add_custom_target(pail_gate_proto_gen DEPENDS
  ${PAIL_GATE_GEN_DIR}/pail.pb.cc ${PAIL_GATE_GEN_DIR}/token_service.pb.cc ${PAIL_GATE_GEN_DIR}/pail_gate_abi.pb.cc)

set(PAIL_GATE_SOURCES
  src/gate_core.cpp
  src/strict_verify.cpp
  src/keyring_bundle.cpp
  src/policy_load.cpp
  src/skills_load.cpp
  src/gate_session.cpp
  src/pail_gate_abi.cpp)

add_library(pail_gate SHARED
  ${PAIL_GATE_SOURCES}
  ${PAIL_GATE_GEN_DIR}/pail.pb.cc
  ${PAIL_GATE_GEN_DIR}/token_service.pb.cc
  ${PAIL_GATE_GEN_DIR}/pail_gate_abi.pb.cc)
add_dependencies(pail_gate pail_gate_proto_gen)
set_target_properties(pail_gate PROPERTIES
  VERSION ${PROJECT_VERSION} SOVERSION 1
  POSITION_INDEPENDENT_CODE ON)
target_include_directories(pail_gate
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
  PRIVATE ${PAIL_GATE_GEN_DIR} ${SODIUM_INCLUDE_DIRS})
target_link_directories(pail_gate PRIVATE ${SODIUM_LIBRARY_DIRS})
target_compile_options(pail_gate PRIVATE ${SODIUM_CFLAGS_OTHER})
target_link_libraries(pail_gate PRIVATE yaml-cpp ${SODIUM_LIBRARIES} protobuf::libprotobuf)

install(TARGETS pail_gate LIBRARY DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
install(FILES abi/pail_gate_abi.proto DESTINATION share/pail_gate/abi)

# ---- tests ---------------------------------------------------------------------------------
# The same batteries whether built here or through the ROS workspace: ctest names are the
# ones tests/RUNBOOK.yaml calls (gate_core, gate_failclosed, contract_golden, gate_two_doors …).
option(BUILD_TESTING "Build the library's test batteries" OFF)
if(BUILD_TESTING)
  enable_testing()
  set(PAIL_GATE_REPO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

  # Core-only batteries: gate_core.cpp alone, no protobuf.
  foreach(t gate_core gate_failclosed gate_defaults world_match time_strict clock_drift)
    add_executable(test_${t} test/test_${t}.cpp src/gate_core.cpp)
    target_include_directories(test_${t} PRIVATE include)
    add_test(NAME ${t} COMMAND test_${t})
  endforeach()

  # Verification batteries: strict_verify against the golden vectors and the RA rules.
  foreach(t contract_golden ra_boundary token_v5)
    add_executable(test_${t} test/test_${t}.cpp src/strict_verify.cpp ${PAIL_GATE_GEN_DIR}/pail.pb.cc)
    add_dependencies(test_${t} pail_gate_proto_gen)
    target_include_directories(test_${t} PRIVATE include ${PAIL_GATE_GEN_DIR} ${SODIUM_INCLUDE_DIRS})
    target_link_directories(test_${t} PRIVATE ${SODIUM_LIBRARY_DIRS})
    target_link_libraries(test_${t} ${SODIUM_LIBRARIES} protobuf::libprotobuf)
    add_test(NAME ${t} COMMAND test_${t})
  endforeach()
  set_tests_properties(contract_golden PROPERTIES ENVIRONMENT "PAIL_REPO_ROOT=${PAIL_GATE_REPO_ROOT}")

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_step_clock_injection test/test_step_clock_injection.cpp)
    add_dependencies(test_step_clock_injection pail_gate_proto_gen)
    target_include_directories(test_step_clock_injection PRIVATE ${PAIL_GATE_GEN_DIR} ${SODIUM_INCLUDE_DIRS})
    target_link_directories(test_step_clock_injection PRIVATE ${SODIUM_LIBRARY_DIRS})
    target_link_libraries(test_step_clock_injection pail_gate ${SODIUM_LIBRARIES} protobuf::libprotobuf)
    target_link_options(test_step_clock_injection PRIVATE -Wl,--export-dynamic)
    target_compile_definitions(test_step_clock_injection PRIVATE
      PAIL_CLOCK_POLICY="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/policy_min.yaml")
    add_test(NAME step_clock_injection COMMAND test_step_clock_injection)
  endif()

  add_executable(test_step_clock test/test_step_clock.cpp)
  target_link_libraries(test_step_clock pail_gate)
  add_test(NAME step_clock COMMAND test_step_clock)

  add_executable(test_session_snapshot test/test_session_snapshot.cpp)
  target_link_libraries(test_session_snapshot pail_gate)
  add_test(NAME session_snapshot COMMAND test_session_snapshot)

  # SK-2: the gate's read of the skill registry and S33 (yaml-cpp + libsodium sha256).
  add_executable(test_skills_load test/test_skills_load.cpp src/skills_load.cpp)
  target_include_directories(test_skills_load PRIVATE include ${SODIUM_INCLUDE_DIRS})
  target_link_directories(test_skills_load PRIVATE ${SODIUM_LIBRARY_DIRS})
  target_link_libraries(test_skills_load yaml-cpp ${SODIUM_LIBRARIES})
  add_test(NAME skills_load COMMAND test_skills_load)

  add_executable(test_key_revocation test/test_key_revocation.cpp src/strict_verify.cpp src/keyring_bundle.cpp ${PAIL_GATE_GEN_DIR}/pail.pb.cc)
  add_dependencies(test_key_revocation pail_gate_proto_gen)
  target_include_directories(test_key_revocation PRIVATE include ${PAIL_GATE_GEN_DIR} ${SODIUM_INCLUDE_DIRS})
  target_link_directories(test_key_revocation PRIVATE ${SODIUM_LIBRARY_DIRS})
  target_link_libraries(test_key_revocation ${SODIUM_LIBRARIES} protobuf::libprotobuf)
  add_test(NAME key_revocation COMMAND test_key_revocation)

  add_executable(test_keyring_bundle test/test_keyring_bundle.cpp src/keyring_bundle.cpp)
  target_include_directories(test_keyring_bundle PRIVATE include ${SODIUM_INCLUDE_DIRS})
  target_link_directories(test_keyring_bundle PRIVATE ${SODIUM_LIBRARY_DIRS})
  target_link_libraries(test_keyring_bundle ${SODIUM_LIBRARIES})
  add_test(NAME keyring_bundle COMMAND test_keyring_bundle)

  # Two doors (AD-1): the C++ session and the C ABI side by side, through the shared library.
  add_executable(test_gate_two_doors test/test_gate_two_doors.cpp)
  add_dependencies(test_gate_two_doors pail_gate_proto_gen)
  target_include_directories(test_gate_two_doors PRIVATE include ${PAIL_GATE_GEN_DIR} ${SODIUM_INCLUDE_DIRS})
  target_link_directories(test_gate_two_doors PRIVATE ${SODIUM_LIBRARY_DIRS})
  target_compile_definitions(test_gate_two_doors PRIVATE
    PAIL_TB7_POLICY_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/policy_min.yaml"
    PAIL_TB7_POLICY_OBSERVE_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/policy_min_observe.yaml"
    PAIL_SK3_SKILLS_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/skills_test.yaml")
  target_link_libraries(test_gate_two_doors pail_gate ${SODIUM_LIBRARIES} protobuf::libprotobuf)
  add_test(NAME gate_two_doors COMMAND test_gate_two_doors)

  # P15-H1: the local fatal latch — a chain the session declared fatal stays refused
  # after safety returns to OK even when the issuer still serves its token. Both doors.
  add_executable(test_fatal_latch test/test_fatal_latch.cpp)
  add_dependencies(test_fatal_latch pail_gate_proto_gen)
  target_include_directories(test_fatal_latch PRIVATE include ${PAIL_GATE_GEN_DIR} ${SODIUM_INCLUDE_DIRS})
  target_link_directories(test_fatal_latch PRIVATE ${SODIUM_LIBRARY_DIRS})
  target_compile_definitions(test_fatal_latch PRIVATE
    PAIL_TB7_POLICY_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/policy_min.yaml")
  target_link_libraries(test_fatal_latch pail_gate ${SODIUM_LIBRARIES} protobuf::libprotobuf)
  add_test(NAME fatal_latch COMMAND test_fatal_latch)

  # SEC-H02: a running gate honours the expiry of its bundle, takes up a newer bundle
  # without a restart, and refuses a key the applied bundle revokes. Both doors; the one
  # seam to the product is test/h02_door.hpp.
  add_executable(test_trust_live test/test_trust_live.cpp)
  add_dependencies(test_trust_live pail_gate_proto_gen)
  target_include_directories(test_trust_live PRIVATE include ${PAIL_GATE_GEN_DIR} ${SODIUM_INCLUDE_DIRS})
  target_link_directories(test_trust_live PRIVATE ${SODIUM_LIBRARY_DIRS})
  target_compile_definitions(test_trust_live PRIVATE
    PAIL_H02_POLICY_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/policy_min.yaml")
  target_link_libraries(test_trust_live pail_gate ${SODIUM_LIBRARIES} protobuf::libprotobuf)
  add_test(NAME trust_live COMMAND test_trust_live)

  # SEC-H02: the parity vectors, gate loader side. The Go loader reads the same file.
  add_executable(test_trust_vectors test/test_trust_vectors.cpp src/keyring_bundle.cpp)
  target_include_directories(test_trust_vectors PRIVATE include ${SODIUM_INCLUDE_DIRS})
  target_link_directories(test_trust_vectors PRIVATE ${SODIUM_LIBRARY_DIRS})
  target_link_libraries(test_trust_vectors yaml-cpp ${SODIUM_LIBRARIES})
  add_test(NAME trust_vectors COMMAND test_trust_vectors)
  set_tests_properties(trust_vectors PROPERTIES ENVIRONMENT "PAIL_REPO_ROOT=${PAIL_GATE_REPO_ROOT}")
endif()
