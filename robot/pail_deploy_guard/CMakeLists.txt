cmake_minimum_required(VERSION 3.8)
project(pail_deploy_guard)

add_compile_options(-Wall -Wextra -Wpedantic)

find_package(ament_cmake REQUIRED)
find_package(ament_cmake_python REQUIRED)

# Deployment guards are header-only; the optional Linux status transport
# additionally requires libsodium, but does not verify authorization tokens.
install(DIRECTORY include/ DESTINATION include)
ament_export_include_directories(include)

# Python twin for rclpy consumers (perception).
ament_python_install_package(${PROJECT_NAME})

# SD3-1 (§4): both implementations are checked against the same truth table file.
if(BUILD_TESTING)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(STATUS_SODIUM REQUIRED libsodium)
  add_executable(test_robotops_status test/test_robotops_status.cpp)
  target_include_directories(test_robotops_status PRIVATE include ${STATUS_SODIUM_INCLUDE_DIRS})
  target_link_libraries(test_robotops_status ${STATUS_SODIUM_LIBRARIES})
  add_test(NAME robotops_status COMMAND test_robotops_status)

  add_executable(test_deploy_guard test/test_deploy_guard.cpp)
  target_include_directories(test_deploy_guard PRIVATE include)
  add_test(NAME deploy_guard_cpp
    COMMAND test_deploy_guard ${CMAKE_CURRENT_SOURCE_DIR}/test/guard_matrix.tsv)

  add_test(NAME deploy_guard_py
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/test_deploy_guard.py)
  set_tests_properties(deploy_guard_py PROPERTIES
    ENVIRONMENT "PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}")

  # SD2-1 (§2.2): the S8 fingerprint list. The Go twin reads the same TSV.
  add_executable(test_known_dev_keys test/test_known_dev_keys.cpp)
  target_include_directories(test_known_dev_keys PRIVATE include)
  add_test(NAME known_dev_keys
    COMMAND test_known_dev_keys ${CMAKE_CURRENT_SOURCE_DIR}/known_dev_keys.tsv)

  # SD2-3 (§4.1): the S10 truth table. The entrypoint shell check reads the
  # same file, so the two implementations cannot drift.
  add_executable(test_thresholds test/test_thresholds.cpp)
  target_include_directories(test_thresholds PRIVATE include)
  add_test(NAME thresholds
    COMMAND test_thresholds ${CMAKE_CURRENT_SOURCE_DIR}/test/threshold_matrix.tsv)

  # SD4-1 (§2): the canonical form of the effective configuration. There is no
  # twin implementation — the issuer hashes the text it receives instead of
  # rebuilding it — so this test carries determinism, escaping and
  # distinguishability on its own.
  add_executable(test_config_seal test/test_config_seal.cpp)
  target_include_directories(test_config_seal PRIVATE include)
  add_test(NAME config_seal COMMAND test_config_seal)

  # `L10` : the process-identity line. Three implementations
  # emit it (C++ nodes, the Python perception node, Go services) and each is
  # measured where it lives — a shared test would let one of them go silent
  # while the other two keep the name green.
  add_executable(test_process_identity test/test_process_identity.cpp)
  target_include_directories(test_process_identity PRIVATE include)
  add_test(NAME process_identity COMMAND test_process_identity)

  add_test(NAME process_identity_py
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test/test_process_identity.py)
  set_tests_properties(process_identity_py PROPERTIES
    ENVIRONMENT "PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}")
endif()

ament_package()
