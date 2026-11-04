cmake_minimum_required(VERSION 3.8)
project(pail_motion_bridge)

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
find_package(pail_pep_gate REQUIRED)  # DC-8: wall_clock.hpp (shared judgment clock)

add_executable(motion_bridge_node src/motion_bridge_node.cpp)
ament_target_dependencies(motion_bridge_node rclcpp geometry_msgs pail_msgs pail_deploy_guard pail_pep_gate)

# TB-7 : deadman wiring battery. The test TU #includes
# motion_bridge_node.cpp with main() compiled out (PAIL_MOTION_BRIDGE_UNDER_TEST).
if(BUILD_TESTING)
  add_executable(test_elapsed_deadman test/test_elapsed_deadman.cpp)
  target_compile_features(test_elapsed_deadman PRIVATE cxx_std_17)
  ament_target_dependencies(test_elapsed_deadman rclcpp geometry_msgs pail_msgs pail_deploy_guard pail_pep_gate)
  add_test(NAME elapsed_deadman COMMAND test_elapsed_deadman)
  set_tests_properties(elapsed_deadman PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=45")
  # P37-L2 (preview.38): HOLD/RESUME diagnostics — gap, sequence-gap kinds, nonzero publish counter, rate cap.
  add_executable(test_hold_resume_diagnostics test/test_hold_resume_diagnostics.cpp)
  target_compile_features(test_hold_resume_diagnostics PRIVATE cxx_std_17)
  ament_target_dependencies(test_hold_resume_diagnostics rclcpp geometry_msgs pail_msgs pail_deploy_guard pail_pep_gate)
  add_test(NAME hold_resume_diagnostics COMMAND test_hold_resume_diagnostics)
  set_tests_properties(hold_resume_diagnostics PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=46")
  add_executable(test_deadman test/test_deadman.cpp)
  ament_target_dependencies(test_deadman rclcpp geometry_msgs pail_msgs pail_deploy_guard pail_pep_gate)
  add_test(NAME deadman COMMAND test_deadman)
  # Own DDS domain: the pep_gate batteries publish /pail/permit, which this
  # battery's bridge subscribes to — parallel runs must not cross-talk.
  set_tests_properties(deadman PROPERTIES ENVIRONMENT "ROS_DOMAIN_ID=44")
endif()

install(TARGETS motion_bridge_node DESTINATION lib/${PROJECT_NAME})

ament_package()
