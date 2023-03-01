cmake_minimum_required(VERSION 3.24.3)
project(wind_test CXX)

include(GoogleTest)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_STANDARD 20)
message(STATUS "Use C++20")

set(TEST_SRC 
    ${CMAKE_CURRENT_SOURCE_DIR}/unit_test/utils/pwt_test.pb.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/unit_test/utils/pwt_test.pb.h
    ${CMAKE_CURRENT_SOURCE_DIR}/unit_test/utils/time_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/unit_test/utils/encrypt_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/unit_test/utils/pwt_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/unit_test/wind/atomic_data_structure_test.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/benchmark/pwt_benchmark.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cc
)

add_executable(${PROJECT_NAME} ${TEST_SRC})
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(${PROJECT_NAME} PRIVATE protobuf::libprotobuf)
target_link_libraries(${PROJECT_NAME} PRIVATE GTest::gmock GTest::gtest GTest::gmock_main GTest::gtest_main)
target_link_libraries(${PROJECT_NAME} PRIVATE benchmark::benchmark benchmark::benchmark_main)
target_link_libraries(${PROJECT_NAME} PRIVATE WindStatic)

gtest_discover_tests(${PROJECT_NAME})
