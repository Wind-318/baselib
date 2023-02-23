cmake_minimum_required(VERSION 3.24.3)
project(wind CXX)

set(CMAKE_CXX_STANDARD 20)
message(STATUS "Use C++20")

option(BUILD_TESTS "Build tests" OFF)

# Set the output directory for executables and libraries
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(WIN32)
    if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
        message(FATAL_ERROR "Please specify the path to the vcpkg toolchain file with the CMAKE_TOOLCHAIN_FILE variable.")
    endif()
    include(${CMAKE_TOOLCHAIN_FILE})
    find_package(Protobuf CONFIG REQUIRED)
    if (BUILD_TESTS)
      find_package(GTest CONFIG REQUIRED)
      find_package(benchmark CONFIG REQUIRED)
    endif()
else()
    find_package(Protobuf REQUIRED)
    if (BUILD_TESTS)
      find_package(GTest REQUIRED)
      find_package(benchmark REQUIRED)
    endif()
endif()

find_package(OpenSSL REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/time
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/encrypt
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/pwt
)

# Gather source files
file(GLOB_RECURSE WIND_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/time/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/encrypt/*.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/encrypt/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/pwt/*.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/pwt/*.h"
)

# Set all sources to a variable
set(ALL_SOURCES ${WIND_SOURCES})

# Add shared library
add_library(WindShared SHARED ${ALL_SOURCES})
target_link_libraries(WindShared PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(WindShared PRIVATE protobuf::libprotoc protobuf::libprotobuf protobuf::libprotobuf-lite)

# Add static library
add_library(WindStatic STATIC ${ALL_SOURCES})
target_link_libraries(WindStatic PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(WindStatic PRIVATE protobuf::libprotoc protobuf::libprotobuf protobuf::libprotobuf-lite)

install(TARGETS WindShared WindStatic
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/utils/
        DESTINATION include/wind
        FILES_MATCHING PATTERN "*.h")

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/utils/
        DESTINATION include/wind
        FILES_MATCHING PATTERN "*.cc")

if (BUILD_TESTS)
  add_subdirectory(test)
endif()