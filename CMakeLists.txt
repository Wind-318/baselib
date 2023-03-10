cmake_minimum_required(VERSION 3.24.3)
project(Wind CXX)

# Include the GNUInstallDirs module
include(GNUInstallDirs)

# Set the installation directories for libraries, headers, and binaries
set(CMAKE_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR_DEFAULT})
set(CMAKE_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR_DEFAULT})
set(CMAKE_INSTALL_BINDIR ${CMAKE_INSTALL_BINDIR_DEFAULT})
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

# Gather source files
file(GLOB_RECURSE WIND_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/*.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/*.h"
)

# Set all sources to a variable
set(ALL_SOURCES ${WIND_SOURCES})

# Add shared library
add_library(wind SHARED ${ALL_SOURCES})
target_link_libraries(wind PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(wind PRIVATE protobuf::libprotoc protobuf::libprotobuf protobuf::libprotobuf-lite)

add_library(wind-static STATIC ${ALL_SOURCES})
target_link_libraries(wind-static PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(wind-static PRIVATE protobuf::libprotoc protobuf::libprotobuf protobuf::libprotobuf-lite)

set(WIND_INCLUDE_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}")
set(WIND_LIBRARY_DIRS "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")

install(TARGETS wind wind-static
    LIBRARY DESTINATION ${WIND_LIBRARY_DIRS}
    ARCHIVE DESTINATION ${WIND_LIBRARY_DIRS}
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DESTINATION ${WIND_INCLUDE_DIR}
    FILES_MATCHING PATTERN "*.h"
)

# Configure wind-config.cmake and wind-config-version.cmake
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/wind-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/wind-config.cmake
    INSTALL_DESTINATION ${WIND_LIBRARY_DIRS}/cmake/Wind
    PATH_VARS WIND_INCLUDE_DIR WIND_LIBRARY_DIRS
)

# Install wind-config.cmake and wind-config-version.cmake
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/wind-config.cmake
    DESTINATION
        ${WIND_LIBRARY_DIRS}/cmake/Wind
)

if (BUILD_TESTS)
  add_subdirectory(test)
endif()