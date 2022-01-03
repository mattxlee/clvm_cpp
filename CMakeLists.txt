cmake_minimum_required(VERSION 3.1)

project(clvm_cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS on)

include(FetchContent)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        release-1.11.0
)

FetchContent_Declare(
  bip3x
  GIT_REPOSITORY https://github.com/edwardstock/bip3x
  GIT_TAG        2.2.0
)

FetchContent_MakeAvailable(googletest bip3x)

file(GLOB googletest_src
    ${googletest_SOURCE_DIR}/googletest/src/gtest-all.cc
    ${googletest_SOURCE_DIR}/googletest/src/gtest_main.cc
    )

set(clvm_cpp_test_src ./src/clvm_test.cpp)

add_executable(clvm_cpp_test ${clvm_cpp_test_src} ${googletest_src})
target_include_directories(clvm_cpp_test PRIVATE
    ${googletest_SOURCE_DIR}/googletest
    ${googletest_SOURCE_DIR}/googletest/include
    )

enable_testing()
add_test(NAME clvm_cpp_test COMMAND clvm_cpp_test)

