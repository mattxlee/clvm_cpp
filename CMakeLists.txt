cmake_minimum_required(VERSION 3.1)

project(clvm_cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS on)

include(FetchContent)

find_package(OpenSSL REQUIRED)

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

FetchContent_Declare(
  utf8proc
  GIT_REPOSITORY https://github.com/JuliaStrings/utf8proc
  GIT_TAG        v2.7.0
  )


FetchContent_Declare(
  toolbox
  GIT_REPOSITORY https://github.com/edwardstock/toolbox
  GIT_TAG        master
  )

FetchContent_MakeAvailable(googletest bip3x utf8proc toolbox)

file(GLOB googletest_src
    ${googletest_SOURCE_DIR}/googletest/src/gtest-all.cc
    ${googletest_SOURCE_DIR}/googletest/src/gtest_main.cc
    )

set(clvm_cpp_test_src ./src/clvm_test.cpp)

add_executable(clvm_cpp_test ${clvm_cpp_test_src} ${googletest_src})
target_include_directories(clvm_cpp_test PRIVATE
  ${googletest_SOURCE_DIR}/googletest
  ${googletest_SOURCE_DIR}/googletest/include
  ${utf8proc_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  )

enable_testing()
add_test(NAME clvm_cpp_test COMMAND clvm_cpp_test)

set(clvm_cpp_src
  ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
  )

add_library(clvm_cpp ${clvm_cpp_src})
target_include_directories(clvm_cpp PRIVATE
  ${googletest_SOURCE_DIR}/googletest
  ${googletest_SOURCE_DIR}/googletest/include
  ${bip3x_SOURCE_DIR}/include
  ${utf8proc_SOURCE_DIR}
  ${toolbox_SOURCE_DIR}/include
  ${OPENSSL_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  )

