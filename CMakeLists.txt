cmake_minimum_required(VERSION 3.1)

project(clvm_cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS on)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG=1")

find_package(OpenSSL REQUIRED)

include(FetchContent)

string(TOLOWER ${CMAKE_BUILD_TYPE} BuildType)

if ("${BuildType}" EQUAL "")
  set(BuildType "release")
else()
  set(BuildType "debug")
endif()

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

FetchContent_Declare(
  bls_signature
  GIT_REPOSITORY https://github.com/Chia-Network/bls-signatures
  GIT_TAG        main
  )

FetchContent_MakeAvailable(googletest bip3x utf8proc toolbox bls_signature)

include_directories(
  /usr/local/include
  ${OPENSSL_INCLUDE_DIR}
  )

file(GLOB clvm_cpp_src
  ${CMAKE_SOURCE_DIR}/src/bech32.cpp
  ${CMAKE_SOURCE_DIR}/src/clvm.cpp
  ${CMAKE_SOURCE_DIR}/src/crypto_utils.cpp
  ${CMAKE_SOURCE_DIR}/src/key.cpp
  ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
  ${CMAKE_SOURCE_DIR}/src/program.cpp
  ${CMAKE_SOURCE_DIR}/src/utils.cpp
  ${CMAKE_SOURCE_DIR}/src/wallet.cpp
  ${CMAKE_SOURCE_DIR}/src/operator_lookup.cpp
  ${CMAKE_SOURCE_DIR}/src/core_opts.cpp
  )

file(GLOB googletest_src
  ${googletest_SOURCE_DIR}/googletest/src/gtest-all.cc
  ${googletest_SOURCE_DIR}/googletest/src/gtest_main.cc
  )

set(test_sha256_treehash_src ${CMAKE_SOURCE_DIR}/tests/test_sha256_treehash.cpp)

add_executable(test_sha256_treehash
  ${test_sha256_treehash_src}
  ${clvm_cpp_src}
  ${bls_src}
  ${googletest_src}
  )
target_include_directories(test_sha256_treehash PRIVATE
  ${googletest_SOURCE_DIR}/googletest
  ${googletest_SOURCE_DIR}/googletest/include
  ${bip3x_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/include
  )

target_link_options(test_sha256_treehash PRIVATE
  "-L${CMAKE_SOURCE_DIR}/../target/${BuildType}")

target_link_libraries(test_sha256_treehash
  clvm_rs
  bip39
  bls
  utf8proc
  OpenSSL::SSL
  OpenSSL::Crypto
  )

enable_testing()
add_test(NAME test_sha256_treehash COMMAND test_sha256_treehash)
