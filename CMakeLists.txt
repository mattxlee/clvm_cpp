cmake_minimum_required(VERSION 3.1)

project(clvm_cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS on)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG=1")

find_package(OpenSSL REQUIRED)
find_package(unofficial-utf8proc CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

find_library(gmp gmp)

include(FetchContent)

if (CMAKE_BUILD_TYPE STREQUAL "")
  set(BuildType "release")
else()
  string(TOLOWER ${CMAKE_BUILD_TYPE} BuildType)
endif()
message(STATUS "Build type: ${BuildType}")

FetchContent_Declare(
  bip3x
  GIT_REPOSITORY https://github.com/edwardstock/bip3x
  GIT_TAG        2.2.0
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

FetchContent_MakeAvailable(bip3x toolbox bls_signature)

include_directories(
  /usr/local/include
  ${OPENSSL_INCLUDE_DIR}
  )

file(GLOB clvm_cpp_src
  ${CMAKE_SOURCE_DIR}/src/types.cpp
  ${CMAKE_SOURCE_DIR}/src/bech32.cpp
  ${CMAKE_SOURCE_DIR}/src/crypto_utils.cpp
  ${CMAKE_SOURCE_DIR}/src/key.cpp
  ${CMAKE_SOURCE_DIR}/src/mnemonic.cpp
  ${CMAKE_SOURCE_DIR}/src/program.cpp
  ${CMAKE_SOURCE_DIR}/src/utils.cpp
  ${CMAKE_SOURCE_DIR}/src/wallet.cpp
  ${CMAKE_SOURCE_DIR}/src/operator_lookup.cpp
  ${CMAKE_SOURCE_DIR}/src/core_opts.cpp
  ${CMAKE_SOURCE_DIR}/src/more_opts.cpp
  ${CMAKE_SOURCE_DIR}/src/int.cpp
  ${CMAKE_SOURCE_DIR}/src/assemble.cpp
  ${CMAKE_SOURCE_DIR}/src/coin.cpp
  )

set(test_clvm_src ${CMAKE_SOURCE_DIR}/tests/test_clvm.cpp)

add_executable(test_clvm
  ${test_clvm_src}
  ${clvm_cpp_src}
  ${bls_src}
  )
target_include_directories(test_clvm PRIVATE
  ${bip3x_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/include
  )

target_link_libraries(test_clvm PRIVATE
  bip39
  bls
  utf8proc
  OpenSSL::SSL
  OpenSSL::Crypto
  ${gmp}
  GTest::gtest_main
  )

enable_testing()
add_test(NAME test_clvm COMMAND test_clvm)
