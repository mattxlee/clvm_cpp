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

FetchContent_Declare(Sodium
  GIT_REPOSITORY https://github.com/AmineKhaldi/libsodium-cmake.git
  # Latest commit at the moment this was added here
  # Anchored to libsodium v1.0.18
  GIT_TAG f73a3fe1afdc4e37ac5fe0ddd401bf521f6bba65
)

FetchContent_Declare(
  relic
  GIT_REPOSITORY https://github.com/Chia-Network/relic.git
  GIT_TAG  "1d98e5abf3ca5b14fd729bd5bcced88ea70ecfd7"
)

FetchContent_MakeAvailable(googletest bip3x utf8proc toolbox bls_signature
  Sodium relic)

include_directories(/usr/local/include)

find_package(OpenSSL REQUIRED)
find_library(gmp gmp)

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
  ${CMAKE_SOURCE_DIR}/src/key.cpp
  )

add_library(clvm_cpp ${clvm_cpp_src})
target_include_directories(clvm_cpp PRIVATE
  ${googletest_SOURCE_DIR}/googletest
  ${googletest_SOURCE_DIR}/googletest/include
  ${bip3x_SOURCE_DIR}/include
  ${utf8proc_SOURCE_DIR}
  ${toolbox_SOURCE_DIR}/include
  ${bls_signature_SOURCE_DIR}/src
  ${relic_SOURCE_DIR}/include
  ${relic_BINARY_DIR}/include
  ${OPENSSL_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  )

