cmake_minimum_required(VERSION 3.4)

project(clvm_cpp)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS on)

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG=1")

option(ENABLE_TEST "compile test")

set(CMAKE_POLICY_DEFAULT_CMP0127 NEW)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED filesystem)

find_library(gmp gmp)

find_library(relic_s relic_s)
find_package(unofficial-sodium CONFIG REQUIRED)

include(FetchContent)

if (NOT CMAKE_BUILD_TYPE)
    set(BuildType "release")
else()
    string(TOLOWER ${CMAKE_BUILD_TYPE} BuildType)
endif()
message(STATUS "Build type: ${BuildType}")

set(ENABLE_BIP39_JNI OFF CACHE INTERNAL "")
set(ENABLE_BIP39_C OFF CACHE INTERNAL "")

set(BUILD_BLS_PYTHON_BINDINGS "0" CACHE STRING "disable bls python bindings")
set(BUILD_BLS_TESTS "0" CACHE STRING "disable bls tests")
set(BUILD_BLS_BENCHMARKS "0" CACHE STRING "disable bls benchmarks")

FetchContent_Declare(
    bip3x
    GIT_REPOSITORY https://github.com/edwardstock/bip3x
    GIT_TAG        2.2.0
    )

FetchContent_Declare(
    bls
    GIT_REPOSITORY https://github.com/Chia-Network/bls-signatures
    GIT_TAG 1.0.9
    )

FetchContent_MakeAvailable(bip3x bls)

find_package(unofficial-utf8proc CONFIG REQUIRED)

include_directories(
    /usr/local/include
    include
    ${bip3x_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    )

file(GLOB clvm_cpp_src
    src/types.cpp
    src/bech32.cpp
    src/crypto_utils.cpp
    src/key.cpp
    src/mnemonic.cpp
    src/program.cpp
    src/utils.cpp
    src/wallet.cpp
    src/operator_lookup.cpp
    src/core_opts.cpp
    src/more_opts.cpp
    src/int.cpp
    src/assemble.cpp
    src/coin.cpp
    )

# Library clvm_cpp
file(GLOB clvm_include_files include/*)
add_library(clvm_cpp STATIC)
target_sources(clvm_cpp PRIVATE ${clvm_cpp_src})
target_link_libraries(clvm_cpp PRIVATE
    bip39
    bls
    relic_s
    OpenSSL::SSL
    OpenSSL::Crypto
    unofficial-sodium:sodium
    ${gmp}
    utf8proc
    Boost::filesystem
    )
install(FILES ${clvm_include_files} DESTINATION include/clvm_cpp)
install(TARGETS clvm_cpp DESTINATION lib)

# Test project
if (ENABLE_TEST)
    find_package(GTest CONFIG REQUIRED)
    enable_testing()
    set(test_clvm_src tests/test_clvm.cpp)
    add_executable(test_clvm)
    target_sources(test_clvm PRIVATE ${test_clvm_src} ${clvm_cpp_src} ${bls_src})
    target_link_libraries(test_clvm PRIVATE
        bip39
        bls
        relic_s
        OpenSSL::SSL
        OpenSSL::Crypto
        unofficial-sodium:sodium
        ${gmp}
        ${utf8proc}
        GTest::gtest
        GTest::gtest_main
        Boost::filesystem
        )
    add_test(NAME test_clvm COMMAND test_clvm)
endif()
