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
find_library(bls bls)
find_library(relic_s relic_s)
find_library(sodium sodium)

include(FetchContent)

if (NOT CMAKE_BUILD_TYPE)
    set(BuildType "release")
else()
    string(TOLOWER ${CMAKE_BUILD_TYPE} BuildType)
endif()
message(STATUS "Build type: ${BuildType}")

set(ENABLE_BIP39_JNI OFF CACHE INTERNAL "")
set(ENABLE_BIP39_C OFF CACHE INTERNAL "")

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

set(utf8proc_PREFIX ${CMAKE_BINARY_DIR}/third-party/utf8proc)

include(ExternalProject)
find_program(MAKE_EXE NAMES make)

ExternalProject_Add(utf8proc
    PREFIX              ${utf8proc_PREFIX}
    URL                 https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v2.7.0.tar.gz
    URL_HASH            SHA256=4bb121e297293c0fd55f08f83afab6d35d48f0af4ecc07523ad8ec99aa2b12a1
    CONFIGURE_COMMAND   ""
    BUILD_IN_SOURCE     1
    BUILD_COMMAND       ${MAKE_EXE}
    INSTALL_COMMAND     ""
    )

set(utf8proc_SRC_DIR ${utf8proc_PREFIX}/src/utf8proc)

include_directories(
    /usr/local/include
    ${OPENSSL_INCLUDE_DIR}
    ${utf8proc_SRC_DIR}
    )

find_library(utf8proc utf8proc HINTS ${utf8proc_SRC_DIR})

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

# Library clvm_cpp
file(GLOB clvm_include_files ${CMAKE_SOURCE_DIR}/include/*)
add_library(clvm_cpp)
add_dependencies(clvm_cpp utf8proc)
target_sources(clvm_cpp PRIVATE ${clvm_cpp_src})
target_include_directories(clvm_cpp PRIVATE
    ${bip3x_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include
    )
target_link_libraries(clvm_cpp PRIVATE
    bip39
    bls
    relic_s
    OpenSSL::SSL
    OpenSSL::Crypto
    ${sodium}
    ${gmp}
    ${utf8proc}
    Boost::filesystem
    )
install(FILES ${clvm_include_files} DESTINATION include/clvm_cpp)
install(TARGETS clvm_cpp DESTINATION lib)

# Test project
if (ENABLE_TEST)
    find_package(GTest REQUIRED)
    enable_testing()
    set(test_clvm_src ${CMAKE_SOURCE_DIR}/tests/test_clvm.cpp)
    add_executable(test_clvm)
    add_dependencies(test_clvm utf8proc)
    target_sources(test_clvm PRIVATE ${test_clvm_src} ${clvm_cpp_src} ${bls_src})
    target_include_directories(test_clvm PRIVATE
        ${bip3x_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include
        )
    target_link_libraries(test_clvm PRIVATE
        bip39
        bls
        relic_s
        OpenSSL::SSL
        OpenSSL::Crypto
        ${sodium}
        ${gmp}
        ${utf8proc}
        GTest::gtest_main
        Boost::filesystem
        )
    add_test(NAME test_clvm COMMAND test_clvm)
endif()
