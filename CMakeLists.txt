cmake_minimum_required(VERSION 3.5)

set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
  CACHE STRING "Vcpkg toolchain file")

project(clvm_cpp)

set(CMAKE_CXX_STANDARD 17)

option(BUILD_TEST "Generate test binaries" OFF)

find_package(OpenSSL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(gmp REQUIRED IMPORTED_TARGET gmp)
pkg_check_modules(gmpxx REQUIRED IMPORTED_TARGET gmpxx)

include(FetchContent)

set(BUILD_BLS_PYTHON_BINDINGS "0" CACHE STRING "")
set(BUILD_BLS_TESTS "0" CACHE STRING "")
set(BUILD_BLS_BENCHMARKS "0" CACHE STRING "")

FetchContent_Declare(
    bls
    GIT_REPOSITORY https://github.com/Chia-Network/bls-signatures
    GIT_TAG 1.0.9
)

FetchContent_MakeAvailable(bls)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

file(GLOB clvm_cpp_src
    src/bech32.cpp
    src/crypto_utils.cpp
    src/key.cpp
    src/mnemonic.cpp
    src/program.cpp
    src/utils.cpp
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
    bls
    OpenSSL::SSL
    OpenSSL::Crypto
)
install(FILES ${clvm_include_files} DESTINATION include/clvm_cpp)
install(TARGETS clvm_cpp DESTINATION lib)

# Test project
if (BUILD_TEST)
    enable_testing()
    find_package(GTest CONFIG REQUIRED)
    enable_testing()
    set(test_clvm_src tests/test_clvm.cpp)
    add_executable(test_clvm)
    target_sources(test_clvm PRIVATE ${test_clvm_src})
    target_link_libraries(test_clvm PRIVATE
        clvm_cpp
        GTest::gtest
        GTest::gtest_main
    )
    add_test(NAME test_clvm COMMAND test_clvm)
endif()
