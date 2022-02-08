# C++ implementation of CLVM

## How to compile the project

### Tools to be installed before compiling the source

* Conan

* CMake version 3.1 or higher

### Libraries should be installed before the compiling

* OpenSSL - Install OpenSSL by using the package manager on your system.

* GMP - Install GMP manually with `./configure --enable-cxx`.

### Prepare

* Create the build dir under the project root `mkdir build`.

* Switch into the build dir and run command `cmake .. -DCMAKE_BUILD_TYPE=Debug`.

### Build

* Run command `make` under the build dir.

## Test cases

Run `build/test_clvm`
