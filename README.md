# C++ implementation of CLVM

## How to compile the project

### Tools to be installed before compiling the source

* CMake version 3.5 or higher

### Build

This library uses Vcpkg to manage all external libraries. Vcpkg is added as a submodule into current repository. You need to initialize it before the compiling procedure.

Following the steps to initialize the repo.

```bash
git clone https://github.com/mattxlee/clvm_cpp && cd clvm_cpp && git submodule update --init && cd vcpkg && ./bootstrap-vcpkg.sh
```

After the initialization of Vcpkg, initialize make script and start the building procedure.

```bash
cd .. && mkdir build && cd build && cmake .. -DBUILD_TEST=1 && make
```

## Test cases

Run `build/test_clvm`
