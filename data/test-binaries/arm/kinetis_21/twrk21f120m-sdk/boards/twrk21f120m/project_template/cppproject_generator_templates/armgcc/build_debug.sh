#!/bin/sh
cmake -DCMAKE_TOOLCHAIN_FILE="../../../../../tools/cmake_toolchain_files/armgcc_force_cpp.cmake" -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug  .
make -j4
