cmake -DCMAKE_TOOLCHAIN_FILE="../../../../../tools/cmake_toolchain_files/armgcc_force_cpp.cmake" -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Debug  .
mingw32-make -j4
cmake -DCMAKE_TOOLCHAIN_FILE="../../../../../tools/cmake_toolchain_files/armgcc_force_cpp.cmake" -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release  .
mingw32-make -j4
IF "%1" == "" ( pause )
