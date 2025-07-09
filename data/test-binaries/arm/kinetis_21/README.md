# Kinetis K21 Demos

## twrk21f120m-sdk
This is an SDK for the twrk21f120m development board, which uses a Kinetis K21F processor.

Examples under `boards/twrk21f120m/` can be build and used as test binaries.

### Dependencies
- `gcc-arm-none-eabi`
- `cmake`
- `make`

### build
To build the debug binaries:
```
make
```

To build the release binaries:
```
make RELEASE=1
```

To remove the executables and reset the builds:
```
make clean
```

### Adding new examples
To add a new example, simply add its directory name to the `TARGET_BUILD_DIRS` variable in the `makefile`.

### Adding new _custom_ examples
To add a new custom example, copy one of the example directories and navigate to the `armgcc` directory. In that directory, do the following:
- Remove previous cmake files
    ```sh
    find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
    ```
- Edit `CMakeLists.txt` to change file names to change the example name (matches the name of the file that includes `main`). Ideally it would match the example's directory name. Note, there will be multiple references to the old name in the `CMakeLists.txt` file.
- Rebuild the build files.
    ```sh
    make .
    ```
- Add the new example to the top-level `makefile`'s `TARGET_BUILD_DIRS` variable.
