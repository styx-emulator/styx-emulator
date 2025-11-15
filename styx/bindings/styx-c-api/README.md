# styx-c-api

C bindings for the Styx Emulator suite.

This crate uses `crate-type = ["cdylib", "staticlib"]` to generate archive and shared object library artifacts, and [`cbindgen`](https://github.com/mozilla/cbindgen/) to generate a C compatible header file.

You can build the crate as you would a normal rust crate via `cargo build` or `cargo build --release`. A `build.rs` uses `cbindgen` to update the header file automatically.

After building, the header file is located in `styx-c-api/inc/styx_emulator.h`. Archive and shared object files are located in `target/[debug|release]/libstyx_c_api.[a|so]`. Note that the target folder for the `styx-c-api` is in `styx/bindings/target`.

An example C source file and Makefile are available in `examples/stm32f107-processor`.
