# `styx-stm32f745-sys`

Generated using [`svd2rust`](https://github.com/styx-emulator/svd2rust) with styx's modifications,
`v0.32.0`, `5cee78`.

This crate was created using the following commands:

```shell
cargo new --lib styx-stm32f745-sys && cd styx-stm32f745-sys/
svd2rust --target none --field-names-for-enums --feature-peripheral -i ../STM32F745.svd
form -i lib.rs -o src/ && rm lib.rs
cargo fmt
```

## Licenses

### `svd2rust`

Licensed under either of

- Apache License, Version 2.0 (<https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license (<https://opensource.org/licenses/MIT>)

at your option.
