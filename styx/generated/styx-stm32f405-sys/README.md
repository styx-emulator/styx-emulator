# `styx-stm32f405-sys`

Generated using [`svd2rust`](https://github.com/styx-emulator/svd2rust) with styx's modifications,
`v0.32.0`, `5cee78`.

This crate was created using the following commands:

```shell
cargo new --lib styx-stm32f405-sys && cd styx-stm32f405-sys/
svd2rust --target none --field-names-for-enums --feature-peripheral -i ../STM32F405.svd
form -i lib.rs -o src/ && rm lib.rs
cargo fmt
```

## Licenses

### `svd2rust`

Licensed under either of

- Apache License, Version 2.0 (<https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license (<https://opensource.org/licenses/MIT>)

at your option.

## Notes

### Feature Flags

The UART4 and UART5 global interrupt definitions `interrupt.rs` are generated behind the `"uart4"` and `"uart5"` feature flags, which is a bit odd. Not a huge issue but just a little weird.
