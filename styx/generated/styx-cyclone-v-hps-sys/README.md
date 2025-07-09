# `styx-cyclone-v-hps-sys`

Generated using [`svd2rust`](https://docs.rs/svd2rust/latest/svd2rust/).

This crate was created using the following commands:

```shell
cargo new --lib styx-cyclone-v-hps-sys && cd styx-cyclone-v-hps-sys/
svd2rust --target none --field-names-for-enums --feature-peripheral -i ../altera_hps.svd
form -i lib.rs -o src/ && rm lib.rs
cargo fmt
```

## Licenses

### `svd2rust`

Licensed under either of

- Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
- MIT license (https://opensource.org/licenses/MIT)

at your option.
