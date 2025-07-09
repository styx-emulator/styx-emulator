# Args macros

## styx_args

Added by `build.rs` while generating proto bufs:
        `.type_attribute(".args", "#[styx_macros_args::styx_args]`

proc_macro

- derive_clap:

### Grpc Messages

- adds `SomeMessageParser`

```rust
#[derive(clap::Parser, Debug, Clone)]
pub struct SomeMessageParser {
    #[clap(flatten)]
    inner: #ident,
}
```

- adds `SomeMessageValueParser`

```rust
#[derive(Clone, Default)]
pub struct SomeMessageValueParser {}
impl clap::builder::TypedValueParser for SomeMessageValueParser {
}
```

- adds `#[derive(clap::Args)]`
- impl SomeMessage

```rust
try_parser_or_default
long_arg_name()
```
