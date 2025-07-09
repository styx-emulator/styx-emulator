# Common Emulation Args

Running styx emulations requires a potentialy large number of required and optional input parameters. We want to centralize the parsing and validation of these parameters for applications (rust-based, python-based, web-based, ...). Furthermore, since running emulations is also exposed via `gRPC` service, it makes sense to extend the functionality to services.

In fact, since emulation parameters must be sent across the wire for `gRPC` services, it make sense to use messages and enumerations defined in the google protobuf proto files as the definition of the emulation parameters (arguments).

Since styx core and service crates are implemented in `rust`, and the de-facto standard for parsing arguments in `rust` is `clap`, it also makes sense to leverage clap parsing.

## Mechanism

In short, the _common emulation args_ mechanism is implemented with two proc macros - `styx_args` and `styx_app_args`. The emulation args are defined inin [args.proto](../styx-grpc/proto/args/args.proto).

### styx_args

During `tonic` proto generation, every message and emumeration gets decorated with `[styx_macros_args::styx_args]` to _clapify_ the item. See [lib.rs](./styx-macros-args/src/lib.rs) for details.

### styx_app_args

This macro defines a _clapified_ `struct` that can be used in the normal sens that a clap argument struct would be used, except that it will automatically include the messages and enumerations defined in the `EmulationArgs` message from the `args.proto`. For example:

```rust
#[styx_macros_args::styx_app_args]
struct MyArgs {}
pub fn main() {
    let args = MyArgs::parse();
    println!("{}", myargs.target);
    ...
}
```

Additional arguments can also be added, using plain old clap syntax, and will work as one would expect:

```rust
#[styx_macros_args::styx_app_args]
struct MyExpandedArgs {
    /// Duration in seconds to run the emulator
    #[arg(long, default_value("0"))]
    emu_duration: u64,
    /// Stop after this many instructions
    #[arg(long, default_value("0"))]
    max_insn: u64,
}
pub fn main() {
    let args = MyExpandedArgs::parse();
    println!("{}", myargs.target);
    println!("{}", myargs.emu_duration);
    println!("{}", myargs.emu_duration);
    ...
}
```
