# Raw Processor

This example is to showcase the the `RawProcessor`. `RawProcessor`'s have no interrupts, and only
execute code based on a `ArchitectureVariant` and a `Backend`. This is useful for prototyping new
processors or in cases where only instruction emulation is needed but want to use Styx's
integrations like fuzzing and GDB.

## Quick Start

```console
cd examples/raw-processor
cargo run
```
