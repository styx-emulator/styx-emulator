# Raw Processor

This example is to showcase the the `RawProcessor`. `RawProcessor`'s have no interrupts, and only
execute code based on a `ArchitectureVariant` and a `Backend`. This is useful for prototyping new
processors or in cases where only instruction emulation is needed but want to use Styx's
integrations like fuzzing and GDB.

**NOTE**: This example shows off using the `ParameterizedLoader` with the `RawProcessor`,
with the `load.yaml` file populated with exemplar values. This example will error if you attempt to run the example as-is since
the `load.yaml` doesn't point to real existing test binaries for `SuperH2A`, it is meant
to demonstrate how you could start to "build your own" `ProcessorImpl` and kickstart you.

## Modifying this example to work

The bare minimum to get this example to execute code it needs:
- a valid `SuperH2A` elf named `foo.elf` (that has a base address at `0x10000`)
- a file `bar.bin` size 0x40 (anything larger will be silently overriden by the next item, which happens to be `hurr.bin` being loaded at `0x90040`)
- a file `hurr.bin`
